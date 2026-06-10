import { LucairnCertificateError } from '../errors.js';
import type {
  VeilCertificate,
  VerifyCertificateKeys,
  VerifyCertificateOptions,
  VerifyCertificateResult,
} from '../types.js';
import { parseCertificate } from './parse.js';
import { deriveWitnessSignedBytes, deriveWitnessSignedBytesV3 } from './signable.js';
import { verifyEd25519 } from './signature.js';

const SUPPORTED_PROTOCOL_VERSION = 2;
// Minimum signable_protocol_version_emitted value that triggers v3 verification.
const V3_SIGNABLE_VERSION_THRESHOLD = 3;

/**
 * Verify a Veil Certificate's witness Ed25519 signature against the
 * certificate's canonical JSON core fields.
 *
 * Version dispatch: when `cert.signable_protocol_version_emitted >= 3` AND
 * `cert.signable_v3_signature` is present, the SDK verifies the 13-key v3
 * signable and returns `signableVersion: 'v3'`. Otherwise it verifies the
 * legacy 7-key v2 signable (using `witness_signature` / `signable_v2_signature`)
 * and returns `signableVersion: 'v2'`.
 *
 * Both v2 and v3 use the SAME witness Ed25519 key — the caller passes the same
 * `keys.witnessPublicKey` for both versions.
 *
 * External RFC 3161 timestamp verification and Sigstore Rekor transparency-
 * log verification are OUT OF SCOPE for this arc; they land in a follow-up
 * arc (2b-cert-strong) pending gateway fixes:
 *   - Declade/dual-sandbox-architecture#42 (anchor_status reliability bug)
 *   - Declade/dual-sandbox-architecture#43 (populate attestation.timestamp)
 *   - Declade/dual-sandbox-architecture#44 (populate attestation.transparency_log)
 *
 * The result surfaces `anchorStatus` and `overallVerdict` as pass-through
 * metadata with JSDoc caveats — the SDK does NOT independently verify them.
 *
 * @param rawCert - protojson-shaped `VeilCertificate` as served by the
 *   gateway at GET /api/v1/veil/certificate/{request_id}. This arc does
 *   NOT fetch the certificate; the caller is responsible for transport.
 * @param keys.witnessKeyId - expected operator-configured label (e.g.
 *   "witness_v1") asserted against `cert.witness_key_id`. Mismatch throws
 *   `LucairnCertificateError({ reason: 'witness_mismatch' })` before any
 *   signature check runs.
 * @param keys.witnessPublicKey - raw 32-byte Ed25519 public key as
 *   `Uint8Array`, OR a base64 string encoding those 32 bytes. NOT PEM
 *   SPKI. Malformed input surfaces as
 *   `LucairnCertificateError({ reason: 'invalid_signature', cause })`.
 * @param options.minimumSignableVersion - when `'v3'`, throws
 *   `LucairnCertificateError({ reason: 'signable_version_insufficient' })`
 *   if the cert is verified via the v2 path. Use this when you rely on
 *   v3-only witness-signed fields (api_key_id, client_id, byok_exempt,
 *   and the sanitizer hash fields). Default: `undefined` (accept both).
 *
 * @returns `VerifyCertificateResult` on success. `signableVersion` indicates
 *   which protocol version was verified ('v2' or 'v3'). `v3SignatureStripped`
 *   is always `false` on a successful return (the downgrade check throws
 *   before returning when a stripped v3 sig is detected).
 *
 * @security When `result.signableVersion === 'v2'`, the fields `api_key_id`,
 *   `client_id`, `byok_exempt`, `redaction_manifest_hash`,
 *   `sanitized_fields_body_hash`, and `tms_manifest_hash` are NOT covered by
 *   the witness Ed25519 signature. Pass `{ minimumSignableVersion: 'v3' }` to
 *   enforce v3 at the call site if you rely on those fields.
 *
 * @throws `LucairnCertificateError` with one of 7 reasons:
 *   - `malformed` — cert shape invalid, or gateway invariant broken
 *     (cert.request_id mismatch vs claims[0]), or unknown verdict literal
 *   - `unsupported_protocol_version` — cert.protocol_version !== 2
 *   - `witness_mismatch` — keys.witnessKeyId !== cert.witness_key_id
 *   - `witness_signature_missing` — cert.witness_signature is empty or
 *     whitespace-only
 *   - `invalid_signature` — Ed25519 verification failed, or the provided
 *     witnessPublicKey is malformed
 *   - `version_downgrade_detected` — `signable_v3_signature` is present but
 *     `signable_protocol_version_emitted` is absent or < 3; this is a
 *     structural anomaly consistent with an attacker stripping the version
 *     field to force the v2 path and leave v3-only fields unverified
 *   - `signable_version_insufficient` — `options.minimumSignableVersion` is
 *     `'v3'` but the resolved signable version is `'v2'`
 */
export async function verifyCertificate(
  rawCert: unknown,
  keys: VerifyCertificateKeys,
  options?: VerifyCertificateOptions,
): Promise<VerifyCertificateResult> {
  // Guard: null/undefined/non-object keys argument.
  if (keys === null || typeof keys !== 'object') {
    throw new TypeError('verifyCertificate: keys argument is required');
  }

  // Step 1: structural parse → malformed on bad shape / missing required
  // fields / non-string overall_verdict.
  const cert = parseCertificate(rawCert);

  // Step 2: protocol-version guard — forward-compat escape hatch. A newer
  // gateway that emits protocol_version=3 with a different signing rule
  // would otherwise silently fail invalid_signature; this surfaces the
  // "upgrade your SDK" intent loudly.
  if (cert.protocol_version !== SUPPORTED_PROTOCOL_VERSION) {
    throw new LucairnCertificateError(
      `Unsupported Veil protocol version: ${cert.protocol_version} (SDK supports ${SUPPORTED_PROTOCOL_VERSION})`,
      { reason: 'unsupported_protocol_version', certificateId: cert.certificate_id },
    );
  }

  // Step 3: witness identity — cheap string check before any crypto work.
  if (cert.witness_key_id !== keys.witnessKeyId) {
    throw new LucairnCertificateError(
      `Witness key ID mismatch: cert has "${cert.witness_key_id}", expected "${keys.witnessKeyId}"`,
      { reason: 'witness_mismatch', certificateId: cert.certificate_id },
    );
  }

  // Step 4: signature presence. trim() routes "" AND whitespace-only
  // signatures to the same reason.
  if (cert.witness_signature.trim().length === 0) {
    throw new LucairnCertificateError('Certificate has no witness signature', {
      reason: 'witness_signature_missing',
      certificateId: cert.certificate_id,
    });
  }

  // Step 5: version dispatch.
  //
  // Use v3 path when ALL of:
  //   (a) cert.signable_protocol_version_emitted >= 3
  //   (b) cert.signable_v3_signature is present and non-empty
  //
  // Otherwise fall back to v2 (legacy + dual-protocol certs served to v0.5.x SDK).
  const sigEmitted = cert.signable_protocol_version_emitted ?? 0;
  const v3SigRaw = cert.signable_v3_signature;
  const v3SigPresent = typeof v3SigRaw === 'string' && v3SigRaw.trim().length > 0;
  const useV3 = sigEmitted >= V3_SIGNABLE_VERSION_THRESHOLD && v3SigPresent;

  // Step 5a: downgrade-attack guard (TOB-SDK-TS-01).
  //
  // A v3 signature is present but the version indicator is absent or < 3.
  // Legitimate v3 certs ALWAYS carry signable_protocol_version_emitted >= 3;
  // legitimate v2-only certs NEVER carry signable_v3_signature. The only path
  // that reaches here is a tampered cert where an attacker stripped the version
  // field to force the v2 path, which would leave the 6 v3-only fields
  // (api_key_id, client_id, byok_exempt, redaction_manifest_hash,
  // sanitized_fields_body_hash, tms_manifest_hash) unverified while returning
  // valid=true. We hard-reject rather than silently downgrade.
  if (v3SigPresent && !useV3) {
    throw new LucairnCertificateError(
      'Version downgrade detected: signable_v3_signature is present but ' +
        `signable_protocol_version_emitted (${sigEmitted}) is below the v3 threshold (${V3_SIGNABLE_VERSION_THRESHOLD}). ` +
        'This is structurally anomalous — legitimate v2-only certs never carry a v3 signature. ' +
        'Pass the cert without modification; if you control the signing infrastructure, ensure ' +
        'signable_protocol_version_emitted is set correctly.',
      { reason: 'version_downgrade_detected', certificateId: cert.certificate_id },
    );
  }

  if (useV3) {
    return verifyV3(cert, keys, v3SigRaw as string, options);
  }
  return verifyV2(cert, keys, options);
}

async function verifyV2(
  cert: VeilCertificate,
  keys: VerifyCertificateKeys,
  options?: VerifyCertificateOptions,
): Promise<VerifyCertificateResult> {
  // v2 uses witness_signature (= signable_v2_signature byte-for-byte).
  let signedBytes: Uint8Array;
  try {
    signedBytes = deriveWitnessSignedBytes(cert);
  } catch (err) {
    if (err instanceof LucairnCertificateError) throw err;
    if (err instanceof TypeError) {
      throw new LucairnCertificateError(
        `Failed to derive v2 signed payload: ${err.message}`,
        { reason: 'malformed', certificateId: cert.certificate_id, cause: err },
      );
    }
    throw err;
  }

  const signatureBytes = new Uint8Array(Buffer.from(cert.witness_signature, 'base64'));
  let valid: boolean;
  try {
    valid = verifyEd25519(signedBytes, signatureBytes, keys.witnessPublicKey);
  } catch (err) {
    if (err instanceof TypeError) {
      throw new LucairnCertificateError(`Invalid witnessPublicKey: ${err.message}`, {
        reason: 'invalid_signature',
        certificateId: cert.certificate_id,
        cause: err,
      });
    }
    throw err;
  }
  if (!valid) {
    throw new LucairnCertificateError('Witness Ed25519 v2 signature verification failed', {
      reason: 'invalid_signature',
      certificateId: cert.certificate_id,
    });
  }

  // Strict-mode gate: caller explicitly requires v3.
  if (options?.minimumSignableVersion === 'v3') {
    throw new LucairnCertificateError(
      'Caller requires minimumSignableVersion=\'v3\' but this certificate was verified via the v2 signable path. ' +
        'v3-only fields (api_key_id, client_id, byok_exempt, and the sanitizer hash fields) are not ' +
        'witness-signed on v2 certs. Upgrade the signing infrastructure or accept v2 certs explicitly.',
      { reason: 'signable_version_insufficient', certificateId: cert.certificate_id },
    );
  }

  return buildResult(cert, 'v2');
}

async function verifyV3(
  cert: VeilCertificate,
  keys: VerifyCertificateKeys,
  v3SigRaw: string,
  _options?: VerifyCertificateOptions,
): Promise<VerifyCertificateResult> {
  let signedBytes: Uint8Array;
  try {
    signedBytes = deriveWitnessSignedBytesV3(cert);
  } catch (err) {
    if (err instanceof LucairnCertificateError) throw err;
    if (err instanceof TypeError) {
      throw new LucairnCertificateError(
        `Failed to derive v3 signed payload: ${err.message}`,
        { reason: 'malformed', certificateId: cert.certificate_id, cause: err },
      );
    }
    throw err;
  }

  const signatureBytes = new Uint8Array(Buffer.from(v3SigRaw, 'base64'));
  let valid: boolean;
  try {
    valid = verifyEd25519(signedBytes, signatureBytes, keys.witnessPublicKey);
  } catch (err) {
    if (err instanceof TypeError) {
      throw new LucairnCertificateError(`Invalid witnessPublicKey: ${err.message}`, {
        reason: 'invalid_signature',
        certificateId: cert.certificate_id,
        cause: err,
      });
    }
    throw err;
  }
  if (!valid) {
    throw new LucairnCertificateError('Witness Ed25519 v3 signature verification failed', {
      reason: 'invalid_signature',
      certificateId: cert.certificate_id,
    });
  }

  return buildResult(cert, 'v3');
}

function buildResult(cert: VeilCertificate, signableVersion: 'v2' | 'v3'): VerifyCertificateResult {
  return {
    certificateId: cert.certificate_id,
    requestId: cert.request_id,
    witnessKeyId: cert.witness_key_id,
    witnessAssertedIssuedAt: new Date(cert.issued_at),
    witnessAssertedIssuedAtIso: cert.issued_at,
    anchorStatus: cert.anchor_status?.status ?? 'ANCHOR_STATUS_UNSPECIFIED',
    overallVerdict: cert.verification.overall_verdict,
    signableVersion,
    // Always false on the success path: the downgrade check throws before
    // buildResult is reached when a stripped v3 sig is detected.
    v3SignatureStripped: false,
  };
}
