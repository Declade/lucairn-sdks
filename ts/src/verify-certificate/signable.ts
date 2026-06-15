// Port of
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:320-414.
//
// v2 signable (7 keys, FROZEN): mirrors assembler.go lines 320-328.
// v3 signable (13 keys): mirrors assembler.go lines 380-414.
//
// TODO(proxy-sync): keep the key sets, the Go short-form enum mapping, and
// the string-vs-number encoding of each field in lockstep with the Go source.
// Any change to the assembler's signable construction must land here in the
// same arc.
//
// Gateway invariant enforced defensively:
//   cert.request_id === cert.claims[0].request_id
// The Go assembler reads claims[0].RequestId for the signed subset; the TS
// port adds a guard so drift surfaces loudly (throws `malformed`) rather
// than silently failing as `invalid_signature` on a cert with a valid
// signature computed over a different request_id.
//
// CRITICAL ENCODING NOTE (resolved 2026-04-20 after contract-drift-detector
// caught it):
//   The Go assembler signs `vr.OverallVerdict` (verifier.go:56 — type
//   `string`) DIRECTLY. vr.OverallVerdict holds short-form strings like
//   "VERIFIED", NOT the proto enum integer and NOT the full-name protojson
//   form "VERDICT_VERIFIED". Therefore the signable emits a JSON string
//   (quoted) via canonical JSON's default string path — NOT an integer
//   via rawIntegerNumber. An earlier version of this file mapped to
//   integer; that version silently disagreed with Go byte-for-byte on
//   every real gateway cert and was only caught by the cert-oracle
//   fixture (cert-go-signed-reference.json), not by the canonical-JSON
//   golden fixture (which tested canonicalJson in isolation and agreed
//   with Go on a closed TS→TS loop).
//
// Protojson → Go short-form mapping: the gateway emits full-name
// VERDICT_* literals on the wire (UseProtoNames + default enum
// serialization); the witness signs the short-form. The SDK must convert.
//
// ISSUED_AT NORMALIZATION (H6 fix, 2026-06-10):
//   The witness signs `issuedAt.Format(time.RFC3339Nano)` which strips
//   trailing fractional-second zeros (e.g., ".1Z" not ".100000000Z").
//   The gateway serves the cert via protojson which zero-pads the
//   google.protobuf.Timestamp to 9 fractional digits (e.g., ".100000000Z").
//   If the SDK feeds the served string straight into the signable it will
//   disagree with Go's bytes — ~10% of certs have a fractional second that
//   ends in trailing zeros and trigger this mismatch.
//   FIX: normalizeIssuedAt() strips trailing zeros before placing issued_at
//   in the signable. Applied to BOTH v2 and v3 paths.
//
// V3 SIGNABLE (13 keys, assembler.go:380-414):
//   The 7 v2 keys plus 6 promoted carry-forward fields:
//     client_id            — cert.client_id (null when absent)
//     api_key_id           — cert.api_key_id (null when absent)
//     byok_exempt          — cert.verification.byok_exempt (false when absent)
//     redaction_manifest_hash   — sanitizer canonical_payload.payload.redaction_manifest_hash
//     sanitized_fields_body_hash — sanitizer canonical_payload.payload.sanitized_fields_hash
//     tms_manifest_hash         — sanitizer canonical_payload.payload.tms_manifest_hash (null until Slice 5)
//
//   The 3 hash fields are read from the SANITIZER CLAIM'S canonical_payload JSON
//   (base64-encoded, signed by the sanitizer service), NOT from top-level cert
//   fields. The gateway strips sanitizer body bytes before serving the cert, but
//   the canonical_payload (which contains the hex hash) is bridge-/sanitizer-
//   signed and travels through the gateway intact.
//
//   Strip-surviving discipline (per assembler.go:337-378 comment):
//     SDK reconstruction reads from canonical_payload, NEVER from body fields.
//
// V3 SIGNING KEY IDENTITY NOTE:
//   The witness signs both v2 and v3 with the SAME Ed25519 key (same
//   LCR_WITNESS_SIGNING_KEY). The SDK verifies v3 against the same public
//   key the caller passes for v2 verification.
//
// PROTOCOL_VERSION IN V3 SIGNABLE:
//   The v3 signable map still carries `protocol_version: 2` (integer, not 3).
//   The witness uses cert.ProtocolVersion (which is 2) for the signable,
//   signaling the SDK-level version separately via cert.signable_protocol_version_emitted=3.
//   A maintainer who "fixes" this literal to 3 breaks v3 byte-identity for
//   every cert in the field (documented in assembler.go:384-388).

import { canonicalJson, rawIntegerNumber } from './canonical-json.js';
import { LucairnCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerdict } from '../types.js';

// Null-prototype object so key lookups never hit Object.prototype. With a
// plain object literal, `VERDICT_FULL_TO_SHORT['__proto__']` returns
// Object.prototype (truthy, not undefined), bypassing membership checks.
// Combined with Object.hasOwn below, this is defense-in-depth.
const VERDICT_FULL_TO_SHORT: Record<VeilVerdict, string> = Object.assign(
  Object.create(null) as Record<VeilVerdict, string>,
  {
    VERDICT_UNSPECIFIED: 'UNSPECIFIED',
    VERDICT_VERIFIED: 'VERIFIED',
    VERDICT_PARTIAL: 'PARTIAL',
    VERDICT_FAILED: 'FAILED',
  } satisfies Record<VeilVerdict, string>,
);

/**
 * Normalize an RFC 3339 issued_at timestamp to the EXACT form the Go witness
 * assembler signs: `time.Parse(time.RFC3339Nano, s)` then
 * `t.UTC().Format(time.RFC3339Nano)`. This (a) converts any non-UTC offset to
 * the equivalent UTC `Z` time and (b) strips trailing fractional-second zeros
 * (dropping the dot entirely when the whole fraction is zero).
 *
 * Parity note (this fix, 2026-06-15): the previous TS implementation kept the
 * original offset suffix and only stripped trailing zeros; Go re-emits in UTC.
 * The witness ALWAYS signs Zulu (UTC) timestamps, so on every real cert this is
 * byte-equivalent to the old behaviour. The change only affects the latent
 * never-emitted shape of a non-Zulu offset timestamp, bringing TS into exact
 * parity with Go (and Python).
 *
 * On parse failure the original string is returned unchanged (fail-open) —
 * matching Go's `if err != nil { return s }`.
 *
 * Examples:
 *   "2026-06-10T00:01:59.878143387Z" → unchanged (no trailing zeros, already UTC)
 *   "2026-05-01T12:00:00.100000000Z" → "2026-05-01T12:00:00.1Z"
 *   "2026-05-01T12:00:00.000000000Z" → "2026-05-01T12:00:00Z"
 *   "2026-05-01T12:00:00Z"           → unchanged (no fractional part)
 *   "2026-05-01T12:00:00.5+02:00"    → "2026-05-01T10:00:00.5Z"  (UTC-normalized)
 *
 * @internal exported for regression test only
 */
export function normalizeIssuedAt(ts: string): string {
  // Parse the RFC3339 components. Group 1 = date+time to the second, group 2 =
  // optional fractional part (".NNN" — the dot is captured), group 3 = the
  // timezone designator (Z or ±HH:MM). The fractional part is offset-invariant.
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(ts);
  if (!m) {
    // Not a parseable RFC3339 timestamp — fail-open (Go returns s on parse err).
    return ts;
  }
  const secondsPart = m[1];
  const fracRaw = m[2] ?? ''; // includes leading dot, or "" if no fraction
  const tz = m[3];

  // Strip trailing zeros from the fractional part (Go time.RFC3339Nano does
  // this); drop the dot entirely if nothing remains.
  let frac = fracRaw;
  if (frac) {
    frac = frac.replace(/0+$/, '');
    if (frac === '.') frac = '';
  }

  if (tz === 'Z') {
    // Already UTC — just emit the (zero-stripped) seconds + Z.
    return `${secondsPart}${frac}Z`;
  }

  // Non-UTC offset: convert the wall-clock seconds to UTC exactly like Go's
  // t.UTC(). The sub-second fraction is offset-invariant (UTC conversion only
  // shifts whole minutes/hours), so we manipulate the seconds-resolution
  // instant separately and re-attach the preserved fraction afterwards.
  const sign = tz[0] === '-' ? -1 : 1;
  const offHours = Number(tz.slice(1, 3));
  const offMins = Number(tz.slice(4, 6));
  const offsetMs = sign * (offHours * 60 + offMins) * 60 * 1000;
  // Interpret secondsPart as if it were UTC, then subtract the offset to get
  // the true UTC instant at second resolution.
  const wallAsUtcMs = new Date(`${secondsPart}Z`).getTime();
  if (Number.isNaN(wallAsUtcMs)) {
    return ts; // fail-open on an unparseable wall-clock
  }
  const trueUtcMs = wallAsUtcMs - offsetMs;
  const utcSeconds = new Date(trueUtcMs).toISOString().slice(0, 19); // "YYYY-MM-DDTHH:mm:ss"
  return `${utcSeconds}${frac}Z`;
}

/**
 * Shared claim-ID extraction with full validation (sparse-array + type guards).
 * Used by both v2 and v3 signable reconstruction.
 */
function extractValidatedClaimIds(cert: VeilCertificate): string[] {
  // N2 — explicit empty-claims check before the request-id invariant guard.
  if (cert.claims.length === 0) {
    throw new LucairnCertificateError(
      'cert.claims is empty — certificate must contain at least one claim',
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }

  // C2 defensive guard — fail loudly on invariant drift.
  if (cert.claims[0]?.request_id !== cert.request_id) {
    throw new LucairnCertificateError(
      'cert.request_id does not match cert.claims[0].request_id (gateway invariant violated)',
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }

  // N1 — index-based for-loop instead of .map to detect sparse-array holes.
  const claimIds: string[] = [];
  for (let i = 0; i < cert.claims.length; i++) {
    if (!(i in cert.claims)) {
      throw new LucairnCertificateError(
        `cert.claims[${i}] is a sparse-array hole`,
        { reason: 'malformed', certificateId: cert.certificate_id },
      );
    }
    const c = cert.claims[i];
    if (!c || typeof c.claim_id !== 'string') {
      throw new LucairnCertificateError(
        `cert.claims[${i}].claim_id must be a string`,
        { reason: 'malformed', certificateId: cert.certificate_id },
      );
    }
    claimIds.push(c.claim_id);
  }
  return claimIds;
}

/**
 * Shared verdict validation + short-form mapping.
 */
function validateAndMapVerdict(cert: VeilCertificate): string {
  const fullName = cert.verification.overall_verdict;
  // C3 + C6 — unknown verdict literal means schema drift.
  if (!Object.hasOwn(VERDICT_FULL_TO_SHORT, fullName)) {
    throw new LucairnCertificateError(
      `Unknown verification.overall_verdict literal: ${fullName} — SDK may be out of date`,
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }
  return VERDICT_FULL_TO_SHORT[fullName];
}

/**
 * Derive the v2 canonical signed bytes (7-key frozen map).
 * Mirrors assembler.go:320-328.
 *
 * The issued_at is normalized (H6 fix) before inclusion so trailing-zero
 * protojson timestamps match Go's time.RFC3339Nano signing output byte-for-byte.
 */
export function deriveWitnessSignedBytes(cert: VeilCertificate): Uint8Array {
  const claimIds = extractValidatedClaimIds(cert);
  const goShortForm = validateAndMapVerdict(cert);

  // v2 signable: 7 keys. protocol_version is integer 2 (rawIntegerNumber).
  // issued_at is normalized to RFC3339Nano (trailing zeros stripped).
  const signable = {
    certificate_id: cert.certificate_id,
    request_id: cert.request_id,
    protocol_version: rawIntegerNumber(2),
    claim_ids: claimIds,
    issued_at: normalizeIssuedAt(cert.issued_at),
    overall_verdict: goShortForm,
    witness_key_id: cert.witness_key_id,
  };
  return canonicalJson(signable);
}

/**
 * Extract a string field from the sanitizer claim's canonical_payload.payload,
 * returning null when absent or empty.
 *
 * Mirror of Go assembler's `sanitizerCanonicalPayloadStringForSignable` helper.
 * Reads from the dsa-sanitizer claim's canonical_payload (base64 JSON) NOT
 * from top-level cert fields — the gateway strips body bytes but canonical_payload
 * travels through intact (strip-surviving discipline from assembler.go:337-378).
 */
function sanitizerHashField(cert: VeilCertificate, key: string): string | null {
  for (const claim of cert.claims) {
    if (claim.service_id !== 'dsa-sanitizer') continue;
    if (!claim.canonical_payload) return null;
    try {
      const cpJson = Buffer.from(claim.canonical_payload, 'base64').toString('utf8');
      const cp = JSON.parse(cpJson) as Record<string, unknown>;
      // Flat-fallback (parity with Go v3_signable.go:157-162 and Python
      // v3_signable.py:114-116): the canonical_payload JSON normally wraps the
      // hash keys under a "payload" object, but some older canonical_payload
      // shapes carry them at the top level. When "payload" is absent or is not
      // an object, treat the outer object itself as the inner — matching the Go
      // assembler oracle. (Byte-equivalent on every cert the gateway emits today,
      // which always carries the wrapped "payload" shape — this only changes the
      // result on the flat shape, which TS previously returned null for while Go
      // and Python read the value.)
      const payloadRaw = cp['payload'];
      const inner =
        typeof payloadRaw === 'object' && payloadRaw !== null
          ? (payloadRaw as Record<string, unknown>)
          : cp;
      const val = inner[key];
      if (typeof val === 'string' && val.length > 0) return val;
    } catch {
      // Malformed canonical_payload — return null (fail-open per strip-surviving contract).
    }
    return null; // found the sanitizer claim but key absent/empty
  }
  return null; // no sanitizer claim at all
}

/**
 * Derive the v3 canonical signed bytes (13-key map).
 * Mirrors assembler.go:380-414.
 *
 * The 13 keys are the 7 v2 keys plus 6 promoted carry-forward fields:
 *   client_id, api_key_id, byok_exempt,
 *   redaction_manifest_hash, sanitized_fields_body_hash, tms_manifest_hash.
 *
 * `protocol_version` in the v3 signable map is STILL 2 (not 3) — mirrors the
 * Go assembler's `"protocol_version": 2` literal which uses cert.ProtocolVersion.
 * The SDK-level protocol is signaled via cert.signable_protocol_version_emitted=3.
 */
export function deriveWitnessSignedBytesV3(cert: VeilCertificate): Uint8Array {
  const claimIds = extractValidatedClaimIds(cert);
  const goShortForm = validateAndMapVerdict(cert);

  // Promote carry-forwards from cert fields and sanitizer canonical_payload.
  // Null values are valid — they render as JSON null (canonical-json passes null through).
  const clientId = cert.client_id ?? null;
  const apiKeyId = cert.api_key_id ?? null;
  const byokExempt = cert.verification.byok_exempt ?? false;

  const redactionManifestHash = sanitizerHashField(cert, 'redaction_manifest_hash');
  const sanitizedFieldsBodyHash = sanitizerHashField(cert, 'sanitized_fields_hash');
  // tms_manifest_hash: absent until Slice 5 — null is valid per assembler.go:399-413.
  const tmsManifestHash = sanitizerHashField(cert, 'tms_manifest_hash');

  // v3 signable: 13 keys. protocol_version is still integer 2.
  // issued_at normalized (H6 fix) — same as v2.
  const signable = {
    certificate_id: cert.certificate_id,
    request_id: cert.request_id,
    protocol_version: rawIntegerNumber(2),
    claim_ids: claimIds,
    issued_at: normalizeIssuedAt(cert.issued_at),
    overall_verdict: goShortForm,
    witness_key_id: cert.witness_key_id,
    // v3-only promoted carry-forwards (assembler.go:393-413)
    client_id: clientId,
    api_key_id: apiKeyId,
    byok_exempt: byokExempt,
    redaction_manifest_hash: redactionManifestHash,
    sanitized_fields_body_hash: sanitizedFieldsBodyHash,
    tms_manifest_hash: tmsManifestHash,
  };
  return canonicalJson(signable);
}
