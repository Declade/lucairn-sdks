import { LucairnCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerificationResult } from '../types.js';

// Structural validation — asserts the shape this arc reads. Does NOT
// validate enum literal membership beyond "string" here (the signable
// derivation layer throws `malformed` on unknown verdict literals, which
// is where that check belongs semantically). Returns the narrowed type
// on success or throws LucairnCertificateError with reason 'malformed'.
export function parseCertificate(raw: unknown): VeilCertificate {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new LucairnCertificateError('Certificate is not a JSON object', {
      reason: 'malformed',
    });
  }
  const cert = raw as Partial<VeilCertificate>;
  const certId = typeof cert.certificate_id === 'string' ? cert.certificate_id : undefined;

  if (
    typeof cert.certificate_id !== 'string' ||
    typeof cert.request_id !== 'string' ||
    typeof cert.witness_key_id !== 'string' ||
    typeof cert.witness_signature !== 'string' ||
    typeof cert.issued_at !== 'string' ||
    typeof cert.protocol_version !== 'number' ||
    !Array.isArray(cert.claims) ||
    typeof cert.verification !== 'object' ||
    cert.verification === null
  ) {
    throw new LucairnCertificateError('Certificate missing required fields', {
      reason: 'malformed',
      certificateId: certId,
    });
  }

  // The two integers this check reads must be integers in [0, 2^64 - 1]
  // (JSON.parse turns an oversized token into Infinity). Anything else is
  // garbage input, not a newer protocol.
  if (!isUint64(cert.protocol_version)) {
    throw new LucairnCertificateError('protocol_version must be an integer in [0, 2^64 - 1]', {
      reason: 'malformed',
      certificateId: certId,
    });
  }
  const emitted: unknown = cert.signable_protocol_version_emitted;
  if (typeof emitted === 'number' && !isUint64(emitted)) {
    throw new LucairnCertificateError(
      'signable_protocol_version_emitted must be an integer in [0, 2^64 - 1]',
      { reason: 'malformed', certificateId: certId },
    );
  }

  // C6 — verification.overall_verdict must be a string (protojson enum
  // form). The signable derivation step later maps this string to a Go
  // int enum; reject non-string values here rather than letting them
  // cascade into a less-legible invalid_signature.
  const verif = cert.verification as Partial<VeilVerificationResult>;
  if (typeof verif.overall_verdict !== 'string') {
    throw new LucairnCertificateError(
      'verification.overall_verdict must be a string enum literal',
      { reason: 'malformed', certificateId: certId },
    );
  }

  return cert as VeilCertificate;
}

/** An integer value in [0, 2^64 - 1] (2^64 is the first double above that range). */
function isUint64(v: number): boolean {
  return Number.isInteger(v) && v >= 0 && v < 2 ** 64;
}
