import { LucairnCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerificationResult } from '../types.js';

// The value rule of the two version fields (protocol_version,
// signable_protocol_version_emitted), the same in the TypeScript, Python and
// Go SDKs and applied before any coercion: a JSON number whose value is an
// integer >= 0 and at most 2^64 − 1. A double cannot hold 2^64 − 1, so here
// the upper bound is "below 2^64". Strings, arrays, booleans, objects,
// fractions, NaN / Infinity and negatives are malformed.
function isVersionValue(v: unknown): boolean {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < 2 ** 64;
}

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
    // The two version fields share one value rule (isVersionValue below):
    // protocol_version is required; signable_protocol_version_emitted may be
    // absent or null (→ 0), anything else must satisfy the rule.
    !isVersionValue(cert.protocol_version) ||
    (cert.signable_protocol_version_emitted !== undefined &&
      cert.signable_protocol_version_emitted !== null &&
      !isVersionValue(cert.signable_protocol_version_emitted)) ||
    !Array.isArray(cert.claims) ||
    typeof cert.verification !== 'object' ||
    cert.verification === null
  ) {
    throw new LucairnCertificateError('Certificate missing required fields', {
      reason: 'malformed',
      certificateId: certId,
    });
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
