import type { VeilCertificate } from './types.js';

/**
 * Read the `client_id` (org_id metadata) from a Veil Certificate.
 *
 * Returns the certificate's `client_id` value, or `null` when the field
 * is missing or not populated. The gateway's protojson marshaller emits
 * unpopulated optional fields as JSON `null` rather than dropping them,
 * so callers see `null` (not `undefined`) on the wire when the witness
 * had no `client_id` to set.
 *
 * IMPORTANT: `client_id` is NOT part of the witness-signed canonical
 * bytes. Treat the returned value as unsigned metadata for client-side
 * correlation only. For tamper-evident proof of the issuing org, walk
 * the bridge claim's `canonical_payload` (which IS covered by the
 * witness signature via `claims`).
 *
 * @param cert A Veil Certificate (typically the result of
 *   `client.getCertificate(...)`).
 * @returns The `client_id` string, or `null` if the field is missing or
 *   `null` on the wire.
 */
export function getClientId(cert: VeilCertificate): string | null {
  return cert.client_id ?? null;
}
