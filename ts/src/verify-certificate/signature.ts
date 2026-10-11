import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { ed25519KeyAcceptable, ed25519SignatureEncodingAcceptable } from './ed25519-rule.js';
import { normalizeEd25519PublicKey } from './keys.js';

// SPKI DER prefix for raw Ed25519 SubjectPublicKeyInfo. Decoded:
//   30 2a                SEQUENCE (42 bytes content = 7 for AlgId + 35 for BITSTRING)
//   30 05                  SEQUENCE (5 bytes content — AlgorithmIdentifier)
//   06 03 2b 65 70           OID 1.3.101.112 (id-Ed25519)
//   03 21 00               BIT STRING (33 bytes content, unused-bits=0) + 32 key bytes
//
// Building the SPKI wrapper ourselves keeps us compatible with Node 18.17+
// without requiring the newer `format: 'raw', type: 'ed25519'` option.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Ed25519 verify. Accepts raw 32-byte pubkey (Uint8Array) or base64 string.
// Node's crypto.verify with 'ed25519' mode requires a KeyObject; we build
// one from the SPKI-wrapped raw key via createPublicKey. Returns a plain
// boolean — the orchestrator layer is responsible for translating false
// into a LucairnCertificateError.
//
// Before the library is called, this SDK's own rule (ed25519-rule.ts) is
// applied to the 32 raw key bytes and to the signature bytes, so the result
// does not depend on the OpenSSL build behind `node:crypto`. Each of these
// returns false (an invalid signature):
//   - a public key that is a small-order encoding or is not the canonical
//     encoding of a curve point;
//   - a signature that is not 64 bytes R ‖ S, has S >= L, or whose R is a
//     non-canonical encoding (y >= p) or a small-order point.
// A MALFORMED key (wrong type, wrong length) still throws TypeError from the
// normaliser, as before.
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array | string,
): boolean {
  const raw = normalizeEd25519PublicKey(publicKey);
  if (!ed25519KeyAcceptable(raw) || !ed25519SignatureEncodingAcceptable(signature)) return false;
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return cryptoVerify(null, Buffer.from(message), key, Buffer.from(signature));
}
