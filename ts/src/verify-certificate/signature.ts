import { canonicalCurvePoint, ed25519Ok, isSmallOrder, keyObject } from '../verify-chain/ed25519.js';
import { normalizeEd25519PublicKey } from './keys.js';

// Ed25519 verify for the witness-only verifier. Accepts a raw 32-byte pubkey
// (Uint8Array) or a base64 string. Returns a plain boolean — the orchestrator
// layer is responsible for translating false into a LucairnCertificateError.
//
// The acceptance rule is the chain verifier's (`verify-chain/ed25519.ts`),
// called here rather than copied, so the two paths cannot drift and the
// result does not depend on the OpenSSL build behind `node:crypto`:
//   - the key (after normalisation, on its 32 raw bytes) must not be a
//     small-order encoding and must be the canonical encoding of a curve
//     point;
//   - the signature must be 64 bytes R ‖ S with S < L and R the canonical
//     encoding (y < p) of a point that is not of small order.
// Each of these returns false (an invalid signature). A MALFORMED key (wrong
// type, wrong length) still throws TypeError from the normaliser, as before.
// The chain verifier's refusal of the published parity-corpus test keys is a
// pinned-key-set policy and is deliberately NOT applied here.
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array | string,
): boolean {
  const raw = normalizeEd25519PublicKey(publicKey);
  if (isSmallOrder(raw) || !canonicalCurvePoint(raw)) return false;
  return ed25519Ok(keyObject(raw), message, signature);
}
