// Ed25519 for the chain verifier — parity corpus README § Pinned keys and
// § Signatures: ONE key policy applied when the pinned key set is loaded, and
// ONE signature acceptance rule for every witness and claim signature.
//
// Node's crypto.verify (OpenSSL) computes the cofactorless equation and
// compares the ENCODING of R, and it refuses a non-canonical S. It accepts a
// small-order R (the identity, nonce 0) — the case that splits Ed25519
// libraries — so that rule, and the other pre-checks, are explicit here and
// never left to the library.

import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

/** The codes a refused pinned key raises, checked in this order. */
export type PinnedKeyErrorCode = 'key_malformed' | 'key_small_order' | 'key_invalid_point' | 'key_test_key';

/**
 * A pinned key that fails the key policy. A CALLER error: the verifier throws
 * it while loading the key set and never returns a verdict. Extends
 * `TypeError`, like every other programmer error of the verifier.
 */
export class PinnedKeyError extends TypeError {
  readonly code: PinnedKeyErrorCode;
  /** Which key was refused: `witnessPublicKey` or `servicePublicKeys["<service_id>"]`. */
  readonly key: string;
  constructor(code: PinnedKeyErrorCode, key: string) {
    super(`verifyCertificateChain: ${key} refused (${code})`);
    this.name = 'PinnedKeyError';
    this.code = code;
    this.key = key;
  }
}

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const D = (((-121665n * modPow(121666n, P - 2n, P)) % P) + P) % P;

function littleEndian(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}

/** The encoding with the sign bit (top bit of byte 31) cleared. */
function masked(enc: Uint8Array): Uint8Array {
  const out = Uint8Array.from(enc);
  out[31] &= 0x7f;
  return out;
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/**
 * The seven small-order y values (little-endian, sign bit cleared) — the
 * libsodium blocklist: 0, 1, p−1, p, p+1 and the two order-8 values. With the
 * sign bit either way: the 8 canonical small-order encodings plus 6
 * non-canonical ones.
 */
const SMALL_ORDER_Y = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);

const isSmallOrder = (enc: Uint8Array): boolean => SMALL_ORDER_Y.has(hex(masked(enc)));

/**
 * The canonical encoding of a curve point: y (the low 255 bits) < p, some x
 * satisfies −x² + y² = 1 + d·x²·y², and the sign bit is clear when x is 0.
 */
function canonicalCurvePoint(enc: Uint8Array): boolean {
  const y = littleEndian(masked(enc));
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const x2 = ((((y2 - 1n) % P) + P) % P) * modPow(D * y2 + 1n, P - 2n, P) % P;
  if (x2 === 0n) return (enc[31] & 0x80) === 0;
  return modPow(x2, (P - 1n) / 2n, P) === 1n;
}

/**
 * The published parity-corpus TEST keys (witness, the seven service keys and
 * the two keys that must never be pinned). Their private keys follow from the
 * public corpus seed, so a verifier refuses them unless the caller sets
 * `allowTestKeys` — which only a parity test harness does.
 */
export const CORPUS_TEST_KEYS: readonly string[] = [
  'DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc=', // witness_parity_v1
  'CEYOK2jlNGFq+qO34Lsv1J683D6o0xP7/zh8CExSEPw=', // dsa-ai
  'g34bEFHw7VjKYrRbblIGfjR7vktJDyqrf5xJfLHTyJE=', // dsa-audit
  'l4pxgBHACNYoETbJISAgKf2GFv32LsF44RZ+5CXsbmk=', // dsa-bridge
  'QfwIjbzb5aYQsBsrp+1dhyh5XeO/wRokwWcQxfgvSc8=', // dsa-gateway
  'ufi3DjW9XlboFkOiQiDHRFZpDFpvPgxZCw516lNr7Kg=', // dsa-reid-guard
  'tS+sf+14i1H/qJLJcrNvIvg2B5iJQ2KMXQhirCKsKLs=', // dsa-sanitizer
  'XF4RayFQtg/k+NkMnsSnlrA/mEgv63vRzi6GKrSSQzY=', // dsa-sanitizer-streaming
  '/eReR5ZWs84YMcnJkk7lNr1iOetpZXTaPIy/EERjio0=', // dsa-unpinned (not pinned)
  '9oGMdHYHc5/aVzMjYZkLNdXqKsNR1A5aNp8bmSdd1Aw=', // rogue (not pinned)
];
const TEST_KEY_HEX = new Set(CORPUS_TEST_KEYS.map((k) => Buffer.from(k, 'base64').toString('hex')));

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

/** CANONICAL standard padded base64 (README step 7b): decode, re-encode, compare. */
export function canonicalBase64(v: string): Uint8Array | null {
  if (!B64.test(v) || v.length % 4 !== 0) return null;
  const raw = Buffer.from(v, 'base64');
  return raw.toString('base64') === v ? new Uint8Array(raw) : null;
}

/**
 * README § Pinned keys: one pinned key, as canonical standard padded base64
 * text or as exactly 32 raw bytes. Throws {@link PinnedKeyError} with the
 * first failing code: `key_malformed`, `key_small_order`,
 * `key_invalid_point`, `key_test_key` (unless `allowTestKeys`).
 */
export function pinnedKey(input: unknown, allowTestKeys: boolean, label: string): Uint8Array {
  let raw: Uint8Array | null = null;
  if (typeof input === 'string') {
    raw = input === '' ? null : canonicalBase64(input);
  } else if (input instanceof Uint8Array) {
    raw = Uint8Array.from(input);
  }
  if (raw === null || raw.length !== 32) throw new PinnedKeyError('key_malformed', label);
  if (isSmallOrder(raw)) throw new PinnedKeyError('key_small_order', label);
  if (!canonicalCurvePoint(raw)) throw new PinnedKeyError('key_invalid_point', label);
  if (!allowTestKeys && TEST_KEY_HEX.has(hex(raw))) throw new PinnedKeyError('key_test_key', label);
  return raw;
}

// SPKI DER prefix for a raw Ed25519 public key (RFC 8410).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** A Node KeyObject for a key that passed {@link pinnedKey}. */
export function keyObject(raw: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

/**
 * README § Signatures — the ONE acceptance rule: a 64-byte R ‖ S with S < L,
 * R the canonical encoding (y < p) of a point not of small order, and the
 * cofactorless equation compared as an encoding (OpenSSL).
 */
export function ed25519Ok(key: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  if (littleEndian(sig.subarray(32)) >= L) return false;
  const r = sig.subarray(0, 32);
  if (littleEndian(masked(r)) >= P || isSmallOrder(r)) return false;
  try {
    return cryptoVerify(null, Buffer.from(msg), key, Buffer.from(sig));
  } catch {
    return false;
  }
}
