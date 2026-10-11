// The Ed25519 acceptance rule of the witness-only verifier, applied by this
// SDK's own code before the bytes reach `node:crypto`.
//
// OpenSSL computes the cofactorless equation and compares the ENCODING of R.
// What it does with a small-order R (for example the identity, a signature
// made with nonce 0) or a small-order public key differs between OpenSSL
// builds, so those checks are explicit here and never left to the library.
//
// Module-internal: nothing in this file is re-exported from the package
// index. Plain BigInt arithmetic only, so it runs on every Node version the
// package supports.

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
 * non-canonical ones. Exported for this package's tests only.
 */
export const SMALL_ORDER_Y: ReadonlySet<string> = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);

/** True for the 14 small-order encodings (32 bytes). Exported for this package's tests only. */
export function isSmallOrder(enc: Uint8Array): boolean {
  return SMALL_ORDER_Y.has(hex(masked(enc)));
}

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
 * The public key (exactly 32 raw bytes, after normalisation) is acceptable:
 * not a small-order encoding, and the canonical encoding of a curve point.
 */
export function ed25519KeyAcceptable(raw: Uint8Array): boolean {
  if (raw.length !== 32) return false;
  return !isSmallOrder(raw) && canonicalCurvePoint(raw);
}

/**
 * The signature encoding is acceptable: 64 bytes R ‖ S with S < L and R the
 * canonical encoding (y < p) of a point that is not of small order. Whether
 * the signature VERIFIES is still the library's cofactorless equation.
 */
export function ed25519SignatureEncodingAcceptable(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  if (littleEndian(sig.subarray(32)) >= L) return false;
  const r = sig.subarray(0, 32);
  return littleEndian(masked(r)) < P && !isSmallOrder(r);
}
