// The witness-only verifier (verifyCertificate → verifyEd25519) applies the
// chain verifier's Ed25519 acceptance rule by its own code: a small-order R,
// a small-order or non-canonical public key and S >= L are refused whatever
// OpenSSL build sits behind node:crypto.
//
// Every assertion here is a refusal (or an honest signature verifying), so
// the file passes on a runtime whose library already refuses these inputs
// and on one whose library accepts them.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LucairnCertificateError } from './errors.js';
import { verifyCertificate } from './verify-certificate/index.js';
import { verifyEd25519 } from './verify-certificate/signature.js';
import {
  PinnedKeyError,
  SMALL_ORDER_Y,
  canonicalCurvePoint,
  ed25519Ok,
  isSmallOrder,
  keyObject,
  pinnedKey,
  signaturePrecheck,
} from './verify-chain/ed25519.js';

const CORPUS = join(__dirname, '..', '..', 'testdata', 'parity-corpus', 'v1');
const readJson = (...p: string[]): any => JSON.parse(readFileSync(join(CORPUS, ...p), 'utf8'));
const KEYS = readJson('keys.json') as { witness: { key_id: string; public_key_base64: string } };
const KEY_POLICY = readJson('key-policy.json') as {
  vectors: Array<{ id: string; public_key: string; expected: string }>;
};
const WITNESS = { witnessKeyId: KEYS.witness.key_id, witnessPublicKey: KEYS.witness.public_key_base64 };

/** The 14 small-order encodings, from the vendored key-policy vectors (not from the code under test). */
const SMALL_ORDER = KEY_POLICY.vectors
  .filter((v) => /^small_order_\d\d_/.test(v.id))
  .map((v) => new Uint8Array(Buffer.from(v.public_key, 'base64')));
const INVALID_POINTS = KEY_POLICY.vectors
  .filter((v) => /^invalid_point_/.test(v.id) && v.expected === 'key_invalid_point')
  .map((v) => new Uint8Array(Buffer.from(v.public_key, 'base64')));

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const BASE_POINT = new Uint8Array(Buffer.from('58' + '66'.repeat(31), 'hex'));

const le = (b: Uint8Array): bigint => {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
};
const le32 = (n: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
  return out;
};
const cat = (...p: Uint8Array[]): Uint8Array => new Uint8Array(Buffer.concat(p.map((x) => Buffer.from(x))));
/** k = SHA-512(R ‖ A ‖ M) mod L. */
const challenge = (r: Uint8Array, a: Uint8Array, m: Uint8Array): bigint =>
  le(new Uint8Array(createHash('sha512').update(cat(r, a, m)).digest())) % L;

// A fixed TEST key (seed = sha256 of a label), with its secret scalar.
const SEED = createHash('sha256').update('lucairn-sdks ts witness-only signature rule').digest();
const PRIVATE = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
  format: 'der',
  type: 'pkcs8',
});
const PUBLIC = new Uint8Array(createPublicKey(PRIVATE).export({ format: 'der', type: 'spki' }).subarray(-32));
const SCALAR = ((): bigint => {
  const h = new Uint8Array(createHash('sha512').update(SEED).digest().subarray(0, 32));
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return le(h);
})();
const MESSAGE = new TextEncoder().encode('witness-only signature rule');

function corpusCertificate(id: string): { certificate: unknown; expected: Record<string, { verdict: string; reason: string }> } {
  return readJson('cases', `${id}.json`);
}

describe('verifyCertificate: corpus case tamper_witness_signature_small_order_r', () => {
  it('is refused as an invalid signature (the honest certificate it was built from verifies)', async () => {
    const honest = await verifyCertificate(corpusCertificate('honest_full_chain_egress').certificate, WITNESS);
    expect(honest.overallVerdict).toBe('VERDICT_VERIFIED');

    const c = corpusCertificate('tamper_witness_signature_small_order_r');
    expect([c.expected.default.verdict, c.expected.default.reason]).toEqual(['FAILED', 'witness_signature_invalid']);
    const err = await verifyCertificate(c.certificate, WITNESS).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(LucairnCertificateError);
    expect((err as LucairnCertificateError).reason).toBe('invalid_signature');
  });

  it('is refused under minimumSignableVersion v3 as well', async () => {
    const c = corpusCertificate('tamper_witness_signature_small_order_r');
    await expect(verifyCertificate(c.certificate, WITNESS, { minimumSignableVersion: 'v3' })).rejects.toMatchObject({
      reason: 'invalid_signature',
    });
  });
});

describe('verifyEd25519: public-key hardening', () => {
  it('the vendored vectors hold 14 small-order encodings and the invalid points', () => {
    expect(SMALL_ORDER).toHaveLength(14);
    expect(new Set(SMALL_ORDER.map((b) => Buffer.from(b).toString('hex'))).size).toBe(14);
    expect(INVALID_POINTS.length).toBeGreaterThanOrEqual(3);
  });

  it('refuses every small-order key, with a signature the cofactorless equation accepts', () => {
    // R = the base point, S = 1: [S]B = R + [k]A holds for a small-order A
    // whenever k is a multiple of 8. Search a message with such a k.
    const sig = cat(BASE_POINT, le32(1n));
    for (const a of SMALL_ORDER) {
      let msg: Uint8Array | null = null;
      for (let n = 0; n < 4096 && msg === null; n++) {
        const m = new TextEncoder().encode(`small-order key ${n}`);
        if (challenge(BASE_POINT, a, m) % 8n === 0n) msg = m;
      }
      expect(msg).not.toBeNull();
      expect(verifyEd25519(msg!, sig, a)).toBe(false);
      expect(verifyEd25519(msg!, sig, Buffer.from(a).toString('base64'))).toBe(false);
      // the chain verifier refuses the same key when it loads the key set
      expect(() => pinnedKey(a, true, 'k')).toThrow(expect.objectContaining({ code: 'key_small_order' }));
    }
  });

  it('refuses a non-canonical or off-curve key as an invalid signature, without throwing', () => {
    const sig = sign(null, Buffer.from(MESSAGE), PRIVATE);
    for (const a of INVALID_POINTS) {
      expect(verifyEd25519(MESSAGE, new Uint8Array(sig), a)).toBe(false);
      expect(() => pinnedKey(a, true, 'k')).toThrow(PinnedKeyError);
    }
  });

  it('a malformed key (wrong length, wrong type) still throws TypeError', () => {
    const sig = new Uint8Array(64);
    expect(() => verifyEd25519(MESSAGE, sig, new Uint8Array(31))).toThrow(TypeError);
    expect(() => verifyEd25519(MESSAGE, sig, new Uint8Array(33))).toThrow(TypeError);
    expect(() => verifyEd25519(MESSAGE, sig, 7 as unknown as string)).toThrow(TypeError);
  });

  it('does not apply the chain verifier test-key refusal: a corpus test key still verifies', async () => {
    // verifyCertificate with the published corpus witness key (no allowTestKeys here).
    const ok = await verifyCertificate(corpusCertificate('honest_full_chain_egress').certificate, WITNESS);
    expect(ok.signableVersion).toBe('v3');
  });
});

describe('verifyEd25519: signature encoding', () => {
  const honest = new Uint8Array(sign(null, Buffer.from(MESSAGE), PRIVATE));

  it('accepts the honest signature (control)', () => {
    expect(verifyEd25519(MESSAGE, honest, PUBLIC)).toBe(true);
    expect(ed25519Ok(keyObject(PUBLIC), MESSAGE, honest)).toBe(true);
  });

  it('refuses S >= L (the honest signature with S + L)', () => {
    const sPlusL = le(honest.subarray(32)) + L;
    expect(sPlusL < 2n ** 256n).toBe(true);
    const bad = cat(honest.subarray(0, 32), le32(sPlusL));
    expect(verifyEd25519(MESSAGE, bad, PUBLIC)).toBe(false);
    expect(ed25519Ok(keyObject(PUBLIC), MESSAGE, bad)).toBe(false);
  });

  it('refuses a signature that is not 64 bytes', () => {
    expect(verifyEd25519(MESSAGE, honest.subarray(0, 63), PUBLIC)).toBe(false);
    expect(verifyEd25519(MESSAGE, cat(honest, new Uint8Array(1)), PUBLIC)).toBe(false);
    expect(verifyEd25519(MESSAGE, new Uint8Array(0), PUBLIC)).toBe(false);
  });

  it('refuses a non-canonical R (y >= p)', () => {
    // y = p + 3, the encoding of a curve point that is not of small order.
    const r = new Uint8Array(Buffer.from('f0' + 'ff'.repeat(30) + '7f', 'hex'));
    const bad = cat(r, honest.subarray(32));
    expect(verifyEd25519(MESSAGE, bad, PUBLIC)).toBe(false);
    expect(ed25519Ok(keyObject(PUBLIC), MESSAGE, bad)).toBe(false);
  });
});

describe('verifyEd25519: byte containers', () => {
  // A genuine signature verifies whatever Uint8Array flavour carries the
  // message, the signature and the key: a plain Uint8Array, a Buffer, and a
  // view at a non-zero offset into a larger buffer.
  const honest = new Uint8Array(sign(null, Buffer.from(MESSAGE), PRIVATE));
  const view = (b: Uint8Array): Uint8Array => {
    const big = new Uint8Array(b.length + 13).fill(0xaa);
    big.set(b, 7);
    return big.subarray(7, 7 + b.length);
  };
  const forms: Array<[string, (b: Uint8Array) => Uint8Array]> = [
    ['Uint8Array', (b) => Uint8Array.from(b)],
    ['Buffer', (b) => Buffer.from(b)],
    ['offset view (Uint8Array.subarray)', view],
    ['offset view (Buffer.subarray)', (b) => Buffer.from(view(b).buffer).subarray(7, 7 + b.length)],
  ];
  for (const [name, f] of forms) {
    it(`accepts a genuine signature given as ${name}`, () => {
      expect(verifyEd25519(MESSAGE, f(honest), PUBLIC)).toBe(true);
      expect(verifyEd25519(f(MESSAGE), honest, PUBLIC)).toBe(true);
      expect(verifyEd25519(MESSAGE, honest, f(PUBLIC))).toBe(true);
      expect(verifyEd25519(f(MESSAGE), f(honest), f(PUBLIC))).toBe(true);
    });
  }
});

describe('drift: the witness-only path and the chain path share ONE rule', () => {
  it('the shared helper names each of the 14 encodings, and the primitive refuses each as R whatever S is', () => {
    // Helper level: removing any one of the seven list entries turns two of
    // these 14 assertions red (the nonce-0 test below only notices the
    // identity entry, because the other constructions fail the equation).
    const honest = new Uint8Array(sign(null, Buffer.from(MESSAGE), PRIVATE));
    for (const r of SMALL_ORDER) {
      expect(isSmallOrder(r)).toBe(true);
      expect(verifyEd25519(MESSAGE, cat(r, honest.subarray(32)), PUBLIC)).toBe(false);
    }
    expect(isSmallOrder(BASE_POINT)).toBe(false);
    expect(isSmallOrder(PUBLIC)).toBe(false);
    expect(isSmallOrder(honest.subarray(0, 32))).toBe(false);
    // 14 encodings = 7 values with the sign bit either way, and the
    // implementation's list is EXACTLY those seven: an extra entry is caught.
    const maskedValues = new Set(SMALL_ORDER.map((b) => Buffer.from([...b.subarray(0, 31), b[31] & 0x7f]).toString('hex')));
    expect(maskedValues.size).toBe(7);
    expect(SMALL_ORDER_Y.size).toBe(7);
    expect([...SMALL_ORDER_Y].sort()).toEqual([...maskedValues].sort());
  });

  it('both refuse all 14 small-order encodings as R (nonce-0 construction)', () => {
    // S = k·a mod L with R the small-order encoding: for R = the identity this
    // is the signature a library that only checks the equation accepts.
    for (const r of SMALL_ORDER) {
      const s = (challenge(r, PUBLIC, MESSAGE) * SCALAR) % L;
      const sig = cat(r, le32(s));
      expect(verifyEd25519(MESSAGE, sig, PUBLIC)).toBe(false);
      expect(ed25519Ok(keyObject(PUBLIC), MESSAGE, sig)).toBe(false);
    }
  });

  it('the witness-only primitive calls the chain rule and holds no list or library call of its own', () => {
    const src = readFileSync(join(__dirname, 'verify-certificate', 'signature.ts'), 'utf8');
    expect(src).toMatch(/from '\.\.\/verify-chain\/ed25519\.js'/);
    expect(src).toMatch(/return ed25519Ok\(keyObject\(raw\), message, signature\);/);
    expect(src).toMatch(/isSmallOrder\(raw\) \|\| !canonicalCurvePoint\(raw\)/);
    expect(src).not.toMatch(/from 'node:crypto'/);
    expect(src).not.toMatch(/cryptoVerify|createPublicKey/);
    expect(src).not.toMatch(/[0-9a-f]{64}/);
  });
});

describe('prechecks, pinned without the crypto library', () => {
  // The library also refuses S >= L and an off-curve key, so a wrong constant
  // or a disabled point check would stay invisible in the tests above. These
  // assert the helpers directly.
  const P = 2n ** 255n - 19n;
  const sigWith = (r: Uint8Array, s: bigint): Uint8Array => cat(r, le32(s));

  it('S = L - 1 passes the precheck, S = L and above fail', () => {
    expect(signaturePrecheck(sigWith(BASE_POINT, L - 1n))).toBe(true);
    expect(signaturePrecheck(sigWith(BASE_POINT, 0n))).toBe(true);
    expect(signaturePrecheck(sigWith(BASE_POINT, L))).toBe(false);
    expect(signaturePrecheck(sigWith(BASE_POINT, L + 1n))).toBe(false);
    expect(signaturePrecheck(sigWith(BASE_POINT, 2n ** 256n - 1n))).toBe(false);
    expect(signaturePrecheck(sigWith(BASE_POINT, 1n).subarray(0, 63))).toBe(false);
  });

  it('R: y = p - 1, p, p + 1 and 2^255 - 1 fail the precheck; an ordinary R passes', () => {
    for (const y of [P - 1n, P, P + 1n, 2n ** 255n - 1n]) {
      expect(signaturePrecheck(sigWith(le32(y), 1n)), y.toString(16)).toBe(false);
    }
    expect(signaturePrecheck(sigWith(PUBLIC, 1n))).toBe(true);
  });

  it('point check: off-curve and non-canonical encodings are not canonical curve points', () => {
    const offCurve = le32(2n); // y = 2 has no x
    expect(canonicalCurvePoint(offCurve)).toBe(false);
    for (const k of INVALID_POINTS) expect(canonicalCurvePoint(k)).toBe(false);
    // y = p - 1 is on the curve (x = 0): canonical with the sign bit clear, not with it set.
    const pMinus1 = le32(P - 1n);
    expect(canonicalCurvePoint(pMinus1)).toBe(true);
    const signSet = Uint8Array.from(pMinus1);
    signSet[31] |= 0x80;
    expect(canonicalCurvePoint(signSet)).toBe(false);
    expect(isSmallOrder(pMinus1)).toBe(true);
    // y = p, p + 1 (non-canonical) and 2^255 - 1 are refused by the point check.
    for (const y of [P, P + 1n, 2n ** 255n - 1n]) expect(canonicalCurvePoint(le32(y)), y.toString(16)).toBe(false);
    expect(isSmallOrder(le32(P))).toBe(true);
    expect(isSmallOrder(le32(P + 1n))).toBe(true);
    expect(isSmallOrder(le32(2n ** 255n - 1n))).toBe(false);
    // honest points
    expect(canonicalCurvePoint(BASE_POINT)).toBe(true);
    expect(canonicalCurvePoint(PUBLIC)).toBe(true);
  });

  it('verifyEd25519 refuses an off-curve key because of the point check (not via the library)', () => {
    const honest = new Uint8Array(sign(null, Buffer.from(MESSAGE), PRIVATE));
    expect(verifyEd25519(MESSAGE, honest, le32(2n))).toBe(false);
  });
});
