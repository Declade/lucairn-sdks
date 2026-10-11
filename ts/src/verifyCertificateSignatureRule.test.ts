// The witness-only verifier (verifyCertificate → verifyEd25519) applies its
// own Ed25519 acceptance rule before the bytes reach node:crypto: a
// small-order R, a small-order or non-canonical public key and S >= L are
// refused whatever OpenSSL build sits behind the runtime (T-1322).
//
// Every assertion here is a refusal, or an honest signature verifying — so
// the file passes on a runtime whose library already refuses these inputs
// and on one whose library accepts them.

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LucairnCertificateError } from './errors.js';
import { verifyCertificate } from './verify-certificate/index.js';
import { verifyEd25519 } from './verify-certificate/signature.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

// The shared vector file: the SAME bytes sit in
//   ts/src/verify-certificate/__fixtures__/ed25519-rule-vectors.json
//   python/tests/fixtures/ed25519-rule-vectors.json
//   go/internal/verify/testdata/ed25519-rule-vectors.json
// and each SDK's test pins this sha256, so the three copies of the rule are
// held to one set of inputs and expected results.
const VECTORS_SHA256 = 'f7bd4f8122c91078a705a480a929b8e832d8f205cf52525d35438d50f53a5818';
const VECTORS_FILE = 'ed25519-rule-vectors.json';

// Parity-corpus case `tamper_witness_signature_small_order_r` (corpus
// v1.2.3), copied verbatim; the same bytes sit in the Python and Go test
// folders. Its witness key is the published corpus TEST key below.
const CORPUS_CASE_SHA256 = '2fc78fe50a778c53d421f4af4e85c9d5a39a1e0b25c37bcd1aa4203465e89db6';
const CORPUS_CASE_FILE = 'corpus-tamper_witness_signature_small_order_r.json';
const CORPUS_WITNESS = {
  witnessKeyId: 'witness_parity_v1',
  witnessPublicKey: 'DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc=',
};

interface Vector {
  id: string;
  group: string;
  public_key_hex: string;
  message_hex: string;
  signature_hex: string;
  expected: 'accept' | 'refuse';
}

const sha256File = (name: string): string =>
  createHash('sha256').update(readFileSync(join(fixturesDir, name))).digest('hex');
const hx = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'));
const VECTORS = (JSON.parse(readFileSync(join(fixturesDir, VECTORS_FILE), 'utf8')) as { vectors: Vector[] }).vectors;

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
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

/** A fresh random key pair with its raw 32-byte public key. */
function freshKey(): { raw: Uint8Array; privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'] } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  return { raw, privateKey };
}

describe('verifyCertificate: corpus case tamper_witness_signature_small_order_r', () => {
  const load = (): { certificate: unknown; expected: Record<string, { verdict: string; reason: string }> } =>
    JSON.parse(readFileSync(join(fixturesDir, CORPUS_CASE_FILE), 'utf8'));

  it('the fixture is the corpus file, byte for byte', () => {
    expect(sha256File(CORPUS_CASE_FILE)).toBe(CORPUS_CASE_SHA256);
    const c = load();
    expect([c.expected.default.verdict, c.expected.default.reason]).toEqual(['FAILED', 'witness_signature_invalid']);
  });

  it('is refused as an invalid signature', async () => {
    const err = await verifyCertificate(load().certificate, CORPUS_WITNESS).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(LucairnCertificateError);
    expect((err as LucairnCertificateError).reason).toBe('invalid_signature');
  });

  it('is refused under minimumSignableVersion v3 as well', async () => {
    await expect(
      verifyCertificate(load().certificate, CORPUS_WITNESS, { minimumSignableVersion: 'v3' }),
    ).rejects.toMatchObject({ reason: 'invalid_signature' });
  });
});

describe('verifyEd25519: shared cross-language vectors', () => {
  it('the vector file is the shared one (sha256 pinned in all three SDKs)', () => {
    expect(sha256File(VECTORS_FILE)).toBe(VECTORS_SHA256);
  });

  it('holds the 14 + 14 small-order encodings, the invalid-point keys, S >= L and genuine signatures', () => {
    const count = (g: string): number => VECTORS.filter((v) => v.group === g).length;
    const distinct = (g: string, f: (v: Vector) => string): number =>
      new Set(VECTORS.filter((v) => v.group === g).map(f)).size;
    expect(distinct('small_order_r', (v) => v.signature_hex.slice(0, 64))).toBe(14);
    expect(distinct('small_order_key', (v) => v.public_key_hex)).toBe(14);
    expect(count('invalid_point_key')).toBeGreaterThanOrEqual(3);
    expect(count('noncanonical_s')).toBeGreaterThanOrEqual(1);
    expect(count('noncanonical_r')).toBeGreaterThanOrEqual(1);
    expect(VECTORS.filter((v) => v.expected === 'accept').length).toBeGreaterThanOrEqual(5);
    expect(VECTORS.length).toBe(48);
  });

  for (const v of VECTORS) {
    it(`${v.id} → ${v.expected}`, () => {
      const want = v.expected === 'accept';
      expect(verifyEd25519(hx(v.message_hex), hx(v.signature_hex), hx(v.public_key_hex))).toBe(want);
      // the base64 form of the key takes the same path
      const b64 = Buffer.from(v.public_key_hex, 'hex').toString('base64');
      expect(verifyEd25519(hx(v.message_hex), hx(v.signature_hex), b64)).toBe(want);
    });
  }
});

describe('verifyEd25519: fresh keys made in the test (no false refusal)', () => {
  const message = new TextEncoder().encode('witness-only signature rule');

  it('accepts genuine signatures of fresh keys, with the key sign bit clear and set', () => {
    let clear = 0;
    let set = 0;
    for (let i = 0; i < 400 && (clear < 4 || set < 4); i++) {
      const { raw, privateKey } = freshKey();
      const sig = new Uint8Array(sign(null, Buffer.from(message), privateKey));
      expect(verifyEd25519(message, sig, raw)).toBe(true);
      expect(verifyEd25519(message, sig, Buffer.from(raw).toString('base64'))).toBe(true);
      if (raw[31] & 0x80) set++;
      else clear++;
    }
    expect(clear).toBeGreaterThanOrEqual(4);
    expect(set).toBeGreaterThanOrEqual(4);
  });

  it('refuses the genuine signature of a fresh key once S is replaced by S + L', () => {
    const { raw, privateKey } = freshKey();
    const sig = new Uint8Array(sign(null, Buffer.from(message), privateKey));
    expect(verifyEd25519(message, sig, raw)).toBe(true);
    const sPlusL = le(sig.subarray(32)) + L;
    expect(sPlusL < 2n ** 256n).toBe(true);
    expect(verifyEd25519(message, cat(sig.subarray(0, 32), le32(sPlusL)), raw)).toBe(false);
  });

  it('refuses every small-order encoding as R and as public key for a fresh key', () => {
    const { raw, privateKey } = freshKey();
    const sig = new Uint8Array(sign(null, Buffer.from(message), privateKey));
    const smallOrder = VECTORS.filter((v) => v.group === 'small_order_key').map((v) => hx(v.public_key_hex));
    expect(smallOrder).toHaveLength(14);
    for (const e of smallOrder) {
      expect(verifyEd25519(message, cat(e, sig.subarray(32)), raw)).toBe(false);
      expect(verifyEd25519(message, sig, e)).toBe(false);
    }
  });

  it('a malformed key (wrong length, wrong type) still throws TypeError', () => {
    const sig = new Uint8Array(64);
    expect(() => verifyEd25519(message, sig, new Uint8Array(31))).toThrow(TypeError);
    expect(() => verifyEd25519(message, sig, new Uint8Array(33))).toThrow(TypeError);
    expect(() => verifyEd25519(message, sig, 7 as unknown as string)).toThrow(TypeError);
  });
});
