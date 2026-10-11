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
import {
  SMALL_ORDER_Y,
  ed25519KeyAcceptable,
  ed25519SignatureEncodingAcceptable,
  isSmallOrder,
} from './verify-certificate/ed25519-rule.js';
import { deriveWitnessSignedBytesV3 } from './verify-certificate/signable.js';
import { verifyEd25519 } from './verify-certificate/signature.js';
import { decodeSignatureText, isBlankSignatureText } from './verify-certificate/text-rule.js';
import type { VeilCertificate } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

// The shared vector file: the SAME bytes sit in
//   ts/src/verify-certificate/__fixtures__/ed25519-rule-vectors.json
//   python/tests/fixtures/ed25519-rule-vectors.json
//   go/internal/verify/testdata/ed25519-rule-vectors.json
// and each SDK's test pins this sha256, so the three copies of the rule are
// held to one set of inputs and expected results.
const VECTORS_SHA256 = 'f72b5055fc223c2c063194b3cf963dbbc639c2330a29b34f8a24ef4d8590ad8b';
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
interface FieldVector {
  id: string;
  base: 'v2' | 'v3';
  field: 'witness_signature' | 'signable_v3_signature';
  text: string;
  expected: string;
}
interface PrecheckVector {
  id: string;
  kind: 'key' | 'signature';
  hex: string;
  acceptable: boolean;
}
interface VersionVector {
  id: string;
  base: 'v2' | 'v3';
  field: 'protocol_version' | 'signable_protocol_version_emitted';
  token: string | null;
  absent: boolean;
  expected: { ts: string; python: string; go_map: string; go_raw: string };
}
const VECTOR_DOC = JSON.parse(readFileSync(join(fixturesDir, VECTORS_FILE), 'utf8')) as {
  vectors: Vector[];
  precheck_vectors: PrecheckVector[];
  small_order_y: string[];
  certificate_field_vectors: FieldVector[];
  version_field_vectors: VersionVector[];
};
const VECTORS = VECTOR_DOC.vectors;
const FIELD_VECTORS = VECTOR_DOC.certificate_field_vectors;
const loadJson = <T = any>(name: string): T => JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;

/** verifyCertificate as one comparable string: `accept:<v2|v3>` or `refuse:<reason>`. */
async function outcome(cert: unknown, keys: { witnessKeyId: string; witnessPublicKey: string }): Promise<string> {
  try {
    const r = await verifyCertificate(cert, keys);
    return `accept:${r.signableVersion}`;
  } catch (e) {
    if (e instanceof LucairnCertificateError) return `refuse:${e.reason}`;
    throw e;
  }
}

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

describe('ed25519-rule helpers: every small-order encoding, one by one', () => {
  const smallOrder = VECTORS.filter((v) => v.group === 'small_order_key').map((v) => hx(v.public_key_hex));
  // S = 1 is below L, so only R decides.
  const sOne = le32(1n);

  it('the 14 encodings are 7 values, each with the sign bit clear and set', () => {
    expect(smallOrder).toHaveLength(14);
    const masked = new Set(smallOrder.map((e) => Buffer.from(Uint8Array.from(e, (b, i) => (i === 31 ? b & 0x7f : b))).toString('hex')));
    expect(masked.size).toBe(7);
  });

  for (const e of smallOrder) {
    const name = Buffer.from(e).toString('hex');
    it(`${name} is on the list, refused as key and refused as R`, () => {
      expect(isSmallOrder(e)).toBe(true);
      expect(ed25519KeyAcceptable(e)).toBe(false);
      expect(ed25519SignatureEncodingAcceptable(cat(e, sOne))).toBe(false);
    });
  }

  it('an ordinary point is not on the list', () => {
    const { raw } = freshKey();
    expect(isSmallOrder(raw)).toBe(false);
    expect(ed25519KeyAcceptable(raw)).toBe(true);
    expect(ed25519SignatureEncodingAcceptable(cat(raw, sOne))).toBe(true);
  });
});

describe('verifyEd25519: buffer forms', () => {
  const message = new TextEncoder().encode('witness-only signature rule');

  it('accepts a genuine signature as Uint8Array, Buffer and as a view into a larger buffer, and does not write to the caller', () => {
    const { raw, privateKey } = freshKey();
    const sigBuf = sign(null, Buffer.from(message), privateKey);
    const padded = new Uint8Array(200).fill(0xff);
    padded.set(sigBuf, 17);
    padded.set(raw, 100);
    padded.set(message, 140);
    const sigView = padded.subarray(17, 17 + 64);
    const keyView = padded.subarray(100, 132);
    const msgView = padded.subarray(140, 140 + message.length);
    const before = Buffer.from(padded).toString('hex');

    expect(verifyEd25519(message, new Uint8Array(sigBuf), raw)).toBe(true);
    expect(verifyEd25519(Buffer.from(message), sigBuf, Buffer.from(raw))).toBe(true);
    expect(verifyEd25519(msgView, sigView, keyView)).toBe(true);
    // refusals on views: a small-order R and a small-order key
    const smallR = Uint8Array.from(padded);
    smallR.fill(0, 17, 17 + 32);
    smallR[17] = 1;
    expect(verifyEd25519(msgView, smallR.subarray(17, 17 + 64), keyView)).toBe(false);

    expect(Buffer.from(padded).toString('hex')).toBe(before);
    // the sign-bit masking works on a copy: a key with the sign bit set stays as given
    const withSign = Uint8Array.from(raw);
    withSign[31] |= 0x80;
    const copy = Uint8Array.from(withSign);
    ed25519KeyAcceptable(withSign);
    isSmallOrder(withSign);
    expect(withSign).toEqual(copy);
  });
});

describe('signature text rules (shared with the Python and Go SDKs)', () => {
  it('white space is the Go unicode.IsSpace set: U+0085 is blank, U+FEFF and U+001C are not', () => {
    const cp = (...c: number[]): string => String.fromCharCode(...c);
    expect(isBlankSignatureText('')).toBe(true);
    expect(isBlankSignatureText(cp(0x85))).toBe(true);
    expect(isBlankSignatureText(cp(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000))).toBe(true);
    for (const c of [0x1c, 0x1d, 0x1e, 0x1f, 0xfeff, 0x200b, 0x180e, 0x00, 0x41]) {
      expect(isBlankSignatureText(cp(c))).toBe(false);
      expect(isBlankSignatureText(' ' + cp(c) + ' ')).toBe(false);
    }
  });

  it('a signature text must be canonical standard padded base64', () => {
    const text = Buffer.from(new Uint8Array(64).fill(7)).toString('base64');
    expect(decodeSignatureText(text)).toEqual(new Uint8Array(64).fill(7));
    for (const bad of [text.slice(0, -2), text + '!', ' ' + text, text + '\n', text.replace(/\+/g, '-')]) {
      if (bad !== text) expect(decodeSignatureText(bad)).toBeNull();
    }
  });

  const BASES = {
    v2: (): Record<string, unknown> => loadJson('cert-valid-anchored.json'),
    v3: (): Record<string, unknown> => loadJson('cert-real-v3-production.json'),
  };
  const KEYS = {
    v2: (): { witnessKeyId: string; witnessPublicKey: string } => ({
      witnessKeyId: 'witness_v1',
      witnessPublicKey: loadJson<{ publicKey: string }>('witness-keypair.json').publicKey,
    }),
    v3: (): { witnessKeyId: string; witnessPublicKey: string } => {
      const k = loadJson<{ witnessKeyId: string; publicKeyBase64: string }>('production-witness-pubkey.json');
      return { witnessKeyId: k.witnessKeyId, witnessPublicKey: k.publicKeyBase64 };
    },
  };

  it('the shared file holds the white-space and base64 field vectors', () => {
    expect(FIELD_VECTORS.length).toBe(100);
    const ids = new Set(FIELD_VECTORS.map((v) => v.id));
    for (const id of [
      'v2_signable_v3_signature_only_u0085',
      'v2_signable_v3_signature_only_ufeff',
      'v2_signable_v3_signature_only_u001c',
      'v3_signable_v3_signature_trailing_bang',
      'v3_signable_v3_signature_nonzero_padding_bits',
      'v3_witness_signature_only_ufeff',
      'v3_witness_signature_only_u001c',
      'v3_witness_signature_bang',
      'v3_witness_signature_trailing_bang',
    ]) {
      expect(ids.has(id)).toBe(true);
    }
  });

  for (const v of FIELD_VECTORS) {
    it(`${v.id} → ${v.expected}`, async () => {
      const cert = BASES[v.base]();
      cert[v.field] = v.text;
      expect(await outcome(cert, KEYS[v.base]())).toBe(v.expected);
    });
  }
});

describe('corpus cases of the parse layer (copied verbatim, same bytes in the Python and Go test folders)', () => {
  const sha = {
    'corpus-tamper_signable_v3_signature_control_char.json': 'f2deec7b3549ab30e42a67a29a70c2b566b42528ea6d1c43ffd2da16e4c35bb2',
    'corpus-tamper_protocol_version_float_token.json': 'e9a576edf871084cf187832b5e7d9506dc8df26641182f78343cf20517c5b69f',
    'corpus-tamper_protocol_version_oversized_integer.json': '0920687b2cd9b01a68689dd2903045fceebcd06ea9186c19635ef8b6056e2bfb',
  };

  it('the fixtures are the corpus files, byte for byte', () => {
    for (const [name, want] of Object.entries(sha)) expect(sha256File(name)).toBe(want);
  });

  it('signable_v3_signature holding only U+001C is present: version_downgrade_detected', async () => {
    const c = loadJson('corpus-tamper_signable_v3_signature_control_char.json');
    expect(c.certificate.signable_v3_signature).toBe(String.fromCharCode(0x1c));
    expect(await outcome(c.certificate, CORPUS_WITNESS)).toBe('refuse:version_downgrade_detected');
  });

  it('a protocol_version too large for a double is malformed (was unsupported_protocol_version)', async () => {
    const c = loadJson('corpus-tamper_protocol_version_oversized_integer.json');
    expect(c.certificate.protocol_version).toBe(Infinity);
    expect(c.expected.default.reason).toBe('malformed');
    expect(await outcome(c.certificate, CORPUS_WITNESS)).toBe('refuse:malformed');
  });

  it('a protocol_version that is not an integer value is malformed; other integers stay unsupported_protocol_version', async () => {
    const base = loadJson('corpus-tamper_protocol_version_float_token.json').certificate;
    expect(await outcome({ ...base, protocol_version: 2.5 }, CORPUS_WITNESS)).toBe('refuse:malformed');
    expect(await outcome({ ...base, protocol_version: NaN }, CORPUS_WITNESS)).toBe('refuse:malformed');
    expect(await outcome({ ...base, protocol_version: 3 }, CORPUS_WITNESS)).toBe('refuse:unsupported_protocol_version');
    expect(await outcome({ ...base, signable_protocol_version_emitted: Infinity }, CORPUS_WITNESS)).toBe('refuse:malformed');
  });

  // The ONE documented difference. The corpus expects `malformed` for the
  // number TOKEN 2.0000000000000001. JSON.parse hands this SDK the number 2 —
  // the same value a genuine certificate has — so a verifier that is given a
  // parsed object cannot see the token. The signed bytes are rebuilt from the
  // VALUE, so nothing unsigned is accepted: they equal those of the same
  // certificate with protocol_version 2.
  it('the float TOKEN 2.0000000000000001 arrives as the value 2: accepted, with the signed bytes of protocol_version 2', async () => {
    const c = loadJson('corpus-tamper_protocol_version_float_token.json');
    expect(c.expected.default.reason).toBe('malformed');
    expect(c.certificate.protocol_version).toBe(2);
    expect(Number.isInteger(c.certificate.protocol_version)).toBe(true);
    expect(await outcome(c.certificate, CORPUS_WITNESS)).toBe('accept:v3');
    const withInteger = { ...c.certificate, protocol_version: JSON.parse('2') } as VeilCertificate;
    expect(Buffer.from(deriveWitnessSignedBytesV3(c.certificate as VeilCertificate)).toString('hex')).toBe(
      Buffer.from(deriveWitnessSignedBytesV3(withInteger)).toString('hex'),
    );
  });

  it('a genuine certificate with protocol_version 2 still verifies (v2 fixture and the recorded v3 certificate)', async () => {
    const v2 = loadJson('cert-valid-anchored.json');
    expect(v2.protocol_version).toBe(2);
    expect(await outcome(v2, { witnessKeyId: 'witness_v1', witnessPublicKey: loadJson('witness-keypair.json').publicKey })).toBe('accept:v2');
    const v3 = loadJson('cert-real-v3-production.json');
    expect(v3.protocol_version).toBe(2);
    const k = loadJson('production-witness-pubkey.json');
    expect(await outcome(v3, { witnessKeyId: k.witnessKeyId, witnessPublicKey: k.publicKeyBase64 })).toBe('accept:v3');
  });
});

describe('ed25519-rule prechecks, independent of the crypto library (shared precheck vectors)', () => {
  const PRE = VECTOR_DOC.precheck_vectors;

  it('the small-order list has exactly the seven shared values', () => {
    expect(SMALL_ORDER_Y.size).toBe(7);
    expect([...SMALL_ORDER_Y].sort()).toEqual([...VECTOR_DOC.small_order_y].sort());
    expect(VECTOR_DOC.small_order_y).toHaveLength(7);
  });

  it('the shared file holds the boundary vectors', () => {
    expect(PRE.length).toBe(56);
    const byId = new Map(PRE.map((v) => [v.id, v.acceptable]));
    expect(byId.get('sig_ordinary_r_s_l_minus_1')).toBe(true);
    expect(byId.get('sig_ordinary_r_s_l')).toBe(false);
    expect(byId.get('key_invalid_point_off_curve')).toBe(false);
    expect(byId.get('key_y_p_minus_1_sign_0')).toBe(false);
    expect(byId.get('key_y_p_sign_0')).toBe(false);
    expect(byId.get('key_y_p_plus_1_sign_0')).toBe(false);
    expect(byId.get('key_y_2_pow_255_minus_1_sign_0')).toBe(false);
    expect(PRE.filter((v) => v.kind === 'key' && v.acceptable).length).toBeGreaterThanOrEqual(6);
    expect(PRE.filter((v) => v.kind === 'key' && !v.acceptable && /off_curve/.test(v.id)).length).toBeGreaterThanOrEqual(7);
  });

  for (const v of PRE) {
    it(`${v.id} → precheck ${v.acceptable ? 'passes' : 'fails'}`, () => {
      const bytes = hx(v.hex);
      const got = v.kind === 'key' ? ed25519KeyAcceptable(bytes) : ed25519SignatureEncodingAcceptable(bytes);
      expect(got).toBe(v.acceptable);
    });
  }
});

describe('version fields: one value rule (shared version vectors, column "ts")', () => {
  const VERSIONS = VECTOR_DOC.version_field_vectors;
  const base = {
    v2: (): Record<string, unknown> => loadJson('cert-valid-anchored.json'),
    v3: (): Record<string, unknown> => loadJson('cert-real-v3-production.json'),
  };
  const keys = {
    v2: (): { witnessKeyId: string; witnessPublicKey: string } => ({
      witnessKeyId: 'witness_v1',
      witnessPublicKey: loadJson<{ publicKey: string }>('witness-keypair.json').publicKey,
    }),
    v3: (): { witnessKeyId: string; witnessPublicKey: string } => {
      const k = loadJson<{ witnessKeyId: string; publicKeyBase64: string }>('production-witness-pubkey.json');
      return { witnessKeyId: k.witnessKeyId, witnessPublicKey: k.publicKeyBase64 };
    },
  };

  it('the shared file holds the version vectors', () => {
    expect(VERSIONS.length).toBe(54);
  });

  for (const v of VERSIONS) {
    it(`${v.id} → ${v.expected.ts}`, async () => {
      const cert = base[v.base]();
      if (v.absent) delete cert[v.field];
      else cert[v.field] = JSON.parse(v.token as string);
      expect(await outcome(cert, keys[v.base]())).toBe(v.expected.ts);
    });
  }

  it('values JSON cannot carry are malformed too (NaN, Infinity, undefined protocol_version)', async () => {
    for (const bad of [NaN, Infinity, -Infinity, 2 ** 64, -0.5]) {
      expect(await outcome({ ...base.v3(), protocol_version: bad }, keys.v3())).toBe('refuse:malformed');
      expect(await outcome({ ...base.v3(), signable_protocol_version_emitted: bad }, keys.v3())).toBe('refuse:malformed');
    }
    expect(await outcome({ ...base.v3(), protocol_version: undefined }, keys.v3())).toBe('refuse:malformed');
    // undefined / null emitted version = absent = 0, unchanged
    expect(await outcome({ ...base.v2(), signable_protocol_version_emitted: undefined }, keys.v2())).toBe('accept:v2');
    expect(await outcome({ ...base.v2(), signable_protocol_version_emitted: null }, keys.v2())).toBe('accept:v2');
  });
});
