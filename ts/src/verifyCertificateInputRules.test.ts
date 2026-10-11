// Input rules of the witness-only verifyCertificate that all three SDKs
// share (parity corpus is the reference):
//   - ONE whitespace set (Go's unicode.IsSpace) for every blank / present test;
//   - a signature text is canonical standard padded base64, else invalid_signature;
//   - protocol_version / signable_protocol_version_emitted are integers in
//     [0, 2^64 - 1], else malformed.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LucairnCertificateError } from './errors.js';
import { verifyCertificate } from './verify-certificate/index.js';
import { deriveWitnessSignedBytes, deriveWitnessSignedBytesV3 } from './verify-certificate/signable.js';
import { parseCertificate } from './verify-certificate/parse.js';
import { verifyCertificateChain } from './verify-chain/index.js';

const CORPUS = join(__dirname, '..', '..', 'testdata', 'parity-corpus', 'v1');
const readJson = (...p: string[]): any => JSON.parse(readFileSync(join(CORPUS, ...p), 'utf8'));
const KEYS = readJson('keys.json') as {
  witness: { key_id: string; public_key_base64: string };
  services: Record<string, { public_key_base64: string }>;
};
const WITNESS = { witnessKeyId: KEYS.witness.key_id, witnessPublicKey: KEYS.witness.public_key_base64 };

type Cert = Record<string, unknown>;
const v3Cert = (): Cert => readJson('cases', 'honest_full_chain_egress.json').certificate;
const v2Cert = (): Cert => readJson('cases', 'legacy_v2_signable_only.json').certificate;

/** 'ACCEPT:<signable version>' or the refusal reason. */
async function outcome(cert: unknown): Promise<string> {
  try {
    return `ACCEPT:${(await verifyCertificate(cert, WITNESS)).signableVersion}`;
  } catch (e) {
    if (e instanceof LucairnCertificateError) return e.reason;
    throw e;
  }
}

describe('ONE whitespace set for blank / present tests (unicode.IsSpace)', () => {
  it('controls: the two base certificates verify', async () => {
    expect(await outcome(v3Cert())).toBe('ACCEPT:v3');
    expect(await outcome(v2Cert())).toBe('ACCEPT:v2');
  });

  it('corpus case tamper_signable_v3_signature_control_char is refused as version_downgrade_detected', async () => {
    const c = readJson('cases', 'tamper_signable_v3_signature_control_char.json');
    expect(c.expected.default.reason).toBe('version_downgrade_detected');
    expect(await outcome(c.certificate)).toBe('version_downgrade_detected');
  });

  // [character, is it in the set?]
  const chars: Array<[string, string, boolean]> = [
    ['U+001C', '\u001c', false],
    ['U+001F', '\u001f', false],
    ['U+0085', '\u0085', true],
    ['U+FEFF', '\ufeff', false],
    ['U+00A0', '\u00a0', true],
    ['U+2028', '\u2028', true],
    ['U+200B', '\u200b', false],
    ['space', ' ', true],
  ];
  for (const [name, ch, blank] of chars) {
    it(`a field holding only ${name} is ${blank ? 'blank' : 'present'}`, async () => {
      // signable_v3_signature on a legacy v2 certificate: blank -> the v2
      // certificate verifies; present -> a v3 signature without the version.
      expect(await outcome({ ...v2Cert(), signable_v3_signature: ch })).toBe(blank ? 'ACCEPT:v2' : 'version_downgrade_detected');
      // on a v3 certificate: blank -> the v3 signature was stripped;
      // present -> it is decoded and is not a signature.
      expect(await outcome({ ...v3Cert(), signable_v3_signature: ch })).toBe(blank ? 'version_downgrade_detected' : 'invalid_signature');
      // witness_signature: blank -> missing; present -> not a signature.
      expect(await outcome({ ...v2Cert(), witness_signature: ch })).toBe(blank ? 'witness_signature_missing' : 'invalid_signature');
    });
  }
});

describe('signature text: canonical standard padded base64', () => {
  const bumpPaddingBits = (s: string): string => {
    const al = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const i = al.indexOf(s[s.length - 3]);
    expect(i % 16).toBe(0); // 64 bytes: the last data character carries 4 zero bits
    return s.slice(0, -3) + al[i + 1] + '==';
  };
  const variants = (s: string): Array<[string, string]> => [
    ['unpadded', s.replace(/=+$/, '')],
    ['one pad character removed', s.slice(0, -1)],
    ['URL-safe alphabet', s.replace(/\+/g, '-').replace(/\//g, '_')],
    ['embedded space', `${s.slice(0, 40)} ${s.slice(40)}`],
    ['embedded LF', `${s.slice(0, 40)}\n${s.slice(40)}`],
    ['embedded CR', `${s.slice(0, 40)}\r${s.slice(40)}`],
    ['leading space', ` ${s}`],
    ['trailing space', `${s} `],
    ['trailing LF', `${s}\n`],
    ['non-zero padding bits', bumpPaddingBits(s)],
    ["trailing '!'", `${s}!`],
    ["trailing 'AAAA'", `${s}AAAA`],
    ["trailing '===='", `${s}====`],
    ["embedded '!'", `${s.slice(0, 40)}!${s.slice(40)}`],
  ];

  it('v3 path: every non-canonical form of signable_v3_signature is invalid_signature', async () => {
    const base = v3Cert();
    const sig = base.signable_v3_signature as string;
    expect(/[+/]/.test(sig)).toBe(true);
    for (const [name, text] of variants(sig)) {
      expect(text, name).not.toBe(sig);
      expect(await outcome({ ...base, signable_v3_signature: text }), name).toBe('invalid_signature');
    }
  });

  it('v2 path: every non-canonical form of witness_signature is invalid_signature', async () => {
    const base = v2Cert();
    const sig = base.witness_signature as string;
    expect(/[+/]/.test(sig)).toBe(true);
    for (const [name, text] of variants(sig)) {
      expect(text, name).not.toBe(sig);
      expect(await outcome({ ...base, witness_signature: text }), name).toBe('invalid_signature');
    }
  });
});

describe('protocol_version and signable_protocol_version_emitted: integers in [0, 2^64 - 1]', () => {
  it('corpus case tamper_protocol_version_oversized_integer is refused as malformed', async () => {
    const text = readFileSync(join(CORPUS, 'cases', 'tamper_protocol_version_oversized_integer.json'), 'utf8');
    const c = JSON.parse(text);
    expect(c.expected.default.reason).toBe('malformed');
    expect(c.certificate.protocol_version).toBe(Infinity); // what JSON.parse makes of 5,000 digits
    expect(await outcome(c.certificate)).toBe('malformed');
  });

  it('protocol_version: garbage numbers are malformed, other integers are unsupported_protocol_version', async () => {
    for (const bad of [Infinity, -Infinity, NaN, 2.5, -1, -2, 2 ** 64, 1e30]) {
      expect(await outcome({ ...v3Cert(), protocol_version: bad }), String(bad)).toBe('malformed');
    }
    for (const other of [0, 1, 3, 4294967295, Number.MAX_SAFE_INTEGER]) {
      expect(await outcome({ ...v3Cert(), protocol_version: other }), String(other)).toBe('unsupported_protocol_version');
    }
    for (const notNumber of ['2', true, null, []]) {
      expect(await outcome({ ...v3Cert(), protocol_version: notNumber }), String(notNumber)).toBe('malformed');
    }
  });

  it('signable_protocol_version_emitted: a number that is not an integer in range is malformed', async () => {
    for (const bad of [Infinity, NaN, 2.5, 3.5, -1, 2 ** 64]) {
      expect(await outcome({ ...v3Cert(), signable_protocol_version_emitted: bad }), String(bad)).toBe('malformed');
      expect(await outcome({ ...v2Cert(), signable_protocol_version_emitted: bad }), String(bad)).toBe('malformed');
    }
    // in range: unchanged dispatch
    expect(await outcome({ ...v3Cert(), signable_protocol_version_emitted: 4 })).toBe('ACCEPT:v3');
    expect(await outcome({ ...v3Cert(), signable_protocol_version_emitted: 2 })).toBe('version_downgrade_detected');
    expect(await outcome({ ...v2Cert(), signable_protocol_version_emitted: 3 })).toBe('version_downgrade_detected');
    const absent = v2Cert();
    delete absent.signable_protocol_version_emitted;
    expect(await outcome(absent)).toBe('ACCEPT:v2');
  });
});

describe('number tokens are judged only where the SDK reads the text', () => {
  // The corpus case writes protocol_version as the token 2.0000000000000001.
  // The caller's JSON.parse hands verifyCertificate the number 2, so the
  // simple check cannot see the edit; the chain verifier, which takes the
  // text, refuses it. The bytes the simple check verifies are those of the
  // untampered certificate.
  it('tamper_protocol_version_float_token: same signable bytes as its untampered parent; the chain verifier refuses the text', async () => {
    const file = readFileSync(join(CORPUS, 'cases', 'tamper_protocol_version_float_token.json'), 'utf8');
    expect(file).toMatch(/"protocol_version":\s*2\.0000000000000001/);
    const c = JSON.parse(file);
    expect(c.expected.default.reason).toBe('malformed');
    expect(c.certificate.protocol_version).toBe(2);

    const tampered = parseCertificate(c.certificate);
    const parent = parseCertificate(v3Cert());
    expect(Buffer.from(deriveWitnessSignedBytesV3(tampered)).equals(Buffer.from(deriveWitnessSignedBytesV3(parent)))).toBe(true);
    expect(Buffer.from(deriveWitnessSignedBytes(tampered)).equals(Buffer.from(deriveWitnessSignedBytes(parent)))).toBe(true);
    expect(await outcome(c.certificate)).toBe('ACCEPT:v3');

    const services: Record<string, string> = {};
    for (const [svc, v] of Object.entries(KEYS.services)) services[svc] = v.public_key_base64;
    const text = JSON.stringify(c.certificate).replace('"protocol_version":2', '"protocol_version":2.0000000000000001');
    expect(text).toContain('"protocol_version":2.0000000000000001');
    const chain = await verifyCertificateChain(text, { ...WITNESS, servicePublicKeys: services, allowTestKeys: true });
    expect([chain.verdict, chain.reason]).toEqual(['FAILED', 'malformed']);
  });
});
