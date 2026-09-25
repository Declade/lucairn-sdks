// T-935 S3 parity: verifyCertificateChain against the vendored corpus
// (testdata/parity-corpus, vendored from Declade/dual-sandbox-architecture
// tools/parity-corpus at the commit in SOURCE.json). The Python
// (python/tests/test_parity_corpus.py) and Go (go/parity_corpus_test.go) SDKs
// run the same cases against the same expectations.

import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyCertificate } from '../verify-certificate/index.js';
import { Lucairn } from '../client.js';
import * as pkg from '../index.js';
import {
  CHAIN_STEPS,
  f32,
  integer,
  rfc3339NanoUtc,
  verifyCertificateChain,
  type CertificateChainKeys,
  type CertificateChainResult,
} from './index.js';
import { JNum, canonical, parseDocument, type JObj } from './json.js';

const ROOT = join(__dirname, '..', '..', '..', 'testdata', 'parity-corpus');
const CORPUS = join(ROOT, 'v1');
const EXPECTED_CASES = 54;

interface Manifest {
  format: string;
  policies: Array<{ name: string; minimum_signable_version: 'v2' | 'v3' }>;
  verdicts: string[];
  reasons: string[];
  egress_states: string[];
  user_unredacted: string[];
  signed_cert_tiers: string[];
  signable_versions: string[];
  cases: Array<{ id: string; file: string; sha256: string; expected: Record<string, CertificateChainResult> }>;
}

const read = (...p: string[]): Buffer => readFileSync(join(ROOT, ...p));
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const SOURCE = JSON.parse(read('SOURCE.json').toString('utf8'));
const MANIFEST = JSON.parse(read('v1', 'manifest.json').toString('utf8')) as Manifest;
const KEYS = JSON.parse(read('v1', 'keys.json').toString('utf8'));

function keys(): CertificateChainKeys {
  const services: Record<string, string> = {};
  for (const [svc, v] of Object.entries(KEYS.services as Record<string, { public_key_base64: string }>)) {
    services[svc] = v.public_key_base64;
  }
  return { witnessKeyId: KEYS.witness.key_id, witnessPublicKey: KEYS.witness.public_key_base64, servicePublicKeys: services };
}

/** The verifier input: certificate_text verbatim when present, else the certificate's JSON text with every number lexeme kept. */
function rawCertificate(file: string): string {
  const doc = parseDocument(readFileSync(join(CORPUS, file))) as JObj;
  const txt = doc.get('certificate_text');
  if (typeof txt === 'string') return txt;
  return canonical(doc.get('certificate')!);
}

describe('parity corpus: vendored copy', () => {
  it('matches the hashes recorded in SOURCE.json and the manifest', () => {
    expect(SOURCE.format).toBe('lucairn-parity-corpus/v1.1');
    expect(MANIFEST.format).toBe(SOURCE.format);
    expect(sha(read('v1', 'manifest.json'))).toBe(SOURCE.manifest_sha256);
    expect(sha(read('v1', 'keys.json'))).toBe(SOURCE.keys_sha256);
    expect(sha(read('recipe-table.md'))).toBe(SOURCE.recipe_table_sha256);
    const onDisk = readdirSync(join(CORPUS, 'cases')).sort();
    const listed = MANIFEST.cases.map((c) => c.file.split('/').pop()!).sort();
    expect(onDisk).toEqual(listed);
    for (const c of MANIFEST.cases) expect(sha(read('v1', c.file)), c.id).toBe(c.sha256);
  });

  it('CHAIN_STEPS equals the vendored recipe table', () => {
    const spec = read('recipe-table.md').toString('utf8');
    const table = spec.split('<!-- recipe-table:begin -->')[1].split('<!-- recipe-table:end -->')[0];
    const rows = table
      .trim()
      .split('\n')
      .slice(2)
      .map((line) => {
        const cells = line.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
        const m = /^(\S+) `(\S+)`$/.exec(cells[2]);
        if (!m) throw new Error(`row ${line}`);
        return [cells[0], m[1], m[2]];
      });
    expect(CHAIN_STEPS.map((s) => [...s])).toEqual(rows);
    expect([...new Set(CHAIN_STEPS.map((s) => s[2]))].sort()).toEqual([...MANIFEST.reasons].sort());
  });
});

describe('parity corpus: every case × every policy', () => {
  it(`reaches the expected result on all ${EXPECTED_CASES} cases under both policies`, async () => {
    expect(MANIFEST.cases).toHaveLength(EXPECTED_CASES);
    expect(MANIFEST.policies.map((p) => p.name)).toEqual(['default', 'minimum_v3']);
    const k = keys();
    const passed: Record<string, number> = { default: 0, minimum_v3: 0 };
    const mismatches: string[] = [];
    for (const c of MANIFEST.cases) {
      const raw = rawCertificate(c.file);
      for (const p of MANIFEST.policies) {
        const got = await verifyCertificateChain(raw, k, { minimumSignableVersion: p.minimum_signable_version });
        const want = c.expected[p.name];
        if (JSON.stringify(got) === JSON.stringify(want)) passed[p.name]++;
        else mismatches.push(`${c.id} [${p.name}]\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
        expect(MANIFEST.verdicts).toContain(got.verdict);
        expect(MANIFEST.reasons).toContain(got.reason);
        expect(MANIFEST.egress_states).toContain(got.egress_attestation);
        expect(MANIFEST.user_unredacted).toContain(got.user_unredacted);
        expect(MANIFEST.signed_cert_tiers).toContain(got.signed_cert_tier);
        expect(MANIFEST.signable_versions).toContain(got.signable_version);
      }
    }
    // eslint-disable-next-line no-console
    console.log(`ts parity: default ${passed.default}/${EXPECTED_CASES}, minimum_v3 ${passed.minimum_v3}/${EXPECTED_CASES}`);
    expect(mismatches).toEqual([]);
    expect(passed).toEqual({ default: EXPECTED_CASES, minimum_v3: EXPECTED_CASES });
  });

  it('string and UTF-8 byte inputs agree', async () => {
    const k = keys();
    for (const c of MANIFEST.cases) {
      const raw = rawCertificate(c.file);
      expect(await verifyCertificateChain(new TextEncoder().encode(raw), k)).toEqual(await verifyCertificateChain(raw, k));
    }
  });
});

describe('RED-PROOF (PRD § RED-PROOF): edited claim body, same id', () => {
  it('the witness-only verifyCertificate accepts it; verifyCertificateChain FAILS it', async () => {
    const raw = rawCertificate('cases/tamper_claim_body_edited_same_id.json');
    const witnessOnly = await verifyCertificate(JSON.parse(raw), {
      witnessKeyId: KEYS.witness.key_id,
      witnessPublicKey: KEYS.witness.public_key_base64,
    });
    expect(witnessOnly.overallVerdict).toBe('VERDICT_VERIFIED');
    for (const minimumSignableVersion of ['v2', 'v3'] as const) {
      const got = await verifyCertificateChain(raw, keys(), { minimumSignableVersion });
      expect([got.verdict, got.reason]).toEqual(['FAILED', 'claim_signature_invalid']);
    }
  });
});

describe('verifyCertificateChain surface', () => {
  it('is exported from the package root and the client', async () => {
    expect(pkg.verifyCertificateChain).toBe(verifyCertificateChain);
    const client = new Lucairn({ apiKey: 'dsa_0123456789abcdef0123456789abcdef' });
    const got = await client.verifyCertificateChain('[]', keys());
    expect(got.reason).toBe('malformed');
  });

  it('throws on programmer errors only', async () => {
    const k = keys();
    await expect(verifyCertificateChain({} as unknown as string, k)).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', k, { minimumSignableVersion: 'v4' as 'v3' })).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', { ...k, witnessPublicKey: new Uint8Array(31) })).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', { ...k, servicePublicKeys: { 'dsa-ai': new Uint8Array(3) } })).rejects.toThrow(TypeError);
    for (const junk of ['', '[]', '{'.repeat(20000), '﻿{}', new Uint8Array([0xff])]) {
      const got = await verifyCertificateChain(junk, k);
      expect([got.verdict, got.reason, got.user_unredacted]).toEqual(['FAILED', 'malformed', 'unknown']);
    }
  });

  it('a "__proto__" key is plain data', async () => {
    const got = await verifyCertificateChain('{"__proto__":{"verification":1}}', keys());
    expect(got.reason).toBe('malformed');
  });
});

// Grammar vectors — the SAME vectors as the DSA references (reference_test.go
// TestGrammar_Vectors, test_reference_verify.py test_grammar_vectors).
describe('grammar vectors', () => {
  it('timestamps (step 5a)', () => {
    const vectors: Array<[string, string | null]> = [
      ['2026-09-25T12:00:02.5Z', '2026-09-25T12:00:02.5Z'],
      ['2026-09-25T12:00:02.500000000Z', '2026-09-25T12:00:02.5Z'],
      ['2026-09-25T12:00:02.5000000000Z', null],
      ['2026-09-25T12:00:00.123456789-00:30', '2026-09-25T12:30:00.123456789Z'],
      ['2026-09-25T14:00:00+02:00', '2026-09-25T12:00:00Z'],
      ['2024-02-29T00:00:00Z', '2024-02-29T00:00:00Z'],
      ['0001-01-01T00:00:00-01:00', '0001-01-01T01:00:00Z'],
      ['2026-09-25T12:00:00+24:00', null],
      ['2026-09-25T12:00:00+23:60', null],
      ['2026-09-25T12:00:00+99:00', null],
      ['2026-09-25T12:00:60Z', null],
      ['2026-09-25T24:00:00Z', null],
      ['2026-02-30T12:00:00Z', null],
      ['0000-01-01T00:00:00Z', null],
      ['0001-01-01T00:00:00+01:00', null],
      ['9999-12-31T23:59:59-01:00', null],
      ['2026-09-25t12:00:00z', null],
      ['2026-09-25T12:00:00.Z', null],
      ['2026-09-25T12:00:00', null],
      ['２026-09-25T12:00:00Z', null],
    ];
    for (const [s, want] of vectors) expect(rfc3339NanoUtc(s), s).toBe(want);
  });

  it('documents (§ Input document)', () => {
    const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
    const vectors: Array<[Uint8Array, boolean]> = [
      [enc('{"a":1}'), true],
      [enc('{"a":1} \n\t\r'), true],
      [enc('{"a":1}]'), false],
      [enc('{"a":1}}'), false],
      [enc('{"a":1} x'), false],
      [enc('{"a":1}{"b":2}'), false],
      [enc('{"a":NaN}'), false],
      [enc('{"a":Infinity}'), false],
      [enc('{"a":-Infinity}'), false],
      [new Uint8Array([0xef, 0xbb, 0xbf, ...enc('{"a":1}')]), false],
      [new Uint8Array([...enc('{"a":"'), 0xff, ...enc('"}')]), false],
    ];
    for (const [doc, ok] of vectors) {
      let parsed = true;
      try {
        parseDocument(doc);
      } catch {
        parsed = false;
      }
      expect(parsed, Buffer.from(doc).toString('latin1')).toBe(ok);
    }
  });

  it('integer tokens and float32 range (§ Canonical JSON)', () => {
    const ints: Array<[string, boolean]> = [
      ['0', true],
      ['2', true],
      ['18446744073709551615', true],
      ['18446744073709551616', false],
      ['00', false],
      ['2.0', false],
      ['2e0', false],
      ['-1', false],
      ['1' + '0'.repeat(4999), false],
    ];
    for (const [t, ok] of ints) expect(integer(new JNum(t), 2n ** 64n - 1n) !== null, t.slice(0, 30)).toBe(ok);
    const floats: Array<[string, boolean]> = [
      ['0.25', true],
      ['1e-50', true],
      ['3.4028235e38', true],
      ['3.4028236e38', false],
      ['1e39', false],
      ['-1e39', false],
      ['1e400', false],
    ];
    for (const [t, ok] of floats) expect(f32(new JNum(t), false) !== null, t).toBe(ok);
  });

  it('canonical JSON keeps lexemes and escapes like Python ensure_ascii', () => {
    const v = parseDocument('{"b":0.0,"a":["\\u00fc<>&/\\u007f","\\ud83d\\ude00"],"\\ud800":1e5}');
    expect(canonical(v)).toBe('{"a":["\\u00fc<>&/\\u007f","\\ud83d\\ude00"],"b":0.0,"\\ufffd":1e5}');
  });
});

describe('cross-SDK rules beyond the corpus', () => {
  it('nesting bound, surrogates, whitespace', async () => {
    expect(() => parseDocument('['.repeat(256) + ']'.repeat(256))).not.toThrow();
    expect(() => parseDocument('['.repeat(257) + ']'.repeat(257))).toThrow();
    expect(() => parseDocument('["' + '['.repeat(300) + '"]')).not.toThrow();
    const v = parseDocument('{"\\udc00":"\\ud800x\\ud83d\\ude00"}') as JObj;
    expect([...v.entries()]).toEqual([['\ufffd', '\ufffdx\u{1f600}']]);
  });

  it('rejects a Map as servicePublicKeys', async () => {
    const k = keys();
    await expect(
      verifyCertificateChain('{}', { ...k, servicePublicKeys: new Map() as unknown as Record<string, string> }),
    ).rejects.toThrow(TypeError);
  });
});
