// Parity: verifyCertificateChain against the vendored corpus
// (testdata/parity-corpus, vendored from Declade/dual-sandbox-architecture
// tools/parity-corpus at the commit in SOURCE.json, format
// lucairn-parity-corpus/v1.2.1). The Python (python/tests/test_parity_corpus.py)
// and Go (go/parity_corpus_test.go) SDKs run the same cases against the same
// expectations: every result field, `verified` compared as canonical JSON,
// under both policies, with each case's request-binding inputs.

import { describe, expect, it } from 'vitest';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyCertificate } from '../verify-certificate/index.js';
import { Lucairn } from '../client.js';
import * as pkg from '../index.js';
import {
  CHAIN_STEPS,
  MAX_INPUT_BYTES,
  MAX_VALUES_POINTER_BYTES,
  PinnedKeyError,
  canonicalVerifiedJson,
  certTierCheck,
  f32,
  integer,
  parseCertificateDocument,
  protoJsonName,
  qiVerdict,
  rfc3339NanoUtc,
  trimSpace,
  valuesBytes,
  verifyCertificateChain,
  type CertificateChainKeys,
  type CertificateChainResult,
  type VerifyCertificateChainOptions,
} from './index.js';
import { CORPUS_TEST_KEYS, pinnedKey } from './ed25519.js';
import { JNum, MAX_DEPTH, canonical, parseDocument, parseLenient, type JObj, type JVal } from './json.js';

const ROOT = join(__dirname, '..', '..', '..', 'testdata', 'parity-corpus');
const CORPUS = join(ROOT, 'v1');
const FORMAT = 'lucairn-parity-corpus/v1.2.1';
const EXPECTED_CASES = 84;

type Summary = Omit<CertificateChainResult, 'verified'>;
interface ManifestCase {
  id: string;
  file: string;
  sha256: string;
  class: string;
  surface: string;
  inputs?: { expected_request_id?: string; expected_certificate_id?: string };
  expected: Record<string, Summary>;
}
interface Manifest {
  format: string;
  seed: string;
  keys: string;
  key_policy: string;
  max_input_bytes: number;
  max_depth: number;
  max_values_pointer_bytes: number;
  policies: Array<{ name: string; minimum_signable_version: 'v2' | 'v3' }>;
  verdicts: string[];
  reasons: string[];
  egress_states: string[];
  user_unredacted: string[];
  signed_cert_tiers: string[];
  signable_versions: string[];
  request_bindings: string[];
  classes: string[];
  cases: ManifestCase[];
}
interface KeyEntry {
  key_id?: string;
  public_key_base64: string;
}

const read = (...p: string[]): Buffer => readFileSync(join(ROOT, ...p));
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const SOURCE = JSON.parse(read('SOURCE.json').toString('utf8'));
const MANIFEST = JSON.parse(read('v1', 'manifest.json').toString('utf8')) as Manifest;
const KEYS = JSON.parse(read('v1', 'keys.json').toString('utf8')) as {
  format: string;
  witness: KeyEntry;
  services: Record<string, KeyEntry>;
  not_pinned: Record<string, KeyEntry>;
};
const KEY_POLICY = JSON.parse(read('v1', 'key-policy.json').toString('utf8')) as {
  format: string;
  codes: string[];
  vectors: Array<{ id: string; public_key: string; allow_test_keys: boolean; expected: string }>;
};

const SUMMARY_FIELDS = [
  'verdict',
  'reason',
  'egress_attestation',
  'user_unredacted',
  'signed_cert_tier',
  'signable_version',
  'request_binding',
] as const;
const V2_KEYS = ['certificate_id', 'claim_ids', 'issued_at', 'overall_verdict', 'protocol_version', 'request_id', 'witness_key_id'];
const V3_KEYS = [...V2_KEYS, 'api_key_id', 'byok_exempt', 'client_id', 'redaction_manifest_hash', 'sanitized_fields_body_hash', 'tms_manifest_hash'].sort();

/** The corpus pins, loaded the ONE way a parity harness may: allowTestKeys. */
function keys(): CertificateChainKeys {
  const services: Record<string, string> = {};
  for (const [svc, v] of Object.entries(KEYS.services)) services[svc] = v.public_key_base64;
  return {
    witnessKeyId: KEYS.witness.key_id!,
    witnessPublicKey: KEYS.witness.public_key_base64,
    servicePublicKeys: services,
    allowTestKeys: true,
  };
}

/**
 * A case file, loaded with a parser that keeps number lexemes but WITHOUT the
 * verifier-input rules (a case wraps inputs that break them on purpose: a
 * 5,000-digit integer, 300 levels of nesting).
 */
function loadCase(file: string): JObj {
  return parseLenient(readFileSync(join(CORPUS, file))) as JObj;
}

/** The verifier input: certificate_text verbatim when present, else the certificate's JSON text with every number lexeme kept. */
function rawCertificate(file: string): string {
  const doc = loadCase(file);
  const txt = doc.get('certificate_text');
  if (typeof txt === 'string') return txt;
  return canonical(doc.get('certificate')!);
}

function options(c: ManifestCase, min: 'v2' | 'v3'): VerifyCertificateChainOptions {
  return {
    minimumSignableVersion: min,
    expectedRequestId: c.inputs?.expected_request_id,
    expectedCertificateId: c.inputs?.expected_certificate_id,
  };
}

const summary = (r: CertificateChainResult): Summary => {
  const out = {} as Record<string, unknown>;
  for (const f of SUMMARY_FIELDS) out[f] = r[f];
  return out as Summary;
};

const caseById = (id: string): ManifestCase => {
  const c = MANIFEST.cases.find((x) => x.id === id);
  if (!c) throw new Error(`case ${id} missing`);
  return c;
};

describe('parity corpus: vendored copy', () => {
  it('matches the hashes recorded in SOURCE.json and the manifest', () => {
    expect(SOURCE.format).toBe(FORMAT);
    expect(MANIFEST.format).toBe(FORMAT);
    expect(KEYS.format).toBe(FORMAT);
    expect(KEY_POLICY.format).toBe(FORMAT);
    expect(MANIFEST.keys).toBe('keys.json');
    expect(MANIFEST.key_policy).toBe('key-policy.json');
    expect(sha(read('v1', 'manifest.json'))).toBe(SOURCE.manifest_sha256);
    expect(sha(read('v1', 'keys.json'))).toBe(SOURCE.keys_sha256);
    expect(sha(read('v1', 'key-policy.json'))).toBe(SOURCE.key_policy_sha256);
    expect(sha(read('recipe-table.md'))).toBe(SOURCE.recipe_table_sha256);
    const onDisk = readdirSync(join(CORPUS, 'cases')).sort();
    const listed = MANIFEST.cases.map((c) => c.file.split('/').pop()!).sort();
    expect(onDisk).toEqual(listed);
    expect(readdirSync(CORPUS).sort()).toEqual(['cases', 'key-policy.json', 'keys.json', 'manifest.json']);
    for (const c of MANIFEST.cases) expect(sha(read('v1', c.file)), c.id).toBe(c.sha256);
  });

  it('every case file carries the manifest entry, and the manifest expected is the case expected without `verified`', () => {
    for (const c of MANIFEST.cases) {
      const doc = JSON.parse(read('v1', c.file).toString('utf8'), (_k, v) => v);
      expect(doc.format, c.id).toBe(FORMAT);
      expect([doc.id, doc.class, doc.surface], c.id).toEqual([c.id, c.class, c.surface]);
      expect(doc.inputs, c.id).toEqual(c.inputs);
      expect(Object.keys(doc.expected).sort(), c.id).toEqual(MANIFEST.policies.map((p) => p.name).sort());
      for (const p of MANIFEST.policies) {
        const { verified: _v, ...rest } = doc.expected[p.name];
        expect(rest, `${c.id} [${p.name}]`).toEqual(c.expected[p.name]);
        expect('verified' in doc.expected[p.name], c.id).toBe(true);
      }
    }
  });

  it('the bounds in the manifest are the verifier constants', () => {
    expect(MANIFEST.max_input_bytes).toBe(MAX_INPUT_BYTES);
    expect(MANIFEST.max_depth).toBe(MAX_DEPTH);
    expect(MANIFEST.max_values_pointer_bytes).toBe(MAX_VALUES_POINTER_BYTES);
  });

  it('the built-in test-key denylist is exactly every key in keys.json', () => {
    const all = [KEYS.witness, ...Object.values(KEYS.services), ...Object.values(KEYS.not_pinned)].map((k) => k.public_key_base64);
    expect([...CORPUS_TEST_KEYS].sort()).toEqual([...new Set(all)].sort());
    expect(CORPUS_TEST_KEYS).toHaveLength(10);
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

  it('every reason is some case expected reason', () => {
    const seen = new Set(MANIFEST.cases.flatMap((c) => Object.values(c.expected).map((e) => e.reason)));
    expect([...seen].sort()).toEqual([...MANIFEST.reasons].sort());
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
      const caseDoc = loadCase(c.file);
      const raw = rawCertificate(c.file);
      expect(MANIFEST.classes).toContain(c.class);
      for (const p of MANIFEST.policies) {
        const got = await verifyCertificateChain(raw, k, options(c, p.minimum_signable_version));
        const wantDoc = (caseDoc.get('expected') as JObj).get(p.name) as JObj;
        const wantVerified = canonical(wantDoc.get('verified') as JVal);
        const gotVerified = canonicalVerifiedJson(got.verified);
        const same = JSON.stringify(summary(got)) === JSON.stringify(c.expected[p.name]) && gotVerified === wantVerified;
        if (same) passed[p.name]++;
        else {
          mismatches.push(
            `${c.id} [${p.name}]\n  got  ${JSON.stringify(summary(got))} verified=${gotVerified.slice(0, 200)}\n` +
              `  want ${JSON.stringify(c.expected[p.name])} verified=${wantVerified.slice(0, 200)}`,
          );
        }
        // Closed vocabularies.
        expect(MANIFEST.verdicts).toContain(got.verdict);
        expect(MANIFEST.reasons).toContain(got.reason);
        expect(MANIFEST.egress_states).toContain(got.egress_attestation);
        expect(MANIFEST.user_unredacted).toContain(got.user_unredacted);
        expect(MANIFEST.signed_cert_tiers).toContain(got.signed_cert_tier);
        expect(MANIFEST.signable_versions).toContain(got.signable_version);
        expect(MANIFEST.request_bindings).toContain(got.request_binding);
        expect(Object.keys(got).sort()).toEqual([...SUMMARY_FIELDS, 'verified'].sort());
        // FAILED ⇔ unknown / not_evaluated / none / not_evaluated / verified null.
        const failed = got.verdict === 'FAILED';
        expect(
          [got.user_unredacted === 'unknown', got.egress_attestation === 'not_evaluated', got.signed_cert_tier === 'not_evaluated',
            got.signable_version === 'none', got.request_binding === 'not_evaluated', got.verified === null],
          c.id,
        ).toEqual(Array(6).fill(failed));
        // request_binding is `matched` exactly on the non-FAILED cases with inputs.
        if (!failed) expect(got.request_binding, c.id).toBe(c.inputs ? 'matched' : 'not_checked');
        // verified.certificate is the signable map of the signature that verified; claims are {canonical, values}.
        if (got.verified) {
          const certKeys = Object.keys(got.verified.certificate).sort();
          expect(certKeys, c.id).toEqual(got.signable_version === 'v3' ? V3_KEYS : V2_KEYS);
          expect(Object.keys(got.verified.claims).length, c.id).toBeGreaterThan(0);
          for (const e of Object.values(got.verified.claims)) {
            expect(Object.keys(e).sort()).toEqual(['canonical', 'values']);
            expect(typeof e.canonical).toBe('string');
            for (const v of Object.values(e.values)) expect(['string', 'boolean', 'bigint']).toContain(typeof v);
          }
        }
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
      const o = options(c, 'v2');
      const a = await verifyCertificateChain(new TextEncoder().encode(raw), k, o);
      const b = await verifyCertificateChain(raw, k, o);
      expect(summary(a), c.id).toEqual(summary(b));
      expect(canonicalVerifiedJson(a.verified), c.id).toBe(canonicalVerifiedJson(b.verified));
    }
  });

  it('without the case inputs, the request-binding cases verify as not_checked', async () => {
    for (const id of ['honest_full_chain_request_bound', 'tamper_request_id_mismatch', 'tamper_certificate_id_mismatch']) {
      const got = await verifyCertificateChain(rawCertificate(caseById(id).file), keys());
      expect(got.verdict, id).not.toBe('FAILED');
      expect(got.request_binding, id).toBe('not_checked');
    }
  });
});

describe('request binding (step 5e)', () => {
  const file = (): string => rawCertificate(caseById('honest_full_chain_egress').file);

  it('matches the witness-signed ids, and an empty string is a supplied value', async () => {
    const raw = file();
    const base = await verifyCertificateChain(raw, keys());
    const cert = base.verified!.certificate;
    const ok = await verifyCertificateChain(raw, keys(), { expectedRequestId: cert.request_id });
    expect([ok.verdict, ok.request_binding]).toEqual(['VERIFIED', 'matched']);
    const both = await verifyCertificateChain(raw, keys(), { expectedRequestId: cert.request_id, expectedCertificateId: cert.certificate_id });
    expect(both.request_binding).toBe('matched');
    for (const o of [{ expectedRequestId: '' }, { expectedCertificateId: '' }, { expectedRequestId: cert.request_id + ' ' }]) {
      const got = await verifyCertificateChain(raw, keys(), o);
      expect([got.verdict, got.reason, got.request_binding, got.verified]).toEqual(['FAILED', 'request_mismatch', 'not_evaluated', null]);
    }
  });

  it('a non-string expected id is a programmer error', async () => {
    await expect(verifyCertificateChain(file(), keys(), { expectedRequestId: null as unknown as string })).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain(file(), keys(), { expectedCertificateId: 5 as unknown as string })).rejects.toThrow(TypeError);
  });
});

describe('pinned-key policy (key-policy.json)', () => {
  it('every vector, directly and through verifyCertificateChain', async () => {
    expect(KEY_POLICY.codes).toEqual(['ok', 'key_malformed', 'key_small_order', 'key_invalid_point', 'key_test_key']);
    const seen: Record<string, number> = {};
    for (const v of KEY_POLICY.vectors) {
      let direct = 'ok';
      try {
        pinnedKey(v.public_key, v.allow_test_keys, 'vector');
      } catch (e) {
        expect(e).toBeInstanceOf(PinnedKeyError);
        direct = (e as PinnedKeyError).code;
      }
      expect(direct, v.id).toBe(v.expected);
      // Same key as the witness pin, then as a service pin.
      for (const place of ['witness', 'service'] as const) {
        const k: CertificateChainKeys = {
          witnessKeyId: 'w',
          witnessPublicKey: place === 'witness' ? v.public_key : '+9E9VmGRMIf8YPRAaMxuIW52ZghahI+7/Wx6YHRReuE=', // key-policy.json vector "ok"
          servicePublicKeys: place === 'service' ? { 'dsa-ai': v.public_key } : {},
          allowTestKeys: v.allow_test_keys,
        };
        let api = 'ok';
        try {
          await verifyCertificateChain('{}', k);
        } catch (e) {
          expect(e).toBeInstanceOf(PinnedKeyError);
          expect(e).toBeInstanceOf(TypeError);
          api = (e as PinnedKeyError).code;
        }
        expect(api, `${v.id} as ${place}`).toBe(v.expected);
      }
      seen[v.expected] = (seen[v.expected] ?? 0) + 1;
    }
    expect(seen.key_small_order).toBe(15);
    expect(seen.key_test_key).toBe(10);
    expect(seen.key_malformed).toBeGreaterThanOrEqual(10);
    expect(seen.key_invalid_point).toBeGreaterThanOrEqual(4);
  });

  it('the corpus keys load ONLY with allowTestKeys (default false)', async () => {
    const { allowTestKeys: _a, ...noFlag } = keys();
    for (const k of [noFlag, { ...noFlag, allowTestKeys: false }]) {
      await expect(verifyCertificateChain('{}', k)).rejects.toMatchObject({ code: 'key_test_key', key: 'witnessPublicKey' });
    }
    await expect(verifyCertificateChain('{}', { ...keys(), allowTestKeys: 'yes' as unknown as boolean })).rejects.toThrow(TypeError);
  });

  it('raw-byte keys must be exactly 32 bytes and pass the same checks', () => {
    expect(() => pinnedKey(new Uint8Array(31), true, 'k')).toThrow(expect.objectContaining({ code: 'key_malformed' }));
    expect(() => pinnedKey(new Uint8Array(33), true, 'k')).toThrow(expect.objectContaining({ code: 'key_malformed' }));
    expect(() => pinnedKey(new Uint8Array(32), true, 'k')).toThrow(expect.objectContaining({ code: 'key_small_order' }));
    const witness = Buffer.from(KEYS.witness.public_key_base64, 'base64');
    expect(() => pinnedKey(new Uint8Array(witness), false, 'k')).toThrow(expect.objectContaining({ code: 'key_test_key' }));
    expect(pinnedKey(new Uint8Array(witness), true, 'k')).toEqual(new Uint8Array(witness));
    expect(() => pinnedKey(42, true, 'k')).toThrow(expect.objectContaining({ code: 'key_malformed' }));
  });
});

describe('RED-PROOF: edited claim body, same id', () => {
  it('the witness-only verifyCertificate accepts it; verifyCertificateChain FAILS it', async () => {
    const raw = rawCertificate('cases/tamper_claim_body_edited_same_id.json');
    const witnessOnly = await verifyCertificate(JSON.parse(raw), {
      witnessKeyId: KEYS.witness.key_id!,
      witnessPublicKey: KEYS.witness.public_key_base64,
    });
    expect(witnessOnly.overallVerdict).toBe('VERDICT_VERIFIED');
    for (const minimumSignableVersion of ['v2', 'v3'] as const) {
      const got = await verifyCertificateChain(raw, keys(), { minimumSignableVersion });
      expect([got.verdict, got.reason]).toEqual(['FAILED', 'claim_signature_invalid']);
    }
  });
});

describe('verified (§ Result)', () => {
  it('integers above 2^53 stay exact (bigint), and display values come from verified', async () => {
    const got = await verifyCertificateChain(rawCertificate(caseById('edge_values_integer_above_2_53').file), keys());
    const ints = Object.values(got.verified!.claims).flatMap((c) => Object.values(c.values).filter((v) => typeof v === 'bigint'));
    expect(ints).toContain(2n ** 53n + 1n);
    expect(got.verified!.certificate.protocol_version).toBe(2n);
  });

  it('a v2-only certificate carries no v3 value in verified (the forged metadata is nowhere)', async () => {
    const got = await verifyCertificateChain(rawCertificate(caseById('tamper_v3_stripped_metadata_forged').file), keys());
    expect([got.verdict, got.signable_version]).toEqual(['VERIFIED', 'v2']);
    expect(Object.keys(got.verified!.certificate).sort()).toEqual(V2_KEYS);
    expect(got.verified!.certificate.client_id).toBeUndefined();
    expect(got.verified!.certificate.byok_exempt).toBeUndefined();
  });

  it('an upstream body is shown only after it hashes to the verified digest at its index', async () => {
    const c = caseById('honest_full_chain_egress_export');
    const got = await verifyCertificateChain(rawCertificate(c.file), keys());
    expect(got.verdict).toBe('VERIFIED');
    const cert = (loadCase(c.file).get('certificate') as JObj).get('claims') as JObj[];
    let checked = 0;
    cert.forEach((cl, i) => {
      const inf = cl.get('inference');
      const bodies = inf instanceof Map ? (inf.get('upstream_request_bodies') as string[] | undefined) : undefined;
      if (!bodies || bodies.length === 0) return;
      const values = got.verified!.claims[`${i}:${cl.get('service_id')}:INFERENCE_COMPLETED`].values;
      bodies.forEach((b, j) => {
        expect(values[`/payload/upstream_body_sha256/${j}`]).toBe(sha(Buffer.from(b, 'base64')));
        checked++;
      });
    });
    expect(checked).toBe(2);
  });

  it('the values-bound case totals exactly the bound + 1', () => {
    const cert = (loadCase(caseById('tamper_values_bound_exceeded').file).get('certificate') as JObj).get('claims') as JObj[];
    let total = 0;
    for (const cl of cert) total += valuesBytes(parseDocument(Buffer.from(cl.get('canonical_payload') as string, 'base64')), 0, 2 ** 40);
    expect(total).toBe(MAX_VALUES_POINTER_BYTES + 1);
  });

  it('canonicalVerifiedJson of a FAILED result is "null"', () => {
    expect(canonicalVerifiedJson(null)).toBe('null');
  });
});

// README § Input document: an honest witness export at the sandbox-b store cap
// (two 8 MiB bodies), built at test time — too large to commit. The DSA Go and
// Python references pin the same bytes and the same `verified`.
describe('store-cap export (the 32 MiB input bound)', () => {
  it('verifies VERIFIED ok and matches the pinned bytes', async () => {
    const c = caseById('honest_full_chain_egress_export');
    const cert = loadCase(c.file).get('certificate') as JObj;
    const bodies = [Buffer.alloc(8 << 20, 'a'), Buffer.alloc(8 << 20, 'b')];
    const digests = bodies.map((b) => sha(b));
    const encoded = bodies.map((b) => b.toString('base64'));
    const seed = createHash('sha256').update(`lucairn-parity-corpus|${MANIFEST.seed}|dsa-ai`).digest();
    const priv = createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
      format: 'der',
      type: 'pkcs8',
    });
    let done = 0;
    for (const cl of cert.get('claims') as JObj[]) {
      if (cl.get('service_id') !== 'dsa-ai') continue;
      const doc = parseDocument(Buffer.from(cl.get('canonical_payload') as string, 'base64')) as JObj;
      (doc.get('payload') as JObj).set('upstream_body_sha256', digests);
      const cp = Buffer.from(canonical(doc), 'latin1');
      cl.set('canonical_payload', cp.toString('base64'));
      cl.set('signature', sign(null, cp, priv).toString('base64'));
      (cl.get('inference') as JObj).set('upstream_request_bodies', encoded);
      done++;
    }
    expect(done).toBe(1);
    const input = Buffer.from(canonical(cert), 'latin1');
    expect(input.length).toBeGreaterThan(16 << 20);
    expect(input.length).toBeLessThanOrEqual(MAX_INPUT_BYTES);
    expect(input.length).toBe(22377772);
    expect(sha(input)).toBe('3b1a18920801e20f239a42ab25fde44ed5bc741e947eb5af8872d24d6cb5469d');
    const got = await verifyCertificateChain(input, keys());
    expect([got.verdict, got.reason, got.egress_attestation]).toEqual(['VERIFIED', 'ok', 'signed_digests']);
    expect(sha(canonicalVerifiedJson(got.verified))).toBe('8d1c784e2d7d2d5b1df7875a7406350169cdac07924ebfbdf806de0623890ebd');
  }, 60_000);
});

// Two-signer rule (corpus v1.2.1 vendors the honest + label-tamper vectors; this
// wider label x shape matrix is kept alongside them): the two-signer
// input-shield chain — a sanitizer claim present, the gateway alone signs
// `cert_tier: "input-shield"`, no dsa-ai claim — pairs with the unsigned label
// `input_shield_two_signer` (and only that label reports that tier). The certificates below are built in-test
// from `honest_input_shield`: drop the dsa-ai claim, set the unsigned label,
// re-seal both witness signatures with the corpus TEST witness key.
describe('two-signer input-shield chain (label x shape matrix)', () => {
  const seedKey = (label: string) =>
    createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        createHash('sha256').update(`lucairn-parity-corpus|${MANIFEST.seed}|${label}`).digest(),
      ]),
      format: 'der',
      type: 'pkcs8',
    });

  /** Recompute the v2 and v3 witness signatures over the (edited) certificate. */
  function reseal(cert: JObj): void {
    const claims = cert.get('claims') as JObj[];
    const ver = cert.get('verification') as JObj;
    const sealed = ver.get('overall_verdict') as string;
    const v2: JObj = new Map<string, JVal>([
      ['certificate_id', cert.get('certificate_id')!],
      ['request_id', cert.get('request_id')!],
      ['protocol_version', new JNum('2')],
      ['claim_ids', claims.map((c) => c.get('claim_id') as string)],
      ['issued_at', rfc3339NanoUtc(cert.get('issued_at') as string)!],
      ['overall_verdict', sealed.replace(/^VERDICT_/, '')],
      ['witness_key_id', cert.get('witness_key_id')!],
    ]);
    const san = claims.find((c) => c.get('service_id') === 'dsa-sanitizer');
    const sp = san
      ? ((parseDocument(Buffer.from(san.get('canonical_payload') as string, 'base64')) as JObj).get('payload') as JObj)
      : new Map<string, JVal>();
    const h = (k: string): JVal => (typeof sp.get(k) === 'string' && sp.get(k) !== '' ? (sp.get(k) as string) : null);
    const v3: JObj = new Map(v2);
    v3.set('client_id', cert.get('client_id') ?? null);
    v3.set('api_key_id', cert.get('api_key_id') ?? null);
    v3.set('byok_exempt', ver.get('byok_exempt') === true);
    v3.set('redaction_manifest_hash', h('redaction_manifest_hash'));
    v3.set('sanitized_fields_body_hash', h('sanitized_fields_hash'));
    v3.set('tms_manifest_hash', h('tms_manifest_hash'));
    const w = seedKey('witness');
    cert.set('witness_signature', sign(null, Buffer.from(canonical(v2), 'latin1'), w).toString('base64'));
    cert.set('signable_v3_signature', sign(null, Buffer.from(canonical(v3), 'latin1'), w).toString('base64'));
  }

  function build(unsignedTier: string, opts: { dropAi: boolean; dropSanitizer?: boolean; sealed?: string }): string {
    const cert = loadCase(caseById('honest_input_shield').file).get('certificate') as JObj;
    const drop = new Set([...(opts.dropAi ? ['dsa-ai'] : []), ...(opts.dropSanitizer ? ['dsa-sanitizer'] : [])]);
    cert.set('claims', (cert.get('claims') as JObj[]).filter((c) => !drop.has(c.get('service_id') as string)));
    const ver = cert.get('verification') as JObj;
    ver.set('cert_tier', unsignedTier);
    if (opts.sealed) ver.set('overall_verdict', opts.sealed);
    reseal(cert);
    return canonical(cert);
  }

  const run = async (raw: string) => {
    const r = await verifyCertificateChain(raw, keys());
    return [r.verdict, r.reason, r.signed_cert_tier];
  };

  it('the witness test key re-seals the untouched case identically (construction sanity)', async () => {
    const got = await verifyCertificateChain(build('input_shield', { dropAi: false }), keys());
    expect(summary(got)).toEqual(caseById('honest_input_shield').expected.default);
  });

  it('pairs with the unsigned input_shield_two_signer label; never green (no signed egress digest)', async () => {
    const raw = build('input_shield_two_signer', { dropAi: true });
    for (const minimumSignableVersion of ['v2', 'v3'] as const) {
      const got = await verifyCertificateChain(raw, keys(), { minimumSignableVersion });
      expect([got.verdict, got.reason, got.egress_attestation, got.signed_cert_tier, got.signable_version]).toEqual([
        'EGRESS_UNATTESTED', 'egress_unattested', 'unattested', 'input_shield_two_signer', 'v3',
      ]);
      expect(Object.keys(got.verified!.claims).some((k) => k.includes(':dsa-ai:'))).toBe(false);
    }
  });

  it('every other combination with that label stays a mismatch', async () => {
    // The full input-shield chain (dsa-ai claim present) with the new label.
    expect(await run(build('input_shield_two_signer', { dropAi: false }))).toEqual(['FAILED', 'cert_tier_mismatch', 'not_evaluated']);
    // ... also under a sealed PARTIAL (a label outside the vocabulary FAILS whatever the seal).
    expect(await run(build('input_shield_two_signer', { dropAi: false, sealed: 'VERDICT_PARTIAL' }))).toEqual([
      'FAILED', 'cert_tier_mismatch', 'not_evaluated',
    ]);
    // The two-signer shape with the other labels, sealed VERIFIED.
    for (const label of ['', 'full_chain', 'input_shield']) {
      expect(await run(build(label, { dropAi: true })), label).toEqual(['FAILED', 'cert_tier_mismatch', 'not_evaluated']);
    }
    // The same shape under any other label keeps today's result: signed tier `inconsistent`, and
    // under a sealed PARTIAL the seal caps the result as before (rule 4).
    for (const label of ['', 'full_chain', 'input_shield']) {
      expect(await run(build(label, { dropAi: true, sealed: 'VERDICT_PARTIAL' })), label).toEqual(['PARTIAL', 'sealed_partial', 'inconsistent']);
    }
    // The shape needs its sanitizer claim: a gateway-only chain (sanitizer claim dropped, re-sealed)
    // with the label is a mismatch, under either seal.
    for (const sealed of ['VERDICT_VERIFIED', 'VERDICT_PARTIAL']) {
      expect(await run(build('input_shield_two_signer', { dropAi: true, dropSanitizer: true, sealed })), sealed).toEqual([
        'FAILED', 'cert_tier_mismatch', 'not_evaluated',
      ]);
    }
    // The two-signer label itself under a sealed PARTIAL: accepted, capped by the seal.
    expect(await run(build('input_shield_two_signer', { dropAi: true, sealed: 'VERDICT_PARTIAL' }))).toEqual([
      'PARTIAL', 'sealed_partial', 'input_shield_two_signer',
    ]);
  });
});

describe('verifyCertificateChain surface', () => {
  it('is exported from the package root and the client', async () => {
    expect(pkg.verifyCertificateChain).toBe(verifyCertificateChain);
    expect(pkg.canonicalVerifiedJson).toBe(canonicalVerifiedJson);
    expect(pkg.PinnedKeyError).toBe(PinnedKeyError);
    const client = new Lucairn({ apiKey: 'dsa_0123456789abcdef0123456789abcdef' });
    const got = await client.verifyCertificateChain('[]', keys());
    expect(got.reason).toBe('malformed');
    const bound = await client.verifyCertificateChain(rawCertificate(caseById('honest_full_chain_egress').file), keys(), {
      expectedRequestId: 'another-turn',
    });
    expect(bound.reason).toBe('request_mismatch');
  });

  it('throws on programmer errors only', async () => {
    const k = keys();
    await expect(verifyCertificateChain({} as unknown as string, k)).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', k, { minimumSignableVersion: 'v4' as 'v3' })).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', { ...k, witnessPublicKey: new Uint8Array(31) })).rejects.toThrow(TypeError);
    await expect(verifyCertificateChain('{}', { ...k, servicePublicKeys: { 'dsa-ai': new Uint8Array(3) } })).rejects.toThrow(TypeError);
    await expect(
      verifyCertificateChain('{}', { ...k, servicePublicKeys: new Map() as unknown as Record<string, string> }),
    ).rejects.toThrow(TypeError);
    const loneHigh = String.fromCharCode(0xd800);
    for (const junk of ['', '[]', '{'.repeat(20000), '﻿{}', new Uint8Array([0xff]), `{"a":"${loneHigh}"}`]) {
      const got = await verifyCertificateChain(junk, k);
      expect([got.verdict, got.reason, got.user_unredacted, got.verified]).toEqual(['FAILED', 'malformed', 'unknown', null]);
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
    const nested = (n: number): string => '['.repeat(n) + ']'.repeat(n);
    const text: Array<[string, boolean]> = [
      ['{"a":1}', true],
      ['{"a":1} \n\t\r', true],
      ['{"a":1}]', false],
      ['{"a":1}}', false],
      ['{"a":1} x', false],
      ['{"a":1}{"b":2}', false],
      ['{"a":NaN}', false],
      ['{"a":Infinity}', false],
      ['{"a":-Infinity}', false],
      ['{"a":1]', false],
      ['[1,]', false],
      ['{"a":1,}', false],
      // Duplicate keys, compared after escape decoding.
      ['{"a":1,"a":1}', false],
      ['{"a":1,"a":2}', false],
      ['{"a":1,"\\u0061":2}', false],
      ['{"client_id":1,"client_\\u0069d":1}', false],
      ['{"a":{"b":1},"c":{"b":1}}', true],
      ['[{"a":1},{"a":1}]', true],
      // Surrogate escapes: a high + low pair only.
      ['{"a":"\\ud83d\\ude00"}', true],
      ['{"a":"\\uD83D\\uDE00"}', true],
      ['{"a":"\\ud800"}', false],
      ['{"a":"\\udc00"}', false],
      ['{"a":"\\ud800A"}', false],
      ['{"a":"\\ud800\\ud800"}', false],
      ['{"a":"\\ud800\\\\udc00"}', false],
      ['{"\\ud800":1}', false],
      ['{"a":"\\\\ud800"}', true],
      // Depth: at most 256 nested arrays / objects; brackets in strings do not count.
      [nested(MAX_DEPTH), true],
      [nested(MAX_DEPTH + 1), false],
      ['{"a":' + nested(MAX_DEPTH - 1) + '}', true],
      ['{"a":' + nested(MAX_DEPTH) + '}', false],
      ['{"a":"' + '['.repeat(MAX_DEPTH + 1) + '"}', true],
    ];
    const bytes: Array<[Uint8Array, boolean]> = [
      ...text.map(([s, ok]): [Uint8Array, boolean] => [enc(s), ok]),
      [new Uint8Array([0xef, 0xbb, 0xbf, ...enc('{"a":1}')]), false],
      [new Uint8Array([...enc('{"a":"'), 0xff, ...enc('"}')]), false],
      [new Uint8Array([...enc('{"a":"'), 0xed, 0xa0, 0x80, ...enc('"}')]), false], // UTF-8-encoded surrogate
    ];
    for (const [doc, ok] of bytes) {
      let parsed = true;
      try {
        parseDocument(doc);
      } catch {
        parsed = false;
      }
      expect(parsed, Buffer.from(doc).toString('latin1').slice(0, 80)).toBe(ok);
      // The string form decides the same.
      let parsedText = true;
      try {
        parseDocument(new TextDecoder('utf-8', { fatal: false, ignoreBOM: true }).decode(doc));
      } catch {
        parsedText = false;
      }
      if (ok) expect(parsedText).toBe(true);
    }
  });

  it('certificate keys: the case-variant rule (and protojson JSON names)', () => {
    const vectors: Array<[string, boolean]> = [
      ['byok_exempt', false],
      ['BYOK_EXEMPT', true],
      ['Client_Id', true],
      ['byoK_exempt', true], // U+212A KELVIN SIGN
      ['ſervice_id', true], // U+017F LATIN SMALL LETTER LONG S
      ['upstream_model', false], // not read by the recipe
      ['UPSTREAM_MODEL', false],
      ['PERSON', false],
      ['byok_exempt ', false],
      ['İssued_at', false], // U+0130 folds to no ASCII letter
      ['byokExempt', true],
      ['ByokExempt', true],
      ['byokexempt', true],
      ['clientId', true],
      ['upstreamRequestBodies', true],
      ['upstreamBodySha256', true],
      ['kAnonymity', true],
      ['model_uſed', true],
      ['upstreamModel', false], // upstream_model is not a spec key
      ['certificate_id_', false],
    ];
    for (const [key, refused] of vectors) {
      let err = false;
      try {
        parseCertificateDocument(JSON.stringify({ [key]: true }));
      } catch {
        err = true;
      }
      expect(err, key).toBe(refused);
      // Nested at any depth too.
      let nestedErr = false;
      try {
        parseCertificateDocument(JSON.stringify({ claims: [{ inference: { [key]: 1 } }] }));
      } catch {
        nestedErr = true;
      }
      expect(nestedErr, `nested ${key}`).toBe(refused);
    }
    expect(protoJsonName('upstream_body_sha256')).toBe('upstreamBodySha256');
    expect(protoJsonName('byok_exempt')).toBe('byokExempt');
  });

  it('the ONE whitespace set (step 4) and the qi_score verdict (step 7i)', () => {
    const blank: Array<[string, boolean]> = [
      ['', true],
      [' \t\n\v\f\r', true],
      ['  　\u0085', true],
      ['\u001c', false],
      ['\u001f', false],
      ['​', false],
      ['﻿', false],
      ['x', false],
    ];
    for (const [s, want] of blank) expect(trimSpace(s) === '', JSON.stringify(s)).toBe(want);
    const qi: Array<[string, string]> = [
      ['PASS', 'QI_VERDICT_PASS'],
      [' pass ', 'QI_VERDICT_PASS'],
      ['generalized', 'QI_VERDICT_GENERALIZED'],
      ['paſs', 'QI_VERDICT_UNKNOWN'],
      ['generalızed', 'QI_VERDICT_UNKNOWN'],
      ['\u001cPASS', 'QI_VERDICT_UNKNOWN'],
    ];
    for (const [s, want] of qi) expect(qiVerdict(s), JSON.stringify(s)).toBe(want);
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

  it('the input size bound: exactly max_input_bytes passes, one more byte is malformed', () => {
    const doc = '{"a":1}';
    const atCap = doc + ' '.repeat(MAX_INPUT_BYTES - doc.length);
    expect(() => parseCertificateDocument(atCap)).not.toThrow();
    expect(() => parseCertificateDocument(atCap + ' ')).toThrow();
    expect(() => parseCertificateDocument(Buffer.from(atCap + ' '))).toThrow();
  });

  it('canonical JSON keeps lexemes, sorts by code point and escapes like Python ensure_ascii', () => {
    const v = parseDocument('{"b":0.0,"a":["\\u00fc<>&/\\u007f","\\ud83d\\ude00"],"\\uffff":1e5,"\\ud83d\\ude00":2}');
    expect(canonical(v)).toBe('{"a":["\\u00fc<>&/\\u007f","\\ud83d\\ude00"],"b":0.0,"\\uffff":1e5,"\\ud83d\\ude00":2}');
  });
});

describe('two-signer cert_tier is not capped by step 8d (corpus v1.2.1)', () => {
  it('reports the tier, passes the label, no cap (the EGRESS_UNATTESTED ceiling comes from the absent digests)', () => {
    const claim = (svc: string): JObj => new Map<string, JVal>([['service_id', svc]]);
    const claims = [claim('dsa-sanitizer'), claim('dsa-gateway')];
    const canon: JObj[] = [new Map(), new Map<string, JVal>([['cert_tier', 'input-shield']])];
    expect(certTierCheck(claims, canon, 'input_shield_two_signer', 'VERDICT_VERIFIED')).toEqual([
      'input_shield_two_signer',
      true,
      false,
    ]);
  });
});
