// Certificate chain verification (T-935 S3 / T-794) — every inner claim.
//
// verifyCertificate() checks the witness signatures only: a certificate whose
// claim body was edited while its claim id stayed the same still passes it,
// because the witness signs the claim-id LIST, not the claim content.
// verifyCertificateChain() adds the layer on top: every claim's own Ed25519
// signature against a PINNED per-service key, the canonical bytes rebuilt
// from the outer fields, claim-id membership in the witness-signed list, the
// typed (unsigned) mirrors against the signed payload, the signed egress
// digests, the unsigned cert_tier against its signed copies, and the
// user_unredacted_segment token read from the SIGNED sanitizer payload only.
//
// The specification is the parity corpus README (Declade/dual-sandbox-
// architecture tools/parity-corpus/README.md; its ordered check table is
// vendored at testdata/parity-corpus/recipe-table.md) § Verification recipe. The Python and Go
// SDKs implement the same table; all three are held to the same corpus under
// both policies (parityCorpus.test.ts).

import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { normalizeEd25519PublicKey } from '../verify-certificate/keys.js';
import type { VerifyCertificateOptions } from '../types.js';
import { JNum, type JObj, type JVal, canonicalBytes, parseDocument } from './json.js';

// ---------------------------------------------------------------------------
// Public types.
// ---------------------------------------------------------------------------

export type CertificateChainVerdict = 'FAILED' | 'PARTIAL' | 'EGRESS_UNATTESTED' | 'VERIFIED';

export type CertificateChainReason =
  | 'ok'
  | 'egress_unattested'
  | 'inference_unfinished'
  | 'user_sent_unredacted'
  | 'sealed_partial'
  | 'malformed'
  | 'unsupported_protocol_version'
  | 'witness_key_mismatch'
  | 'version_downgrade_detected'
  | 'witness_signature_invalid'
  | 'signable_version_insufficient'
  | 'sealed_failed'
  | 'duplicate_claim_id'
  | 'unknown_service'
  | 'service_key_mismatch'
  | 'claim_signature_invalid'
  | 'claim_not_witness_listed'
  | 'claim_canonical_mismatch'
  | 'request_id_splice'
  | 'typed_payload_mismatch'
  | 'egress_digest_malformed'
  | 'egress_body_unbound'
  | 'egress_body_hash_mismatch'
  | 'cert_tier_mismatch';

/** The pinned trust roots for {@link verifyCertificateChain}. */
export interface CertificateChainKeys {
  /** The witness `key_id` the certificate must name. */
  witnessKeyId: string;
  /** Raw 32-byte Ed25519 key or its base64 string. */
  witnessPublicKey: Uint8Array | string;
  /**
   * One Ed25519 key (raw 32 bytes or base64) per claim-emitting `service_id`
   * (e.g. `dsa-sanitizer`, `dsa-ai`, `dsa-gateway`, `dsa-bridge`, `dsa-audit`,
   * `dsa-reid-guard`). A claim from a service with no pinned key FAILS the
   * certificate (`unknown_service`); it is never skipped.
   */
  servicePublicKeys: Record<string, Uint8Array | string>;
}

/**
 * README § Result — field names and values are the parity corpus's, verbatim
 * (snake_case on purpose: all four Lucairn verifiers return the same object).
 */
export interface CertificateChainResult {
  /** `FAILED` < `PARTIAL` < `EGRESS_UNATTESTED` < `VERIFIED`; only `VERIFIED` is green. */
  verdict: CertificateChainVerdict;
  /** The reason of the recipe step that decided. */
  reason: CertificateChainReason;
  egress_attestation: 'signed_digests' | 'unattested' | 'not_evaluated';
  /**
   * A STRING, three-state, read from the verified, signed sanitizer payload
   * only. Compare it to `'true'`, never by truthiness (`'false'` is truthy).
   */
  user_unredacted: 'true' | 'false' | 'unknown';
  /** Show THIS tier, never the unsigned `verification.cert_tier`. */
  signed_cert_tier: 'absent' | 'input_shield' | 'inconsistent' | 'not_evaluated';
  signable_version: 'v3' | 'v2' | 'none';
  /** The witness-signable keys that authenticated the certificate metadata (sorted). */
  authenticated_fields: string[];
  /**
   * Fields NO signature covers (sorted). Every entry MUST be labelled
   * unverified wherever it is displayed and MUST NEVER be the basis of a
   * decision (not a BYOK / "sent unredacted" mark, not a client or API-key
   * attribution, not a model claim).
   */
  unauthenticated_fields: string[];
}

// ---------------------------------------------------------------------------
// The ordered check list (README § Verification recipe, recipe-table).
// ---------------------------------------------------------------------------

export const CHAIN_STEPS: ReadonlyArray<readonly [string, CertificateChainVerdict, CertificateChainReason]> = [
  ['1', 'FAILED', 'malformed'],
  ['2', 'FAILED', 'unsupported_protocol_version'],
  ['3', 'FAILED', 'witness_key_mismatch'],
  ['4', 'FAILED', 'version_downgrade_detected'],
  ['5a', 'FAILED', 'malformed'],
  ['5b', 'FAILED', 'witness_signature_invalid'],
  ['5c', 'FAILED', 'witness_signature_invalid'],
  ['5d', 'FAILED', 'signable_version_insufficient'],
  ['6a', 'FAILED', 'sealed_failed'],
  ['6b', 'FAILED', 'malformed'],
  ['6c', 'FAILED', 'duplicate_claim_id'],
  ['7a', 'FAILED', 'unknown_service'],
  ['7b', 'FAILED', 'malformed'],
  ['7c', 'FAILED', 'service_key_mismatch'],
  ['7d', 'FAILED', 'claim_signature_invalid'],
  ['7e', 'FAILED', 'claim_canonical_mismatch'],
  ['7f', 'FAILED', 'claim_not_witness_listed'],
  ['7g', 'FAILED', 'claim_canonical_mismatch'],
  ['7h', 'FAILED', 'request_id_splice'],
  ['7i', 'FAILED', 'typed_payload_mismatch'],
  ['8a', 'FAILED', 'egress_digest_malformed'],
  ['8b', 'FAILED', 'egress_body_unbound'],
  ['8c', 'FAILED', 'egress_body_hash_mismatch'],
  ['8d', 'FAILED', 'cert_tier_mismatch'],
  ['9a', 'PARTIAL', 'inference_unfinished'],
  ['9b', 'PARTIAL', 'user_sent_unredacted'],
  ['9c', 'PARTIAL', 'sealed_partial'],
  ['9d', 'EGRESS_UNATTESTED', 'egress_unattested'],
  ['9e', 'VERIFIED', 'ok'],
];

const V2_FIELDS = ['certificate_id', 'claim_ids', 'issued_at', 'overall_verdict', 'protocol_version', 'request_id', 'witness_key_id'];
const V3_ONLY = ['api_key_id', 'byok_exempt', 'client_id', 'redaction_manifest_hash', 'sanitized_fields_body_hash', 'tms_manifest_hash'];
const DISPLAYED_V3_ONLY = ['api_key_id', 'byok_exempt', 'client_id'];
const TOKEN = 'user_unredacted_segment';
const CLAIM_TYPES: Record<string, string> = {
  CLAIM_TYPE_TOKEN_GENERATED: 'TOKEN_GENERATED',
  CLAIM_TYPE_PII_SANITIZED: 'PII_SANITIZED',
  CLAIM_TYPE_INFERENCE_COMPLETED: 'INFERENCE_COMPLETED',
  CLAIM_TYPE_EVENTS_RECORDED: 'EVENTS_RECORDED',
};
const TYPED_KINDS: Record<string, readonly [string, readonly string[]]> = {
  TOKEN_GENERATED: ['bridge', ['token_hash', 'encryption_enabled']],
  PII_SANITIZED: ['sanitizer', ['pii_entities_found', 'layers_active', 'qi_score']],
  INFERENCE_COMPLETED: ['inference', ['response_hash', 'isolation_probe', 'model_used', 'inference_outcome']],
  EVENTS_RECORDED: ['audit', ['chain_head_hash', 'chain_length']],
};
const PROBE: Record<string, string> = {
  VERIFIED: 'ISOLATION_PROBE_VERIFIED',
  BREACHED: 'ISOLATION_PROBE_BREACHED',
  LOCKED: 'ISOLATION_PROBE_LOCKED',
  BYOK_EXEMPT: 'ISOLATION_PROBE_BYOK_EXEMPT',
};
const CONDITIONAL_TYPED: ReadonlyArray<readonly [string, string, 'string' | 'number' | 'boolean']> = [
  ['inference', 'isolation_probe', 'string'],
  ['inference', 'model_used', 'string'],
  ['sanitizer', 'pii_entities_found', 'number'],
  ['bridge', 'token_hash', 'string'],
  ['bridge', 'encryption_enabled', 'boolean'],
  ['audit', 'chain_head_hash', 'string'],
  ['audit', 'chain_length', 'number'],
];
const HEX64 = /^[0-9a-f]{64}$/;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const INT_TOKEN = /^(?:0|[1-9][0-9]*)$/;
const INT_MAX_DIGITS = 20;
const TIMESTAMP = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|([+-])(\d\d):(\d\d))$/;
const GO_SPACE = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g;
const U32 = 2n ** 32n - 1n;
const I31 = 2n ** 31n - 1n;
const U64 = 2n ** 64n - 1n;

// ---------------------------------------------------------------------------
// Value helpers (absent and null are the same unless a step reads presence).
// ---------------------------------------------------------------------------

const isObj = (v: JVal | undefined): v is JObj => v instanceof Map;
const get = (m: JObj, k: string): JVal => {
  const v = m.get(k);
  return v === undefined ? null : v;
};

/** @internal README step 7b — CANONICAL standard padded base64; null → empty. */
export function b64(v: JVal): Uint8Array | null {
  if (v === null) return new Uint8Array(0);
  if (typeof v !== 'string' || !B64.test(v) || v.length % 4 !== 0) return null;
  const raw = Buffer.from(v, 'base64');
  return raw.toString('base64') === v ? new Uint8Array(raw) : null;
}

function strList(v: JVal): string[] | null {
  if (v === null) return [];
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) return null;
  return v as string[];
}

function optStr(v: JVal): [string, boolean] {
  if (v === null) return ['', true];
  return typeof v === 'string' ? [v, true] : ['', false];
}

function uintToken(text: string, max: bigint): bigint | null {
  if (text.length > INT_MAX_DIGITS || !INT_TOKEN.test(text)) return null;
  const n = BigInt(text);
  return n <= max ? n : null;
}

/** @internal A JSON number written as an integer TOKEN, in [0, max]. */
export function integer(v: JVal, max: bigint): bigint | null {
  return v instanceof JNum ? uintToken(v.text, max) : null;
}

function typedUint(v: JVal): bigint | null {
  if (v === null) return 0n;
  if (typeof v === 'string') return uintToken(v, U64);
  return integer(v, U64);
}

/** @internal A JSON number rounded to float32; out of range never matches. */
export function f32(v: JVal, zeroIfAbsent: boolean): number | null {
  if (v === null && zeroIfAbsent) return 0;
  if (!(v instanceof JNum)) return null;
  const d = Number(v.text);
  if (!Number.isFinite(d)) return null;
  const g = Math.fround(d);
  return Number.isFinite(g) ? g : null;
}

const pad = (n: number, w: number): string => String(n).padStart(w, '0');

/** @internal README step 5a — the ONE timestamp grammar → UTC RFC3339Nano, or null. */
export function rfc3339NanoUtc(s: string): string | null {
  const m = TIMESTAMP.exec(s);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  const frac = m[7] ?? '';
  const sign = m[9];
  if (sign && (Number(m[10]) > 23 || Number(m[11]) > 59)) return null;
  if (year < 1 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return null;
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, 0);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) return null;
  if (sign) {
    const offsetMin = (sign === '+' ? 1 : -1) * (Number(m[10]) * 60 + Number(m[11]));
    d.setTime(d.getTime() - offsetMin * 60_000);
  }
  const y = d.getUTCFullYear();
  if (y < 1 || y > 9999) return null;
  const f = frac.replace(/0+$/, '');
  return (
    `${pad(y, 4)}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)}T` +
    `${pad(d.getUTCHours(), 2)}:${pad(d.getUTCMinutes(), 2)}:${pad(d.getUTCSeconds(), 2)}` +
    (f ? '.' + f : '') +
    'Z'
  );
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

// SPKI DER prefix for a raw Ed25519 public key (see verify-certificate/signature.ts).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function keyObject(raw: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

function ed25519Ok(key: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  try {
    return cryptoVerify(null, Buffer.from(msg), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

// ---------------------------------------------------------------------------
// Recipe helpers.
// ---------------------------------------------------------------------------

const STEP = new Map(CHAIN_STEPS.map(([id, verdict, reason]) => [id, { verdict, reason }]));

interface PassState {
  egress: CertificateChainResult['egress_attestation'];
  sv: 'v2' | 'v3';
  userUnredacted: 'true' | 'false';
  tier: CertificateChainResult['signed_cert_tier'];
  typedUnauth: string[];
}

const byteOrder = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function outcome(step: string, st?: PassState): CertificateChainResult {
  const { verdict, reason } = STEP.get(step)!;
  if (verdict === 'FAILED' || !st) {
    return {
      verdict: 'FAILED',
      reason,
      egress_attestation: 'not_evaluated',
      user_unredacted: 'unknown',
      signed_cert_tier: 'not_evaluated',
      signable_version: 'none',
      authenticated_fields: [],
      unauthenticated_fields: [...DISPLAYED_V3_ONLY],
    };
  }
  const auth = st.sv === 'v3' ? [...V2_FIELDS, ...V3_ONLY].sort(byteOrder) : [...V2_FIELDS];
  const unauth = [...(st.sv === 'v3' ? [] : DISPLAYED_V3_ONLY), ...st.typedUnauth].sort(byteOrder);
  return {
    verdict,
    reason,
    egress_attestation: st.egress,
    user_unredacted: st.userUnredacted,
    signed_cert_tier: st.tier,
    signable_version: st.sv,
    authenticated_fields: auth,
    unauthenticated_fields: unauth,
  };
}

/** The FIRST dsa-sanitizer claim's canonical payload.payload[key] as a non-empty string, else null. */
function sanitizerHash(claims: JObj[], key: string): JVal {
  for (const c of claims) {
    if (get(c, 'service_id') !== 'dsa-sanitizer') continue;
    const cp = b64(get(c, 'canonical_payload'));
    if (!cp || cp.length === 0) return null;
    let outer: JVal;
    try {
      outer = parseDocument(cp);
    } catch {
      return null;
    }
    if (!isObj(outer)) return null;
    const p = get(outer, 'payload');
    const inner = isObj(p) ? p : outer;
    const val = get(inner, key);
    return typeof val === 'string' && val !== '' ? val : null;
  }
  return null;
}

function qiVerdict(s: string): string {
  // ASCII-only upper-casing (Unicode case mapping differs between languages).
  const v = s.replace(/^[ \t\n\r\f\v]+|[ \t\n\r\f\v]+$/g, '').replace(/[a-z]/g, (ch) => ch.toUpperCase());
  return v === 'PASS' || v === 'GENERALIZED' || v === 'BLOCKED' ? `QI_VERDICT_${v}` : 'QI_VERDICT_UNKNOWN';
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function qiBound(signed: JVal, typed: JVal): boolean {
  if (!isObj(signed)) return typed === null;
  if (!isObj(typed)) return false;
  const ka = integer(get(signed, 'k_anonymity'), U32);
  const tka = typedUint(get(typed, 'k_anonymity'));
  if (ka === null || tka === null || ka !== tka) return false;
  for (const k of ['l_diversity', 'risk_score', 'threshold']) {
    const sf = f32(get(signed, k), false);
    const tf = f32(get(typed, k), true);
    if (sf === null || tf === null || sf !== tf) return false;
  }
  const sv = get(signed, 'verdict');
  const [tv, ok] = optStr(get(typed, 'verdict'));
  if (typeof sv !== 'string' || !ok || qiVerdict(sv) !== (tv || 'QI_VERDICT_UNKNOWN')) return false;
  const sfg = get(signed, 'fields_generalized');
  if (!Array.isArray(sfg)) return false;
  const a = strList(sfg);
  const b = strList(get(typed, 'fields_generalized'));
  return a !== null && b !== null && sameList(a, b);
}

/** README step 7i: the typed (unsigned) mirror agrees with the signed payload p. */
function typedBound(c: JObj, claimType: string, p: JObj): boolean {
  let present = '';
  for (const k of ['bridge', 'sanitizer', 'inference', 'audit']) {
    const v = get(c, k);
    if (v === null) continue;
    if (!isObj(v) || present) return false;
    present = k;
  }
  const kind = TYPED_KINDS[claimType];
  if (present && (kind === undefined || present !== kind[0])) return false;
  if (kind !== undefined && !present && kind[1].some((k) => p.has(k))) return false;
  const signedLayers = get(p, 'layers_active');
  if (Array.isArray(signedLayers) && signedLayers.includes(TOKEN) && present !== 'sanitizer') return false;
  if (!present) return true;
  const t = get(c, present) as JObj;
  if (present === 'inference') {
    let [probe, ok] = optStr(get(t, 'isolation_probe'));
    if (!ok) return false;
    probe = probe || 'ISOLATION_PROBE_UNKNOWN';
    const sp = get(p, 'isolation_probe');
    if (typeof sp === 'string') {
      const want = Object.prototype.hasOwnProperty.call(PROBE, sp) ? PROBE[sp] : 'ISOLATION_PROBE_UNKNOWN';
      if (probe !== want) return false;
    } else if (probe === 'ISOLATION_PROBE_VERIFIED' || probe === 'ISOLATION_PROBE_BYOK_EXEMPT') {
      return false;
    }
    const [model, okM] = optStr(get(t, 'model_used'));
    const sm = get(p, 'model_used');
    if (!okM || (typeof sm === 'string' && model !== sm)) return false;
    const rh = b64(get(t, 'response_hash'));
    if (rh === null) return false;
    const srh = get(p, 'response_hash');
    if (rh.length > 0 !== (typeof srh === 'string') || (rh.length > 0 && hex(rh) !== srh)) return false;
  } else if (present === 'sanitizer') {
    const spf = get(p, 'pii_entities_found');
    if (spf instanceof JNum) {
      const want = integer(spf, U32);
      const got = typedUint(get(t, 'pii_entities_found'));
      if (want === null || got === null || want !== got) return false;
    }
    const typedLayers = strList(get(t, 'layers_active'));
    const signedList = strList(get(p, 'layers_active'));
    if (typedLayers === null || signedList === null || !sameList(typedLayers, signedList)) return false;
    if (!qiBound(get(p, 'qi_score'), get(t, 'qi_score'))) return false;
  } else if (present === 'bridge') {
    const se = get(p, 'encryption_enabled');
    if (typeof se === 'boolean') {
      const te = get(t, 'encryption_enabled');
      if (te !== null && typeof te !== 'boolean') return false;
      if ((te === true) !== se) return false;
    }
    const sth = get(p, 'token_hash');
    if (typeof sth === 'string') {
      const th = b64(get(t, 'token_hash'));
      if (th === null || hex(th) !== sth) return false;
    }
  } else if (present === 'audit') {
    const sch = get(p, 'chain_head_hash');
    if (typeof sch === 'string') {
      const h = b64(get(t, 'chain_head_hash'));
      if (h === null || hex(h) !== sch) return false;
    }
    const scl = get(p, 'chain_length');
    if (scl instanceof JNum) {
      const want = integer(scl, U64);
      const got = typedUint(get(t, 'chain_length'));
      if (want === null || got === null || want !== got) return false;
    }
  }
  return true;
}

/** README step 7i: typed fields present while their signed key is absent, null or of another JSON type. */
function typedUnbound(i: number, c: JObj, p: JObj): string[] {
  const out: string[] = [];
  for (const [kind, field, want] of CONDITIONAL_TYPED) {
    if (!isObj(get(c, kind))) continue;
    const v = get(p, field);
    const got = typeof v === 'boolean' ? 'boolean' : typeof v === 'string' ? 'string' : v instanceof JNum ? 'number' : null;
    if (got !== want) out.push(`claims[${i}].${kind}.${field}`);
  }
  return out;
}

/** README step 8d → [signed tier, the unsigned label passes, capped at EGRESS_UNATTESTED (fix A)]. */
function certTierCheck(
  claims: JObj[],
  canon: JObj[],
  unsigned: string,
  sealed: string,
): [CertificateChainResult['signed_cert_tier'], boolean, boolean] {
  const carriers: Array<[string, JVal]> = [];
  claims.forEach((c, i) => {
    if (canon[i].has('cert_tier')) carriers.push([get(c, 'service_id') as string, get(canon[i], 'cert_tier')]);
  });
  let signed: CertificateChainResult['signed_cert_tier'];
  if (carriers.length === 0) {
    signed = 'absent';
  } else {
    const sorted = [...carriers].sort((a, b) => byteOrder(a[0], b[0]));
    signed =
      sorted.length === 2 &&
      sorted[0][0] === 'dsa-ai' &&
      sorted[0][1] === 'input-shield' &&
      sorted[1][0] === 'dsa-gateway' &&
      sorted[1][1] === 'input-shield'
        ? 'input_shield'
        : 'inconsistent';
  }
  if (unsigned !== '' && unsigned !== 'full_chain' && unsigned !== 'input_shield') return [signed, false, false];
  if ((signed === 'absent' && (unsigned === '' || unsigned === 'full_chain')) || (signed === 'input_shield' && unsigned === 'input_shield')) {
    return [signed, true, false];
  }
  if (signed === 'input_shield' && unsigned === '') return [signed, true, true];
  return [signed, sealed === 'VERDICT_PARTIAL', false];
}

// ---------------------------------------------------------------------------
// The recipe.
// ---------------------------------------------------------------------------

interface PinnedKeys {
  witnessKeyId: string;
  witness: KeyObject;
  services: Map<string, KeyObject>;
}

/**
 * Verify a Lucairn certificate AND every claim inside it (T-935 S3 / T-794).
 *
 * Runs the parity-corpus recipe (steps 1–9e) and returns a
 * {@link CertificateChainResult}. Certificate problems never throw: they are
 * a `FAILED` verdict with the deciding step's reason.
 *
 * @param certificate - the certificate JSON exactly as received (the raw body
 *   of `GET /api/v1/veil/certificate/{id}`, or a witness export) as a string
 *   or UTF-8 bytes. Pass the raw text, NOT a `JSON.parse` result: integer
 *   tokens, float lexemes and trailing data are part of the checks, and
 *   `JSON.parse` loses them.
 * @param keys - the pinned witness key and per-service claim keys.
 * @param options.minimumSignableVersion - `'v2'` / omitted = policy `default`
 *   (legacy-tolerant: v2-only certificates verify, and their v3-only fields
 *   are listed in `unauthenticated_fields`); `'v3'` = policy `minimum_v3` (a
 *   certificate that authenticates only through the v2 signable FAILS with
 *   `signable_version_insufficient`).
 * @returns a promise that REJECTS with a TypeError for programmer errors only
 *   (a malformed key set, a non-string/bytes certificate, an unknown policy);
 *   a bad certificate resolves to a FAILED result.
 */
export async function verifyCertificateChain(
  certificate: string | Uint8Array,
  keys: CertificateChainKeys,
  options?: VerifyCertificateOptions,
): Promise<CertificateChainResult> {
  if (typeof certificate !== 'string' && !(certificate instanceof Uint8Array)) {
    throw new TypeError('verifyCertificateChain: certificate must be the raw certificate JSON (string or Uint8Array)');
  }
  const min = options?.minimumSignableVersion;
  if (min !== undefined && min !== 'v2' && min !== 'v3') {
    throw new TypeError(`verifyCertificateChain: minimumSignableVersion must be 'v2' or 'v3', got ${String(min)}`);
  }
  if (keys === null || typeof keys !== 'object') throw new TypeError('verifyCertificateChain: keys argument is required');
  if (typeof keys.witnessKeyId !== 'string' || keys.witnessKeyId === '') {
    throw new TypeError('verifyCertificateChain: keys.witnessKeyId must be a non-empty string');
  }
  if (
    keys.servicePublicKeys === null ||
    typeof keys.servicePublicKeys !== 'object' ||
    keys.servicePublicKeys instanceof Map ||
    Array.isArray(keys.servicePublicKeys)
  ) {
    throw new TypeError('verifyCertificateChain: keys.servicePublicKeys must be a { service_id: key } record');
  }
  const services = new Map<string, KeyObject>();
  for (const [svc, k] of Object.entries(keys.servicePublicKeys)) {
    if (svc === '') throw new TypeError('verifyCertificateChain: empty service_id in servicePublicKeys');
    services.set(svc, keyObject(normalizeEd25519PublicKey(k)));
  }
  const pinned: PinnedKeys = {
    witnessKeyId: keys.witnessKeyId,
    witness: keyObject(normalizeEd25519PublicKey(keys.witnessPublicKey)),
    services,
  };
  return run(certificate, pinned, min === 'v3');
}

function run(certJson: string | Uint8Array, keys: PinnedKeys, minV3: boolean): CertificateChainResult {
  // 1. Shape.
  let root: JVal;
  try {
    root = parseDocument(certJson);
  } catch {
    return outcome('1');
  }
  if (!isObj(root)) return outcome('1');
  const cert = root;
  const ver = get(cert, 'verification');
  const claimsRaw = get(cert, 'claims');
  const pv = integer(get(cert, 'protocol_version'), U32);
  const strs = ['certificate_id', 'request_id', 'witness_key_id', 'issued_at'].map((k) => get(cert, k));
  if (
    !strs.every((v) => typeof v === 'string') ||
    pv === null ||
    !Array.isArray(claimsRaw) ||
    claimsRaw.length === 0 ||
    !isObj(ver) ||
    typeof get(ver, 'overall_verdict') !== 'string'
  ) {
    return outcome('1');
  }
  const [certId, reqId, wkid, issuedAt] = strs as string[];
  const [unsignedTier, okT] = optStr(get(ver, 'cert_tier'));
  const byok = get(ver, 'byok_exempt');
  const okB = byok === null || typeof byok === 'boolean';
  const emittedRaw = get(cert, 'signable_protocol_version_emitted');
  const emitted = emittedRaw === null ? 0n : integer(emittedRaw, I31);
  const [v3sig, okV3] = optStr(get(cert, 'signable_v3_signature'));
  const okRest = ['witness_signature', 'client_id', 'api_key_id'].every((k) => optStr(get(cert, k))[1]);
  if (!okT || !okB || emitted === null || !okV3 || !okRest) return outcome('1');
  if (!claimsRaw.every((c) => isObj(c) && typeof get(c, 'claim_id') === 'string' && typeof get(c, 'service_id') === 'string')) {
    return outcome('1');
  }
  const claims = claimsRaw as JObj[];
  const sealed = get(ver, 'overall_verdict') as string;
  const claimIds = claims.map((c) => get(c, 'claim_id') as string);

  // 2. Protocol version.
  if (pv !== 2n) return outcome('2');
  // 3. Witness identity.
  if (wkid !== keys.witnessKeyId) return outcome('3');
  // 4. Signable-version tri-state ("non-blank" = not empty after trimming
  // whitespace — Go's unicode.IsSpace set, as the witness; String.trim would
  // also strip U+FEFF).
  const v3present = v3sig.replace(GO_SPACE, '') !== '';
  if (emitted >= 3n !== v3present) return outcome('4');
  // 5a. issued_at grammar.
  const issued = rfc3339NanoUtc(issuedAt);
  if (issued === null) return outcome('5a');
  // 5b. v2 witness signature.
  const v2: JObj = new Map<string, JVal>([
    ['certificate_id', certId],
    ['request_id', reqId],
    ['protocol_version', new JNum('2')],
    ['claim_ids', claimIds],
    ['issued_at', issued],
    ['overall_verdict', sealed.startsWith('VERDICT_') ? sealed.slice('VERDICT_'.length) : sealed],
    ['witness_key_id', wkid],
  ]);
  const wsig = b64(get(cert, 'witness_signature'));
  if (!wsig || wsig.length === 0 || !ed25519Ok(keys.witness, canonicalBytes(v2), wsig)) return outcome('5b');
  // 5c. v3 witness signature.
  let sv: 'v2' | 'v3' = 'v2';
  if (v3present) {
    const v3: JObj = new Map(v2);
    v3.set('client_id', get(cert, 'client_id'));
    v3.set('api_key_id', get(cert, 'api_key_id'));
    v3.set('byok_exempt', byok === true);
    v3.set('redaction_manifest_hash', sanitizerHash(claims, 'redaction_manifest_hash'));
    v3.set('sanitized_fields_body_hash', sanitizerHash(claims, 'sanitized_fields_hash'));
    v3.set('tms_manifest_hash', sanitizerHash(claims, 'tms_manifest_hash'));
    const sig = b64(v3sig);
    if (sig === null || !ed25519Ok(keys.witness, canonicalBytes(v3), sig)) return outcome('5c');
    sv = 'v3';
  }
  // 5d. Policy.
  if (minV3 && sv !== 'v3') return outcome('5d');
  // 6. Sealed verdict + claim-id uniqueness.
  if (sealed === 'VERDICT_FAILED') return outcome('6a');
  if (sealed !== 'VERDICT_VERIFIED' && sealed !== 'VERDICT_PARTIAL') return outcome('6b');
  const listed = new Set(claimIds);
  if (listed.size !== claimIds.length) return outcome('6c');

  // 7. Every claim, in array order.
  const canon: JObj[] = [];
  const typedUnauth: string[] = [];
  for (let i = 0; i < claims.length; i++) {
    const c = claims[i];
    const svc = get(c, 'service_id') as string;
    // 7a.
    const pub = keys.services.get(svc);
    if (pub === undefined) return outcome('7a');
    // 7b.
    const cp = b64(get(c, 'canonical_payload'));
    const sig = b64(get(c, 'signature'));
    if (cp === null || sig === null) return outcome('7b');
    // 7c / 7d.
    const own = ed25519Ok(pub, cp, sig);
    if (!own) {
      for (const [other, k] of keys.services) {
        if (other !== svc && ed25519Ok(k, cp, sig)) return outcome('7c');
      }
      return outcome('7d');
    }
    // 7e.
    let cm: JVal;
    try {
      cm = parseDocument(cp);
    } catch {
      return outcome('7e');
    }
    if (!isObj(cm)) return outcome('7e');
    // 7f.
    const signedId = get(cm, 'claim_id');
    if (typeof signedId !== 'string' || !listed.has(signedId)) return outcome('7f');
    // 7g.
    const ds = strList(get(c, 'data_seen'));
    const dns = strList(get(c, 'data_not_seen'));
    const [outerReq, okReq] = optStr(get(c, 'request_id'));
    if (ds === null || dns === null || !okReq) return outcome('7g');
    const ctRaw = get(c, 'claim_type');
    const claimType = typeof ctRaw === 'string' && Object.prototype.hasOwnProperty.call(CLAIM_TYPES, ctRaw) ? CLAIM_TYPES[ctRaw] : '';
    const rebuilt = canonicalBytes(
      new Map<string, JVal>([
        ['claim_id', get(c, 'claim_id')],
        ['request_id', outerReq],
        ['service_id', svc],
        ['claim_type', claimType],
        ['data_seen', ds],
        ['data_not_seen', dns],
        ['payload', get(cm, 'payload')],
        ['timestamp', get(cm, 'timestamp')],
      ]),
    );
    if (!sameBytes(rebuilt, cp)) return outcome('7g');
    // 7h.
    if (get(cm, 'request_id') !== reqId) return outcome('7h');
    // 7i.
    const pRaw = get(cm, 'payload');
    const payload: JObj = isObj(pRaw) ? pRaw : new Map();
    if (!typedBound(c, claimType, payload)) return outcome('7i');
    typedUnauth.push(...typedUnbound(i, c, payload));
    canon.push(payload);
  }

  // 8a. Signed digest lists.
  let digestClaim = -1;
  let digests: string[] = [];
  for (let i = 0; i < claims.length; i++) {
    const c = claims[i];
    const p = canon[i];
    if (get(c, 'service_id') !== 'dsa-ai' || get(c, 'claim_type') !== 'CLAIM_TYPE_INFERENCE_COMPLETED' || !p.has('upstream_body_sha256')) continue;
    const d = get(p, 'upstream_body_sha256');
    if (!Array.isArray(d) || d.length === 0 || digestClaim >= 0 || !d.every((x) => typeof x === 'string' && HEX64.test(x))) {
      return outcome('8a');
    }
    digestClaim = i;
    digests = d as string[];
  }
  const bodiesOf = (c: JObj): JVal[] | null => {
    const inf = get(c, 'inference');
    if (!isObj(inf) || get(inf, 'upstream_request_bodies') === null) return [];
    const b = get(inf, 'upstream_request_bodies');
    return Array.isArray(b) ? b : null;
  };
  // 8b. Stored bodies only on the digest-carrying claim.
  for (let i = 0; i < claims.length; i++) {
    const b = bodiesOf(claims[i]);
    if (b === null || (b.length > 0 && i !== digestClaim)) return outcome('8b');
  }
  // 8c. Stored bodies hash to the signed digests.
  if (digestClaim >= 0) {
    const bodies = bodiesOf(claims[digestClaim]) ?? [];
    if (bodies.length > 0) {
      if (bodies.length !== digests.length) return outcome('8c');
      for (let j = 0; j < bodies.length; j++) {
        const raw = b64(bodies[j]);
        if (raw === null || createHash('sha256').update(raw).digest('hex') !== digests[j]) return outcome('8c');
      }
    }
  }
  // 8d. cert_tier against the signed copies.
  const [tier, tierOk, tierCap] = certTierCheck(claims, canon, unsignedTier, sealed);
  if (!tierOk) return outcome('8d');

  const egress = digestClaim >= 0 ? 'signed_digests' : 'unattested';
  const userUnredacted = claims.some((c, i) => {
    const svc = get(c, 'service_id');
    const layers = get(canon[i], 'layers_active');
    return (svc === 'dsa-sanitizer' || svc === 'dsa-sanitizer-streaming') && Array.isArray(layers) && layers.includes(TOKEN);
  })
    ? 'true'
    : 'false';
  const st: PassState = { egress, sv, userUnredacted, tier, typedUnauth };

  // 9. Ceilings (first match wins).
  if (canon.some((p) => p.has('inference_outcome'))) return outcome('9a', st); // key PRESENCE: a signed null counts
  if (userUnredacted === 'true') return outcome('9b', st);
  if (sealed === 'VERDICT_PARTIAL') return outcome('9c', st);
  if (egress === 'unattested' || tierCap) return outcome('9d', st);
  return outcome('9e', st);
}
