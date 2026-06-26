/**
 * Cross-language signable-reconstruction PARITY tests (2026-06-15).
 *
 * These tests lock the TS signable reconstruction against a SHARED golden hex
 * that lives BYTE-IDENTICALLY in all three SDK fixture directories:
 *
 *   go/internal/verify/testdata/real-v{2,3}-signable-go-reference.hex
 *   ts/src/verify-certificate/__fixtures__/real-v{2,3}-signable-go-reference.hex
 *   python/tests/fixtures/real-v{2,3}-signable-go-reference.hex
 *
 * The hex is the canonical signable bytes derived from the SHARED real cert
 * fixture (cert-real-v3-production.json, byte-identical to the Go/Python
 * real-v3-cert.fixture.json). Each language asserts it reproduces this exact
 * hex; because the same hex is pinned in every tree, byte-identity in each
 * language is a transitive proof of cross-language byte-equivalence.
 *
 * HARD GATE: these bytes are UNCHANGED from origin/main — the signable
 * reconstruction parity fixes (TS flat-fallback, TS+Python issued_at UTC
 * normalization, TS bytewise-UTF-8 key sort) are byte-equivalent on every real
 * cert (wrapped canonical_payload, Zulu timestamps, ASCII keys). If this test
 * fails, the reconstruction drifted — fix the reconstruction, do NOT regenerate
 * the hex.
 *
 * It ALSO pins the parity SHAPE behaviour for the previously-divergent edge
 * cases (flat canonical_payload, offset timestamp, non-ASCII key sort) so the
 * TS output matches the Go reference (TestParity_* in
 * go/internal/verify/parity_test.go) byte-for-byte.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  deriveWitnessSignedBytes,
  deriveWitnessSignedBytesV3,
  normalizeIssuedAt,
} from './verify-certificate/signable.js';
import { canonicalJson } from './verify-certificate/canonical-json.js';
import { parseCertificate } from './verify-certificate/parse.js';
import type { VeilCertificate } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadRaw(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as Record<
    string,
    unknown
  >;
}

function realCert(): VeilCertificate {
  return parseCertificate(loadRaw('cert-real-v3-production.json'));
}

function sharedHex(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf8').trim();
}

// ---------------------------------------------------------------------------
// Shared golden-hex anchors — the cross-language byte-equivalence proof.
// ---------------------------------------------------------------------------

describe('cross-language signable byte-equivalence (shared golden hex)', () => {
  it('v2 real-cert signable matches the shared golden hex', () => {
    const got = Buffer.from(deriveWitnessSignedBytes(realCert())).toString('hex');
    expect(got).toBe(sharedHex('real-v2-signable-go-reference.hex'));
  });

  it('v3 real-cert signable matches the shared golden hex', () => {
    const got = Buffer.from(deriveWitnessSignedBytesV3(realCert())).toString('hex');
    expect(got).toBe(sharedHex('real-v3-signable-go-reference.hex'));
  });
});

// ---------------------------------------------------------------------------
// Parity SHAPE tests — match the Go reference (TestParity_*) on the
// previously-divergent shapes.
// ---------------------------------------------------------------------------

// Helper: clone the real cert and replace its dsa-sanitizer claim's
// canonical_payload with the given JSON, so we exercise the v3 hash extraction
// path on both the flat and wrapped canonical_payload shapes.
function realCertWithSanitizerPayload(canonicalPayloadJson: string): VeilCertificate {
  const raw = loadRaw('cert-real-v3-production.json');
  const claims = raw['claims'] as Array<Record<string, unknown>>;
  const cpB64 = Buffer.from(canonicalPayloadJson, 'utf8').toString('base64');
  let replaced = false;
  for (const c of claims) {
    if (c['service_id'] === 'dsa-sanitizer') {
      c['canonical_payload'] = cpB64;
      replaced = true;
      break;
    }
  }
  if (!replaced) throw new Error('real fixture has no dsa-sanitizer claim to mutate');
  return parseCertificate(raw);
}

describe('parity: canonical_payload flat fallback (fix 1)', () => {
  it('reads the hash from a FLAT canonical_payload (no "payload" wrapper)', () => {
    // Previously TS returned null for this shape (only Go + Python had the flat
    // fallback). The flat-fallback fix brings TS into parity.
    const cert = realCertWithSanitizerPayload('{"redaction_manifest_hash":"abc123"}');
    const bytes = deriveWitnessSignedBytesV3(cert);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    expect(decoded['redaction_manifest_hash']).toBe('abc123');
  });

  it('reads the hash from a WRAPPED canonical_payload (under "payload")', () => {
    const cert = realCertWithSanitizerPayload(
      '{"payload":{"redaction_manifest_hash":"abc123"}}',
    );
    const bytes = deriveWitnessSignedBytesV3(cert);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    expect(decoded['redaction_manifest_hash']).toBe('abc123');
  });
});

describe('parity: issued_at offset → UTC normalization (fix 2)', () => {
  // These exact input/output pairs are byte-identical to the Go reference
  // (TestParity_OffsetTimestamp_NormalizedToUTC in parity_test.go).
  const cases: Array<[string, string]> = [
    ['2026-05-01T14:00:00.100000000+02:00', '2026-05-01T12:00:00.1Z'],
    ['2026-05-01T08:00:00-03:00', '2026-05-01T11:00:00Z'],
    ['2026-06-10T00:01:59.100000000+00:00', '2026-06-10T00:01:59.1Z'],
    ['2026-06-10T00:01:59.878143387Z', '2026-06-10T00:01:59.878143387Z'],
    ['2026-06-10T00:01:59.000000000Z', '2026-06-10T00:01:59Z'],
    ['2026-06-10T00:01:59Z', '2026-06-10T00:01:59Z'],
    ['not-a-timestamp', 'not-a-timestamp'], // fail-open
  ];
  for (const [src, want] of cases) {
    it(`normalizes ${src} -> ${want}`, () => {
      expect(normalizeIssuedAt(src)).toBe(want);
    });
  }
});

describe('parity: bytewise-UTF-8 canonical-JSON key sort (fix 4)', () => {
  it('sorts non-ASCII keys by UTF-8 bytes, matching Go encoding/json', () => {
    // bmpKey    = U+E000 (BMP)   -> UTF-8 ee 80 80
    // astralKey = U+1F600 (emoji) -> UTF-8 f0 9f 98 80
    // UTF-16 (the old Array.prototype.sort) would order astralKey BEFORE bmpKey
    // (its leading surrogate 0xD83D < 0xE000). UTF-8 orders bmpKey BEFORE
    // astralKey (0xee < 0xf0). ASCII 'a' (0x61) sorts first.
    const bmpKey = '\u{E000}';
    const astralKey = '\u{1F600}';
    const out = canonicalJson({ [bmpKey]: 'bmp', [astralKey]: 'astral', a: 'ascii' });
    const got = new TextDecoder().decode(out);
    // M3: keys render ensure_ascii-escaped (U+E000 -> , U+1F600 -> the
    // UTF-16 surrogate pair 😀), matching the witness. The SORT ORDER
    // (bytewise UTF-8) is unchanged and remains the load-bearing assertion.
    const want = '{"a":"ascii","\\ue000":"bmp","\\ud83d\\ude00":"astral"}';
    expect(got).toBe(want);
  });

  it('is unchanged for ASCII-only keys (real-cert keys)', () => {
    // Regression guard: the sort-change must be a no-op on ASCII keys.
    const out = canonicalJson({ b: '1', a: '2', certificate_id: '3' });
    expect(new TextDecoder().decode(out)).toBe(
      '{"a":"2","b":"1","certificate_id":"3"}',
    );
  });
});
