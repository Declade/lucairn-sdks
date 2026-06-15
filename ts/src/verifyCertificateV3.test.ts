/**
 * v3 dual-protocol certificate verification acceptance tests.
 *
 * PRD: prd-2026-06-08-typed-message-schema-sanitizer-rewrite.md
 * Criteria #7 (signableVersion='v3'), #8 (v2 byte-identical backward compat),
 * and H6 (issued_at RFC3339Nano normalization).
 *
 * Test (a): real production v3 cert round-trip — valid=true, signableVersion='v3'.
 *   PASSES ONLY if v3 reconstruction is byte-exact (Ed25519 sig verifies
 *   against the real production witness public key). Non-negotiable per brief.
 *
 * Test (b): same cert verifies v2-path (carries both sigs) → backward compat (criterion #8).
 *
 * Test (c): issued_at trailing-zero normalization (H6) — verifies a cert
 *   whose issued_at has protojson zero-padding, which would fail without
 *   normalizeIssuedAt().
 *
 * Test (d): v3 signable key-set freeze — exactly 13 keys, correct v3-only promotes.
 *
 * Test (e): tms_manifest_hash absent → null in v3 signable (pre-Slice-5 contract).
 *
 * Test (f): v3 dispatch when signable_protocol_version_emitted absent (both v3 sig + version stripped).
 *
 * Test (f2): throws version_downgrade_detected when v3 sig present but version < 3.
 *   (behavior CHANGED by TOB-SDK-TS-01 fix — previously returned signableVersion='v2',
 *   now throws because a v3 sig present with version < 3 is structurally anomalous.)
 *
 * Test (g): v3 dispatch skipped when signable_v3_signature absent or empty.
 *
 * Test (h): signableVersion propagated on verifyCertificate result for both paths.
 *
 * Tests (i)-(l): downgrade / minimumSignableVersion coverage (TOB-SDK-TS-01).
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sign, generateKeyPairSync } from 'node:crypto';
import { verifyCertificate } from './verify-certificate/index.js';
import {
  deriveWitnessSignedBytes,
  deriveWitnessSignedBytesV3,
  normalizeIssuedAt,
} from './verify-certificate/signable.js';
import { canonicalJson, rawIntegerNumber } from './verify-certificate/canonical-json.js';
import { parseCertificate } from './verify-certificate/parse.js';
import { LucairnCertificateError } from './errors.js';
import type { VeilCertificate, VerifyCertificateKeys } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadFixture<T = VeilCertificate>(name: string): T {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;
}

interface ProductionPubkeyFixture {
  publicKeyBase64: string;
  witnessKeyId: string;
}

/**
 * Keys for verifying against the real production Lucairn pilot witness.
 * Fixture: production-witness-pubkey.json (public key only — no private key stored).
 */
function productionKeys(): VerifyCertificateKeys {
  const kp = loadFixture<ProductionPubkeyFixture>('production-witness-pubkey.json');
  return {
    witnessKeyId: kp.witnessKeyId,
    witnessPublicKey: kp.publicKeyBase64,
  };
}

// ---------------------------------------------------------------------------
// Test (a): Real production v3 cert round-trip — THE non-negotiable test
// ---------------------------------------------------------------------------
describe('verifyCertificate v3 — real production cert round-trip', () => {
  /**
   * Test (a): Verifying the real production v3 cert returns valid=true,
   * signableVersion='v3'. PASSES ONLY IF v3 reconstruction is byte-exact —
   * if it fails, the reconstruction is wrong, not the test.
   */
  it('(a) real production v3 cert verifies with signableVersion=v3', async () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const keys = productionKeys();

    // Non-negotiable acceptance gate per brief: if this throws invalid_signature,
    // fix the reconstruction — do NOT weaken this test.
    const result = await verifyCertificate(cert, keys);

    expect(result.signableVersion).toBe('v3');
    expect(result.certificateId).toBe('veil_019eaed5-fc46-724d-ad80-2ad67ef87d3d');
    expect(result.requestId).toBe('0ad683d6a85692cc1631422a8c4293ba');
    expect(result.witnessKeyId).toBe('witness_v1');
    // Real cert verdict from the production run
    expect(result.overallVerdict).toBe('VERDICT_PARTIAL');
  });

  /**
   * Test (b): The same cert verifies via the v2 path when we force-strip the
   * v3 fields — confirming v2 byte-identical backward compat (criterion #8).
   */
  it('(b) real production cert v2 path verifies (backward compat, criterion #8)', async () => {
    // Take the real cert and remove v3 fields to simulate a v0.5.x SDK view.
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const v2OnlyCert: Record<string, unknown> = {
      ...rawCert,
      signable_protocol_version_emitted: null, // absent → force v2 path
      signable_v3_signature: null,
    };

    const keys = productionKeys();
    const result = await verifyCertificate(v2OnlyCert, keys);

    // Must verify successfully via v2 path
    expect(result.signableVersion).toBe('v2');
    expect(result.certificateId).toBe('veil_019eaed5-fc46-724d-ad80-2ad67ef87d3d');
    // v2 uses witness_signature which equals signable_v2_signature byte-for-byte
  });
});

// ---------------------------------------------------------------------------
// Test (c): issued_at RFC3339Nano normalization (H6)
// ---------------------------------------------------------------------------
describe('normalizeIssuedAt — H6 trailing-zero fix', () => {
  it('(c) strips trailing zeros from fractional seconds to match Go time.RFC3339Nano', () => {
    // Protojson zero-pads to 9 digits; Go strips trailing zeros
    expect(normalizeIssuedAt('2026-05-01T12:00:00.100000000Z')).toBe(
      '2026-05-01T12:00:00.1Z',
    );
    expect(normalizeIssuedAt('2026-06-10T00:01:59.878143387Z')).toBe(
      '2026-06-10T00:01:59.878143387Z', // no trailing zeros → unchanged
    );
    expect(normalizeIssuedAt('2026-05-01T12:00:00.000000000Z')).toBe(
      '2026-05-01T12:00:00Z', // all zeros → drop fractional part
    );
    expect(normalizeIssuedAt('2026-05-01T12:00:00Z')).toBe(
      '2026-05-01T12:00:00Z', // no fractional → unchanged
    );
    expect(normalizeIssuedAt('2026-05-01T12:00:00.500000000Z')).toBe(
      '2026-05-01T12:00:00.5Z', // trailing zeros stripped
    );
    // Timezone offset form (not UTC Z): cross-language parity fix (2026-06-15)
    // — now converted to the equivalent UTC `Z` time exactly like Go's
    // `time.Parse(RFC3339Nano).UTC().Format(RFC3339Nano)`. 14:00 at +02:00 ==
    // 12:00 UTC, trailing zeros stripped. The witness only ever signs Zulu, so
    // this is never exercised on a real cert; it brings TS into byte parity
    // with Go (and Python) on the latent shape.
    expect(normalizeIssuedAt('2026-05-01T14:00:00.100000000+02:00')).toBe(
      '2026-05-01T12:00:00.1Z',
    );
    // Negative offset shifts the wall-clock the other way.
    expect(normalizeIssuedAt('2026-05-01T08:00:00-03:00')).toBe(
      '2026-05-01T11:00:00Z',
    );
    // +00:00 (== UTC) collapses to Z with trailing zeros stripped.
    expect(normalizeIssuedAt('2026-06-10T00:01:59.100000000+00:00')).toBe(
      '2026-06-10T00:01:59.1Z',
    );
    // Unparseable input fails open (matches Go's `return s` on parse error).
    expect(normalizeIssuedAt('not-a-timestamp')).toBe('not-a-timestamp');
  });

  it('(c2) issued_at normalization is applied in v2 signable reconstruction', () => {
    // Build a minimal cert whose issued_at has trailing zeros (protojson zero-padded form).
    // Without normalization, the canonical bytes would disagree with Go's signing output.
    const { privateKey, publicKey: pkObj } = generateKeyPairSync('ed25519');
    const pubJwk = pkObj.export({ format: 'jwk' });
    const pubB64 = (pubJwk.x as string).replace(/-/g, '+').replace(/_/g, '/');
    const pubRaw = new Uint8Array(Buffer.from(pubB64, 'base64'));

    // Construct the signable manually using normalized issued_at, then sign it.
    const zeroPaddedTs = '2026-05-01T12:00:00.100000000Z';
    const normalizedTs = '2026-05-01T12:00:00.1Z';

    const claimIds = ['clm_test_001'];
    const signableMap = {
      certificate_id: 'veil_test_h6',
      request_id: 'req_test_h6',
      protocol_version: rawIntegerNumber(2),
      claim_ids: claimIds,
      issued_at: normalizedTs, // normalized, as Go would sign
      overall_verdict: 'VERIFIED',
      witness_key_id: 'witness_v1',
    };
    const canonicalBytes = canonicalJson(signableMap);
    const sig = sign(null, Buffer.from(canonicalBytes), privateKey);
    const sigB64 = Buffer.from(sig).toString('base64');

    // Now construct a cert using zero-padded issued_at (as protojson serves it).
    const cert: VeilCertificate = {
      certificate_id: 'veil_test_h6',
      request_id: 'req_test_h6',
      protocol_version: 2,
      witness_key_id: 'witness_v1',
      witness_signature: sigB64,
      issued_at: zeroPaddedTs, // zero-padded form as served by gateway
      claims: [
        {
          claim_id: 'clm_test_001',
          request_id: 'req_test_h6',
          service_id: 'dsa-bridge',
          claim_type: 'CLAIM_TYPE_TOKEN_GENERATED',
          data_seen: [],
          data_not_seen: [],
          canonical_payload: '',
          timestamp: '2026-05-01T12:00:00Z',
          signature: '',
        },
      ],
      verification: {
        signatures_valid: true,
        completeness: 'COMPLETENESS_FULL',
        missing_services: [],
        temporal_consistent: true,
        data_visibility_consistent: true,
        isolation_verified: true,
        qi_score: null,
        overall_verdict: 'VERDICT_VERIFIED',
      },
    };

    // The cert was signed with normalized issued_at. SDK normalizes on the fly.
    // Without H6 fix: SDK would compute canonical bytes with ".100000000Z" → mismatch → invalid_sig.
    // With H6 fix: SDK computes ".1Z" → match → verifies.
    const sdkBytes = deriveWitnessSignedBytes(cert);
    expect(Buffer.from(sdkBytes).toString('hex')).toBe(
      Buffer.from(canonicalBytes).toString('hex'),
    );
  });
});

// ---------------------------------------------------------------------------
// Test (d): v3 signable key-set freeze
// ---------------------------------------------------------------------------
describe('deriveWitnessSignedBytesV3 — key-set freeze', () => {
  it('(d) v3 signable contains exactly 13 keys including all carry-forwards', () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const parsed = parseCertificate(cert);
    const bytes = deriveWitnessSignedBytesV3(parsed);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    const keys = Object.keys(decoded).sort();

    expect(keys).toEqual([
      'api_key_id',
      'byok_exempt',
      'certificate_id',
      'claim_ids',
      'client_id',
      'issued_at',
      'overall_verdict',
      'protocol_version',
      'redaction_manifest_hash',
      'request_id',
      'sanitized_fields_body_hash',
      'tms_manifest_hash',
      'witness_key_id',
    ]);
    // 13 keys exactly
    expect(keys.length).toBe(13);

    // Spot-check specific values
    expect(decoded['protocol_version']).toBe(2); // still 2, not 3
    expect(decoded['api_key_id']).toBe('k_ix3sgwowzhyz6gri');
    expect(decoded['byok_exempt']).toBe(false);
    expect(decoded['client_id']).toBeNull(); // JSON null
  });

  // Test (e): tms_manifest_hash absent → null in v3 signable (pre-Slice-5 contract)
  it('(e) tms_manifest_hash is null in pre-Slice-5 cert (absent from sanitizer canonical_payload)', () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const parsed = parseCertificate(cert);
    const bytes = deriveWitnessSignedBytesV3(parsed);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    // sanitizer canonical_payload.payload has no tms_manifest_hash key →
    // sanitizerHashField returns null → signable carries "tms_manifest_hash": null.
    expect(decoded['tms_manifest_hash']).toBeNull();
  });

  it('v3 signable contains redaction_manifest_hash and sanitized_fields_body_hash from sanitizer canonical_payload', () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const parsed = parseCertificate(cert);
    const bytes = deriveWitnessSignedBytesV3(parsed);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;

    // These hex hashes come from the sanitizer claim's canonical_payload.payload
    expect(decoded['redaction_manifest_hash']).toBe(
      '7b49ac38baa96a6a60fadb7fa2eb0d3ef962100adfed5e793ff283ea818bc1fb',
    );
    expect(decoded['sanitized_fields_body_hash']).toBe(
      '6b30a9d35844b4cb2aeaeb4d1ca8d3e2503373cc7f43263325a380cd04b55b8f',
    );
  });

  it('v2 and v3 signed bytes are DIFFERENT (v3 is not the same as v2)', () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const parsed = parseCertificate(cert);
    const v2Bytes = deriveWitnessSignedBytes(parsed);
    const v3Bytes = deriveWitnessSignedBytesV3(parsed);
    // They should be different byte sequences
    expect(Buffer.from(v2Bytes).toString('hex')).not.toBe(
      Buffer.from(v3Bytes).toString('hex'),
    );
  });
});

// ---------------------------------------------------------------------------
// Test (f): v3 dispatch is skipped when signable_protocol_version_emitted < 3 or absent
// ---------------------------------------------------------------------------
describe('verifyCertificate v3 — version dispatch', () => {
  it('(f) falls back to v2 when signable_protocol_version_emitted is absent', async () => {
    // Take the real v3 cert and strip the protocol version field — simulates
    // an old cert that doesn't carry the v3 fields.
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_protocol_version_emitted: null,
      signable_v3_signature: null,
    };
    const keys = productionKeys();
    const result = await verifyCertificate(cert, keys);
    expect(result.signableVersion).toBe('v2');
  });

  it('(f2) throws version_downgrade_detected when v3 sig present but signable_protocol_version_emitted is 2', async () => {
    // TOB-SDK-TS-01: previously this silently fell back to v2 (leaving v3-only
    // fields unverified). After the fix, this is a hard reject — a v3 sig
    // present alongside version < 3 is structurally anomalous (attacker
    // stripped the version field to force the v2 path).
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_protocol_version_emitted: 2, // not >= 3, but v3 sig still present
      // NOTE: signable_v3_signature is intentionally NOT stripped here —
      // that's what makes this a downgrade attempt.
    };
    const keys = productionKeys();
    await expect(verifyCertificate(cert, keys)).rejects.toMatchObject({
      reason: 'version_downgrade_detected',
    });
  });

  it('(g) throws version_downgrade_detected when signable_v3_signature is empty but version=3', async () => {
    // TOB-SDK-TS-01 second direction: emitted >= 3 but v3 sig stripped/blank.
    // Attacker could strip the v3 sig to bypass v3 field verification while
    // keeping version >= 3. Canonical dispatch hard-rejects this.
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_v3_signature: '', // stripped v3 sig, but version=3 still present
    };
    const keys = productionKeys();
    await expect(verifyCertificate(cert, keys)).rejects.toMatchObject({
      reason: 'version_downgrade_detected',
    });
  });

  it('(g2) throws version_downgrade_detected when signable_v3_signature is whitespace-only but version=3', async () => {
    // Same attack vector as (g) with whitespace-only signature.
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_v3_signature: '   ', // whitespace-only stripped v3 sig, but version=3 still present
    };
    const keys = productionKeys();
    await expect(verifyCertificate(cert, keys)).rejects.toMatchObject({
      reason: 'version_downgrade_detected',
    });
  });

  it('(g3) falls back to v2 when BOTH signable_v3_signature and version are absent', async () => {
    // Legitimate legacy v2 path: neither version field nor v3 sig present.
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_protocol_version_emitted: null,
      signable_v3_signature: '', // both absent → legitimate v2
    };
    const keys = productionKeys();
    const result = await verifyCertificate(cert, keys);
    expect(result.signableVersion).toBe('v2');
  });
});

// ---------------------------------------------------------------------------
// Test (h): signableVersion propagated on both paths
// ---------------------------------------------------------------------------
describe('verifyCertificate — signableVersion on result', () => {
  it('(h) returns signableVersion=v2 for legacy cert without v3 fields', async () => {
    // Use the test witness keypair (fixture certs are signed with it)
    const kp = loadFixture<{ publicKey: string }>('witness-keypair.json');
    const keys: VerifyCertificateKeys = {
      witnessKeyId: 'witness_v1',
      witnessPublicKey: kp.publicKey,
    };
    // cert-valid-anchored.json has no signable_protocol_version_emitted or signable_v3_signature
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await verifyCertificate(cert, keys);
    expect(result.signableVersion).toBe('v2');
  });

  it('(h2) returns signableVersion=v3 for production cert', async () => {
    const result = await verifyCertificate(
      loadFixture('cert-real-v3-production.json'),
      productionKeys(),
    );
    expect(result.signableVersion).toBe('v3');
  });
});

// ---------------------------------------------------------------------------
// Tampered v3 signature
// ---------------------------------------------------------------------------
describe('verifyCertificate v3 — tampered signature rejection', () => {
  it('throws invalid_signature when signable_v3_signature is tampered', async () => {
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    // Flip one base64 character in the v3 signature to make it invalid
    const origSig = rawCert['signable_v3_signature'] as string;
    // Replace first char with next char in alphabet (wrapping Z→A)
    const tamperedSig = origSig[0] === 'Z'
      ? 'A' + origSig.slice(1)
      : String.fromCharCode(origSig.charCodeAt(0) + 1) + origSig.slice(1);
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_v3_signature: tamperedSig,
    };
    await expect(verifyCertificate(cert, productionKeys())).rejects.toMatchObject({
      reason: 'invalid_signature',
    });
  });
});

// ---------------------------------------------------------------------------
// TOB-SDK-TS-01: downgrade detection + minimumSignableVersion strict mode
// ---------------------------------------------------------------------------
describe('verifyCertificate v3 — TOB-SDK-TS-01 downgrade detection', () => {
  /**
   * Test (i): v3 cert with version field stripped but v3 sig present → throws
   * version_downgrade_detected. This is the primary TOB-SDK-TS-01 attack vector.
   */
  it('(i) throws version_downgrade_detected when v3 sig present but version field absent', async () => {
    const rawCert = loadFixture<Record<string, unknown>>('cert-real-v3-production.json');
    const cert: Record<string, unknown> = {
      ...rawCert,
      signable_protocol_version_emitted: null, // version stripped
      // signable_v3_signature intentionally kept — this is the downgrade attempt
    };
    const keys = productionKeys();
    await expect(verifyCertificate(cert, keys)).rejects.toMatchObject({
      reason: 'version_downgrade_detected',
    });
  });

  /**
   * Test (j): minimumSignableVersion:'v3' on a fully-stripped legacy v2 cert
   * (both version and v3 sig absent) → throws signable_version_insufficient.
   */
  it('(j) throws signable_version_insufficient when minimumSignableVersion=v3 and cert is legacy v2', async () => {
    const kp = loadFixture<{ publicKey: string }>('witness-keypair.json');
    const keys: VerifyCertificateKeys = {
      witnessKeyId: 'witness_v1',
      witnessPublicKey: kp.publicKey,
    };
    // cert-valid-anchored.json has no v3 fields — pure v2
    const cert = loadFixture('cert-valid-anchored.json');
    await expect(
      verifyCertificate(cert, keys, { minimumSignableVersion: 'v3' }),
    ).rejects.toMatchObject({ reason: 'signable_version_insufficient' });
  });

  /**
   * Test (k): genuine v3 cert + minimumSignableVersion:'v3' → succeeds with
   * signableVersion='v3'. The production cert is the ground truth here.
   */
  it('(k) genuine v3 cert with minimumSignableVersion:v3 → passes, signableVersion=v3', async () => {
    const cert = loadFixture('cert-real-v3-production.json');
    const keys = productionKeys();
    const result = await verifyCertificate(cert, keys, { minimumSignableVersion: 'v3' });
    expect(result.signableVersion).toBe('v3');
    expect(result.v3SignatureStripped).toBe(false);
  });

  /**
   * Test (l): genuine legacy v2 cert, default options (no minimumSignableVersion) →
   * still succeeds with signableVersion='v2'. No regression on legacy certs.
   */
  it('(l) genuine legacy v2 cert, default opts → succeeds signableVersion=v2 (no regression)', async () => {
    const kp = loadFixture<{ publicKey: string }>('witness-keypair.json');
    const keys: VerifyCertificateKeys = {
      witnessKeyId: 'witness_v1',
      witnessPublicKey: kp.publicKey,
    };
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await verifyCertificate(cert, keys);
    expect(result.signableVersion).toBe('v2');
    expect(result.v3SignatureStripped).toBe(false);
  });

  /**
   * Test (m): v3SignatureStripped field is false on a normal v3 result.
   */
  it('(m) v3SignatureStripped=false on normal v3 result', async () => {
    const result = await verifyCertificate(
      loadFixture('cert-real-v3-production.json'),
      productionKeys(),
    );
    expect(result.v3SignatureStripped).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// V3 cert with no sanitizer claim (edge case: sanitizer hash fields → null)
// ---------------------------------------------------------------------------
describe('deriveWitnessSignedBytesV3 — no sanitizer claim', () => {
  it('returns null for all hash fields when no dsa-sanitizer claim is present', () => {
    // Build a minimal cert with only a bridge claim
    const cert: VeilCertificate = {
      certificate_id: 'veil_test_no_sanitizer',
      request_id: 'req_test_no_sanitizer',
      protocol_version: 2,
      witness_key_id: 'witness_v1',
      witness_signature: Buffer.alloc(64).toString('base64'),
      issued_at: '2026-06-10T00:00:00Z',
      claims: [
        {
          claim_id: 'clm_bridge_001',
          request_id: 'req_test_no_sanitizer',
          service_id: 'dsa-bridge',
          claim_type: 'CLAIM_TYPE_TOKEN_GENERATED',
          data_seen: [],
          data_not_seen: [],
          canonical_payload: '',
          timestamp: '2026-06-10T00:00:00Z',
          signature: '',
        },
      ],
      verification: {
        signatures_valid: false,
        completeness: 'COMPLETENESS_PARTIAL',
        missing_services: ['dsa-sanitizer'],
        temporal_consistent: true,
        data_visibility_consistent: true,
        isolation_verified: false,
        qi_score: null,
        overall_verdict: 'VERDICT_PARTIAL',
      },
    };

    const bytes = deriveWitnessSignedBytesV3(cert);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;

    expect(decoded['redaction_manifest_hash']).toBeNull();
    expect(decoded['sanitized_fields_body_hash']).toBeNull();
    expect(decoded['tms_manifest_hash']).toBeNull();
    expect(decoded['client_id']).toBeNull();
    expect(decoded['api_key_id']).toBeNull();
    expect(decoded['byok_exempt']).toBe(false);
  });
});
