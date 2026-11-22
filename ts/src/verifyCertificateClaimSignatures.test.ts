/**
 * Claim-signature check of the simple verifyCertificate (security fix stream
 * T-1474, slice F16; level-3 review entry 5: "the SDK's certificate check
 * reports valid for a certificate whose claim contents were changed").
 *
 * The witness signature covers only the list of claim ids. With
 * `keys.servicePublicKeys` supplied, verifyCertificate must also verify each
 * claim's own Ed25519 signature over its canonical_payload. Synthetic keys and
 * data only.
 */

import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { verifyCertificate } from './verify-certificate/index.js';
import { deriveWitnessSignedBytes, deriveWitnessSignedBytesV3 } from './verify-certificate/signable.js';
import { LucairnCertificateError } from './errors.js';
import type { VeilCertificate, VerifyCertificateKeys } from './types.js';

interface Pair {
  priv: KeyObject;
  pub: string; // base64 raw 32 bytes
}

function pair(): Pair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x as string;
  return { priv: privateKey, pub: Buffer.from(x.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('base64') };
}

const witness = pair();
const bridge = pair();
const sanitizer = pair();

function signedClaim(p: Pair, claimId: string, serviceId: string, claimType: string, payload: Record<string, unknown>) {
  // The gateway signs the short claim-type name (the chain recipe's step 7g).
  const doc = {
    claim_id: claimId,
    claim_type: claimType.replace(/^CLAIM_TYPE_/, ''),
    data_not_seen: [],
    data_seen: [],
    payload,
    request_id: 'req_f16_0001',
    service_id: serviceId,
    timestamp: '2026-11-21T08:00:00Z',
  };
  const cp = Buffer.from(JSON.stringify(doc));
  return {
    claim_id: claimId,
    request_id: 'req_f16_0001',
    service_id: serviceId,
    claim_type: claimType as VeilCertificate['claims'][number]['claim_type'],
    data_seen: [],
    data_not_seen: [],
    canonical_payload: cp.toString('base64'),
    timestamp: '2026-11-21T08:00:00Z',
    signature: Buffer.from(sign(null, cp, p.priv)).toString('base64'),
  };
}

function buildCert(v3: boolean): VeilCertificate {
  const cert = {
    certificate_id: 'veil_f16_0001',
    request_id: 'req_f16_0001',
    protocol_version: 2,
    claims: [
      signedClaim(bridge, 'clm_f16_bridge', 'dsa-bridge', 'CLAIM_TYPE_TOKEN_GENERATED', { org_id: 'org_synthetic' }),
      signedClaim(sanitizer, 'clm_f16_sanitizer', 'dsa-sanitizer', 'CLAIM_TYPE_PII_SANITIZED', {
        entities_found: 3,
        redaction_manifest_hash: 'aGFzaA==',
      }),
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
    issued_at: '2026-11-21T08:00:01Z',
    witness_signature: '',
    witness_key_id: 'witness_f16',
  } as unknown as VeilCertificate;
  cert.witness_signature = Buffer.from(sign(null, Buffer.from(deriveWitnessSignedBytes(cert)), witness.priv)).toString('base64');
  if (v3) {
    cert.signable_protocol_version_emitted = 3;
    cert.signable_v3_signature = Buffer.from(
      sign(null, Buffer.from(deriveWitnessSignedBytesV3(cert)), witness.priv),
    ).toString('base64');
  }
  return cert;
}

// The level-3 case: change what a claim says after signing (here: the
// sanitizer claim's entity count), leaving the witness-signed claim ids intact.
function tamperClaim(cert: VeilCertificate): VeilCertificate {
  const out = structuredClone(cert);
  const c = out.claims[1];
  const doc = JSON.parse(Buffer.from(c.canonical_payload, 'base64').toString('utf8'));
  doc.payload.entities_found = 0;
  c.canonical_payload = Buffer.from(JSON.stringify(doc)).toString('base64');
  return out;
}

const witnessOnly: VerifyCertificateKeys = { witnessKeyId: 'witness_f16', witnessPublicKey: witness.pub };
const withServices: VerifyCertificateKeys = {
  ...witnessOnly,
  servicePublicKeys: { 'dsa-bridge': bridge.pub, 'dsa-sanitizer': sanitizer.pub },
};

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    if (err instanceof LucairnCertificateError) return err.reason;
    throw err;
  }
  return 'valid';
}

describe('verifyCertificate — claim signatures (F16, level-3 entry 5)', () => {
  for (const v3 of [false, true]) {
    const label = v3 ? 'v3' : 'v2';

    it(`${label}: genuine certificate verifies with service keys, claimSignaturesVerified=true`, async () => {
      const r = await verifyCertificate(buildCert(v3), withServices);
      expect(r.signableVersion).toBe(label);
      expect(r.claimSignaturesVerified).toBe(true);
    });

    it(`${label}: a claim changed after signing is NOT valid when service keys are supplied`, async () => {
      const tampered = tamperClaim(buildCert(v3));
      // The witness signature alone still verifies (it covers only claim ids) ...
      const r = await verifyCertificate(tampered, witnessOnly);
      expect(r.claimSignaturesVerified).toBe(false);
      // ... the claim-signature check catches the change.
      expect(await reason(verifyCertificate(tampered, withServices))).toBe('invalid_signature');
    });

    it(`${label}: tampered claim surfaces invalid_signature before the v3 floor`, async () => {
      expect(
        await reason(verifyCertificate(tamperClaim(buildCert(v3)), withServices, { minimumSignableVersion: 'v3' })),
      ).toBe('invalid_signature');
    });
  }

  it('a claim whose service has no supplied key fails, never skipped', async () => {
    const keys = { ...witnessOnly, servicePublicKeys: { 'dsa-bridge': bridge.pub } };
    expect(await reason(verifyCertificate(buildCert(false), keys))).toBe('invalid_signature');
  });

  it("a claim signed by another service's key fails", async () => {
    const keys = { ...witnessOnly, servicePublicKeys: { 'dsa-bridge': sanitizer.pub, 'dsa-sanitizer': sanitizer.pub } };
    expect(await reason(verifyCertificate(buildCert(false), keys))).toBe('invalid_signature');
  });

  it('a genuinely signed payload naming another claim_id fails (payload swap)', async () => {
    const cert = buildCert(false);
    const other = signedClaim(sanitizer, 'clm_other_cert', 'dsa-sanitizer', 'CLAIM_TYPE_PII_SANITIZED', {
      entities_found: 0,
    });
    cert.claims[1].canonical_payload = other.canonical_payload;
    cert.claims[1].signature = other.signature;
    expect(await reason(verifyCertificate(cert, withServices))).toBe('invalid_signature');
  });

  it('a non-canonical base64 claim signature fails', async () => {
    const cert = buildCert(false);
    cert.claims[0].signature = cert.claims[0].signature.replace(/=+$/, '');
    expect(await reason(verifyCertificate(cert, withServices))).toBe('invalid_signature');
  });

  // Review round 1, finding 1: with service keys, every OUTER claim field must
  // agree with the signed canonical_payload (the chain verifier's step 7g
  // rebuild, shared code). Each edit below leaves every signature valid.
  // [field, claim index, edit]. The service_id case edits the bridge claim
  // (the v3 witness signable reads sanitizer hashes by service_id).
  const outerEdits: Array<[string, number, (c: Record<string, unknown>) => void]> = [
    ['data_seen', 1, (c) => { c.data_seen = ['raw_prompt']; }],
    ['data_not_seen', 1, (c) => { c.data_not_seen = ['pii_values']; }],
    ['claim_type', 1, (c) => { c.claim_type = 'CLAIM_TYPE_EVENTS_RECORDED'; }],
    ['request_id', 1, (c) => { c.request_id = 'req_f16_other'; }],
    ['timestamp', 1, (c) => { c.timestamp = '2026-11-21T09:00:00Z'; }],
    ['service_id', 0, (c) => { c.service_id = 'dsa-bridge-twin'; }],
  ];
  for (const v3 of [false, true]) {
    for (const [field, idx, edit] of outerEdits) {
      it(`${v3 ? 'v3' : 'v2'}: an edited outer ${field} with valid signatures is NOT valid`, async () => {
        const cert = buildCert(v3);
        edit(cert.claims[idx] as unknown as Record<string, unknown>);
        // The twin service name carries the same key, so the claim signature itself verifies.
        const keys = { ...witnessOnly, servicePublicKeys: { ...withServices.servicePublicKeys, 'dsa-bridge-twin': bridge.pub } };
        const witnessResult = await verifyCertificate(cert, witnessOnly);
        expect(witnessResult.claimSignaturesVerified).toBe(false);
        expect(await reason(verifyCertificate(cert, keys))).toBe('invalid_signature');
      });
    }
  }

  it('the outer timestamp is compared as an instant, not as text', async () => {
    const cert = buildCert(false);
    cert.claims[1].timestamp = '2026-11-21T08:00:00.000Z';
    const r = await verifyCertificate(cert, withServices);
    expect(r.claimSignaturesVerified).toBe(true);
  });

  it('a signed canonical_payload with a duplicate claim_id key fails (strict parse, as the chain verifier)', async () => {
    const cert = buildCert(false);
    const c = cert.claims[1];
    const text = Buffer.from(c.canonical_payload, 'base64').toString('utf8');
    const dup = Buffer.from(text.replace('{"claim_id":', '{"claim_id":"clm_other","claim_id":'));
    c.canonical_payload = dup.toString('base64');
    c.signature = Buffer.from(sign(null, dup, sanitizer.priv)).toString('base64');
    expect(await reason(verifyCertificate(cert, withServices))).toBe('invalid_signature');
  });
});
