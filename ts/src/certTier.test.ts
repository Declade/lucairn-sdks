/**
 * Optional, UNSIGNED `verification.cert_tier` on the type.
 *
 * Types only, no verifier or signable change. The field parses when present,
 * absent or unknown (never an error), and the offline verifier's outcome does
 * not depend on it — the real production v3 certificate verifies identically
 * with or without a tier, because neither witness signable carries it.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseCertificate } from './verify-certificate/parse.js';
import { verifyCertificate } from './verify-certificate/index.js';
import type { VeilCertificate, VeilCertTier, VerifyCertificateKeys } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function realCert(): VeilCertificate {
  return JSON.parse(readFileSync(join(fixturesDir, 'cert-real-v3-production.json'), 'utf8')) as VeilCertificate;
}

function productionKeys(): VerifyCertificateKeys {
  const kp = JSON.parse(readFileSync(join(fixturesDir, 'production-witness-pubkey.json'), 'utf8')) as {
    publicKeyBase64: string;
    witnessKeyId: string;
  };
  return { witnessKeyId: kp.witnessKeyId, witnessPublicKey: kp.publicKeyBase64 };
}

function withTier(tier: string | undefined): VeilCertificate {
  const cert = realCert();
  if (tier === undefined) delete cert.verification.cert_tier;
  else cert.verification.cert_tier = tier;
  return cert;
}

describe('verification.cert_tier (optional, unsigned)', () => {
  it('is absent on the pre-tier production fixture and parses as undefined', () => {
    const cert = parseCertificate(realCert());
    expect('cert_tier' in cert.verification).toBe(false);
    expect(cert.verification.cert_tier).toBeUndefined();
  });

  it.each(['full_chain', 'input_shield', 'input_shield_two_signer', '', 'input-shield', 'some_future_tier'])(
    'parses %j verbatim, never an error',
    (tier) => {
      const cert = parseCertificate(withTier(tier));
      expect(cert.verification.cert_tier).toBe(tier);
    },
  );

  it('accepts the documented values and an unknown string at the type level', () => {
    const tiers: VeilCertTier[] = ['full_chain', 'input_shield', 'input_shield_two_signer', '', 'some_future_tier'];
    expect(tiers).toHaveLength(4);
  });

  it.each([undefined, 'full_chain', 'input_shield', 'input_shield_two_signer', '', 'some_future_tier'])(
    'the verifier outcome does not depend on cert_tier=%j (outside both signables)',
    async (tier) => {
      const result = await verifyCertificate(withTier(tier), productionKeys());
      expect(result.signableVersion).toBe('v3');
      expect(result.overallVerdict).toBe('VERDICT_PARTIAL');
      expect(result.requestId).toBe('0ad683d6a85692cc1631422a8c4293ba');
    },
  );
});
