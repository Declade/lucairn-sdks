/**
 * Lucairn.verifyCertificate() — minimumSignableVersion parity tests.
 *
 * Mirrors the standalone verifyCertificate({ minimumSignableVersion }) tests
 * in verifyCertificateV3.test.ts at the client-method level.
 *
 * Goal: confirm the options arg threads through to verifyCertificateImpl
 * unchanged, and that the default (undefined) preserves backward compat.
 *
 * Tests mirror verifyCertificateV3.test.ts tests (j), (k), (l):
 *   (j) v2 cert + minimumSignableVersion:'v3' → signable_version_insufficient
 *   (k) v3 cert + minimumSignableVersion:'v3' → passes, signableVersion='v3'
 *   (l) v2 cert, no options → passes, signableVersion='v2' (no regression)
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Lucairn } from './client.js';
import { LucairnCertificateError } from './errors.js';
import type { VeilCertificate, VerifyCertificateKeys } from './types.js';

const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadFixture<T = VeilCertificate>(name: string): T {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;
}

interface ProductionPubkeyFixture {
  publicKeyBase64: string;
  witnessKeyId: string;
}

function productionKeys(): VerifyCertificateKeys {
  const kp = loadFixture<ProductionPubkeyFixture>('production-witness-pubkey.json');
  return {
    witnessKeyId: kp.witnessKeyId,
    witnessPublicKey: kp.publicKeyBase64,
  };
}

function testKeys(): VerifyCertificateKeys {
  const kp = loadFixture<{ publicKey: string }>('witness-keypair.json');
  return {
    witnessKeyId: 'witness_v1',
    witnessPublicKey: kp.publicKey,
  };
}

describe('Lucairn.verifyCertificate() — minimumSignableVersion forwarding', () => {
  /**
   * Mirror of standalone test (j): v2 cert + minimumSignableVersion:'v3' →
   * throws LucairnCertificateError reason='signable_version_insufficient'.
   *
   * Confirms the options arg is forwarded to verifyCertificateImpl.
   */
  it('(j) v2 cert + minimumSignableVersion:v3 throws signable_version_insufficient', async () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    const cert = loadFixture('cert-valid-anchored.json');
    const keys = testKeys();

    // Fixture must be pure v2 — no v3 sig, no version field
    expect((cert as unknown as Record<string, unknown>)['signable_v3_signature']).toBeFalsy();
    expect((cert as unknown as Record<string, unknown>)['signable_protocol_version_emitted']).toBeFalsy();

    await expect(
      client.verifyCertificate(cert, keys, { minimumSignableVersion: 'v3' }),
    ).rejects.toMatchObject({ reason: 'signable_version_insufficient' });

    await expect(
      client.verifyCertificate(cert, keys, { minimumSignableVersion: 'v3' }),
    ).rejects.toBeInstanceOf(LucairnCertificateError);
  });

  /**
   * Mirror of standalone test (k): genuine v3 cert + minimumSignableVersion:'v3'
   * → passes with signableVersion='v3'.
   */
  it('(k) v3 cert + minimumSignableVersion:v3 passes with signableVersion=v3', async () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    const cert = loadFixture('cert-real-v3-production.json');
    const keys = productionKeys();

    const result = await client.verifyCertificate(cert, keys, { minimumSignableVersion: 'v3' });
    expect(result.signableVersion).toBe('v3');
    expect(result.v3SignatureStripped).toBe(false);
  });

  /**
   * Mirror of standalone test (l): v2 cert with no options → passes,
   * signableVersion='v2'. Default-call backward compat is unchanged.
   */
  it('(l) v2 cert, no options → passes signableVersion=v2 (no regression)', async () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    const cert = loadFixture('cert-valid-anchored.json');
    const keys = testKeys();

    const result = await client.verifyCertificate(cert, keys);
    expect(result.signableVersion).toBe('v2');
    expect(result.v3SignatureStripped).toBe(false);
  });
});
