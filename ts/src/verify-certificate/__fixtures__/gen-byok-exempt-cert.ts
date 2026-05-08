// One-shot generator for cert-byok-exempt.json.
//
// Usage (from ts/):
//   npx tsx src/verify-certificate/__fixtures__/gen-byok-exempt-cert.ts
//
// Mirrors generate-certs.ts but produces a single new fixture for the
// BYOK_EXEMPT-enabled cert path. The witness signable map is UNCHANGED —
// still the 7-key set; ``verification.byok_exempt`` and the new
// ``ISOLATION_PROBE_BYOK_EXEMPT`` enum value live OUTSIDE the signable. So
// signing reuses the same stable test keypair and produces a valid signature
// exactly as for cert-valid-anchored.json.

import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deriveWitnessSignedBytes } from '../signable.js';
import type { VeilCertificate } from '../../types.js';

const FIXTURES_DIR = __dirname;

interface StableKeypair {
  publicKey: string;
  privateKey: string;
}
function loadStableKeypair(): StableKeypair {
  const raw = readFileSync(join(FIXTURES_DIR, 'test-witness-keypair.json'), 'utf8');
  return JSON.parse(raw) as StableKeypair;
}

function buildByokExemptCert(): VeilCertificate {
  return {
    certificate_id: 'veil_test_byok_exempt_0001',
    request_id: 'req_test_byok_exempt_0001',
    protocol_version: 2,
    claims: [
      {
        claim_id: 'clm_test_byok_token_generated_0001',
        request_id: 'req_test_byok_exempt_0001',
        service_id: 'dsa-bridge',
        claim_type: 'CLAIM_TYPE_TOKEN_GENERATED',
        data_seen: ['customer_id'],
        data_not_seen: ['context', 'prompt_template', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"bridge"}').toString('base64'),
        timestamp: '2026-05-08T05:24:09.617230313Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        bridge: { token_hash: 'AAA=', epoch: '0', encryption_enabled: true },
      },
      {
        claim_id: 'clm_test_byok_pii_sanitized_0002',
        request_id: 'req_test_byok_exempt_0001',
        service_id: 'dsa-sanitizer',
        claim_type: 'CLAIM_TYPE_PII_SANITIZED',
        data_seen: ['context_fields'],
        data_not_seen: ['customer_id', 'token', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"sanitizer"}').toString('base64'),
        timestamp: '2026-05-08T05:24:09.666135Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        sanitizer: {
          pii_entities_found: 1,
          redaction_manifest_hash: 'AAA=',
          layers_active: ['known_entity_matching', 'presidio_ner', 'llm_pii_scan'],
        },
      },
      {
        claim_id: 'clm_test_byok_inference_completed_0003',
        request_id: 'req_test_byok_exempt_0001',
        service_id: 'dsa-ai',
        claim_type: 'CLAIM_TYPE_INFERENCE_COMPLETED',
        data_seen: ['opaque_token', 'sanitized_context'],
        data_not_seen: ['customer_id', 'raw_context', 'pii'],
        canonical_payload: Buffer.from('{"test":"inference"}').toString('base64'),
        timestamp: '2026-05-08T05:24:11.066748Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        inference: {
          // The new enum value — gateway-managed probe was intentionally
          // skipped because the customer brought their own upstream key.
          isolation_probe: 'ISOLATION_PROBE_BYOK_EXEMPT',
          model_used: 'gpt-4o-mini',
          response_hash: 'AAA=',
        },
      },
      {
        claim_id: 'clm_test_byok_events_recorded_0004',
        request_id: 'req_test_byok_exempt_0001',
        service_id: 'dsa-audit',
        claim_type: 'CLAIM_TYPE_EVENTS_RECORDED',
        data_seen: ['event_hashes'],
        data_not_seen: ['pii', 'context', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"audit"}').toString('base64'),
        timestamp: '2026-05-08T05:24:12.704438306Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        audit: {
          event_ids: ['test_event_byok_0001'],
          chain_head_hash: 'AAA=',
          chain_length: '1',
        },
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
      // The new field — proto number 9 on VerificationResult. NOT in the
      // 7-key signable; carried as informational metadata so callers can
      // render "VERIFIED (BYOK exempt)" badges.
      byok_exempt: true,
    },
    issued_at: '2026-05-08T05:24:12.710321721Z',
    formal_verification: null,
    audit_integrity: null,
    privacy_budget: null,
    witness_signature: '', // filled in after signing
    witness_key_id: 'witness_v1',
    attestation: {
      timestamp: null,
      transparency_log: null,
      notary: {
        provider: 'dsa-veil-witness',
        notary_signature: '',
        notary_public_key_id: 'witness_v1',
        checks_performed: ['canonical_json_signing'],
        attested_at: null,
      },
    },
    anchor_status: {
      status: 'ANCHOR_STATUS_ANCHORED',
      attempts: 1,
      last_error: '',
      human_note: '',
    },
  };
}

function main(): void {
  const kp = loadStableKeypair();
  const privBytes = Buffer.from(kp.privateKey, 'base64');
  if (privBytes.length !== 64) {
    throw new Error(`expected Ed25519 private key of 64 bytes, got ${privBytes.length}`);
  }
  const seed = privBytes.subarray(0, 32);
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const pkcs8 = Buffer.concat([pkcs8Prefix, seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });

  const cert = buildByokExemptCert();
  const signedBytes = deriveWitnessSignedBytes(cert);
  const signature = sign(null, Buffer.from(signedBytes), privateKey);
  const signatureB64 = Buffer.from(signature).toString('base64');
  cert.witness_signature = signatureB64;
  if (cert.attestation?.notary) cert.attestation.notary.notary_signature = signatureB64;

  writeFileSync(
    join(FIXTURES_DIR, 'cert-byok-exempt.json'),
    JSON.stringify(cert, null, 2) + '\n',
    'utf8',
  );
  // eslint-disable-next-line no-console
  console.log('Wrote cert-byok-exempt.json');
}

main();
