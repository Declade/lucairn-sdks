import { describe, expect, it } from 'vitest';
import { getClientId } from './client-id.js';
import type { VeilCertificate } from './types.js';

// Minimal cert builder. The verify-certificate suite owns the full fixture
// loader; this helper just wires up enough fields to satisfy the type while
// exercising the client_id accessor.
function makeCert(overrides: Partial<VeilCertificate> = {}): VeilCertificate {
  return {
    certificate_id: 'veil_test',
    request_id: 'req_test',
    protocol_version: 2,
    claims: [],
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
    issued_at: '2026-01-01T00:00:00Z',
    witness_signature: '',
    witness_key_id: 'witness_v1',
    ...overrides,
  };
}

describe('getClientId()', () => {
  it('returns the string value when client_id is populated', () => {
    const cert = makeCert({ client_id: 'org_abc123' });
    expect(getClientId(cert)).toBe('org_abc123');
  });

  it('returns null when client_id is JSON null on the wire', () => {
    // EmitUnpopulated:true on the gateway side emits `client_id: null`
    // for an unset optional field; the SDK must surface that as null.
    const cert = makeCert({ client_id: null });
    expect(getClientId(cert)).toBeNull();
  });

  it('returns null when client_id is undefined (field missing)', () => {
    const cert = makeCert();
    expect(getClientId(cert)).toBeNull();
  });

  it('preserves the empty string verbatim (does NOT collapse "" to null)', () => {
    // Empty-string is a legitimate (if pathological) wire value; nullish-
    // coalescing intentionally keeps it. If a future change collapses it
    // for tighter typing, that's a deliberate API change — this test will
    // fail and force the discussion.
    const cert = makeCert({ client_id: '' });
    expect(getClientId(cert)).toBe('');
  });
});
