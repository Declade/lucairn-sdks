import { describe, expect, it } from 'vitest';
import {
  LucairnCertificateError,
  LucairnConfigError,
  LucairnError,
  LucairnHttpError,
  LucairnResponseValidationError,
  LucairnTimeoutError,
} from './errors.js';
import type { VerifyCertificateFailureReason } from './errors.js';

describe('LucairnError hierarchy', () => {
  it('LucairnError is an Error and preserves the message', () => {
    const err = new LucairnError('boom');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err.name).toBe('LucairnError');
    expect(err.message).toBe('boom');
  });

  it('LucairnConfigError extends LucairnError and Error', () => {
    const err = new LucairnConfigError('bad config');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err).toBeInstanceOf(LucairnConfigError);
    expect(err.name).toBe('LucairnConfigError');
    expect(err.message).toBe('bad config');
  });

  it('LucairnHttpError preserves status and body', () => {
    const err = new LucairnHttpError('nope', 503, { reason: 'degraded' });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err).toBeInstanceOf(LucairnHttpError);
    expect(err.name).toBe('LucairnHttpError');
    expect(err.status).toBe(503);
    expect(err.body).toEqual({ reason: 'degraded' });
  });

  it('LucairnHttpError keeps a non-object body verbatim', () => {
    const err = new LucairnHttpError('plain', 502, 'upstream timeout');
    expect(err.body).toBe('upstream timeout');
  });

  it('LucairnTimeoutError extends LucairnError and preserves cause', () => {
    const underlying = new Error('aborted');
    underlying.name = 'AbortError';
    const err = new LucairnTimeoutError('timeout', { cause: underlying });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err).toBeInstanceOf(LucairnTimeoutError);
    expect(err.name).toBe('LucairnTimeoutError');
    expect(err.cause).toBe(underlying);
  });

  it('LucairnResponseValidationError extends LucairnError and carries .body', () => {
    const err = new LucairnResponseValidationError('wrong shape', {
      body: { unexpected: true },
    });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err).toBeInstanceOf(LucairnResponseValidationError);
    expect(err.name).toBe('LucairnResponseValidationError');
    expect(err.body).toEqual({ unexpected: true });
    expect(err.message).toBe('wrong shape');
  });

  it('LucairnResponseValidationError keeps a non-object body verbatim and preserves cause', () => {
    const underlying = new Error('decode failed');
    const err = new LucairnResponseValidationError('not json', {
      body: 'raw text',
      cause: underlying,
    });
    expect(err.body).toBe('raw text');
    expect(err.cause).toBe(underlying);
  });

  it('LucairnResponseValidationError is NOT a LucairnHttpError (distinct branch)', () => {
    const err = new LucairnResponseValidationError('x', { body: null });
    expect(err).not.toBeInstanceOf(LucairnHttpError);
  });
});

describe('LucairnCertificateError', () => {
  it('extends LucairnError and carries .reason + optional .certificateId', () => {
    const err = new LucairnCertificateError('bad sig', {
      reason: 'invalid_signature',
      certificateId: 'veil_abc',
    });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LucairnError);
    expect(err).toBeInstanceOf(LucairnCertificateError);
    expect(err.name).toBe('LucairnCertificateError');
    expect(err.reason).toBe('invalid_signature');
    expect(err.certificateId).toBe('veil_abc');
    expect(err.message).toBe('bad sig');
  });

  it('omits certificateId cleanly when unset', () => {
    const err = new LucairnCertificateError('boom', { reason: 'malformed' });
    expect(err.certificateId).toBeUndefined();
  });

  it('preserves cause when passed via ErrorOptions', () => {
    const underlying = new TypeError('bad key length');
    const err = new LucairnCertificateError('sig verify fail', {
      reason: 'invalid_signature',
      cause: underlying,
    });
    expect(err.cause).toBe(underlying);
  });

  it('throws cleanly (instanceof survives throw)', () => {
    expect(() => {
      throw new LucairnCertificateError('x', { reason: 'witness_mismatch' });
    }).toThrow(LucairnCertificateError);
  });

  it('reason union is exhaustive over all 7 reasons (compile-time check)', () => {
    // Record<Reason, true> — missing a key is a compile error, catching any
    // future rename or accidental removal of a reason literal.
    const exhaustive: Record<VerifyCertificateFailureReason, true> = {
      malformed: true,
      unsupported_protocol_version: true,
      witness_mismatch: true,
      witness_signature_missing: true,
      invalid_signature: true,
      version_downgrade_detected: true,
      signable_version_insufficient: true,
    };
    expect(Object.keys(exhaustive)).toHaveLength(7);
  });
});

// ---------------------------------------------------------------------------
// Legacy alias regression guard — the pre-Stage-3 names must stay re-exported
// and refer to the same constructors. If the next minor bump removes the
// aliases, this block goes with it.
// ---------------------------------------------------------------------------
describe('legacy TheVeil* alias re-exports', () => {
  it('TheVeil* names from index resolve to the Lucairn* constructors', async () => {
    const idx = await import('./index.js');
    expect(idx.TheVeilError).toBe(LucairnError);
    expect(idx.TheVeilConfigError).toBe(LucairnConfigError);
    expect(idx.TheVeilHttpError).toBe(LucairnHttpError);
    expect(idx.TheVeilTimeoutError).toBe(LucairnTimeoutError);
    expect(idx.TheVeilCertificateError).toBe(LucairnCertificateError);
    expect(idx.TheVeilResponseValidationError).toBe(LucairnResponseValidationError);
  });
});
