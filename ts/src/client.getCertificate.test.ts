import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { delay, http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { Lucairn } from './client.js';
import {
  LucairnError,
  LucairnHttpError,
  LucairnTimeoutError,
} from './errors.js';
import { server } from './test-server.js';
import type { VeilCertificate } from './types.js';

// Obviously-fake API key — same shape as the rest of the suite.
const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';
const BASE = 'https://gateway.lucairn.eu';
const CERT_URL_PREFIX = `${BASE}/api/v1/veil/certificate/`;

const fixturesDir = join(
  __dirname,
  'verify-certificate',
  '__fixtures__',
);

function loadCert(name: string): VeilCertificate {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as VeilCertificate;
}

describe('Lucairn.getCertificate() — happy path (200)', () => {
  it('returns the VeilCertificate body deep-equal to the gateway payload', async () => {
    const fixture = loadCert('cert-valid-anchored.json');
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, () => HttpResponse.json(fixture)),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const cert = await client.getCertificate(fixture.request_id);

    expect(cert).toEqual(fixture);
  });

  it('sends x-api-key header and targets the request-id-scoped path', async () => {
    const fixture = loadCert('cert-valid-anchored.json');
    let capturedUrl = '';
    const capturedHeaders: Record<string, string> = {};
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, ({ request }) => {
        capturedUrl = request.url;
        request.headers.forEach((value, key) => {
          capturedHeaders[key] = value;
        });
        return HttpResponse.json(fixture);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.getCertificate('req_test_0000000000000001');

    expect(capturedUrl).toBe(`${CERT_URL_PREFIX}req_test_0000000000000001`);
    expect(capturedHeaders['x-api-key']).toBe(VALID_KEY);
  });
});

describe('Lucairn.getCertificate() — 202 pending', () => {
  it('throws LucairnHttpError with .status=202 and the pending wrapper body', async () => {
    const pendingBody = {
      status: 'pending' as const,
      request_id: 'req_pending_0001',
      message: 'Veil certificate is not ready yet.',
      retry_after_seconds: 30,
    };
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, () =>
        HttpResponse.json(pendingBody, { status: 202 }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificate('req_pending_0001');
      expect.fail('expected 202 pending to throw LucairnHttpError');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(202);
      expect(httpErr.body).toEqual(pendingBody);
      expect((httpErr.body as Record<string, unknown>).status).toBe('pending');
      expect((httpErr.body as Record<string, unknown>).retry_after_seconds).toBe(30);
    }
  });
});

describe('Lucairn.getCertificate() — HTTP error mapping', () => {
  const cases: Array<{ status: number; label: string; body: Record<string, unknown> }> = [
    {
      status: 401,
      label: 'missing_api_key',
      body: { error: { code: 'missing_api_key', message: 'API key is required.' } },
    },
    {
      status: 401,
      label: 'invalid_api_key',
      body: { error: { code: 'invalid_api_key', message: 'API key is invalid.' } },
    },
    {
      status: 403,
      label: 'tier_insufficient',
      body: {
        error: { code: 'tier_insufficient', message: 'Pro tier required.' },
      },
    },
    {
      status: 404,
      label: 'veil_not_configured',
      body: {
        error: { code: 'veil_not_configured', message: 'Veil Protocol is not enabled on this instance.' },
      },
    },
    {
      status: 502,
      label: 'upstream_error',
      body: { error: { code: 'upstream_error', message: 'Failed to retrieve certificate.' } },
    },
  ];

  for (const { status, label, body } of cases) {
    it(`maps ${status} ${label} to LucairnHttpError with matching status and body`, async () => {
      server.use(
        http.get(`${CERT_URL_PREFIX}:id`, () =>
          HttpResponse.json(body, { status }),
        ),
      );

      const client = new Lucairn({ apiKey: VALID_KEY });
      try {
        await client.getCertificate('req_err_0001');
        expect.fail(`expected ${status} to throw LucairnHttpError`);
      } catch (err) {
        expect(err).toBeInstanceOf(LucairnHttpError);
        expect(err).toBeInstanceOf(LucairnError);
        const httpErr = err as LucairnHttpError;
        expect(httpErr.status).toBe(status);
        expect(httpErr.body).toEqual(body);
        expect(
          ((httpErr.body as Record<string, Record<string, unknown>>).error).code,
        ).toBe(label);
      }
    });
  }

  it('maps 503 veil_unavailable with retry_after_seconds=30 in the body envelope', async () => {
    const body = {
      error: {
        code: 'veil_unavailable',
        message: 'Veil Witness is temporarily unavailable.',
        retry_after_seconds: 30,
      },
    };
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, () =>
        HttpResponse.json(body, { status: 503 }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificate('req_unavailable_0001');
      expect.fail('expected 503 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(503);
      expect(
        ((httpErr.body as Record<string, Record<string, unknown>>).error).retry_after_seconds,
      ).toBe(30);
    }
  });
});

describe('Lucairn.getCertificate() — transport errors', () => {
  it('wraps a network failure in LucairnError (not LucairnHttpError)', async () => {
    server.use(http.get(`${CERT_URL_PREFIX}:id`, () => HttpResponse.error()));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificate('req_network_0001');
      expect.fail('expected network failure to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnError);
      expect(err).not.toBeInstanceOf(LucairnHttpError);
    }
  });
});

describe('Lucairn.getCertificate() — timeout and abort', () => {
  it('fires LucairnTimeoutError when the per-call timeout elapses', async () => {
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, async () => {
        await delay(500);
        return HttpResponse.json(loadCert('cert-valid-anchored.json'));
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificate('req_slow_0001', { timeoutMs: 50 });
      expect.fail('expected timeout to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnTimeoutError);
      expect((err as LucairnTimeoutError).message).toContain('50ms');
    }
  });

  it('rethrows the caller abort reason verbatim (not wrapped in LucairnTimeoutError)', async () => {
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, async () => {
        await delay(10_000);
        return HttpResponse.json(loadCert('cert-valid-anchored.json'));
      }),
    );

    const controller = new AbortController();
    const abortReason = new Error('caller-initiated abort');
    // Fire the abort before the call so composed signal is aborted at entry.
    controller.abort(abortReason);

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificate('req_abort_0001', { signal: controller.signal });
      expect.fail('expected caller abort to throw');
    } catch (err) {
      expect(err).toBe(abortReason);
    }
  });
});

describe('Lucairn.getCertificate() — path encoding', () => {
  it('percent-encodes slashes, spaces, and other reserved characters in requestId', async () => {
    let capturedUrl = '';
    server.use(
      // MSW's `:id` pattern matches a single path segment, but an encoded
      // %2F is not treated as a separator by fetch — so the handler still
      // matches and we can read the exact URL the SDK emitted.
      http.get(`${CERT_URL_PREFIX}:id`, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(loadCert('cert-valid-anchored.json'));
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.getCertificate('req/weird id?');

    // Slash → %2F, space → %20, question-mark → %3F. None of these appear raw
    // in the final URL — that's the whole point of the encoding pass.
    expect(capturedUrl).toBe(`${CERT_URL_PREFIX}req%2Fweird%20id%3F`);
    expect(capturedUrl).not.toContain('req/weird id?');
  });
});

describe('Lucairn.getCertificate() — observed behaviour on malformed 200 body', () => {
  // Per the locked thin-transport / no-semantic-guards rule: if the gateway
  // ever returns a 200 with a non-JSON payload (or a JSON-but-not-cert
  // payload), the SDK passes it through as-is. This test documents that
  // observed behaviour rather than asserting a guard — callers are expected
  // to run verifyCertificate() next, which will reject malformed bodies with
  // LucairnCertificateError({ reason: 'malformed' }).
  it('passes a non-JSON 200 body through as the raw text (no throw at transport layer)', async () => {
    server.use(
      http.get(`${CERT_URL_PREFIX}:id`, () =>
        new HttpResponse('not json at all', {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    // Typed as VeilCertificate at the call site but the runtime value is the
    // raw string — the caller is responsible for validation downstream.
    const result = (await client.getCertificate('req_malformed_0001')) as unknown;
    expect(result).toBe('not json at all');
  });
});
