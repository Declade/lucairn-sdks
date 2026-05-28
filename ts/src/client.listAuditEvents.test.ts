import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { Lucairn } from './client.js';
import {
  LucairnError,
  LucairnHttpError,
  LucairnResponseValidationError,
} from './errors.js';
import { server } from './test-server.js';
import type { AuditExportResponse } from './types.js';

const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';
const BASE = 'https://gateway.lucairn.eu';
const EXPORT_URL = `${BASE}/api/v1/audit/export`;

const SAMPLE_RESPONSE: AuditExportResponse = {
  customer_id: 'cust_test_001',
  tier: 'pro',
  period: '2026-04-01 to 2026-05-01',
  events: [
    {
      timestamp: '2026-04-15T12:34:56Z',
      event_type: 'gateway_request_completed',
      actor: 'cust_test_001',
      details: '{"request_id":"req_x"}',
      request_id: 'req_x',
    },
  ],
  total_events: 1,
  source: 'audit_service+memory_buffer',
};

describe('Lucairn.listAuditEvents() — happy path (200)', () => {
  it('returns the AuditExportResponse body verbatim', async () => {
    server.use(http.get(EXPORT_URL, () => HttpResponse.json(SAMPLE_RESPONSE)));

    const client = new Lucairn({ apiKey: VALID_KEY });
    const out = await client.listAuditEvents();
    expect(out).toEqual(SAMPLE_RESPONSE);
  });

  it('sends x-api-key header and targets /api/v1/audit/export', async () => {
    let capturedUrl = '';
    const capturedHeaders: Record<string, string> = {};
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        request.headers.forEach((value, key) => {
          capturedHeaders[key] = value;
        });
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents();
    expect(capturedUrl).toBe(EXPORT_URL);
    expect(capturedHeaders['x-api-key']).toBe(VALID_KEY);
  });
});

describe('Lucairn.listAuditEvents() — query parameters', () => {
  it('encodes days as a query parameter', async () => {
    let capturedUrl = '';
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents({ days: 7 });
    expect(capturedUrl).toBe(`${EXPORT_URL}?days=7`);
  });

  it('encodes eventType as the `type` query parameter (snake-case wire mapping)', async () => {
    let capturedUrl = '';
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents({ eventType: 'gateway_request_completed' });
    expect(capturedUrl).toBe(`${EXPORT_URL}?type=gateway_request_completed`);
  });

  it('encodes both days and eventType together', async () => {
    let capturedUrl = '';
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents({ days: 14, eventType: 'request_recorded' });
    expect(capturedUrl).toBe(`${EXPORT_URL}?days=14&type=request_recorded`);
  });

  it('omits the query string entirely when no filters are supplied', async () => {
    let capturedUrl = '';
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents();
    expect(capturedUrl).toBe(EXPORT_URL);
    expect(capturedUrl).not.toContain('?');
  });

  it('does NOT validate days client-side — the gateway is the truth source', async () => {
    // Server-side max is 90 (audit_export.go:22) but the SDK forwards the
    // user value verbatim; the gateway responds 400 if out of range. This
    // test pins that no client-side reject happens.
    let capturedUrl = '';
    server.use(
      http.get(EXPORT_URL, ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.json(SAMPLE_RESPONSE);
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.listAuditEvents({ days: 999 });
    expect(capturedUrl).toBe(`${EXPORT_URL}?days=999`);
  });
});

describe('Lucairn.listAuditEvents() — HTTP error mapping', () => {
  it('maps 503 audit_export_unavailable to LucairnHttpError', async () => {
    const errBody = {
      error: { code: 'audit_export_unavailable', message: 'Audit export unavailable. Try again shortly.' },
    };
    server.use(http.get(EXPORT_URL, () => HttpResponse.json(errBody, { status: 503 })));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.listAuditEvents();
      expect.fail('expected 503 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      expect(err).toBeInstanceOf(LucairnError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(503);
      expect(httpErr.body).toEqual(errBody);
    }
  });

  it('maps 403 tier_insufficient (audit not enabled for tier) to LucairnHttpError', async () => {
    const errBody = {
      error: { code: 'tier_insufficient', message: 'Pro tier required.' },
    };
    server.use(http.get(EXPORT_URL, () => HttpResponse.json(errBody, { status: 403 })));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.listAuditEvents();
      expect.fail('expected 403 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(403);
      expect(httpErr.body).toEqual(errBody);
    }
  });

  it('maps 400 invalid days to LucairnHttpError with the gateway error envelope', async () => {
    const errBody = {
      error: { code: 'invalid_field', message: 'days: cannot exceed 90' },
    };
    server.use(http.get(EXPORT_URL, () => HttpResponse.json(errBody, { status: 400 })));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.listAuditEvents({ days: 999 });
      expect.fail('expected 400 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(400);
      expect(httpErr.body).toEqual(errBody);
    }
  });
});

describe('Lucairn.listAuditEvents() — 2xx response-shape validation (CON-02)', () => {
  // CON-02 parity: a 2xx body missing the minimum field set raises
  // LucairnResponseValidationError rather than passing through a bogus typed
  // value. Mirrors the Go SDK's decodeInto + ResponseValidationError path.
  it('throws LucairnResponseValidationError on a non-JSON 200 body', async () => {
    server.use(
      http.get(EXPORT_URL, () =>
        new HttpResponse('oops', { status: 200, headers: { 'content-type': 'text/plain' } }),
      ),
    );
    const client = new Lucairn({ apiKey: VALID_KEY });
    await expect(client.listAuditEvents()).rejects.toBeInstanceOf(
      LucairnResponseValidationError,
    );
  });

  it('throws LucairnResponseValidationError when events is not an array', async () => {
    server.use(
      http.get(EXPORT_URL, () =>
        HttpResponse.json({ customer_id: 'c', period: '2026-04-01 to 2026-05-01', events: 'nope' }),
      ),
    );
    const client = new Lucairn({ apiKey: VALID_KEY });
    await expect(client.listAuditEvents()).rejects.toBeInstanceOf(
      LucairnResponseValidationError,
    );
  });

  it('accepts a valid response with an empty events array', async () => {
    server.use(
      http.get(EXPORT_URL, () =>
        HttpResponse.json({
          customer_id: 'cust_x',
          tier: 'pro',
          period: '2026-04-01 to 2026-05-01',
          events: [],
          total_events: 0,
          source: 'none',
        }),
      ),
    );
    const client = new Lucairn({ apiKey: VALID_KEY });
    const out = await client.listAuditEvents();
    expect(out.events).toEqual([]);
  });
});
