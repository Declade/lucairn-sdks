import { delay, http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { Lucairn } from './client.js';
import {
  LucairnConfigError,
  LucairnError,
  LucairnHttpError,
  LucairnTimeoutError,
} from './errors.js';
import { server } from './test-server.js';
import type {
  ProxyMessagesRequest,
  ProxyAcceptedResponse,
  ProxyResponse,
  ProxySyncResponse,
} from './types.js';

// Obviously-fake identifiers — no real keys, names, or PII.
const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';
const MESSAGES_URL = 'https://gateway.lucairn.eu/api/v1/proxy/messages';

// Minimal valid request body reused across tests.
const BASIC_REQUEST: ProxyMessagesRequest = {
  prompt_template: 'Hello {name}',
  context: { name: 'Example Person' },
  model: 'claude-sonnet-4-5',
  max_tokens: 1024,
};

describe('Lucairn.messages() — happy path (sync 200)', () => {
  it('returns a typed ProxySyncResponse on 200', async () => {
    server.use(
      http.post(MESSAGES_URL, () =>
        HttpResponse.json({
          status: 'JOB_STATUS_COMPLETED',
          model_used: 'claude-sonnet-4-5',
          latency_ms: 142,
          result: { content: [{ type: 'text', text: 'Hello [PERSON_1]' }] },
          relinked: true,
          request_id: 'req_test_0001',
        }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const response = await client.messages(BASIC_REQUEST);

    // Discriminated union: narrow via the `status` literal. The async path
    // sets status='processing'; the sync path sets it to a JobStatus enum.
    if (response.status === 'processing') {
      expect.fail('expected sync response, got async 202 shape');
      return;
    }
    expect(response.status).toBe('JOB_STATUS_COMPLETED');
    expect(response.model_used).toBe('claude-sonnet-4-5');
    expect(response.latency_ms).toBe(142);
    expect(response.request_id).toBe('req_test_0001');
    expect(response.relinked).toBe(true);
  });

  it('sends the request body and SDK-owned headers', async () => {
    let capturedBody: unknown;
    const capturedHeaders: Record<string, string> = {};
    server.use(
      http.post(MESSAGES_URL, async ({ request }) => {
        capturedBody = await request.json();
        request.headers.forEach((value, key) => {
          capturedHeaders[key] = value;
        });
        return HttpResponse.json({
          status: 'completed',
          model_used: 'claude-sonnet-4-5',
          latency_ms: 1,
        });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.messages(BASIC_REQUEST);

    expect(capturedBody).toEqual(BASIC_REQUEST);
    expect(capturedHeaders['x-api-key']).toBe(VALID_KEY);
    expect(capturedHeaders['content-type']).toBe('application/json');
  });
});

describe('Lucairn.messages() — async 202 accepted', () => {
  it('returns a typed ProxyAcceptedResponse when the gateway times out to 202', async () => {
    server.use(
      http.post(MESSAGES_URL, () =>
        HttpResponse.json(
          {
            status: 'processing',
            job_id: 'job_test_0001',
            request_id: 'req_test_0001',
            status_url: '/api/v1/proxy/jobs/job_test_0001',
          },
          { status: 202 },
        ),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const response = await client.messages(BASIC_REQUEST);

    // Narrow into the accepted branch. After this check, the compiler should
    // expose job_id / status_url and hide model_used / latency_ms.
    if (response.status !== 'processing') {
      expect.fail('expected async 202 response, got sync shape');
      return;
    }
    expect(response.status).toBe('processing');
    expect(response.job_id).toBe('job_test_0001');
    expect(response.request_id).toBe('req_test_0001');
    expect(response.status_url).toBe('/api/v1/proxy/jobs/job_test_0001');
  });

  it('carries the optional veil receipt when pro/enterprise tier is active', async () => {
    server.use(
      http.post(MESSAGES_URL, () =>
        HttpResponse.json(
          {
            status: 'processing',
            job_id: 'job_test_0002',
            request_id: 'req_test_0002',
            status_url: '/api/v1/proxy/jobs/job_test_0002',
            veil: {
              status: 'pending',
              certificate_url: '/api/v1/veil/certificate/req_test_0002',
              summary_url: '/api/v1/veil/certificate/req_test_0002/summary',
            },
          },
          { status: 202 },
        ),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const response = await client.messages(BASIC_REQUEST);

    if (response.status !== 'processing') {
      expect.fail('expected async 202 response');
      return;
    }
    expect(response.veil).toEqual({
      status: 'pending',
      certificate_url: '/api/v1/veil/certificate/req_test_0002',
      summary_url: '/api/v1/veil/certificate/req_test_0002/summary',
    });
  });
});

describe('Lucairn.messages() — HTTP error mapping', () => {
  const cases: Array<{ status: number; label: string; body: Record<string, unknown> }> = [
    { status: 400, label: 'bad request', body: { error: 'invalid_request', message: 'missing prompt_template' } },
    { status: 401, label: 'unauthorized', body: { error: 'invalid_api_key' } },
    { status: 429, label: 'rate limit', body: { error: 'rate_limit_exceeded', retry_after: 30 } },
    { status: 500, label: 'server error', body: { error: 'internal' } },
  ];

  for (const { status, label, body } of cases) {
    it(`maps ${status} ${label} to LucairnHttpError with .status=${status} and parsed body`, async () => {
      server.use(
        http.post(MESSAGES_URL, () => HttpResponse.json(body, { status })),
      );

      const client = new Lucairn({ apiKey: VALID_KEY });
      try {
        await client.messages(BASIC_REQUEST);
        expect.fail(`expected ${status} to throw LucairnHttpError`);
      } catch (err) {
        expect(err).toBeInstanceOf(LucairnHttpError);
        expect(err).toBeInstanceOf(LucairnError);
        const httpErr = err as LucairnHttpError;
        expect(httpErr.status).toBe(status);
        expect(httpErr.body).toEqual(body);
      }
    });
  }
});

describe('Lucairn.messages() — transport errors', () => {
  it('wraps a network failure in LucairnError (not LucairnHttpError)', async () => {
    server.use(http.post(MESSAGES_URL, () => HttpResponse.error()));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.messages(BASIC_REQUEST);
      expect.fail('expected network failure to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnError);
      expect(err).not.toBeInstanceOf(LucairnHttpError);
    }
  });
});

describe('Lucairn.messages() — timeout', () => {
  it('fires LucairnTimeoutError when the per-call timeout elapses', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.messages(BASIC_REQUEST, { timeoutMs: 50 });
      expect.fail('expected timeout to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnTimeoutError);
      expect((err as LucairnTimeoutError).message).toContain('50ms');
    }
  });

  it('uses the client-level timeout when no per-call override is given', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY, timeoutMs: 60 });
    try {
      await client.messages(BASIC_REQUEST);
      expect.fail('expected client-level timeout to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnTimeoutError);
      expect((err as LucairnTimeoutError).message).toContain('60ms');
    }
  });
});

describe('Lucairn.messages() — numeric field finite guard', () => {
  const client = new Lucairn({ apiKey: VALID_KEY });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects %s max_tokens with LucairnConfigError mentioning the field', async (_label, value) => {
    try {
      await client.messages({ ...BASIC_REQUEST, max_tokens: value });
      expect.fail('expected rejection');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnConfigError);
      expect((err as LucairnConfigError).message).toContain('max_tokens');
    }
  });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects %s temperature with LucairnConfigError mentioning the field', async (_label, value) => {
    try {
      await client.messages({ ...BASIC_REQUEST, temperature: value });
      expect.fail('expected rejection');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnConfigError);
      expect((err as LucairnConfigError).message).toContain('temperature');
    }
  });

  it.each([
    ['NaN start', { start: Number.NaN, end: 10 }, 'start'],
    ['Infinity end', { start: 0, end: Number.POSITIVE_INFINITY }, 'end'],
    ['-Infinity start', { start: Number.NEGATIVE_INFINITY, end: 10 }, 'start'],
  ])(
    'rejects non-finite ground_truth offset: %s',
    async (_label, offsets, expectedField) => {
      try {
        await client.messages({
          ...BASIC_REQUEST,
          ground_truth: {
            name: [{ type: 'PERSON', value: 'Example Person', ...offsets }],
          },
        });
        expect.fail('expected rejection');
      } catch (err) {
        expect(err).toBeInstanceOf(LucairnConfigError);
        // Error message names the offending nested field path so callers can
        // locate the bad annotation without diffing their payload.
        expect((err as LucairnConfigError).message).toContain('ground_truth');
        expect((err as LucairnConfigError).message).toContain(expectedField);
      }
    },
  );

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['non-array string', 'not-an-array'],
    ['non-array object', { foo: 'bar' }],
    ['non-array number', 42],
  ])(
    'rejects malformed ground_truth[field] = %s with LucairnConfigError',
    async (_label, value) => {
      try {
        // Simulate a JS-only caller or `any`-typed payload bypassing the
        // ProxyPIIAnnotation[] compile-time contract.
        await client.messages({
          ...BASIC_REQUEST,
          ground_truth: { name: value } as unknown as ProxyMessagesRequest['ground_truth'],
        });
        expect.fail('expected rejection');
      } catch (err) {
        expect(err).toBeInstanceOf(LucairnConfigError);
        expect((err as LucairnConfigError).message).toContain('ground_truth.name');
      }
    },
  );

  it('accepts finite numeric fields on the happy path', async () => {
    server.use(
      http.post(MESSAGES_URL, () =>
        HttpResponse.json({ status: 'JOB_STATUS_COMPLETED', model_used: 'm', latency_ms: 1 }),
      ),
    );

    await expect(
      client.messages({
        ...BASIC_REQUEST,
        max_tokens: 1024,
        temperature: 0.7,
        ground_truth: {
          name: [{ type: 'PERSON', value: 'Example Person', start: 0, end: 14 }],
        },
      }),
    ).resolves.toBeDefined();
  });
});

describe('Lucairn.messages() — per-call timeoutMs validation', () => {
  // Mirrors the constructor's rejection set so callers can't silently slip
  // invalid values past the per-call path.
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('rejects %s timeoutMs with LucairnConfigError', async (_label, value) => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    await expect(
      client.messages(BASIC_REQUEST, { timeoutMs: value }),
    ).rejects.toBeInstanceOf(LucairnConfigError);
  });
});

describe('Lucairn.messages() — caller abort', () => {
  it('rethrows the caller-supplied abort reason verbatim', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('caller cancelled');

    // Abort shortly after the fetch is in-flight.
    const promise = client.messages(BASIC_REQUEST, { signal: controller.signal });
    setTimeout(() => controller.abort(reason), 20);

    try {
      await promise;
      expect.fail('expected caller abort to throw');
    } catch (err) {
      expect(err).toBe(reason);
      expect(err).not.toBeInstanceOf(LucairnTimeoutError);
    }
  });

  it('rejects immediately without issuing fetch when caller signal is already aborted', async () => {
    // No MSW handler — onUnhandledRequest: 'error' would fire if fetch ran,
    // which is the behavioural proof that we short-circuit before fetch().
    const client = new Lucairn({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('pre-aborted');
    controller.abort(reason);

    await expect(
      client.messages(BASIC_REQUEST, { signal: controller.signal }),
    ).rejects.toBe(reason);
  });
});

describe('Lucairn.messages() — composed signal (caller + timeout)', () => {
  it("caller aborts before timeout → caller's reason wins", async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('caller wins');

    const promise = client.messages(BASIC_REQUEST, {
      signal: controller.signal,
      timeoutMs: 300, // caller aborts first at ~20ms
    });
    setTimeout(() => controller.abort(reason), 20);

    try {
      await promise;
      expect.fail('expected caller abort to win');
    } catch (err) {
      expect(err).toBe(reason);
      expect(err).not.toBeInstanceOf(LucairnTimeoutError);
    }
  });

  it('timeout fires before caller aborts → LucairnTimeoutError wins', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const controller = new AbortController(); // never fired

    try {
      await client.messages(BASIC_REQUEST, {
        signal: controller.signal,
        timeoutMs: 50,
      });
      expect.fail('expected timeout to win');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnTimeoutError);
      expect((err as LucairnTimeoutError).message).toContain('50ms');
    }
  });
});

describe('ProxyResponse — compile-time discrimination', () => {
  it('narrows ProxyResponse on status — wrong-branch field access is a type error', () => {
    // Type-level tripwire. If the discriminated union regresses (e.g.
    // someone flattens the two branches back into a single interface), the
    // suppressions below will become unused and typecheck will fail.
    const fakeSync = {} as ProxyResponse;
    if (fakeSync.status !== 'processing') {
      // Now narrowed to ProxySyncResponse. Async-only fields must be
      // inaccessible.
      // @ts-expect-error job_id lives only on ProxyAcceptedResponse.
      const _noJobId: string = fakeSync.job_id;
      // @ts-expect-error status_url lives only on ProxyAcceptedResponse.
      const _noStatusUrl: string = fakeSync.status_url;
      expect([_noJobId, _noStatusUrl]).toHaveLength(2);
    }

    const fakeAsync = {} as ProxyResponse;
    if (fakeAsync.status === 'processing') {
      // Now narrowed to ProxyAcceptedResponse. Sync-only fields must be
      // inaccessible.
      // @ts-expect-error model_used lives only on ProxySyncResponse.
      const _noModel: string = fakeAsync.model_used;
      // @ts-expect-error latency_ms lives only on ProxySyncResponse.
      const _noLatency: number = fakeAsync.latency_ms;
      expect([_noModel, _noLatency]).toHaveLength(2);
    }
  });

  it('assignability: shape literals satisfy each variant', () => {
    // Positive: canonical sync literal.
    const sync: ProxySyncResponse = {
      status: 'JOB_STATUS_COMPLETED',
      model_used: 'claude-sonnet-4-5',
      latency_ms: 1,
    };
    // Positive: canonical accepted literal.
    const async_: ProxyAcceptedResponse = {
      status: 'processing',
      job_id: 'job_x',
      request_id: 'req_x',
      status_url: '/api/v1/proxy/jobs/job_x',
    };
    // Assign each into the union slot.
    const u1: ProxyResponse = sync;
    const u2: ProxyResponse = async_;
    expect([u1, u2]).toHaveLength(2);
  });
});

describe('ProxyMessagesRequest — compile-time typing', () => {
  it('rejects stream: true (type-level only; runtime is not exercised)', () => {
    // If the Omit/narrow on ProxyMessagesRequest regresses, the suppression
    // below will become unused and typecheck will fail — that is the point.
    const streamTrueRejected: ProxyMessagesRequest = {
      prompt_template: 'x',
      context: {},
      // @ts-expect-error streaming not supported this session.
      stream: true,
    };

    // stream: false is explicitly allowed.
    const streamFalseAllowed: ProxyMessagesRequest = {
      prompt_template: 'x',
      context: {},
      stream: false,
    };

    // Omitting stream entirely is allowed (it's optional).
    const streamOmittedAllowed: ProxyMessagesRequest = {
      prompt_template: 'x',
      context: {},
    };

    expect([streamTrueRejected, streamFalseAllowed, streamOmittedAllowed]).toHaveLength(3);
  });
});

describe('Lucairn.messages() — per-call header merge', () => {
  it('preserves caller custom headers but keeps SDK-owned headers SDK-owned', async () => {
    const captured: Record<string, string> = {};
    server.use(
      http.post(MESSAGES_URL, ({ request }) => {
        request.headers.forEach((value, key) => {
          captured[key] = value;
        });
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 1 });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.messages(BASIC_REQUEST, {
      headers: {
        'X-Request-ID': 'trace-abc-123',
        // These two must NOT override the SDK-owned values.
        'X-Api-Key': 'wrong-key',
        'Content-Type': 'text/plain',
      },
    });

    // SDK-owned: always the real key, always JSON.
    expect(captured['x-api-key']).toBe(VALID_KEY);
    expect(captured['content-type']).toBe('application/json');
    // Caller-only: preserved on its lowercased key.
    expect(captured['x-request-id']).toBe('trace-abc-123');
  });
});
