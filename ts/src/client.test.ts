import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Lucairn } from './client.js';
import {
  LucairnConfigError,
  LucairnError,
  LucairnHttpError,
  LucairnTimeoutError,
} from './errors.js';

const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';

// Handle on the private request<T>() so tests can exercise the plumbing
// without exporting it or changing its visibility.
type Internal = {
  request: <T>(path: string, init: RequestInit) => Promise<T>;
};
const asInternal = (client: Lucairn): Internal => client as unknown as Internal;

describe('Lucairn constructor — apiKey validation', () => {
  it('accepts a well-formed dsa_ key', () => {
    // The key is stored on a private field (#apiKey), so we cannot — and
    // intentionally must not — assert on a read-back here. Successful
    // construction (no throw) is the whole observable contract.
    expect(() => new Lucairn({ apiKey: VALID_KEY })).not.toThrow();
  });

  it('rejects a key with the wrong prefix', () => {
    expect(() => new Lucairn({ apiKey: 'sk_0123456789abcdef0123456789abcdef' })).toThrow(
      LucairnConfigError,
    );
  });

  it('rejects a key with the wrong length', () => {
    expect(() => new Lucairn({ apiKey: 'dsa_0123456789abcdef' })).toThrow(LucairnConfigError);
  });

  it('rejects a key that contains uppercase hex', () => {
    expect(() => new Lucairn({ apiKey: 'dsa_ABCDEF0123456789ABCDEF0123456789' })).toThrow(
      LucairnConfigError,
    );
  });

  it('rejects a non-string apiKey', () => {
    // @ts-expect-error — exercising runtime guard against mis-typed input.
    expect(() => new Lucairn({ apiKey: undefined })).toThrow(LucairnConfigError);
  });
});

describe('Lucairn constructor — defaults and baseUrl', () => {
  it('applies the default baseUrl when none is supplied', () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    expect(client.baseUrl).toBe('https://gateway.lucairn.eu');
  });

  it('applies the default timeoutMs when none is supplied', () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    expect(client.timeoutMs).toBe(30_000);
  });

  it('accepts a valid baseUrl and strips trailing slashes', () => {
    const client = new Lucairn({ apiKey: VALID_KEY, baseUrl: 'https://vault.example.com/' });
    expect(client.baseUrl).toBe('https://vault.example.com');
  });

  it('strips trailing slashes even when caller omits baseUrl (default path)', () => {
    // Defense-in-depth: default is already well-formed; assert the normalize
    // step runs regardless of where the baseUrl came from.
    const client = new Lucairn({ apiKey: VALID_KEY });
    expect(client.baseUrl.endsWith('/')).toBe(false);
  });

  it('rejects an invalid baseUrl', () => {
    expect(() => new Lucairn({ apiKey: VALID_KEY, baseUrl: 'not a url' })).toThrow(
      LucairnConfigError,
    );
  });

  it('rejects a non-positive timeoutMs', () => {
    expect(() => new Lucairn({ apiKey: VALID_KEY, timeoutMs: 0 })).toThrow(LucairnConfigError);
    expect(() => new Lucairn({ apiKey: VALID_KEY, timeoutMs: -1 })).toThrow(LucairnConfigError);
    expect(() => new Lucairn({ apiKey: VALID_KEY, timeoutMs: Number.NaN })).toThrow(
      LucairnConfigError,
    );
  });
});

describe('Lucairn constructor — baseUrl scheme guard', () => {
  it('rejects a file:// URL', () => {
    expect(() => new Lucairn({ apiKey: VALID_KEY, baseUrl: 'file:///etc/passwd' })).toThrow(
      LucairnConfigError,
    );
  });

  it('rejects a javascript: URL', () => {
    expect(() => new Lucairn({ apiKey: VALID_KEY, baseUrl: 'javascript:alert(1)' })).toThrow(
      LucairnConfigError,
    );
  });
});

describe('Lucairn.request() — header merge', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('forces SDK-owned headers to win over caller-supplied ones, case-insensitively', async () => {
    let captured: RequestInit | undefined;
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      captured = init;
      return Promise.resolve(
        new Response('{"ok":true}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    });

    const client = new Lucairn({ apiKey: VALID_KEY });
    await asInternal(client).request('/health', {
      headers: {
        'X-Api-Key': 'wrong-key',
        'Content-Type': 'text/plain',
        'X-Custom': 'keep-me',
      },
    });

    expect(captured).toBeDefined();
    const h = captured!.headers as Record<string, string>;

    // SDK-owned headers use canonical lowercase names and cannot be overridden.
    expect(h['x-api-key']).toBe(VALID_KEY);
    expect(h['content-type']).toBe('application/json');

    // The uppercase duplicates must not have survived the Headers() normalization.
    expect(h['X-Api-Key']).toBeUndefined();
    expect(h['Content-Type']).toBeUndefined();

    // Caller-only headers are preserved (on their lowercased key).
    expect(h['x-custom']).toBe('keep-me');
  });
});

describe('Lucairn.request() — error wrapping', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('wraps an AbortError from fetch into LucairnTimeoutError', async () => {
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          const err = new Error('The operation was aborted.');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });

    const client = new Lucairn({ apiKey: VALID_KEY, timeoutMs: 5 });
    await expect(asInternal(client).request('/slow', {})).rejects.toSatisfy(
      (err) => err instanceof LucairnTimeoutError && err instanceof LucairnError,
    );
  });

  it('wraps a generic fetch rejection in LucairnError and preserves cause', async () => {
    const underlying = new TypeError('network failure');
    vi.stubGlobal('fetch', () => Promise.reject(underlying));

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await asInternal(client).request('/x', {});
      expect.fail('expected request to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnError);
      expect(err).not.toBeInstanceOf(LucairnTimeoutError);
      expect((err as LucairnError).cause).toBe(underlying);
    }
  });

  it('surfaces a non-2xx response as LucairnHttpError without re-wrapping via the generic catch', async () => {
    // Invariant: the `err instanceof LucairnError` guard in request()'s catch
    // block must rethrow LucairnHttpError unchanged. If a future refactor drops
    // that guard, HTTP errors would be wrapped in LucairnError('Request failed')
    // with the HttpError moved onto `.cause` — this test is the tripwire.
    const upstreamBody = { error: 'upstream failed' };
    vi.stubGlobal('fetch', () =>
      Promise.resolve(
        new Response(JSON.stringify(upstreamBody), {
          status: 500,
          statusText: 'Internal Server Error',
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await asInternal(client).request('/boom', {});
      expect.fail('expected request to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      expect(err).not.toBeInstanceOf(LucairnTimeoutError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(500);
      expect(httpErr.body).toEqual(upstreamBody);
      // The invariant: the generic catch must NOT have re-wrapped this error,
      // which would have moved the original onto `.cause`.
      expect(httpErr.cause).toBeUndefined();
    }
  });
});

describe('Lucairn — apiKey hiding', () => {
  // The key is held on a JS private class field (#apiKey). These three tests
  // pin the three observable consequences of that choice; a future regression
  // (e.g. someone re-adding a `public readonly apiKey` shim or a `toJSON`
  // getter) will fail at least one of them.
  it('does not include the apiKey in JSON.stringify output', () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    const serialized = JSON.stringify(client);
    expect(serialized).not.toContain(VALID_KEY);
  });

  it('does not include the apiKey in util.inspect output', () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    // showHidden surfaces non-enumerable own props; private class fields are
    // still excluded by spec, so this is the strictest practical check.
    const inspected = inspect(client, { showHidden: true, depth: null });
    expect(inspected).not.toContain(VALID_KEY);
  });

  it('does not expose apiKey as an instance property at the type level', () => {
    const client = new Lucairn({ apiKey: VALID_KEY });
    // Structural checks come first: a regression that re-adds
    // `public readonly apiKey` would fail these BEFORE any read of the
    // property, so the actual key value never reaches the test output as
    // part of the failure message.
    expect('apiKey' in client).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(client, 'apiKey')).toBe(false);
    // @ts-expect-error apiKey is a private class field (#apiKey); reading it
    // off the public instance type must be a TS error. If this directive ever
    // stops firing, tsc will flag it as an unused @ts-expect-error — that is
    // the compile-time regression signal.
    const leaked = client.apiKey;
    // Runtime tripwire: only reached when the structural checks above pass,
    // so this assertion confirms there is no compatibility getter quietly
    // returning the key when TS isn't looking.
    expect(leaked).toBeUndefined();
  });
});
