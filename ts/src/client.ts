import {
  LucairnConfigError,
  LucairnError,
  LucairnHttpError,
  LucairnTimeoutError,
} from './errors.js';
import type {
  AuditExportResponse,
  ListAuditEventsOptions,
  LucairnConfig,
  MessagesOptions,
  ProxyMessagesRequest,
  ProxyResponse,
  VeilCertificate,
  VerifyCertificateKeys,
  VerifyCertificateResult,
} from './types.js';
import { verifyCertificate as verifyCertificateImpl } from './verify-certificate/index.js';

const API_KEY_PATTERN = /^dsa_[0-9a-f]{32}$/;

// Default points at the hosted Lucairn gateway for the Developer tier.
// Enterprise self-hosters must pass baseUrl explicitly.
const DEFAULT_BASE_URL = 'https://gateway.lucairn.eu';

const DEFAULT_TIMEOUT_MS = 30_000;

function normalizeBaseUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new LucairnConfigError(`Invalid baseUrl: ${raw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new LucairnConfigError(
      `baseUrl must use http or https, got: ${parsed.protocol}`,
    );
  }
  return raw.replace(/\/+$/, '');
}

// Shared validator so constructor-level and per-call timeouts reject the same
// set of inputs. Returns the validated number; throws LucairnConfigError on
// 0, negative, NaN, or Infinity.
function validateTimeoutMs(value: number, source: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new LucairnConfigError(
      `Invalid ${source}: ${value} — must be a positive finite number`,
    );
  }
  return value;
}

// Rejects NaN, +Infinity, and -Infinity for any numeric request field.
// JSON.stringify turns these into `null`, which the gateway decodes to zero —
// e.g. max_tokens: NaN silently becomes a 0-token request. Name the field in
// the error so nested paths (ground_truth.<field>[i].start) are locatable.
function validateFiniteNumber(value: number, fieldName: string): void {
  if (!Number.isFinite(value)) {
    throw new LucairnConfigError(
      `Invalid ${fieldName}: ${value} — must be a finite number`,
    );
  }
}

function validateProxyMessagesRequest(params: ProxyMessagesRequest): void {
  if (params.max_tokens !== undefined) {
    validateFiniteNumber(params.max_tokens, 'max_tokens');
  }
  if (params.temperature !== undefined) {
    validateFiniteNumber(params.temperature, 'temperature');
  }
  if (params.ground_truth) {
    for (const [field, annotations] of Object.entries(params.ground_truth)) {
      // Guard against malformed runtime payloads from JS-only callers or
      // `any`-typed bodies. TypeScript enforces ProxyPIIAnnotation[] at compile
      // time, but undefined / null / non-array values would otherwise throw a
      // bare TypeError from .forEach instead of the expected
      // LucairnConfigError with a locatable field path.
      if (!Array.isArray(annotations)) {
        throw new LucairnConfigError(
          `Invalid ground_truth.${field}: expected ProxyPIIAnnotation[], got ${annotations === null ? 'null' : typeof annotations}`,
        );
      }
      annotations.forEach((a, i) => {
        validateFiniteNumber(a.start, `ground_truth.${field}[${i}].start`);
        validateFiniteNumber(a.end, `ground_truth.${field}[${i}].end`);
      });
    }
  }
}

/**
 * Lucairn — privacy-preserving AI gateway client for TypeScript.
 *
 * Wraps the hosted Lucairn gateway (default `https://gateway.lucairn.eu`)
 * with construction-time `apiKey` validation, `baseUrl` normalization,
 * per-call timeout composition, and typed error classes. Self-host
 * deployments must pass `baseUrl` explicitly.
 *
 * @example
 * ```ts
 * import { Lucairn, LucairnHttpError } from '@lucairn/sdk';
 *
 * const client = new Lucairn({ apiKey: process.env.LUCAIRN_API_KEY! });
 * const response = await client.messages({
 *   prompt_template: 'Hello {name}',
 *   context: { name: 'Example Person' },
 *   model: 'claude-sonnet-4-5',
 *   max_tokens: 1024,
 * });
 * ```
 */
export class Lucairn {
  // Private class field: excluded from JSON.stringify and util.inspect, and
  // unreachable via `client.apiKey` at both compile time and runtime. Keeps
  // the key out of accidental log lines, structured-clone payloads, and
  // serialized error contexts.
  readonly #apiKey: string;
  public readonly baseUrl: string;
  public readonly timeoutMs: number;

  constructor(config: LucairnConfig) {
    // Runtime capability check: AbortSignal.any landed in Node 18.17.
    // Older runtimes fail opaquely inside request<T>() with a
    // "AbortSignal.any is not a function" TypeError — much friendlier to
    // surface the incompatibility at construction time.
    if (typeof AbortSignal.any !== 'function') {
      throw new LucairnConfigError(
        'Unsupported runtime: AbortSignal.any is not available. Node 18.17+ (or equivalent) is required.',
      );
    }

    if (!config || typeof config.apiKey !== 'string' || !API_KEY_PATTERN.test(config.apiKey)) {
      throw new LucairnConfigError(
        'Invalid apiKey — expected format "dsa_" followed by 32 lowercase hex characters',
      );
    }

    // Defense in depth: validate and normalize both the default and any caller override.
    const rawBaseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
    const baseUrl = normalizeBaseUrl(rawBaseUrl);

    const timeoutMs =
      config.timeoutMs === undefined
        ? DEFAULT_TIMEOUT_MS
        : validateTimeoutMs(config.timeoutMs, 'timeoutMs');

    this.#apiKey = config.apiKey;
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
  }

  // Public entry point for /api/v1/proxy/messages. The gateway can return
  // either a sync terminal result (200) or an async processing receipt (202);
  // callers discriminate on `response.status === 'processing'`.
  async messages(params: ProxyMessagesRequest, options?: MessagesOptions): Promise<ProxyResponse> {
    // Validate finite-ness of numeric fields before JSON.stringify, which
    // would otherwise silently coerce NaN/Infinity to null on the wire.
    validateProxyMessagesRequest(params);

    const { body } = await this.request<ProxyResponse>(
      '/api/v1/proxy/messages',
      {
        method: 'POST',
        body: JSON.stringify(params),
        headers: options?.headers,
      },
      {
        timeoutMs: options?.timeoutMs,
        signal: options?.signal,
      },
    );
    return body;
  }

  // Verify a Veil Certificate's witness Ed25519 signature against the
  // certificate's canonical JSON core fields. See
  // ./verify-certificate/index.ts for full JSDoc, failure-reason list,
  // and key-format conventions. External RFC 3161 timestamp + Sigstore
  // Rekor transparency-log verification are out of scope for this SDK
  // release — see session 2b-cert-strong for the follow-up.
  async verifyCertificate(
    cert: VeilCertificate,
    keys: VerifyCertificateKeys,
  ): Promise<VerifyCertificateResult> {
    return verifyCertificateImpl(cert, keys);
  }

  // Fetch a Veil Certificate by request_id from the gateway's
  // GET /api/v1/veil/certificate/{request_id} endpoint. The happy-path
  // return is narrowly Promise<VeilCertificate>; the gateway's 202
  // pending-wrapper response (cert not yet assembled, or unknown
  // request_id — the gateway does not distinguish those two cases)
  // surfaces as LucairnHttpError{ status: 202, body: {status:"pending",
  // retry_after_seconds, ...} } so callers get a narrow happy-path type
  // and an explicit retry signal on the error branch. The `.status` on
  // the thrown error is the real HTTP status reported by the gateway.
  //
  // No auto-verification: the returned cert is raw. Chain
  // verifyCertificate() explicitly if you want witness-signature proof.
  async getCertificate(
    requestId: string,
    options?: MessagesOptions,
  ): Promise<VeilCertificate> {
    // encodeURIComponent is defense-in-depth against path injection. The
    // gateway's path extractor tolerates unencoded slashes, but the SDK
    // should never emit a raw `..` or unescaped segment separator.
    const encoded = encodeURIComponent(requestId);
    const { status, body } = await this.request<unknown>(
      `/api/v1/veil/certificate/${encoded}`,
      { method: 'GET', headers: options?.headers },
      { timeoutMs: options?.timeoutMs, signal: options?.signal },
    );

    // 202 means the gateway reached the witness but the certificate is
    // not yet assembled (or the request_id is unknown — the gateway does
    // not distinguish the two). Surface as LucairnHttpError so the
    // happy-path return stays a narrow VeilCertificate. Inspect
    // err.body.retry_after_seconds on the caller side.
    if (status === 202) {
      throw new LucairnHttpError(
        'Veil certificate is not yet assembled; retry after the indicated delay.',
        status,
        body,
      );
    }

    // Thin-transport rule: do NOT validate the body shape on the 2xx
    // happy path. A non-JSON or wrong-shaped 200 passes through typed
    // as VeilCertificate; downstream verifyCertificate() will reject
    // it with LucairnCertificateError{ reason:"malformed" }.
    return body as VeilCertificate;
  }

  /**
   * Fetch a DPO-friendly HTML summary of a Veil Certificate from the
   * gateway's GET /api/v1/veil/certificate/{request_id}/summary endpoint.
   * The endpoint always returns text/html with no JSON wrapper.
   *
   * Pending state: when the certificate is not yet assembled, the gateway
   * returns 202 Accepted with a pending-summary HTML body. We surface that
   * as `LucairnHttpError{ status: 202, body: "<html>...</html>" }` so the
   * happy-path return type stays the rendered ready-to-display HTML and
   * callers get an explicit retry signal on the error branch.
   *
   * Auth: same `x-api-key` header as `getCertificate()`. The gateway's
   * `authenticateAndAuthorize` gate decides whether the caller's tier may
   * read summaries — 401/403/404 errors flow through as `LucairnHttpError`
   * verbatim.
   *
   * @security
   * The returned HTML is server-rendered on the gateway and contains
   * fields derived from the original request payload. Do **NOT** pass the
   * return value directly to `dangerouslySetInnerHTML`, `innerHTML`, or
   * any equivalent unsanitized HTML sink. Render only inside a sandboxed
   * `<iframe srcdoc>` or after passing through a trusted sanitizer such
   * as DOMPurify. The SDK is a thin transport — it does not sanitize on
   * the client side.
   */
  async getCertificateSummary(
    requestId: string,
    options?: MessagesOptions,
  ): Promise<string> {
    // encodeURIComponent mirrors getCertificate(): the gateway extracts
    // request_id from the path string between two known delimiters, but
    // the SDK should never emit raw segment separators.
    const encoded = encodeURIComponent(requestId);
    const { status, body } = await this.request<unknown>(
      `/api/v1/veil/certificate/${encoded}/summary`,
      { method: 'GET', headers: options?.headers },
      { timeoutMs: options?.timeoutMs, signal: options?.signal },
    );

    // 202 = pending-summary HTML returned by the gateway's
    // renderPendingSummaryHTML path. Verified empirically against
    // services/gateway/internal/api/veil.go:848 (WriteHeader(StatusAccepted)).
    if (status === 202) {
      throw new LucairnHttpError(
        'Veil certificate summary is not yet ready; retry after a short delay.',
        status,
        body,
      );
    }

    // The endpoint sets Content-Type: text/html. The shared request<T>
    // transport attempts JSON.parse and falls back to raw text on parse
    // failure (HTML is not valid JSON, so body is the raw string).
    return typeof body === 'string' ? body : String(body);
  }

  // List audit events for the calling customer from the gateway's
  // GET /api/v1/audit/export endpoint. Query params:
  //   days       — integer, server default 30, server max 90.
  //   eventType  — maps to the `type` query parameter; optional.
  // Citations: services/gateway/internal/api/audit_export.go:21-22 (defaults
  // and max), audit_export.go:75 (eventType param), audit_export.go:91-99
  // (response shape).
  //
  // Auth: x-api-key (same as the rest of the SDK). The gateway gates this
  // endpoint on tier; callers whose tier doesn't include audit export receive
  // 403 tier_insufficient. We do NOT replicate that gate client-side — the
  // gateway is the truth source.
  //
  // 503 audit_export_unavailable, 400 invalid days, 401/403 auth errors all
  // surface as LucairnHttpError verbatim.
  async listAuditEvents(opts?: ListAuditEventsOptions): Promise<AuditExportResponse> {
    const params = new URLSearchParams();
    if (opts?.days !== undefined) {
      params.set('days', String(opts.days));
    }
    if (opts?.eventType !== undefined) {
      params.set('type', opts.eventType);
    }
    const query = params.toString();
    const path = query.length > 0 ? `/api/v1/audit/export?${query}` : '/api/v1/audit/export';

    const { body } = await this.request<AuditExportResponse>(
      path,
      { method: 'GET', headers: opts?.headers },
      { timeoutMs: opts?.timeoutMs, signal: opts?.signal },
    );
    // Thin-transport rule: do NOT validate the body shape on the 2xx happy
    // path. A wrong-shaped 200 passes through typed as AuditExportResponse;
    // callers needing stricter guards can layer their own validation.
    return body;
  }

  private async request<T>(
    path: string,
    init: RequestInit,
    opts?: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<{ status: number; body: T }> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const callerSignal = opts?.signal;
    // Per-call timeoutMs is validated with the same strictness as the
    // constructor — 0, negative, NaN, and Infinity all throw instead of
    // silently falling back to the client default.
    const timeoutMs =
      opts?.timeoutMs === undefined
        ? this.timeoutMs
        : validateTimeoutMs(opts.timeoutMs, 'options.timeoutMs');

    // Fail fast on an already-aborted caller signal so we don't spend a fetch
    // round-trip just to throw the same reason.
    if (callerSignal?.aborted) {
      throw callerSignal.reason;
    }

    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
    // AbortSignal.any (Node 20.3+) propagates whichever signal aborts first.
    // Its `.reason` is locked to the first source's reason and never changes,
    // which is how we distinguish caller-initiated aborts from timeouts below.
    const composedSignal: AbortSignal = callerSignal
      ? AbortSignal.any([callerSignal, timeoutController.signal])
      : timeoutController.signal;

    // Normalize caller headers via the Headers API — this lowercases all header
    // names per the fetch spec, so the SDK-owned keys below unambiguously win.
    const callerHeaders: Record<string, string> = {};
    if (init.headers !== undefined) {
      const h = new Headers(init.headers);
      h.forEach((value, key) => {
        callerHeaders[key] = value;
      });
    }
    const mergedHeaders: Record<string, string> = {
      ...callerHeaders,
      'x-api-key': this.#apiKey,
      'content-type': 'application/json',
    };

    try {
      const response = await fetch(url, {
        ...init,
        headers: mergedHeaders,
        signal: composedSignal,
      });

      const text = await response.text();
      let body: unknown = text;
      if (text.length > 0) {
        try {
          body = JSON.parse(text);
        } catch {
          // non-JSON body — keep raw text
        }
      }

      if (!response.ok) {
        throw new LucairnHttpError(
          `Lucairn request failed: ${response.status} ${response.statusText}`,
          response.status,
          body,
        );
      }
      return { status: response.status, body: body as T };
    } catch (err) {
      if (err instanceof LucairnError) {
        throw err;
      }
      // Abort path: if our composed signal fired, identity-compare its reason
      // against the caller's to learn which source aborted FIRST (not "who
      // ended up aborted by catch-time"). AbortSignal.any locks `.reason` to
      // the first source at composite-abort time and never updates it, so a
      // late caller abort after a timeout cannot misattribute blame.
      if (composedSignal.aborted) {
        if (callerSignal && composedSignal.reason === callerSignal.reason) {
          // Rethrow the caller's reason verbatim so they see the same value
          // they passed to controller.abort(reason).
          throw callerSignal.reason;
        }
        throw new LucairnTimeoutError(
          `Request timed out after ${timeoutMs}ms`,
          { cause: err },
        );
      }
      throw new LucairnError('Request failed', { cause: err });
    } finally {
      clearTimeout(timer);
    }
  }
}

// Legacy alias — pre-Stage-3 callers used `TheVeil`. Removed in next minor bump.
export { Lucairn as TheVeil };
