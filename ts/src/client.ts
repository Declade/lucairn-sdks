import {
  LucairnConfigError,
  LucairnError,
  LucairnHttpError,
  LucairnResponseValidationError,
  LucairnTimeoutError,
} from './errors.js';
import type {
  AuditExportResponse,
  ListAuditEventsOptions,
  LucairnConfig,
  MessagesOptions,
  ProxyAcceptedResponse,
  ProxyMessagesRequest,
  ProxyResponse,
  ProxySyncResponse,
  VeilCertificate,
  VerifyCertificateKeys,
  VerifyCertificateResult,
} from './types.js';
import { verifyCertificate as verifyCertificateImpl } from './verify-certificate/index.js';

// Stage 3: gateway accepts both `dsa_<32hex>` (legacy customer keys) and
// `lcr_live_<chars>` (post-Stage-3 website-minted keys). Keep both shapes
// here so the SDK doesn't reject either flavor at construction time.
// Gateway is the truth source for whether the key is actually valid.
const API_KEY_PATTERN = /^(dsa_[0-9a-f]{32}|lcr_live_[A-Za-z0-9_-]{20,})$/;

// Default points at the hosted Lucairn gateway for the Developer tier.
// Enterprise self-hosters must pass baseUrl explicitly.
const DEFAULT_BASE_URL = 'https://gateway.lucairn.eu';

// 60s default. Deliberately ABOVE the gateway's 30s sync-wait boundary (after
// which it returns a 202 processing receipt with a job_id) and BELOW the
// gateway's 120s proxyClientTimeout. A 30s SDK default would abort exactly at
// the 202-receipt boundary, throwing LucairnTimeoutError and losing the
// job_id the caller needs to poll. See CON-07 in the 2026-05-28 hardening
// audit.
const DEFAULT_TIMEOUT_MS = 60_000;

// Caps the response body the SDK will read before raising
// LucairnResponseValidationError (2xx) / LucairnHttpError (non-2xx). Mirrors
// Python `_DEFAULT_MAX_RESPONSE_BYTES` and Go `DefaultMaxResponseBytes`
// (both 10 MiB). Callers can override via LucairnConfig.maxResponseBytes.
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

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

// Mirrors Python/Go: maxResponseBytes must be a positive finite integer.
// Throws LucairnConfigError on 0, negative, non-integer, NaN, or Infinity.
function validateMaxResponseBytes(value: number): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new LucairnConfigError(
      `Invalid maxResponseBytes: ${value} — must be a positive integer`,
    );
  }
  return value;
}

function validateProxyMessagesRequest(params: ProxyMessagesRequest): void {
  // Runtime reject of stream=true. TypeScript's ProxyMessagesRequest type
  // already forbids `stream: true` at compile time (`stream?: false`), but a
  // JS-only caller or an `any`-typed body can still set it. The gateway does
  // not support a streaming proxy response, so fail loudly with a locatable
  // LucairnConfigError rather than silently sending an unsupported flag.
  // Parity with Python's runtime guard (client.py: `if params.stream is True`).
  // See CON-06 in the 2026-05-28 hardening audit — this HARDENS the locked
  // no-streaming contract, it does not reopen it.
  if ((params as { stream?: unknown }).stream === true) {
    throw new LucairnConfigError(
      'messages() does not support stream=true — use a future streaming API once available',
    );
  }
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

// ---------------------------------------------------------------------------
// 2xx response-shape validation (CON-02 parity).
//
// The gateway is the truth source for content, but a 2xx body that doesn't
// carry the minimum field set is a gateway bug or version skew, not a valid
// response. These validators enforce the SAME minimal required-field set as
// the Go SDK (go/lucairn.go validateVeilCertificate / validateProxySyncResponse
// / validateProxyAcceptedResponse) — deliberately NOT the stricter set the TS
// verify-certificate parser uses. Widening this set is gated on reopening the
// locked "minimal required-field set" decision (audit CON-10). On failure
// they throw LucairnResponseValidationError so callers can branch on
// "transport failed (LucairnHttpError)" vs "2xx body wrong shape".
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

// Throws LucairnResponseValidationError unless `body` carries the 5 fields the
// SDK's signature-verification pipeline needs. Mirrors Go validateVeilCertificate.
function validateVeilCertificateShape(body: unknown): VeilCertificate {
  const missing = (field: string): never => {
    throw new LucairnResponseValidationError(
      `Response body failed to deserialize as VeilCertificate: missing or empty ${field}`,
      { body },
    );
  };
  if (!isRecord(body)) {
    throw new LucairnResponseValidationError(
      'Response body failed to deserialize as VeilCertificate: not a JSON object',
      { body },
    );
  }
  if (!nonEmptyString(body.certificate_id)) missing('certificate_id');
  if (!nonEmptyString(body.request_id)) missing('request_id');
  if (!nonEmptyString(body.witness_signature)) missing('witness_signature');
  if (!nonEmptyString(body.witness_key_id)) missing('witness_key_id');
  if (!nonEmptyString(body.issued_at)) missing('issued_at');
  return body as unknown as VeilCertificate;
}

// Throws LucairnResponseValidationError unless `body` is a ProxyResponse with
// the minimum field set. Discriminates sync vs async on `status==='processing'`,
// mirroring Go's _parse_proxy_response branch + the two Go validators.
function validateProxyResponseShape(body: unknown): ProxyResponse {
  if (!isRecord(body)) {
    throw new LucairnResponseValidationError(
      'Response body failed to deserialize as ProxyResponse: not a JSON object',
      { body },
    );
  }
  if (body.status === 'processing') {
    // Async (202) receipt: job_id + request_id + status_url all needed to poll.
    const missing = (field: string): never => {
      throw new LucairnResponseValidationError(
        `Response body failed to deserialize as ProxyAcceptedResponse: missing or empty ${field}`,
        { body },
      );
    };
    if (!nonEmptyString(body.job_id)) missing('job_id');
    if (!nonEmptyString(body.request_id)) missing('request_id');
    if (!nonEmptyString(body.status_url)) missing('status_url');
    return body as unknown as ProxyAcceptedResponse;
  }
  // Sync (200) terminal result: status + model_used. latency_ms is NOT
  // required (the gateway may legitimately emit 0 on sub-ms paths) — matches
  // Go validateProxySyncResponse.
  if (!nonEmptyString(body.status)) {
    throw new LucairnResponseValidationError(
      'Response body failed to deserialize as ProxySyncResponse: missing or empty status',
      { body },
    );
  }
  if (!nonEmptyString(body.model_used)) {
    throw new LucairnResponseValidationError(
      'Response body failed to deserialize as ProxySyncResponse: missing or empty model_used',
      { body },
    );
  }
  return body as unknown as ProxySyncResponse;
}

// Throws LucairnResponseValidationError unless `body` is an AuditExportResponse
// with the minimum field set. The events array must be present (it may be empty).
function validateAuditExportResponseShape(body: unknown): AuditExportResponse {
  const missing = (field: string): never => {
    throw new LucairnResponseValidationError(
      `Response body failed to deserialize as AuditExportResponse: missing or invalid ${field}`,
      { body },
    );
  };
  if (!isRecord(body)) {
    throw new LucairnResponseValidationError(
      'Response body failed to deserialize as AuditExportResponse: not a JSON object',
      { body },
    );
  }
  if (!nonEmptyString(body.customer_id)) missing('customer_id');
  if (!nonEmptyString(body.period)) missing('period');
  if (!Array.isArray(body.events)) missing('events');
  return body as unknown as AuditExportResponse;
}

// Read a fetch Response body, accumulating at most `maxBytes` decoded as
// UTF-8. Returns the (possibly truncated) text and an `overCap` flag set when
// the body exceeded the cap. Streams via response.body so a multi-GB body is
// never fully buffered. Falls back to response.text() when response.body is
// absent (some test/runtime shims), applying the cap on the resulting string
// length so the invariant still holds. Mirrors the Python/Go bounded reads.
async function readBodyCapped(
  response: Response,
  maxBytes: number,
): Promise<{ text: string; overCap: boolean }> {
  const decoder = new TextDecoder('utf-8');

  if (!response.body) {
    // No stream available (e.g. a non-streaming test double). Read fully,
    // then enforce the cap on the byte length of the encoded body.
    const full = await response.text();
    const bytes = new TextEncoder().encode(full);
    if (bytes.byteLength > maxBytes) {
      return { text: decoder.decode(bytes.subarray(0, maxBytes)), overCap: true };
    }
    return { text: full, overCap: false };
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let accumulated = 0;
  let overCap = false;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined) {
        continue;
      }
      const budget = maxBytes - accumulated;
      if (budget <= 0) {
        overCap = true;
        break;
      }
      if (value.byteLength > budget) {
        chunks.push(value.subarray(0, budget));
        accumulated += budget;
        overCap = true;
        break;
      }
      chunks.push(value);
      accumulated += value.byteLength;
    }
  } finally {
    // Release the underlying connection; ignore cancel errors on a drained
    // or already-closed stream.
    reader.cancel().catch(() => {});
  }

  const merged = new Uint8Array(accumulated);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: decoder.decode(merged), overCap };
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
  public readonly maxResponseBytes: number;

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
        'Invalid apiKey — expected either "dsa_" followed by 32 lowercase hex characters, or "lcr_live_" followed by at least 20 alphanumeric/underscore/hyphen characters',
      );
    }

    // Defense in depth: validate and normalize both the default and any caller override.
    const rawBaseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
    const baseUrl = normalizeBaseUrl(rawBaseUrl);

    const timeoutMs =
      config.timeoutMs === undefined
        ? DEFAULT_TIMEOUT_MS
        : validateTimeoutMs(config.timeoutMs, 'timeoutMs');

    const maxResponseBytes =
      config.maxResponseBytes === undefined
        ? DEFAULT_MAX_RESPONSE_BYTES
        : validateMaxResponseBytes(config.maxResponseBytes);

    this.#apiKey = config.apiKey;
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
    this.maxResponseBytes = maxResponseBytes;
  }

  // Public entry point for /api/v1/proxy/messages. The gateway can return
  // either a sync terminal result (200) or an async processing receipt (202);
  // callers discriminate on `response.status === 'processing'`.
  async messages(params: ProxyMessagesRequest, options?: MessagesOptions): Promise<ProxyResponse> {
    // Validate finite-ness of numeric fields before JSON.stringify, which
    // would otherwise silently coerce NaN/Infinity to null on the wire.
    validateProxyMessagesRequest(params);

    const { body } = await this.request<unknown>(
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
    // Validate the 2xx body carries the minimum ProxyResponse field set
    // (CON-02 parity). A wrong-shaped 200/202 raises
    // LucairnResponseValidationError rather than passing through a bogus
    // typed value the caller would dereference and crash on.
    return validateProxyResponseShape(body);
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

    // Validate the 2xx body carries the minimum VeilCertificate field set
    // (CON-02 parity). A non-JSON or wrong-shaped 200 raises
    // LucairnResponseValidationError so callers can branch on "transport
    // failed (LucairnHttpError)" vs "2xx body doesn't look like a cert". The
    // required-field set matches the Go SDK's validateVeilCertificate (the 5
    // fields verifyCertificate() needs), NOT the stricter TS verify-parser —
    // widening is gated on the locked minimal-required-field decision.
    return validateVeilCertificateShape(body);
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

    const { body } = await this.request<unknown>(
      path,
      { method: 'GET', headers: opts?.headers },
      { timeoutMs: opts?.timeoutMs, signal: opts?.signal },
    );
    // Validate the 2xx body carries the minimum AuditExportResponse field set
    // (CON-02 parity). A wrong-shaped 200 raises LucairnResponseValidationError
    // rather than passing through a bogus typed value. Mirrors the Go SDK's
    // decodeInto + ResponseValidationError path on this endpoint.
    return validateAuditExportResponseShape(body);
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

      // Bounded read: stream + accumulate up to maxResponseBytes so a
      // hostile / misbehaving gateway streaming an unbounded body can't OOM
      // the process. Mirrors the Python (httpx iter_bytes budget loop) and Go
      // (io.LimitReader) caps. On overflow we surface the cap-sized prefix on
      // the error's body for diagnostics — LucairnResponseValidationError for
      // 2xx (body not consumable) and LucairnHttpError for non-2xx, matching
      // Python's branch.
      const { text, overCap } = await readBodyCapped(response, this.maxResponseBytes);
      let body: unknown = text;
      if (text.length > 0) {
        try {
          body = JSON.parse(text);
        } catch {
          // non-JSON body — keep raw text
        }
      }

      if (overCap) {
        const capMessage = `response body exceeded maxResponseBytes cap of ${this.maxResponseBytes}`;
        if (response.ok) {
          throw new LucairnResponseValidationError(capMessage, { body });
        }
        throw new LucairnHttpError(capMessage, response.status, body);
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

// Legacy alias — pre-Stage-3 callers used `TheVeil`. Scheduled for removal in
// @lucairn/sdk@1.1.0. The @deprecated JSDoc tag tells VS Code and other
// JSDoc-aware editors to render strikethrough on legacy usages.
/** @deprecated Use {@link Lucairn} instead. The TheVeil alias will be removed in @lucairn/sdk@1.1.0. */
export { Lucairn as TheVeil };
