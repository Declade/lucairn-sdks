/**
 * Thin HTTP client for the Lucairn gateway's MCP-compatible endpoint.
 *
 * Wraps a single route:
 *   POST {baseUrl}/api/v1/mcp/messages
 *
 * Source: dual-sandbox-architecture/services/gateway/internal/api/mcp_handler.go:23-30
 * Route registered at handler.go:242.
 *
 * Authentication: x-api-key header (Lucairn API key, lcr_live_* or
 * legacy veil_live_*). See mcp_handler.go:128-129 (extractDSAKey) and
 * the apikey-auth middleware wrapping registered at handler.go:227.
 *
 * Optional BYOK upstream key: forwarded as X-Upstream-Key header per
 * mcp_handler.go:226-229 / extractUpstreamKey. When unset and the
 * customer profile has ManagedAI=false with a stored ProviderKey, the
 * gateway uses the stored key. When set on a managed-AI profile, the
 * customer's BYOK is used for that request only.
 *
 * The gateway routes upstream based on the request's `model` field, so
 * a single `/api/v1/mcp/messages` call can target Anthropic OR OpenAI
 * (verified live 2026-05-05: claude-* models route to Anthropic, gpt-*
 * route to OpenAI). The MCP server picks which BYOK key to forward by
 * inspecting the model prefix — see pickUpstreamKey below.
 */
import type {
  AnthropicErrorBody,
  AnthropicResponseBody,
  ChatToolInput,
} from './types.js'
import { GatewayError } from './types.js'

export interface GatewayClientOptions {
  /** Lucairn API key. Required. */
  apiKey: string
  /** Gateway base URL — no trailing slash. Required. */
  baseUrl: string
  /** Optional Anthropic BYOK key — used for Claude/Anthropic models. */
  anthropicKey?: string
  /** Optional OpenAI BYOK key — used for GPT/o1/o3/o4 models. */
  openaiKey?: string
  /**
   * Optional fetch implementation override — used by the test suite to
   * inject a stub. Defaults to the global fetch (Node 18.17+).
   */
  fetchImpl?: typeof fetch
}

/**
 * Build the request body sent to POST /api/v1/mcp/messages.
 *
 * Streaming is forced to `false`. The gateway does support SSE
 * streaming when stream=true (mcp_handler.go:387-462), but Claude
 * Desktop's MCP tool-call protocol surfaces only the final tool
 * result — the intermediate SSE chunks would be discarded. Non-stream
 * keeps the response simple and within the gateway's 25-30s poll
 * budget (mcp_handler.go:516-524 falls back to 202 ASYNC_PROCESSING
 * past the budget; we surface that as an error).
 */
export function buildMessagesRequestBody(input: ChatToolInput): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: input.model,
    max_tokens: input.max_tokens,
    messages: input.messages,
    stream: false,
  }
  if (input.system !== undefined) body.system = input.system
  if (input.temperature !== undefined) body.temperature = input.temperature
  return body
}

export class GatewayClient {
  private readonly apiKey: string
  private readonly baseUrl: string
  private readonly anthropicKey: string | undefined
  private readonly openaiKey: string | undefined
  private readonly fetchImpl: typeof fetch

  constructor(opts: GatewayClientOptions) {
    if (!opts.apiKey) throw new Error('GatewayClient: apiKey is required')
    if (!opts.baseUrl) throw new Error('GatewayClient: baseUrl is required')

    // Reject http:// for non-loopback hosts so a misconfigured
    // DSA_GATEWAY_URL=http://gateway.lucairn.eu cannot ship the
    // x-api-key header in plaintext over the wire (TOB-001).
    let parsed: URL
    try {
      parsed = new URL(opts.baseUrl)
    } catch {
      throw new Error(
        `GatewayClient: baseUrl is not a valid URL: ${opts.baseUrl}`,
      )
    }
    if (parsed.protocol !== 'https:') {
      const host = parsed.hostname.toLowerCase()
      const isLoopback =
        host === 'localhost' || host === '127.0.0.1' || host === '::1'
      if (!isLoopback) {
        throw new Error(
          `lucairn-mcp-server: baseUrl must use https:// for non-loopback hosts; got ${opts.baseUrl}`,
        )
      }
    }

    this.apiKey = opts.apiKey
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.anthropicKey = opts.anthropicKey
    this.openaiKey = opts.openaiKey
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch
    if (!this.fetchImpl) {
      throw new Error(
        'GatewayClient: global fetch is unavailable. Use Node 18.17+ or pass fetchImpl.',
      )
    }
  }

  /**
   * Pick which BYOK key to forward based on the request's `model`
   * field. The Lucairn gateway routes requests to the correct upstream
   * provider based on the same field, so the MCP server forwards the
   * matching provider key as X-Upstream-Key.
   *
   * - claude-* / anthropic-* → Anthropic BYOK
   * - gpt-* / openai-* / o1-* / o3-* / o4-* → OpenAI BYOK
   * - unknown / future-model → prefer Anthropic (matches the existing
   *   /api/v1/mcp/messages Anthropic-shape default), then fall back to
   *   OpenAI if no Anthropic key is configured.
   */
  pickUpstreamKey(model: string): string | undefined {
    const m = model.toLowerCase()
    if (m.startsWith('claude') || m.startsWith('anthropic')) return this.anthropicKey
    if (
      m.startsWith('gpt') ||
      m.startsWith('openai') ||
      m.startsWith('o1') ||
      m.startsWith('o3') ||
      m.startsWith('o4')
    ) {
      return this.openaiKey
    }
    // Unknown / future-model: prefer anthropic (matches the existing
    // /api/v1/mcp/messages Anthropic-shape default).
    return this.anthropicKey ?? this.openaiKey
  }

  /**
   * POST /api/v1/mcp/messages — see gateway mcp_handler.go:55-693.
   *
   * Returns the parsed JSON body on 2xx. On non-2xx, throws a
   * GatewayError carrying the upstream error envelope when present
   * (gateway emits anthropicErrorResponse — see anthropic_errors.go:8-16).
   */
  async sendMessage(input: ChatToolInput): Promise<AnthropicResponseBody> {
    const url = `${this.baseUrl}/api/v1/mcp/messages`
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'x-api-key': this.apiKey,
    }
    const upstreamKey = this.pickUpstreamKey(input.model)
    if (upstreamKey) {
      // Header name verified against mcp_handler.go:226-229.
      headers['X-Upstream-Key'] = upstreamKey
    }

    let res: Response
    try {
      res = await this.fetchImpl(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(buildMessagesRequestBody(input)),
        // 30s ceiling matches the gateway's 25-30s upstream-poll budget
        // (mcp_handler.go:516-524). Beyond that the gateway returns 202
        // ASYNC_PROCESSING; we abort instead of hanging forever.
        signal: AbortSignal.timeout(30_000),
      })
    } catch (err) {
      // AbortSignal.timeout fires a DOMException with name="TimeoutError"
      // (or, in some Node versions, an AbortError). Surface as a clear
      // GatewayError(_, "timeout") rather than a generic network_error.
      const isTimeout =
        (err instanceof Error && err.name === 'TimeoutError') ||
        (err instanceof Error && err.name === 'AbortError') ||
        (typeof err === 'object' &&
          err !== null &&
          'name' in err &&
          ((err as { name: unknown }).name === 'TimeoutError' ||
            (err as { name: unknown }).name === 'AbortError'))
      if (isTimeout) {
        throw new GatewayError(
          `gateway request timed out after 30s reaching ${url}`,
          0,
          'timeout',
        )
      }
      // Network-level failure: TLS error, DNS, connection reset.
      const msg = err instanceof Error ? err.message : String(err)
      throw new GatewayError(
        `network error reaching ${url}: ${msg}`,
        0,
        'network_error',
      )
    }

    const text = await res.text()

    // 202 ASYNC_PROCESSING — gateway timed out polling upstream LLM
    // (proxy_async.go:128-144 / mcp_handler.go:516-524). The body has
    // no Anthropic content[]; surface as a clear retry-shortly error
    // instead of letting formatToolResult crash on undefined content.
    if (res.status === 202) {
      throw new GatewayError(
        'Gateway timed out polling upstream LLM. Retry shortly.',
        202,
        'async_processing',
      )
    }

    if (!res.ok) {
      let upstream: AnthropicErrorBody | undefined
      try {
        const parsed = JSON.parse(text) as AnthropicErrorBody
        if (parsed && parsed.type === 'error' && parsed.error?.type) {
          upstream = parsed
        }
      } catch {
        // Body wasn't JSON. That's acceptable — fall through.
      }
      const errType =
        upstream?.error?.type ?? this.errorTypeForStatus(res.status)
      const detail =
        upstream?.error?.message ??
        text.slice(0, 500) ??
        res.statusText ??
        'gateway returned non-2xx status'
      throw new GatewayError(
        `gateway ${res.status} ${errType}: ${detail}`,
        res.status,
        errType,
        upstream,
      )
    }

    let body: AnthropicResponseBody
    try {
      body = JSON.parse(text) as AnthropicResponseBody
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new GatewayError(
        `gateway returned non-JSON 2xx body: ${msg}`,
        res.status,
        'malformed_response',
      )
    }

    // Runtime shape guard: the downstream formatToolResult assumes
    // body.content is an array (server.ts:127). Reject any 2xx body
    // that doesn't satisfy that contract before it crashes the tool.
    if (!Array.isArray((body as { content?: unknown }).content)) {
      throw new GatewayError(
        'Gateway response missing content array (unexpected shape).',
        res.status,
        'malformed_response',
      )
    }
    return body
  }

  /** Best-effort mapping of HTTP status → MCP-friendly error category. */
  private errorTypeForStatus(status: number): string {
    if (status === 401) return 'authentication_error'
    if (status === 403) return 'permission_error'
    // 422 passthrough_audit contraindication (DSA PR #263 on
    // /api/v1/mcp/messages): a system block carried PII above the refusal
    // threshold, so the gateway refused the passthrough audit.
    if (status === 422) return 'passthrough_audit_contraindicated'
    if (status === 429) return 'rate_limit_error'
    if (status === 503) return 'service_unavailable'
    if (status >= 500) return 'api_error'
    if (status >= 400) return 'invalid_request_error'
    return 'unknown_error'
  }
}
