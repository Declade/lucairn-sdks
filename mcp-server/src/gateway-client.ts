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
  /** Optional Anthropic-compatible BYOK key forwarded as X-Upstream-Key. */
  upstreamKey?: string
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
  private readonly upstreamKey: string | undefined
  private readonly fetchImpl: typeof fetch

  constructor(opts: GatewayClientOptions) {
    if (!opts.apiKey) throw new Error('GatewayClient: apiKey is required')
    if (!opts.baseUrl) throw new Error('GatewayClient: baseUrl is required')
    this.apiKey = opts.apiKey
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.upstreamKey = opts.upstreamKey
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch
    if (!this.fetchImpl) {
      throw new Error(
        'GatewayClient: global fetch is unavailable. Use Node 18.17+ or pass fetchImpl.',
      )
    }
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
    if (this.upstreamKey) {
      // Header name verified against mcp_handler.go:226-229.
      headers['X-Upstream-Key'] = this.upstreamKey
    }

    let res: Response
    try {
      res = await this.fetchImpl(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(buildMessagesRequestBody(input)),
      })
    } catch (err) {
      // Network-level failure: TLS error, DNS, connection reset.
      const msg = err instanceof Error ? err.message : String(err)
      throw new GatewayError(
        `network error reaching ${url}: ${msg}`,
        0,
        'network_error',
      )
    }

    const text = await res.text()

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
    return body
  }

  /** Best-effort mapping of HTTP status → MCP-friendly error category. */
  private errorTypeForStatus(status: number): string {
    if (status === 401) return 'authentication_error'
    if (status === 403) return 'permission_error'
    if (status === 429) return 'rate_limit_error'
    if (status === 503) return 'service_unavailable'
    if (status >= 500) return 'api_error'
    if (status >= 400) return 'invalid_request_error'
    return 'unknown_error'
  }
}
