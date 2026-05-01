/**
 * Anthropic Messages API request and response types as accepted and
 * returned by the Lucairn gateway at POST /api/v1/mcp/messages.
 *
 * Source of truth: `dual-sandbox-architecture/services/gateway/internal/api/`
 *   - request struct  → anthropic_types.go anthropicRequest (gateway file:line ref:
 *     anthropic_types.go around the anthropicRequest definition)
 *   - response struct → anthropic_types.go:292-302 anthropicResponse
 *   - error struct    → anthropic_errors.go:8-16  anthropicErrorResponse
 *
 * Only the subset we accept and forward is typed here. Extra fields on
 * the request are passed through verbatim — drift detection lives on
 * the gateway side via TestMCPPayloadSchemaMatchesLiveRequest in
 * mcp_payload_schema_test.go.
 */

/** A single content block in an Anthropic Messages API message. */
export type AnthropicMessageContent =
  | string
  | Array<{
      type: string
      text?: string
      [k: string]: unknown
    }>

/** A single message in the conversation array. */
export interface AnthropicMessage {
  role: 'user' | 'assistant'
  content: AnthropicMessageContent
}

/** Inputs accepted by the chat_via_lucairn MCP tool. */
export interface ChatToolInput {
  /** Required. Anthropic model identifier (e.g. "claude-sonnet-4-6"). */
  model: string
  /** Required. Maximum tokens to generate in the response. */
  max_tokens: number
  /** Required. Conversation messages array. */
  messages: AnthropicMessage[]
  /** Optional. System prompt — may be a string or an array of content blocks. */
  system?: string | Array<{ type: string; text: string; [k: string]: unknown }>
  /** Optional. Sampling temperature (0..1). */
  temperature?: number
}

/** Anthropic API response shape returned by the gateway (subset). */
export interface AnthropicResponseBody {
  id: string
  type: 'message'
  role: 'assistant'
  content: Array<{ type: string; text: string }>
  model: string
  stop_reason: string
  usage: { input_tokens: number; output_tokens: number }
  metadata?: {
    dsa_compliance?: {
      request_id: string
      veil_certificate_url?: string
      veil_summary_url?: string
      pii_in_ai?: boolean
      identity_in_ai?: boolean
      sanitizer_layers?: string[]
      redaction_count: number
      latency_ms: number
    }
  }
}

/** Anthropic-shape error envelope returned by the gateway on non-2xx. */
export interface AnthropicErrorBody {
  type: 'error'
  error: {
    type: string
    message: string
  }
}

/**
 * Thrown by GatewayClient when the gateway returns a non-2xx response
 * or when a network error occurs. Carries the upstream HTTP status and
 * the gateway's error envelope (if it could be parsed).
 */
export class GatewayError extends Error {
  readonly status: number
  readonly errorType: string
  readonly upstream?: AnthropicErrorBody
  constructor(message: string, status: number, errorType: string, upstream?: AnthropicErrorBody) {
    super(message)
    this.name = 'GatewayError'
    this.status = status
    this.errorType = errorType
    this.upstream = upstream
  }
}
