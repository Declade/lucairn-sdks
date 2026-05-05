/**
 * Lucairn MCP server — stdio transport.
 *
 * Exposes one MCP tool, `chat_via_lucairn`, which forwards Anthropic
 * Messages API requests to the Lucairn gateway at:
 *   POST {baseUrl}/api/v1/mcp/messages
 * (see dual-sandbox-architecture/services/gateway/internal/api/mcp_handler.go:23-30
 *  and the route registration at handler.go:242).
 *
 * The gateway runs sanitization (Presidio + QI) on the user content
 * and applies a per-key MCP system policy (sanitize | passthrough_audit)
 * to the system prompt before forwarding to the upstream LLM. Output
 * re-linkage (swapping placeholders back to the original PII before
 * return) is gated by the customer profile's `relink_response` flag —
 * Developer (free) tier defaults to `false` (placeholders visible to
 * the caller); Pro and Enterprise tiers default to `true`. See
 * `dual-sandbox-architecture/services/gateway/internal/auth/apikey.go:54`.
 *
 * The server intentionally exposes only one tool: the gateway exposes
 * one Anthropic-Messages-compatible HTTP endpoint, not a JSON-RPC MCP
 * tool/resource catalog. Tool catalogs (listTools) are static here.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { GatewayClient } from './gateway-client.js'
import type { AnthropicResponseBody, ChatToolInput } from './types.js'
import { GatewayError } from './types.js'

export interface ServerOptions {
  apiKey: string
  baseUrl: string
  /** Optional Anthropic BYOK key — forwarded as X-Upstream-Key for Claude/Anthropic models. */
  anthropicKey?: string
  /** Optional OpenAI BYOK key — forwarded as X-Upstream-Key for GPT/o1/o3/o4 models. */
  openaiKey?: string
  /** Optional fetch override — used by tests. */
  fetchImpl?: typeof fetch
}

/** Tool name exposed to MCP clients. */
export const CHAT_TOOL_NAME = 'chat_via_lucairn'

/**
 * Soft input cap for chat_via_lucairn arguments (TOB-005). Bounds the
 * local-memory JSON.stringify cost before any network shipping. The
 * gateway has its own per-key limits; this is purely a client-side
 * safety net against a buggy or malicious MCP client.
 */
export const MAX_INPUT_BYTES = 1 * 1024 * 1024

/**
 * Returns true when the JSON-stringified args exceed MAX_INPUT_BYTES.
 * Exported separately from the request-handler closure so unit tests
 * can drive the cap check without spinning up an MCP transport.
 */
export function exceedsInputCap(args: unknown): boolean {
  return JSON.stringify(args ?? {}).length > MAX_INPUT_BYTES
}

/** Static MCP tool descriptor for chat_via_lucairn. */
export const CHAT_TOOL_DESCRIPTOR = {
  name: CHAT_TOOL_NAME,
  description:
    'Send an Anthropic Messages API request through the Lucairn ' +
    'privacy gateway. PII is detected and replaced with placeholders ' +
    'before reaching the upstream LLM. Developer-tier responses ' +
    'contain those placeholders; Pro and Enterprise tiers can enable ' +
    'automatic re-linking back to the original values.',
  inputSchema: {
    type: 'object',
    properties: {
      model: {
        type: 'string',
        description:
          'Model identifier — `claude-sonnet-4-6` (Anthropic), ' +
          '`gpt-4o-mini` (OpenAI), or any model the Lucairn gateway ' +
          'routes upstream. Set ANTHROPIC_API_KEY and/or OPENAI_API_KEY ' +
          'in your MCP client env to bring your own provider key (BYOK); ' +
          'free/Pro tier supports BYOK on either provider.',
      },
      max_tokens: {
        type: 'number',
        description:
          'Maximum tokens to generate in the response. Required by ' +
          'the Anthropic Messages API.',
      },
      messages: {
        type: 'array',
        description:
          'Conversation messages. Each item is { role: "user" | "assistant", content: string | array }.',
        items: {
          type: 'object',
          properties: {
            role: { type: 'string', enum: ['user', 'assistant'] },
            content: {},
          },
          required: ['role', 'content'],
        },
      },
      system: {
        description:
          'Optional system prompt. May be a string or an array of ' +
          'content blocks. Sanitization policy is per-API-key on the ' +
          'gateway side (sanitize or passthrough_audit).',
      },
      temperature: {
        type: 'number',
        description: 'Optional sampling temperature (0..1).',
      },
    },
    required: ['model', 'max_tokens', 'messages'],
  },
} as const

/**
 * Validate and narrow the raw arguments object received from the MCP
 * client into a ChatToolInput. Throws on missing required fields with
 * MCP-friendly error text.
 */
export function parseChatToolArgs(raw: unknown): ChatToolInput {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Tool arguments must be an object.')
  }
  const args = raw as Record<string, unknown>
  if (typeof args.model !== 'string' || args.model.length === 0) {
    throw new Error('Tool argument `model` is required and must be a string.')
  }
  if (typeof args.max_tokens !== 'number' || args.max_tokens <= 0) {
    throw new Error(
      'Tool argument `max_tokens` is required and must be a positive number.',
    )
  }
  if (!Array.isArray(args.messages) || args.messages.length === 0) {
    throw new Error(
      'Tool argument `messages` is required and must be a non-empty array.',
    )
  }
  // Pass through; deeper validation lives on the gateway side
  // (anthropicRequest unmarshal + validate at mcp_handler.go:84-99).
  return args as unknown as ChatToolInput
}

/**
 * Format the gateway's Anthropic response into the MCP CallToolResult
 * shape. We collapse content blocks to text and surface the privacy
 * compliance metadata as a hint to the calling agent.
 */
export function formatToolResult(resp: AnthropicResponseBody): {
  content: Array<{ type: 'text'; text: string }>
} {
  const text = resp.content
    .filter((b) => b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text)
    .join('')

  const compliance = resp.metadata?.dsa_compliance
  const trailer =
    compliance && compliance.veil_summary_url
      ? `\n\n_Lucairn certificate: ${compliance.veil_summary_url}_`
      : ''

  return {
    content: [{ type: 'text', text: text + trailer }],
  }
}

/**
 * Map a GatewayError to an MCP CallToolResult with isError: true.
 * Honors MCP's contract that tools surface domain errors via the
 * result rather than throwing — see CallToolResultSchema in
 * @modelcontextprotocol/sdk/types.js.
 */
function gatewayErrorToToolResult(err: GatewayError): {
  isError: true
  content: Array<{ type: 'text'; text: string }>
} {
  const lines: string[] = []
  lines.push(`Lucairn gateway error (${err.status} ${err.errorType}).`)
  if (err.upstream?.error?.message) {
    lines.push(err.upstream.error.message)
  } else if (err.message) {
    lines.push(err.message)
  }
  if (err.status === 401) {
    lines.push('Check your DSA_API_KEY value.')
  } else if (err.status === 403) {
    lines.push('License or permission denied. See https://lucairn.eu/account.')
  } else if (err.status === 429) {
    lines.push('Rate or quota limit exceeded.')
  } else if (err.status >= 500) {
    lines.push('Gateway is unavailable. Retry shortly.')
  }
  return {
    isError: true,
    content: [{ type: 'text', text: lines.join(' ') }],
  }
}

/**
 * Build a configured MCP Server instance with the chat_via_lucairn
 * tool wired to the supplied GatewayClient. Exported separately from
 * startStdioServer so tests can drive it without binding stdio.
 */
export function buildServer(client: GatewayClient): Server {
  const server = new Server(
    { name: 'lucairn-mcp-server', version: '1.1.0' },
    { capabilities: { tools: {} } },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: [CHAT_TOOL_DESCRIPTOR] }
  })

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params
    if (name !== CHAT_TOOL_NAME) {
      return {
        isError: true,
        content: [
          { type: 'text', text: `Unknown tool: ${name}` },
        ],
      }
    }
    // Soft input cap (TOB-005): a malicious or buggy MCP client could
    // hand a 100MB messages[] and we'd JSON.stringify it before any
    // network shipping. Bound local memory at 1 MiB and surface a
    // structured tool error instead of crashing the process.
    if (exceedsInputCap(args)) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `Tool input exceeds max size (${MAX_INPUT_BYTES} bytes). Reduce messages[] or system prompt size.`,
          },
        ],
      }
    }
    let parsed: ChatToolInput
    try {
      parsed = parseChatToolArgs(args)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return {
        isError: true,
        content: [{ type: 'text', text: msg }],
      }
    }
    try {
      const resp = await client.sendMessage(parsed)
      return formatToolResult(resp)
    } catch (err) {
      if (err instanceof GatewayError) {
        return gatewayErrorToToolResult(err)
      }
      const msg = err instanceof Error ? err.message : String(err)
      return {
        isError: true,
        content: [{ type: 'text', text: `Internal error: ${msg}` }],
      }
    }
  })

  return server
}

/**
 * Boot the MCP server over stdio. Called by the bin entry (index.ts).
 */
export async function startStdioServer(opts: ServerOptions): Promise<void> {
  const client = new GatewayClient({
    apiKey: opts.apiKey,
    baseUrl: opts.baseUrl,
    anthropicKey: opts.anthropicKey,
    openaiKey: opts.openaiKey,
    fetchImpl: opts.fetchImpl,
  })
  const server = buildServer(client)
  const transport = new StdioServerTransport()
  await server.connect(transport)
}
