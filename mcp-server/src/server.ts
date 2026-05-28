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
import { createRequire } from 'node:module'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { GatewayClient } from './gateway-client.js'
import type { AnthropicResponseBody, ChatToolInput } from './types.js'
import { GatewayError } from './types.js'

/**
 * Resolve the package version at runtime from package.json so the MCP
 * server advertisement stays in lockstep with the published manifest.
 *
 * We use `createRequire` rather than an ESM `import ... with { type:
 * 'json' }` attribute because import attributes still need a flag on
 * some Node 18.x runtimes the package supports (`engines.node >=18.17`).
 * `createRequire` is stable on Node 18+ ESM and adds no tsconfig
 * surface area.
 *
 * Falls back to the string `'unknown'` if package.json can't be loaded
 * (e.g. an exotic bundler that strips the file). Failing soft avoids a
 * regression where a malformed package layout takes down the MCP
 * handshake; the worst case is a one-line cosmetic regression in the
 * version surfaced over MCP, not a process crash.
 */
const require = createRequire(import.meta.url)
let pkgVersion: string
try {
  const pkg = require('../package.json') as { version?: unknown }
  pkgVersion =
    typeof pkg.version === 'string' && pkg.version.length > 0
      ? pkg.version
      : 'unknown'
} catch {
  pkgVersion = 'unknown'
}
/** Version string advertised on the MCP server handshake. Sourced from package.json at import time. */
export const SERVER_VERSION: string = pkgVersion

/**
 * Supported values of LUCAIRN_TRANSPORT.
 *
 * - `direct-http` (default, v1.1 behavior): the npm package owns the
 *   MCP tool catalog locally and forwards each tool call to the
 *   gateway's Anthropic-Messages-shape endpoint
 *   (POST /api/v1/mcp/messages). Lowest latency, no extra round-trips.
 * - `stdio-bridge` (opt-in, v1.2): the npm package degenerates into a
 *   thin transport bridge — stdio frames in, HTTP frames to the
 *   gateway's streamable-HTTP MCP endpoint (POST /mcp), HTTP responses
 *   back out as stdio frames. Tool catalog comes from the gateway, so
 *   future tools and tier-aware descriptors land without a re-publish.
 *
 * A value other than these two causes a non-zero exit at startup with
 * a clear error — see index.ts.
 */
export const TRANSPORT_DIRECT_HTTP = 'direct-http'
export const TRANSPORT_STDIO_BRIDGE = 'stdio-bridge'
export type LucairnTransport =
  | typeof TRANSPORT_DIRECT_HTTP
  | typeof TRANSPORT_STDIO_BRIDGE
export const SUPPORTED_TRANSPORTS: readonly LucairnTransport[] = [
  TRANSPORT_DIRECT_HTTP,
  TRANSPORT_STDIO_BRIDGE,
] as const

/**
 * Validate a raw `LUCAIRN_TRANSPORT` value. Returns the narrowed mode on
 * success. Returns null on an empty/undefined input — the caller treats
 * that as "unset, use the default". Throws on any other invalid value.
 */
export function parseTransport(raw: string | undefined | null): LucairnTransport | null {
  if (raw === undefined || raw === null || raw === '') return null
  if ((SUPPORTED_TRANSPORTS as readonly string[]).includes(raw)) {
    return raw as LucairnTransport
  }
  throw new Error(
    `LUCAIRN_TRANSPORT must be one of ${SUPPORTED_TRANSPORTS.join(', ')}; got "${raw}"`,
  )
}

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
    'Send a chat request through the Lucairn privacy gateway with ' +
    'cross-provider BYOK (Anthropic + OpenAI). PII is detected and ' +
    'replaced with placeholders before reaching the upstream LLM. ' +
    'The gateway picks the upstream provider based on the `model` ' +
    'parameter: `claude-*` / `anthropic-*` use ANTHROPIC_API_KEY; ' +
    '`gpt-*` / `openai-*` / `o1-*` / `o3-*` / `o4-*` use OPENAI_API_KEY. ' +
    'Wire format follows the Anthropic Messages API. Developer-tier ' +
    'responses contain raw placeholders; Pro and Enterprise tiers can ' +
    'enable automatic re-linking back to the original values.',
  inputSchema: {
    type: 'object',
    properties: {
      model: {
        type: 'string',
        description:
          'Model identifier. Routing rules: `claude-*` and ' +
          '`anthropic-*` route to Anthropic via ANTHROPIC_API_KEY; ' +
          '`gpt-*`, `openai-*`, `o1-*`, `o3-*`, and `o4-*` route to ' +
          'OpenAI via OPENAI_API_KEY. Examples: `claude-sonnet-4-6`, ' +
          '`gpt-4o-mini`, `o3-mini`. Set one or both of ' +
          'ANTHROPIC_API_KEY and OPENAI_API_KEY in your MCP client env ' +
          'for BYOK; matching is case-insensitive.',
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
  annotations: {
    title: 'Chat via Lucairn',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
  outputSchema: {
    type: 'object',
    properties: {
      text: {
        type: 'string',
        description:
          'Concatenated text from all assistant content blocks, plus an ' +
          'optional trailing line referencing the Lucairn compliance ' +
          'certificate URL when present in gateway metadata.',
      },
      model: {
        type: 'string',
        description: 'The upstream model that produced the response.',
      },
      stop_reason: {
        type: 'string',
        description:
          'Anthropic-Messages-API stop reason (end_turn, max_tokens, ' +
          'stop_sequence, tool_use).',
      },
      usage: {
        type: 'object',
        properties: {
          input_tokens: { type: 'number' },
          output_tokens: { type: 'number' },
        },
        required: ['input_tokens', 'output_tokens'],
      },
      compliance: {
        type: 'object',
        description:
          'Lucairn privacy-compliance metadata. Present when the gateway ' +
          'attached a dsa_compliance block (always for v1 of the proxy).',
        properties: {
          request_id: { type: 'string' },
          veil_certificate_url: { type: 'string' },
          veil_summary_url: { type: 'string' },
          pii_in_ai: { type: 'boolean' },
          identity_in_ai: { type: 'boolean' },
          sanitizer_layers: {
            type: 'array',
            items: { type: 'string' },
          },
          redaction_count: { type: 'number' },
          latency_ms: { type: 'number' },
        },
        required: ['request_id', 'redaction_count', 'latency_ms'],
      },
    },
    required: ['text', 'model', 'stop_reason', 'usage'],
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
  structuredContent: {
    text: string
    model: string
    stop_reason: string
    usage: { input_tokens: number; output_tokens: number }
    compliance?: NonNullable<NonNullable<AnthropicResponseBody['metadata']>['dsa_compliance']>
  }
} {
  const text = resp.content
    .filter((b) => b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text)
    .join('')

  const compliance = resp.metadata?.dsa_compliance
    ? publicComplianceMetadata(resp.metadata.dsa_compliance)
    : undefined
  const certificateUrl = compliance?.veil_summary_url
    ? compliance.veil_summary_url
    : undefined
  const trailer =
    certificateUrl
      ? `\n\n_Lucairn certificate: ${certificateUrl}_`
      : ''

  return {
    content: [{ type: 'text', text: text + trailer }],
    structuredContent: {
      text: text + trailer,
      model: resp.model,
      stop_reason: resp.stop_reason,
      usage: resp.usage,
      ...(compliance ? { compliance } : {}),
    },
  }
}

function publicComplianceMetadata(
  compliance: NonNullable<NonNullable<AnthropicResponseBody['metadata']>['dsa_compliance']>,
): NonNullable<NonNullable<AnthropicResponseBody['metadata']>['dsa_compliance']> {
  return {
    ...compliance,
    ...(compliance.veil_summary_url
      ? { veil_summary_url: publicCertificateUrl(compliance.veil_summary_url) }
      : {}),
    ...(compliance.veil_certificate_url
      ? { veil_certificate_url: publicCertificateUrl(compliance.veil_certificate_url) }
      : {}),
  }
}

function publicCertificateUrl(url: string): string {
  try {
    const parsed = new URL(url)
    if (parsed.pathname.endsWith('/summary')) {
      parsed.pathname = parsed.pathname.replace(/\/summary$/, '/public-summary')
      return parsed.toString()
    }
  } catch {
    return url.replace(/\/summary$/, '/public-summary')
  }
  return url
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
    lines.push('Check your LUCAIRN_API_KEY value.')
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
    { name: 'lucairn-mcp-server', version: SERVER_VERSION },
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
