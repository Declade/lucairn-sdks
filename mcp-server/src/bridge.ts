/**
 * stdio-bridge transport mode (LUCAIRN_TRANSPORT=stdio-bridge).
 *
 * Reads JSON-RPC 2.0 frames from a local MCP client over stdio and
 * forwards each frame as-is to the gateway's streamable-HTTP MCP
 * endpoint:
 *
 *   POST {baseUrl}/mcp
 *
 * Source-of-truth for the gateway endpoint:
 *   dual-sandbox-architecture/services/gateway/internal/api/mcp_streamable.go
 *   (PR #135, merged 2026-05-06).
 *
 * Auth flows over the same `Authorization: Bearer lcr_live_*` header
 * that the gateway accepts via the openaiAuthShim composed in front of
 * MCPStreamableHandler. Per-request BYOK upstream-key selection
 * (X-Upstream-Key) is preserved by inspecting the JSON-RPC frame: when
 * the method is `tools/call` with arguments containing a `model` field,
 * the matching provider key is forwarded — identical routing to
 * direct-http mode (gateway-client.ts pickUpstreamKey).
 *
 * Server-initiated SSE messages from `GET /mcp` are NOT proxied here —
 * the gateway's GET endpoint is a keepalive-only stub in PR 1, and the
 * brief explicitly scopes streaming out of v1.2. Only `POST /mcp`
 * request/response round-trips are bridged.
 *
 * Failure modes:
 *   - Malformed JSON-RPC from stdin → answer with -32700 ParseError if
 *     the frame had a request-shape ID we can echo, else swallow per
 *     JSON-RPC spec for notifications.
 *   - Network/timeout reaching gateway → answer with -32603 InternalError
 *     containing a clear retry hint; the local MCP client surfaces it.
 *   - Gateway returns non-2xx with a JSON-RPC error envelope → forward
 *     verbatim. With a non-JSON-RPC body → wrap as -32603 with status code.
 */
import process from 'node:process'
import type { Readable, Writable } from 'node:stream'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js'

/**
 * Options for {@link runStdioBridge}. Mirrors {@link ServerOptions} on
 * the direct-http path but adds optional stdio overrides for testability.
 */
export interface BridgeOptions {
  /** Lucairn API key (lcr_live_* or legacy veil_live_*). Required. */
  apiKey: string
  /** Gateway base URL — no trailing slash. Required. */
  baseUrl: string
  /** Optional Anthropic BYOK upstream key. */
  anthropicKey?: string
  /** Optional OpenAI BYOK upstream key. */
  openaiKey?: string
  /** Optional fetch override — used by tests. */
  fetchImpl?: typeof fetch
  /** Optional stdin override — used by tests. */
  stdin?: Readable
  /** Optional stdout override — used by tests. */
  stdout?: Writable
  /**
   * Optional shutdown signal — when this AbortSignal aborts the bridge
   * stops reading stdin and resolves the promise returned by
   * runStdioBridge. Used by tests so the harness can cleanly stop the
   * transport without relying on stdin EOF.
   */
  signal?: AbortSignal
}

/** Per-frame fetch timeout. Mirrors gateway-client.ts (30s ceiling). */
export const BRIDGE_FETCH_TIMEOUT_MS = 30_000

/** JSON-RPC 2.0 standard error codes (RFC §5.1). */
const JSON_RPC_PARSE_ERROR = -32700
const JSON_RPC_INVALID_REQUEST = -32600
const JSON_RPC_INTERNAL_ERROR = -32603

/**
 * Look at a JSON-RPC frame and, when it is a `tools/call` request whose
 * arguments name a model, return the matching BYOK key to forward as
 * `X-Upstream-Key`. Behavior matches gateway-client.ts pickUpstreamKey.
 *
 * Exported separately so the test suite can drive it without standing
 * up a full bridge.
 */
export function pickUpstreamKeyForFrame(
  frame: unknown,
  anthropicKey: string | undefined,
  openaiKey: string | undefined,
): string | undefined {
  if (!frame || typeof frame !== 'object') return undefined
  const f = frame as Record<string, unknown>
  if (f.method !== 'tools/call') return undefined
  const params = f.params
  if (!params || typeof params !== 'object') return undefined
  const args = (params as Record<string, unknown>).arguments
  if (!args || typeof args !== 'object') return undefined
  const model = (args as Record<string, unknown>).model
  if (typeof model !== 'string' || model.length === 0) return undefined
  const m = model.toLowerCase()
  if (m.startsWith('claude') || m.startsWith('anthropic')) return anthropicKey
  if (
    m.startsWith('gpt') ||
    m.startsWith('openai') ||
    m.startsWith('o1') ||
    m.startsWith('o3') ||
    m.startsWith('o4')
  ) {
    return openaiKey
  }
  // Unknown / future model — prefer Anthropic, fall back to OpenAI. Same
  // policy as gateway-client.ts.pickUpstreamKey for the direct-http path.
  return anthropicKey ?? openaiKey
}

/**
 * Forward a single JSON-RPC frame to `<baseUrl>/mcp` and return the
 * gateway's parsed JSON response (the JSON-RPC reply envelope). On
 * network or shape failure, returns a synthetic JSON-RPC error envelope
 * carrying the original frame's ID (when present) so the local client
 * can correlate the failure.
 *
 * Notifications (frames lacking an `id` field) are forwarded too — the
 * gateway responds with HTTP 204 / empty body / null and we resolve to
 * undefined so the caller skips writing a stdout reply.
 */
export async function forwardFrame(opts: {
  frame: JSONRPCMessage
  apiKey: string
  baseUrl: string
  anthropicKey?: string
  openaiKey?: string
  fetchImpl: typeof fetch
}): Promise<JSONRPCMessage | JSONRPCMessage[] | undefined> {
  const url = `${opts.baseUrl}/mcp`
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
    // Use the canonical MCP transport auth header (Bearer). The gateway
    // also accepts x-api-key via openaiAuthShim, but Bearer is the
    // streamable-HTTP-spec default and the value the gateway logs as
    // "client uses spec-canonical auth".
    authorization: `Bearer ${opts.apiKey}`,
  }
  const upstreamKey = pickUpstreamKeyForFrame(
    opts.frame,
    opts.anthropicKey,
    opts.openaiKey,
  )
  if (upstreamKey) {
    headers['X-Upstream-Key'] = upstreamKey
  }
  const frameId = (opts.frame as { id?: unknown }).id

  let res: Response
  try {
    res = await opts.fetchImpl(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(opts.frame),
      signal: AbortSignal.timeout(BRIDGE_FETCH_TIMEOUT_MS),
    })
  } catch (err) {
    const name =
      err instanceof Error
        ? err.name
        : typeof err === 'object' && err !== null && 'name' in err
          ? String((err as { name: unknown }).name)
          : ''
    const isTimeout = name === 'TimeoutError' || name === 'AbortError'
    const detail =
      err instanceof Error ? err.message : 'unknown network error'
    return errorEnvelope(
      frameId,
      JSON_RPC_INTERNAL_ERROR,
      isTimeout
        ? `gateway request timed out after ${BRIDGE_FETCH_TIMEOUT_MS / 1000}s`
        : `network error reaching ${url}: ${detail}`,
    )
  }

  // 204 No Content — the gateway acknowledges a notification with no
  // body. JSON-RPC notifications never get a response written to stdout.
  if (res.status === 204) return undefined

  const text = await res.text()
  // Empty body on 200/202 also means "ack only" — happens when the
  // forwarded frame was a notification.
  if (text === '' || text === 'null') return undefined

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    return errorEnvelope(
      frameId,
      JSON_RPC_INTERNAL_ERROR,
      `gateway returned non-JSON body (status ${res.status}): ${detail}`,
    )
  }

  // Gateway returned a JSON-RPC envelope (single or batch). Forward verbatim.
  if (looksLikeJSONRPCEnvelope(parsed)) {
    return parsed as JSONRPCMessage | JSONRPCMessage[]
  }

  // Non-JSON-RPC body on a non-2xx status: wrap as JSON-RPC internal-error
  // so the local MCP client can surface the failure as a tool error
  // rather than a transport hang.
  if (!res.ok) {
    const snippet = text.slice(0, 500)
    return errorEnvelope(
      frameId,
      JSON_RPC_INTERNAL_ERROR,
      `gateway ${res.status} ${res.statusText || 'error'}: ${snippet}`,
    )
  }

  // 2xx with an unknown body shape. Treat as malformed.
  return errorEnvelope(
    frameId,
    JSON_RPC_INTERNAL_ERROR,
    'gateway returned 2xx with unrecognized body shape',
  )
}

/** Construct a JSON-RPC error envelope echoing the original frame's id. */
function errorEnvelope(
  id: unknown,
  code: number,
  message: string,
): JSONRPCMessage {
  return {
    jsonrpc: '2.0',
    // JSON-RPC §5: when the request id can't be detected, must be null.
    id: id ?? null,
    error: { code, message },
  } as unknown as JSONRPCMessage
}

/** Loose runtime check for a JSON-RPC envelope or batch. */
function looksLikeJSONRPCEnvelope(value: unknown): boolean {
  if (Array.isArray(value)) {
    // Reject empty arrays — JSON-RPC §6 says batches must contain at
    // least one element. An empty `[]` more likely indicates a stripped
    // body than a valid batch reply.
    if (value.length === 0) return false
    return value.every(looksLikeJSONRPCEnvelope)
  }
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return v.jsonrpc === '2.0'
}

/**
 * Boot the stdio-bridge transport. Reads framed JSON-RPC messages from
 * stdin, forwards each to the gateway's `/mcp` endpoint, writes the
 * gateway's reply back to stdout. Resolves when stdin EOFs (the local
 * MCP client closed the pipe) or when the optional shutdown signal aborts.
 */
export async function runStdioBridge(opts: BridgeOptions): Promise<void> {
  if (!opts.apiKey) throw new Error('runStdioBridge: apiKey is required')
  if (!opts.baseUrl) throw new Error('runStdioBridge: baseUrl is required')

  // Reject http:// for non-loopback hosts — same plaintext-credential
  // guard the GatewayClient enforces (TOB-001). The bridge ships the
  // Authorization header, which carries the same lcr_live_* secret.
  let parsed: URL
  try {
    parsed = new URL(opts.baseUrl)
  } catch {
    throw new Error(
      `runStdioBridge: baseUrl is not a valid URL: ${opts.baseUrl}`,
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

  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  if (!fetchImpl) {
    throw new Error(
      'runStdioBridge: global fetch is unavailable. Use Node 18.17+ or pass fetchImpl.',
    )
  }
  const baseUrl = opts.baseUrl.replace(/\/+$/, '')
  const stdin = opts.stdin ?? process.stdin
  const stdout = opts.stdout ?? process.stdout

  const transport = new StdioServerTransport(stdin, stdout)

  // Resolve the returned promise once stdin EOFs OR the abort signal
  // fires. The MCP SDK's StdioServerTransport listens for 'data' /
  // 'error' on stdin but does NOT fire onclose on stdin EOF — we must
  // observe 'end' / 'close' ourselves below to avoid hanging forever
  // after the local MCP client closes the pipe.
  return new Promise<void>((resolve, reject) => {
    let settled = false
    const settle = (err?: Error): void => {
      if (settled) return
      settled = true
      // Best-effort transport close. Errors here are logged via onerror
      // already; nothing else to do.
      transport.close().catch(() => {
        /* swallow */
      })
      if (err) reject(err)
      else resolve()
    }

    transport.onmessage = (frame: JSONRPCMessage): void => {
      // Fire-and-forget: each frame round-trips independently. JSON-RPC
      // does not require strict in-order responses, and fire-and-forget
      // lets a slow tools/call not block a fast tools/list.
      void (async (): Promise<void> => {
        try {
          const reply = await forwardFrame({
            frame,
            apiKey: opts.apiKey,
            baseUrl,
            anthropicKey: opts.anthropicKey,
            openaiKey: opts.openaiKey,
            fetchImpl,
          })
          if (reply === undefined) return
          if (Array.isArray(reply)) {
            for (const m of reply) await transport.send(m)
          } else {
            await transport.send(reply)
          }
        } catch (err) {
          // Any unexpected failure inside forwardFrame is already wrapped
          // in a JSON-RPC error envelope. If we end up here, something
          // truly internal blew up — log to stderr and continue serving.
          const detail = err instanceof Error ? err.message : String(err)
          process.stderr.write(
            `lucairn-mcp-server: bridge frame failed: ${detail}\n`,
          )
        }
      })()
    }

    transport.onclose = (): void => {
      settle()
    }
    transport.onerror = (err): void => {
      // Frame-level errors from the SDK's stdio ReadBuffer come in two
      // flavours (see @modelcontextprotocol/sdk shared/stdio.ts):
      //
      //   1. JSON.parse() failed on the line → SyntaxError → -32700 Parse error.
      //   2. JSONRPCMessageSchema.parse() (Zod) rejected the parsed object
      //      because the frame shape isn't a valid JSON-RPC envelope (e.g.
      //      `{"foo":"bar"}\n`) → ZodError or similar non-SyntaxError →
      //      -32600 Invalid Request.
      //
      // In either case the bridge MUST stay alive: a single bad frame
      // from a buggy MCP client must not tear down the transport. We
      // don't have an id to echo, so emit id:null per JSON-RPC §5.
      const code =
        err instanceof SyntaxError
          ? JSON_RPC_PARSE_ERROR
          : JSON_RPC_INVALID_REQUEST
      const message =
        err instanceof SyntaxError ? 'Parse error' : 'Invalid Request'
      void transport
        .send(errorEnvelope(null, code, message) as JSONRPCMessage)
        .catch(() => {
          /* swallow — best-effort, never tear down the bridge */
        })
    }

    if (opts.signal) {
      if (opts.signal.aborted) {
        settle()
        return
      }
      opts.signal.addEventListener('abort', () => settle(), { once: true })
    }

    // The SDK's StdioServerTransport listens for 'data' / 'error' on
    // stdin but does NOT subscribe to 'end' or 'close' — so we must
    // observe stdin EOF ourselves and trigger a clean shutdown when the
    // local MCP client closes the pipe. Without this, runStdioBridge
    // would block forever after the last frame.
    const onStdinEnd = (): void => {
      // Give any in-flight fetches a couple of microtasks to write their
      // replies to stdout before we close the transport. setImmediate is
      // good enough — fetch promises resolve as microtasks, transport
      // .send writes synchronously.
      setImmediate(() => settle())
    }
    stdin.once('end', onStdinEnd)
    stdin.once('close', onStdinEnd)

    transport.start().catch((err) => {
      settle(err instanceof Error ? err : new Error(String(err)))
    })
  })
}
