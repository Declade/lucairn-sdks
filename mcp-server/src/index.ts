#!/usr/bin/env node
/**
 * @lucairn/mcp-server bin entry.
 *
 * Started by Claude Desktop (or any MCP client) via:
 *   "command": "npx", "args": ["-y", "@lucairn/mcp-server"]
 *
 * Reads the API key + base URL + optional transport mode from the
 * environment, then hands off to one of two transport paths:
 *
 *   - LUCAIRN_TRANSPORT=direct-http (default, v1.1 behavior):
 *     run a local MCP server that exposes the chat_via_lucairn tool and
 *     forwards each call to POST {baseUrl}/api/v1/mcp/messages.
 *
 *   - LUCAIRN_TRANSPORT=stdio-bridge (opt-in, v1.2):
 *     proxy stdio JSON-RPC frames straight to the gateway's
 *     streamable-HTTP MCP endpoint at POST {baseUrl}/mcp.
 *
 * LUCAIRN_* env-var prefixes are the canonical names; the retired DSA_*
 * prefixes remain accepted as a SILENT fallback for the migration path
 * documented at https://lucairn.eu/developer/mcp.
 */
import { runStdioBridge } from './bridge.js'
import {
  parseTransport,
  startStdioServer,
  SUPPORTED_TRANSPORTS,
  TRANSPORT_DIRECT_HTTP,
  TRANSPORT_STDIO_BRIDGE,
} from './server.js'

// LUCAIRN_* first (canonical brand), DSA_* as a SILENT legacy fallback.
// `||` (not `??`) so that an explicitly-set empty string falls through to
// the next candidate. With `??`, LUCAIRN_API_KEY="" would mask a
// DSA_API_KEY="lcr_live_..." and the server would die with a confusing
// "missing key" error.
const apiKey = process.env.LUCAIRN_API_KEY || process.env.DSA_API_KEY
const baseUrl =
  process.env.LUCAIRN_BASE_URL ||
  process.env.DSA_GATEWAY_URL ||
  'https://gateway.lucairn.eu'
const anthropicKey = process.env.ANTHROPIC_API_KEY || undefined
const openaiKey = process.env.OPENAI_API_KEY || undefined

let transport
try {
  transport = parseTransport(process.env.LUCAIRN_TRANSPORT) ?? TRANSPORT_DIRECT_HTTP
} catch (err) {
  const detail = err instanceof Error ? err.message : String(err)
  // eslint-disable-next-line no-console
  console.error(
    `Error: ${detail}.\n` +
      `Supported values: ${SUPPORTED_TRANSPORTS.join(', ')}.\n` +
      'See https://lucairn.eu/developer/mcp for details.',
  )
  process.exit(1)
}

if (!apiKey) {
  // eslint-disable-next-line no-console
  console.error(
    'Error: LUCAIRN_API_KEY environment variable is required.\n' +
      'Get a key at https://lucairn.eu/account/signup and add it to your\n' +
      'claude_desktop_config.json under mcpServers.lucairn.env.',
  )
  process.exit(1)
}

if (!anthropicKey && !openaiKey) {
  // eslint-disable-next-line no-console
  console.error(
    'Warning: neither ANTHROPIC_API_KEY nor OPENAI_API_KEY is set. ' +
      'You can still call the gateway with a Lucairn-managed upstream pool ' +
      '(Pro/Enterprise tiers), but Developer tier requires BYOK. ' +
      'Set one or both of these vars in your client config to use BYOK.',
  )
}

const onFatal = (err: unknown): void => {
  // eslint-disable-next-line no-console
  console.error('lucairn-mcp-server failed:', err)
  process.exit(1)
}

if (transport === TRANSPORT_STDIO_BRIDGE) {
  runStdioBridge({ apiKey, baseUrl, anthropicKey, openaiKey }).catch(onFatal)
} else {
  // transport === TRANSPORT_DIRECT_HTTP — v1.1 behavior, bit-identical.
  startStdioServer({ apiKey, baseUrl, anthropicKey, openaiKey }).catch(onFatal)
}
