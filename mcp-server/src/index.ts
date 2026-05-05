#!/usr/bin/env node
/**
 * @lucairn/mcp-server bin entry.
 *
 * Started by Claude Desktop (or any MCP client) via:
 *   "command": "npx", "args": ["-y", "@lucairn/mcp-server"]
 *
 * Reads the API key + base URL from the environment, then hands off
 * to startStdioServer which speaks the MCP wire protocol over
 * stdin/stdout and forwards tool calls to the Lucairn gateway.
 *
 * Both DSA_* (legacy) and LUCAIRN_* (new) env-var prefixes are
 * accepted, matching the migration path documented at
 * https://lucairn.eu/developer/mcp.
 */
import { startStdioServer } from './server.js'

// `||` (not `??`) so that an explicitly-set empty string falls through
// to the next candidate. With `??`, DSA_API_KEY="" would mask a
// LUCAIRN_API_KEY="lcr_live_..." and the server would die with a
// confusing "missing key" error.
const apiKey = process.env.DSA_API_KEY || process.env.LUCAIRN_API_KEY
const baseUrl =
  process.env.DSA_GATEWAY_URL ||
  process.env.LUCAIRN_BASE_URL ||
  'https://gateway.lucairn.eu'
const anthropicKey = process.env.ANTHROPIC_API_KEY || undefined
const openaiKey = process.env.OPENAI_API_KEY || undefined

if (!apiKey) {
  // eslint-disable-next-line no-console
  console.error(
    'Error: DSA_API_KEY (or LUCAIRN_API_KEY) environment variable is required.\n' +
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

startStdioServer({ apiKey, baseUrl, anthropicKey, openaiKey }).catch((err) => {
  // eslint-disable-next-line no-console
  console.error('lucairn-mcp-server failed:', err)
  process.exit(1)
})
