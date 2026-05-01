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

const apiKey = process.env.DSA_API_KEY ?? process.env.LUCAIRN_API_KEY
const baseUrl =
  process.env.DSA_GATEWAY_URL ??
  process.env.LUCAIRN_BASE_URL ??
  'https://gateway.lucairn.eu'
const upstreamKey = process.env.ANTHROPIC_API_KEY ?? undefined

if (!apiKey) {
  // eslint-disable-next-line no-console
  console.error(
    'Error: DSA_API_KEY (or LUCAIRN_API_KEY) environment variable is required.\n' +
      'Get a key at https://lucairn.eu/account/signup and add it to your\n' +
      'claude_desktop_config.json under mcpServers.lucairn.env.',
  )
  process.exit(1)
}

startStdioServer({ apiKey, baseUrl, upstreamKey }).catch((err) => {
  // eslint-disable-next-line no-console
  console.error('lucairn-mcp-server failed:', err)
  process.exit(1)
})
