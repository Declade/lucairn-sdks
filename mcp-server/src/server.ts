/**
 * Lucairn MCP server — stdio transport.
 *
 * Stub: the full implementation (with gateway forwarding and the
 * chat_via_lucairn tool) is added in the next commit. This file
 * exists so the bin entry at index.ts imports cleanly; running the
 * stub will start a server that exposes no tools.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'

export interface ServerOptions {
  apiKey: string
  baseUrl: string
  upstreamKey?: string
}

export async function startStdioServer(_opts: ServerOptions): Promise<void> {
  const server = new Server(
    { name: 'lucairn-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  )
  const transport = new StdioServerTransport()
  await server.connect(transport)
}
