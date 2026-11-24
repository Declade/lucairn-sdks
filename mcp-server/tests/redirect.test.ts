/**
 * Key-carrying requests never follow a redirect (security fix stream
 * T-1474, slice F16; level-2 entry 11): a 307 from the gateway address to
 * another local port is an error, and neither the API key nor the provider
 * key reaches the second address. Synthetic keys, two local stand-in
 * servers, the real global fetch.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { GatewayClient } from '../src/gateway-client.js'
import { forwardFrame } from '../src/bridge.js'
import { GatewayError } from '../src/types.js'

const SYNTHETIC_KEY = 'lcr_live_' + 'a'.repeat(32)
const SYNTHETIC_UPSTREAM = 'sk-ant-synthetic-' + 'b'.repeat(16)

function listen(handler: Parameters<typeof createServer>[1]): Promise<Server> {
  return new Promise((resolve) => {
    const s = createServer(handler)
    s.listen(0, '127.0.0.1', () => resolve(s))
  })
}
const port = (s: Server) => (s.address() as AddressInfo).port

describe('mcp-server clients — redirects are never followed (F16)', () => {
  let first: Server
  let second: Server
  const secondSaw: IncomingHttpHeaders[] = []

  beforeEach(async () => {
    secondSaw.length = 0
    second = await listen((req, res) => {
      secondSaw.push(req.headers)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"jsonrpc":"2.0","id":1,"result":{}}')
    })
    first = await listen((req, res) => {
      res.writeHead(307, { location: `http://127.0.0.1:${port(second)}${req.url}` })
      res.end()
    })
  })

  afterEach(async () => {
    for (const s of [first, second]) {
      s.closeAllConnections()
      await new Promise((r) => s.close(r))
    }
  })

  it('GatewayClient: 307 is a GatewayError and no key reaches the second address', async () => {
    const client = new GatewayClient({
      apiKey: SYNTHETIC_KEY,
      baseUrl: `http://127.0.0.1:${port(first)}`,
      anthropicKey: SYNTHETIC_UPSTREAM,
    })
    const err = await client
      .sendMessage({ model: 'claude-sonnet-4-6', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }] })
      .then(() => null, (e: unknown) => e)
    expect(err).toBeInstanceOf(GatewayError)
    expect((err as GatewayError).status).toBe(307)
    expect((err as GatewayError).errorType).toBe('redirect_refused')
    expect(secondSaw).toHaveLength(0)
  })

  it('stdio bridge: 307 is a JSON-RPC error and no key reaches the second address', async () => {
    const reply = await forwardFrame({
      frame: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      apiKey: SYNTHETIC_KEY,
      baseUrl: `http://127.0.0.1:${port(first)}`,
      anthropicKey: SYNTHETIC_UPSTREAM,
      fetchImpl: globalThis.fetch,
    })
    expect(JSON.stringify(reply)).toContain('redirected (307)')
    expect(secondSaw).toHaveLength(0)
  })
})
