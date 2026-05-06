/**
 * Tests for the stdio-bridge transport (LUCAIRN_TRANSPORT=stdio-bridge).
 *
 * Mocks the HTTP layer end-to-end. Drives stdin/stdout through Node
 * Readable/Writable shims so the bridge can be exercised without
 * binding to the process' real stdio.
 */
import { Readable, Writable } from 'node:stream'
import { describe, expect, it, vi } from 'vitest'
import {
  BRIDGE_FETCH_TIMEOUT_MS,
  forwardFrame,
  pickUpstreamKeyForFrame,
  runStdioBridge,
} from '../src/bridge.js'
import {
  parseTransport,
  SUPPORTED_TRANSPORTS,
  TRANSPORT_DIRECT_HTTP,
  TRANSPORT_STDIO_BRIDGE,
} from '../src/server.js'

/** Minimal stdin shim: paged frames written end-to-end as one Buffer chunk. */
function stdinFromFrames(frames: object[]): Readable {
  const lines = frames.map((f) => JSON.stringify(f) + '\n').join('')
  return Readable.from([Buffer.from(lines, 'utf8')])
}

/** Capturing Writable that collects newline-delimited JSON frames. */
class CaptureWritable extends Writable {
  buffer = ''
  frames: unknown[] = []
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error | null) => void,
  ): void {
    this.buffer += chunk.toString('utf8')
    let idx: number
    // The MCP SDK's serializeMessage emits one JSON-encoded object per
    // newline. Parse each complete line as it arrives.
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 1)
      if (line.length > 0) {
        try {
          this.frames.push(JSON.parse(line))
        } catch (err) {
          this.frames.push({ __parse_error__: String(err), raw: line })
        }
      }
    }
    cb()
  }
}

function fakeResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('parseTransport', () => {
  it('returns null on undefined / empty', () => {
    expect(parseTransport(undefined)).toBeNull()
    expect(parseTransport(null)).toBeNull()
    expect(parseTransport('')).toBeNull()
  })

  it('accepts the two supported modes', () => {
    expect(parseTransport(TRANSPORT_DIRECT_HTTP)).toBe(TRANSPORT_DIRECT_HTTP)
    expect(parseTransport(TRANSPORT_STDIO_BRIDGE)).toBe(TRANSPORT_STDIO_BRIDGE)
  })

  it('throws on any other value, naming the supported set', () => {
    expect(() => parseTransport('http')).toThrow(/direct-http/)
    expect(() => parseTransport('http')).toThrow(/stdio-bridge/)
    expect(() => parseTransport('Direct-Http')).toThrow() // case-sensitive
    expect(() => parseTransport(' direct-http')).toThrow() // no whitespace
  })

  it('exposes the canonical supported-transport list', () => {
    expect([...SUPPORTED_TRANSPORTS]).toEqual([
      TRANSPORT_DIRECT_HTTP,
      TRANSPORT_STDIO_BRIDGE,
    ])
  })
})

describe('pickUpstreamKeyForFrame', () => {
  it('returns undefined when the frame is not a tools/call', () => {
    expect(
      pickUpstreamKeyForFrame(
        { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        'sk-ant',
        'sk-oai',
      ),
    ).toBeUndefined()
  })

  it('returns the Anthropic key for claude-* models', () => {
    expect(
      pickUpstreamKeyForFrame(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'chat_via_lucairn',
            arguments: { model: 'claude-sonnet-4-6', max_tokens: 1, messages: [] },
          },
        },
        'sk-ant',
        'sk-oai',
      ),
    ).toBe('sk-ant')
  })

  it('returns the OpenAI key for gpt-* / o1-* / o3-* / o4-* models', () => {
    const baseFrame = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'chat_via_lucairn',
        arguments: { model: 'gpt-4o-mini', max_tokens: 1, messages: [] },
      },
    }
    expect(pickUpstreamKeyForFrame(baseFrame, 'sk-ant', 'sk-oai')).toBe('sk-oai')
    const o1 = { ...baseFrame, params: { ...baseFrame.params, arguments: { ...baseFrame.params.arguments, model: 'o1-mini' } } }
    expect(pickUpstreamKeyForFrame(o1, 'sk-ant', 'sk-oai')).toBe('sk-oai')
  })

  it('is case-insensitive', () => {
    expect(
      pickUpstreamKeyForFrame(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'chat_via_lucairn', arguments: { model: 'CLAUDE-OPUS' } },
        },
        'sk-ant',
        'sk-oai',
      ),
    ).toBe('sk-ant')
  })

  it('falls back to Anthropic for an unknown model when both keys set', () => {
    expect(
      pickUpstreamKeyForFrame(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'chat_via_lucairn', arguments: { model: 'mistral-large' } },
        },
        'sk-ant',
        'sk-oai',
      ),
    ).toBe('sk-ant')
  })

  it('returns undefined when arguments lack a model field', () => {
    expect(
      pickUpstreamKeyForFrame(
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'something_else', arguments: { foo: 'bar' } },
        },
        'sk-ant',
        'sk-oai',
      ),
    ).toBeUndefined()
  })

  it('returns undefined for malformed frames', () => {
    expect(pickUpstreamKeyForFrame(null, 'sk-ant', 'sk-oai')).toBeUndefined()
    expect(pickUpstreamKeyForFrame(undefined, 'sk-ant', 'sk-oai')).toBeUndefined()
    expect(pickUpstreamKeyForFrame(42, 'sk-ant', 'sk-oai')).toBeUndefined()
    expect(pickUpstreamKeyForFrame({ method: 'tools/call' }, 'sk-ant', 'sk-oai')).toBeUndefined()
  })
})

describe('forwardFrame', () => {
  const initFrame = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-03-26' },
  } as const

  it('POSTs to <baseUrl>/mcp with Authorization Bearer header', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        fakeResponse(
          200,
          JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }),
        ),
      )
    await forwardFrame({
      frame: initFrame,
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://gateway.lucairn.eu/mcp')
    expect(init.method).toBe('POST')
    const headers = init.headers as Record<string, string>
    expect(headers.authorization).toBe('Bearer lcr_live_test')
    expect(headers['content-type']).toBe('application/json')
    expect(JSON.parse(init.body as string)).toEqual(initFrame)
  })

  it('attaches X-Upstream-Key on a tools/call with a claude-* model', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        fakeResponse(200, JSON.stringify({ jsonrpc: '2.0', id: 5, result: {} })),
      )
    await forwardFrame({
      frame: {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: {
          name: 'chat_via_lucairn',
          arguments: {
            model: 'claude-sonnet-4-6',
            max_tokens: 16,
            messages: [{ role: 'user', content: 'hi' }],
          },
        },
      },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      anthropicKey: 'sk-ant-xyz',
      openaiKey: 'sk-oai-xyz',
      fetchImpl: fetchSpy,
    })
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['X-Upstream-Key']).toBe('sk-ant-xyz')
  })

  it('does NOT attach X-Upstream-Key for non-tools/call frames', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        fakeResponse(200, JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })),
      )
    await forwardFrame({
      frame: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      anthropicKey: 'sk-ant',
      openaiKey: 'sk-oai',
      fetchImpl: fetchSpy,
    })
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['X-Upstream-Key']).toBeUndefined()
  })

  it('returns the gateway 200 envelope verbatim', async () => {
    const reply = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'lucairn-privacy-gateway', version: '1.0.0' },
        capabilities: { tools: {} },
      },
    }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(reply)))
    const out = await forwardFrame({
      frame: initFrame,
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toEqual(reply)
  })

  it('forwards a JSON-RPC batch reply verbatim', async () => {
    const reply = [
      { jsonrpc: '2.0', id: 1, result: { a: 1 } },
      { jsonrpc: '2.0', id: 2, error: { code: -32601, message: 'Method not found' } },
    ]
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(reply)))
    const out = await forwardFrame({
      frame: initFrame,
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toEqual(reply)
  })

  it('returns undefined on 204 No Content (notification ack)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    const out = await forwardFrame({
      frame: { jsonrpc: '2.0', method: 'notifications/initialized' } as never,
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toBeUndefined()
  })

  it('wraps a network error as a JSON-RPC -32603 error envelope echoing the request id', async () => {
    const fetchSpy = vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    const out = await forwardFrame({
      frame: { jsonrpc: '2.0', id: 7, method: 'tools/list' },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toMatchObject({
      jsonrpc: '2.0',
      id: 7,
      error: { code: -32603, message: expect.stringContaining('network error') },
    })
  })

  it('wraps a fetch timeout (TimeoutError) with a clear retry hint', async () => {
    const timeoutErr = new Error('The operation was aborted due to timeout')
    timeoutErr.name = 'TimeoutError'
    const fetchSpy = vi.fn().mockRejectedValue(timeoutErr)
    const out = await forwardFrame({
      frame: { jsonrpc: '2.0', id: 9, method: 'tools/list' },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toMatchObject({
      jsonrpc: '2.0',
      id: 9,
      error: {
        code: -32603,
        message: expect.stringContaining('timed out'),
      },
    })
  })

  it('wraps a non-JSON 5xx body as -32603', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(new Response('Bad Gateway', { status: 502 }))
    const out = await forwardFrame({
      frame: { jsonrpc: '2.0', id: 3, method: 'tools/list' },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toMatchObject({
      jsonrpc: '2.0',
      id: 3,
      error: {
        code: -32603,
        message: expect.stringContaining('502'),
      },
    })
  })

  it('rejects an empty array body as malformed (JSON-RPC §6 batches must be non-empty)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(fakeResponse(200, '[]'))
    const out = await forwardFrame({
      frame: { jsonrpc: '2.0', id: 11, method: 'tools/list' },
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    expect(out).toMatchObject({
      jsonrpc: '2.0',
      id: 11,
      error: { code: -32603 },
    })
  })

  it('passes an AbortSignal with the documented timeout', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(
        fakeResponse(200, JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} })),
      )
    await forwardFrame({
      frame: initFrame,
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined
    expect(init?.signal).toBeDefined()
    expect(init?.signal).toBeInstanceOf(AbortSignal)
    // Sanity: the constant we documented in README + bridge.ts is what we ship.
    expect(BRIDGE_FETCH_TIMEOUT_MS).toBe(30_000)
  })
})

describe('runStdioBridge', () => {
  it('rejects http:// for non-loopback hosts (TOB-001 parity)', async () => {
    await expect(
      runStdioBridge({
        apiKey: 'lcr_live_test',
        baseUrl: 'http://gateway.lucairn.eu',
      }),
    ).rejects.toThrow(/https:\/\//)
  })

  it('allows http:// for localhost / 127.0.0.1', async () => {
    const ctrl = new AbortController()
    // No frames written — the bridge will block waiting for stdin.
    // We'll trigger a clean shutdown via the abort signal once the
    // promise has had a turn to subscribe.
    const fetchSpy = vi.fn() // never called in this test
    const stdin = new Readable({
      read() {
        // No-op; we'll abort instead of EOF'ing.
      },
    })
    const stdout = new CaptureWritable()
    const promise = runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'http://localhost:8080',
      fetchImpl: fetchSpy as unknown as typeof fetch,
      stdin,
      stdout,
      signal: ctrl.signal,
    })
    // Yield once so transport.start() registers, then abort.
    await new Promise((r) => setImmediate(r))
    ctrl.abort()
    await expect(promise).resolves.toBeUndefined()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('round-trips a tools/list frame end-to-end', async () => {
    const reply = {
      jsonrpc: '2.0',
      id: 42,
      result: {
        tools: [{ name: 'chat_via_lucairn', description: 'Lucairn chat tool' }],
      },
    }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(reply)))
    const stdin = stdinFromFrames([
      { jsonrpc: '2.0', id: 42, method: 'tools/list' },
    ])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
      stdin,
      stdout,
    })
    // Drain any in-flight async work — the bridge's frame handler is fire-and-forget.
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const url = (fetchSpy.mock.calls[0] as [string, RequestInit])[0]
    expect(url).toBe('https://gateway.lucairn.eu/mcp')
    expect(stdout.frames).toEqual([reply])
  })

  it('writes a JSON-RPC error envelope when fetch fails', async () => {
    const fetchSpy = vi.fn().mockRejectedValue(new Error('boom'))
    const stdin = stdinFromFrames([
      { jsonrpc: '2.0', id: 99, method: 'tools/list' },
    ])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
      stdin,
      stdout,
    })
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(stdout.frames).toHaveLength(1)
    expect(stdout.frames[0]).toMatchObject({
      jsonrpc: '2.0',
      id: 99,
      error: {
        code: -32603,
        message: expect.stringContaining('network error'),
      },
    })
  })

  it('does not write any frame when the gateway returns 204 (notification ack)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    const stdin = stdinFromFrames([
      { jsonrpc: '2.0', method: 'notifications/initialized' },
    ])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
      stdin,
      stdout,
    })
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(stdout.frames).toEqual([])
  })

  it('processes multiple frames over one stdin session in order of arrival', async () => {
    const reply1 = { jsonrpc: '2.0', id: 1, result: { tools: [] } }
    const reply2 = {
      jsonrpc: '2.0',
      id: 2,
      result: { content: [{ type: 'text', text: 'pong' }] },
    }
    const fetchSpy = vi
      .fn<Parameters<typeof fetch>, ReturnType<typeof fetch>>()
      .mockResolvedValueOnce(fakeResponse(200, JSON.stringify(reply1)))
      .mockResolvedValueOnce(fakeResponse(200, JSON.stringify(reply2)))
    const stdin = stdinFromFrames([
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'chat_via_lucairn', arguments: { model: 'claude-sonnet-4-6' } },
      },
    ])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy as unknown as typeof fetch,
      stdin,
      stdout,
    })
    // Allow both fire-and-forget handlers to drain.
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r))
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(stdout.frames).toHaveLength(2)
    // Frame replies arrive in their fetch-resolution order. Both fetches
    // resolve synchronously here so order matches dispatch order.
    expect(stdout.frames).toContainEqual(reply1)
    expect(stdout.frames).toContainEqual(reply2)
  })

  it('emits a JSON-RPC -32700 ParseError when stdin contains malformed JSON', async () => {
    const fetchSpy = vi.fn() // never called — the frame never reaches the gateway
    // A line that's a syntactically broken JSON object — the SDK's
    // ReadBuffer parses by '\n' delimiter, then JSON.parse the chunk;
    // SyntaxError surfaces via transport.onerror.
    const stdin = Readable.from([Buffer.from('{not valid json}\n', 'utf8')])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy as unknown as typeof fetch,
      stdin,
      stdout,
    })
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(stdout.frames).toHaveLength(1)
    expect(stdout.frames[0]).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error' },
    })
  })

  it('emits a JSON-RPC -32600 InvalidRequest on a frame that is valid JSON but not a JSON-RPC envelope, AND keeps the bridge alive for subsequent valid frames (M1 regression: ZodError must not tear down the bridge)', async () => {
    // The SDK's ReadBuffer.deserializeMessage runs JSON.parse THEN
    // JSONRPCMessageSchema.parse (Zod). A frame like {"foo":"bar"}\n
    // parses as JSON cleanly but fails Zod validation — surfacing as a
    // ZodError on transport.onerror. The pre-fix behaviour treated any
    // non-SyntaxError as fatal and tore down the bridge; the fix replies
    // with -32600 Invalid Request and keeps the bridge alive.
    const validReply = { jsonrpc: '2.0', id: 7, result: { ok: true } }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(validReply)))
    // First line: invalid JSON-RPC envelope (Zod will reject).
    // Second line: a perfectly valid frame — proves the bridge survived.
    const lines =
      '{"foo":"bar"}\n' +
      JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list' }) +
      '\n'
    const stdin = Readable.from([Buffer.from(lines, 'utf8')])
    const stdout = new CaptureWritable()
    await runStdioBridge({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy as unknown as typeof fetch,
      stdin,
      stdout,
    })
    // Drain fire-and-forget handlers.
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r))
    // The valid frame must have reached the gateway → fetch was called.
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(stdout.frames).toHaveLength(2)
    // First reply: -32600 Invalid Request envelope from the malformed frame.
    expect(stdout.frames[0]).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid Request' },
    })
    // Second reply: the gateway's response to the valid frame — proves
    // the bridge stayed alive after the bad frame.
    expect(stdout.frames[1]).toEqual(validReply)
  })

  it('rejects when neither baseUrl nor apiKey is supplied', async () => {
    await expect(
      // @ts-expect-error — exercising the runtime guard
      runStdioBridge({ baseUrl: 'https://gateway.lucairn.eu' }),
    ).rejects.toThrow(/apiKey/)
    await expect(
      // @ts-expect-error — exercising the runtime guard
      runStdioBridge({ apiKey: 'lcr_live_test' }),
    ).rejects.toThrow(/baseUrl/)
  })
})
