import { describe, it, expect, vi } from 'vitest'
import { GatewayClient, buildMessagesRequestBody } from '../src/gateway-client.js'
import { GatewayError } from '../src/types.js'

const baseInput = {
  model: 'claude-sonnet-4-6',
  max_tokens: 256,
  messages: [{ role: 'user' as const, content: 'hi' }],
}

function fakeResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('buildMessagesRequestBody', () => {
  it('forces stream:false and forwards the optional system + temperature', () => {
    const body = buildMessagesRequestBody({
      ...baseInput,
      system: 'helpful',
      temperature: 0.7,
    })
    expect(body.stream).toBe(false)
    expect(body.model).toBe('claude-sonnet-4-6')
    expect(body.max_tokens).toBe(256)
    expect(body.system).toBe('helpful')
    expect(body.temperature).toBe(0.7)
  })

  it('omits system and temperature when not provided', () => {
    const body = buildMessagesRequestBody(baseInput)
    expect(body).not.toHaveProperty('system')
    expect(body).not.toHaveProperty('temperature')
  })
})

describe('GatewayClient constructor scheme guard (TOB-001)', () => {
  it('rejects http:// for a non-loopback host', () => {
    expect(
      () =>
        new GatewayClient({
          apiKey: 'lcr_live_test',
          baseUrl: 'http://gateway.lucairn.eu',
        }),
    ).toThrow(/https:\/\//)
  })

  it('allows http:// for localhost', () => {
    expect(
      () =>
        new GatewayClient({
          apiKey: 'lcr_live_test',
          baseUrl: 'http://localhost:8080',
        }),
    ).not.toThrow()
  })

  it('allows http:// for 127.0.0.1', () => {
    expect(
      () =>
        new GatewayClient({
          apiKey: 'lcr_live_test',
          baseUrl: 'http://127.0.0.1:8080',
        }),
    ).not.toThrow()
  })

  it('allows https:// for any host', () => {
    expect(
      () =>
        new GatewayClient({
          apiKey: 'lcr_live_test',
          baseUrl: 'https://gateway.lucairn.eu',
        }),
    ).not.toThrow()
  })
})

describe('GatewayClient.pickUpstreamKey (v1.1.0 model-prefix routing)', () => {
  function makeClient(opts: {
    anthropicKey?: string
    openaiKey?: string
  }): GatewayClient {
    return new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      anthropicKey: opts.anthropicKey,
      openaiKey: opts.openaiKey,
      // No fetchImpl needed — pickUpstreamKey is pure.
      fetchImpl: (() => undefined) as unknown as typeof fetch,
    })
  }

  it('returns the Anthropic key for claude-sonnet-4-6', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('claude-sonnet-4-6')).toBe('sk-ant')
  })

  it('returns the OpenAI key for gpt-4o-mini', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('gpt-4o-mini')).toBe('sk-oai')
  })

  it('returns the OpenAI key for o1-* / o3-* / o4-* (reasoning models)', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('o1-mini')).toBe('sk-oai')
    expect(client.pickUpstreamKey('o3-mini')).toBe('sk-oai')
    expect(client.pickUpstreamKey('o4-preview')).toBe('sk-oai')
  })

  it('returns the Anthropic key for the anthropic-* prefix', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('anthropic-claude-3.7-sonnet')).toBe('sk-ant')
    expect(client.pickUpstreamKey('anthropic.claude-haiku')).toBe('sk-ant')
  })

  it('returns the OpenAI key for the openai-* prefix', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('openai-gpt-5')).toBe('sk-oai')
    expect(client.pickUpstreamKey('openai.o5-preview')).toBe('sk-oai')
  })

  it('is case-insensitive on the model prefix', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('CLAUDE-SONNET-4-6')).toBe('sk-ant')
    expect(client.pickUpstreamKey('GPT-4O-MINI')).toBe('sk-oai')
  })

  it('falls back to Anthropic for an unknown model when both keys set', () => {
    const client = makeClient({ anthropicKey: 'sk-ant', openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('mistral-large')).toBe('sk-ant')
  })

  it('falls back to OpenAI for an unknown model when only OpenAI key set', () => {
    const client = makeClient({ openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('mistral-large')).toBe('sk-oai')
  })

  it('returns undefined for claude-* when only OpenAI key is set', () => {
    const client = makeClient({ openaiKey: 'sk-oai' })
    expect(client.pickUpstreamKey('claude-sonnet-4-6')).toBeUndefined()
  })

  it('returns undefined for gpt-* when only Anthropic key is set', () => {
    const client = makeClient({ anthropicKey: 'sk-ant' })
    expect(client.pickUpstreamKey('gpt-4o-mini')).toBeUndefined()
  })

  it('returns undefined for any model when neither key is set', () => {
    const client = makeClient({})
    expect(client.pickUpstreamKey('claude-sonnet-4-6')).toBeUndefined()
    expect(client.pickUpstreamKey('gpt-4o-mini')).toBeUndefined()
    expect(client.pickUpstreamKey('mistral-large')).toBeUndefined()
  })
})

describe('GatewayClient.sendMessage', () => {
  it('forwards x-api-key and optional X-Upstream-Key headers', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      fakeResponse(
        200,
        JSON.stringify({
          id: 'msg_dsa_abc',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'ok' }],
          model: 'claude-sonnet-4-6',
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
      ),
    )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu/',
      anthropicKey: 'sk-ant-xyz',
      fetchImpl: fetchSpy,
    })
    await client.sendMessage(baseInput)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://gateway.lucairn.eu/api/v1/mcp/messages')
    expect(init.method).toBe('POST')
    const headers = init.headers as Record<string, string>
    expect(headers['x-api-key']).toBe('lcr_live_test')
    expect(headers['X-Upstream-Key']).toBe('sk-ant-xyz')
    expect(headers['content-type']).toBe('application/json')
  })

  it('forwards OPENAI_API_KEY as X-Upstream-Key for gpt-* models (v1.1.0)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      fakeResponse(
        200,
        JSON.stringify({
          id: 'msg_dsa_abc',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'ok' }],
          model: 'gpt-4o-mini',
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
      ),
    )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      anthropicKey: 'sk-ant-xyz',
      openaiKey: 'sk-openai-abc',
      fetchImpl: fetchSpy,
    })
    await client.sendMessage({ ...baseInput, model: 'gpt-4o-mini' })

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['X-Upstream-Key']).toBe('sk-openai-abc')
  })

  it('omits X-Upstream-Key when neither BYOK key is set (managed-AI mode)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      fakeResponse(
        200,
        JSON.stringify({
          id: 'msg_dsa_abc',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'ok' }],
          model: 'claude-sonnet-4-6',
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
      ),
    )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await client.sendMessage(baseInput)

    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const headers = init.headers as Record<string, string>
    expect(headers['X-Upstream-Key']).toBeUndefined()
  })

  it('parses and returns the gateway 200 body', async () => {
    const responseBody = {
      id: 'msg_dsa_xyz',
      type: 'message' as const,
      role: 'assistant' as const,
      content: [{ type: 'text', text: 'hello back' }],
      model: 'claude-sonnet-4-6',
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 3 },
      metadata: {
        dsa_compliance: {
          request_id: 'xyz',
          veil_summary_url: 'https://gateway.lucairn.eu/api/v1/veil/certificate/xyz/summary',
          redaction_count: 0,
          latency_ms: 1234,
        },
      },
    }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(responseBody)))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    const out = await client.sendMessage(baseInput)
    expect(out).toEqual(responseBody)
  })

  it('maps a 503 with anthropic-error envelope to GatewayError', async () => {
    const errBody = {
      type: 'error',
      error: {
        type: 'api_error',
        message: 'Inference service unavailable. Retry after 30 seconds.',
      },
    }
    // Each call needs a fresh Response — Response.body is single-use.
    const fetchSpy = vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(fakeResponse(503, JSON.stringify(errBody))),
      )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 503,
      errorType: 'api_error',
    })
    await expect(client.sendMessage(baseInput)).rejects.toBeInstanceOf(GatewayError)
  })

  it('maps a 401 without a parseable body to authentication_error', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(fakeResponse(401, 'Unauthorized'))
    const client = new GatewayClient({
      apiKey: 'lcr_live_bad',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 401,
      errorType: 'authentication_error',
    })
  })

  it('wraps fetch network errors as GatewayError with status 0', async () => {
    const fetchSpy = vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 0,
      errorType: 'network_error',
    })
  })

  it('handles 202 ASYNC_PROCESSING with retry-shortly error', async () => {
    // Gateway shape per proxy_async.go:128-144: 202 + JSON envelope with
    // status/job_id/request_id/status_url/veil — no Anthropic content[].
    const asyncBody = {
      status: 'processing',
      job_id: 'job_abc',
      request_id: 'req_xyz',
      status_url: 'https://gateway.lucairn.eu/api/v1/jobs/job_abc',
      veil: { compliance: 'pending' },
    }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(202, JSON.stringify(asyncBody)))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 202,
      errorType: 'async_processing',
    })
  })

  it('rejects 2xx with non-array content field as malformed_response', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify({ content: 'not-an-array' })))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 200,
      errorType: 'malformed_response',
    })
  })

  it('rejects 2xx with missing content field as malformed_response', async () => {
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify({ id: 'abc' })))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 200,
      errorType: 'malformed_response',
    })
  })

  it('maps fetch timeout (TimeoutError) to GatewayError(_, "timeout") (TOB-002)', async () => {
    // Simulate AbortSignal.timeout firing: fetch rejects with a DOMException
    // whose name is "TimeoutError". We can't easily wait the real 30s in a
    // test, so we mock the rejection synchronously.
    const timeoutErr = new Error('The operation was aborted due to timeout')
    timeoutErr.name = 'TimeoutError'
    const fetchSpy = vi.fn().mockRejectedValue(timeoutErr)
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 0,
      errorType: 'timeout',
    })
  })

  it('passes an AbortSignal to fetch (TOB-002)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      fakeResponse(
        200,
        JSON.stringify({
          id: 'msg_dsa_abc',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'ok' }],
          model: 'claude-sonnet-4-6',
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
      ),
    )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await client.sendMessage(baseInput)
    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit | undefined
    expect(init?.signal).toBeDefined()
    expect(init?.signal).toBeInstanceOf(AbortSignal)
  })
})
