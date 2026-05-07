import { describe, it, expect, vi } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import {
  buildServer,
  CHAT_TOOL_DESCRIPTOR,
  CHAT_TOOL_NAME,
  exceedsInputCap,
  formatToolResult,
  MAX_INPUT_BYTES,
  parseChatToolArgs,
} from '../src/server.js'
import { GatewayClient } from '../src/gateway-client.js'
import type { AnthropicResponseBody } from '../src/types.js'

describe('CHAT_TOOL_DESCRIPTOR', () => {
  it('uses the canonical tool name', () => {
    expect(CHAT_TOOL_NAME).toBe('chat_via_lucairn')
    expect(CHAT_TOOL_DESCRIPTOR.name).toBe('chat_via_lucairn')
  })

  it('declares model + max_tokens + messages as required inputs', () => {
    const required = CHAT_TOOL_DESCRIPTOR.inputSchema.required
    expect(required).toContain('model')
    expect(required).toContain('max_tokens')
    expect(required).toContain('messages')
  })

  it('declares MCP tool annotations matching the gateway streamable-HTTP descriptor', () => {
    expect(CHAT_TOOL_DESCRIPTOR.annotations.readOnlyHint).toBe(false)
    expect(CHAT_TOOL_DESCRIPTOR.annotations.destructiveHint).toBe(false)
    expect(CHAT_TOOL_DESCRIPTOR.annotations.idempotentHint).toBe(false)
    expect(CHAT_TOOL_DESCRIPTOR.annotations.openWorldHint).toBe(true)
  })

  it('declares an outputSchema with text/model/stop_reason/usage required', () => {
    expect(CHAT_TOOL_DESCRIPTOR.outputSchema.type).toBe('object')
    const required = CHAT_TOOL_DESCRIPTOR.outputSchema.required
    expect(required).toContain('text')
    expect(required).toContain('model')
    expect(required).toContain('stop_reason')
    expect(required).toContain('usage')
  })
})

describe('parseChatToolArgs', () => {
  it('accepts a well-formed call', () => {
    const out = parseChatToolArgs({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
    })
    expect(out.model).toBe('claude-sonnet-4-6')
    expect(out.max_tokens).toBe(512)
    expect(out.messages).toHaveLength(1)
  })

  it('rejects missing model', () => {
    expect(() =>
      parseChatToolArgs({
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    ).toThrow(/model/)
  })

  it('rejects non-positive max_tokens', () => {
    expect(() =>
      parseChatToolArgs({
        model: 'm',
        max_tokens: 0,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    ).toThrow(/max_tokens/)
  })

  it('rejects empty messages', () => {
    expect(() =>
      parseChatToolArgs({
        model: 'm',
        max_tokens: 1,
        messages: [],
      }),
    ).toThrow(/messages/)
  })

  it('rejects non-object input', () => {
    expect(() => parseChatToolArgs(null)).toThrow()
    expect(() => parseChatToolArgs('hi')).toThrow()
  })
})

describe('formatToolResult', () => {
  const baseResp: AnthropicResponseBody = {
    id: 'msg_dsa_abc',
    type: 'message',
    role: 'assistant',
    content: [
      { type: 'text', text: 'Hello world' },
      { type: 'text', text: '. Have a nice day.' },
    ],
    model: 'claude-sonnet-4-6',
    stop_reason: 'end_turn',
    usage: { input_tokens: 10, output_tokens: 7 },
  }

  it('joins text content blocks into one MCP text result', () => {
    const out = formatToolResult(baseResp)
    expect(out.content).toHaveLength(1)
    expect(out.content[0]).toMatchObject({
      type: 'text',
      text: 'Hello world. Have a nice day.',
    })
  })

  it('appends a Lucairn certificate URL when present in metadata', () => {
    const out = formatToolResult({
      ...baseResp,
      metadata: {
        dsa_compliance: {
          request_id: 'abc',
          veil_summary_url: 'https://gateway.lucairn.eu/api/v1/veil/certificate/abc/summary',
          redaction_count: 0,
          latency_ms: 100,
        },
      },
    })
    expect(out.content[0].text).toContain('Lucairn certificate:')
    expect(out.content[0].text).toContain('certificate/abc/summary')
  })

  it('omits the certificate trailer when metadata is missing', () => {
    const out = formatToolResult(baseResp)
    expect(out.content[0].text).not.toContain('Lucairn certificate:')
  })

  it('returns structuredContent matching the declared outputSchema', () => {
    const out = formatToolResult(baseResp)
    expect(out.structuredContent).toBeDefined()
    expect(out.structuredContent.text).toBe(out.content[0].text)
    expect(out.structuredContent.model).toBe(baseResp.model)
    expect(out.structuredContent.stop_reason).toBe(baseResp.stop_reason)
    expect(out.structuredContent.usage).toEqual(baseResp.usage)
  })

  it('omits structuredContent.compliance when metadata is absent', () => {
    const out = formatToolResult(baseResp)
    expect(out.structuredContent.compliance).toBeUndefined()
  })

  it('populates structuredContent.compliance when gateway metadata is present', () => {
    const out = formatToolResult({
      ...baseResp,
      metadata: {
        dsa_compliance: {
          request_id: 'req_xyz',
          veil_summary_url: 'https://gateway.lucairn.eu/api/v1/veil/certificate/req_xyz/summary',
          redaction_count: 3,
          latency_ms: 142,
        },
      },
    })
    expect(out.structuredContent.compliance).toBeDefined()
    expect(out.structuredContent.compliance?.request_id).toBe('req_xyz')
    expect(out.structuredContent.compliance?.redaction_count).toBe(3)
    expect(out.structuredContent.compliance?.latency_ms).toBe(142)
  })
})

describe('exceedsInputCap (TOB-005 soft input cap)', () => {
  it('returns false for small inputs', () => {
    expect(exceedsInputCap({ messages: [{ role: 'user', content: 'hi' }] })).toBe(false)
  })

  it('returns true for inputs > MAX_INPUT_BYTES', () => {
    const huge = 'A'.repeat(MAX_INPUT_BYTES + 1)
    expect(exceedsInputCap({ messages: [{ role: 'user', content: huge }] })).toBe(true)
  })

  it('returns false at the exact cap boundary', () => {
    // Construct args whose JSON.stringify length is exactly MAX_INPUT_BYTES.
    // The structure overhead is ~50 bytes; leave a small headroom so we
    // don't accidentally exceed.
    const filler = 'A'.repeat(MAX_INPUT_BYTES - 100)
    expect(exceedsInputCap({ messages: [{ role: 'user', content: filler }] })).toBe(false)
  })
})

describe('CallToolRequestSchema input cap (TOB-005 integration)', () => {
  it('rejects oversized tool input without making a fetch call', async () => {
    // Mock fetch — must NOT be called when args exceed the cap.
    const fetchSpy = vi.fn().mockRejectedValue(new Error('fetch should not be called'))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    const server = buildServer(client)

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    const mcpClient = new Client({ name: 'test-client', version: '0.0.1' }, { capabilities: {} })

    await Promise.all([server.connect(serverTransport), mcpClient.connect(clientTransport)])

    const huge = 'A'.repeat(2_000_000)
    const result = (await mcpClient.callTool({
      name: CHAT_TOOL_NAME,
      arguments: {
        model: 'claude-sonnet-4-6',
        max_tokens: 256,
        messages: [{ role: 'user', content: huge }],
      },
    })) as { isError?: boolean; content: Array<{ type: string; text: string }> }

    expect(result.isError).toBe(true)
    expect(result.content[0].text).toContain('exceeds max size')
    expect(fetchSpy).not.toHaveBeenCalled()

    await mcpClient.close()
    await server.close()
  })
})
