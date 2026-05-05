# @lucairn/mcp-server

Model Context Protocol (MCP) server for [Lucairn](https://lucairn.eu) — privacy-preserving AI gateway.

This package lets [Claude Desktop](https://claude.ai/download) (or any MCP-compatible client) route messages through Lucairn's privacy pipeline. PII is detected and replaced with placeholders before reaching the LLM; responses are re-linked back to the originals before delivery to you.

## Status

Pre-1.0. The Lucairn gateway exposes a single Anthropic-Messages-API-compatible endpoint at `POST /api/v1/mcp/messages` — see the [gateway source](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_handler.go). This MCP server wraps that endpoint and exposes it as one MCP tool: `chat_via_lucairn`.

## Install

You typically don't install this package globally — Claude Desktop runs it via `npx` on demand. See the config snippet below.

To install globally for testing or scripted use:

```bash
npm install -g @lucairn/mcp-server
```

## Claude Desktop config

Edit your `claude_desktop_config.json` (in Claude Desktop: Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "lucairn": {
      "command": "npx",
      "args": ["-y", "@lucairn/mcp-server"],
      "env": {
        "DSA_GATEWAY_URL": "https://gateway.lucairn.eu",
        "DSA_API_KEY": "lcr_live_...",
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

You can set either or both BYOK keys. The MCP server picks which one to forward to the gateway based on the requested `model`:

- `claude-*` / `anthropic-*` → `ANTHROPIC_API_KEY` is forwarded as `X-Upstream-Key`
- `gpt-*` / `openai-*` / `o1-*` / `o3-*` / `o4-*` → `OPENAI_API_KEY` is forwarded as `X-Upstream-Key`

If neither key is set, the gateway falls back to its provisioned upstream credential (Pro/Enterprise managed-AI pool); Developer-tier callers must bring their own key for at least one provider.

Restart Claude Desktop after saving. You should see `lucairn` in the MCP servers list, and a `chat_via_lucairn` tool will be available for Claude to call.

## Environment variables

All variables accept either the legacy `DSA_*` prefix (matching gateway / website conventions) or the new `LUCAIRN_*` prefix. Both work; pick one and stay consistent.

| Variable | Required | Description |
|---|---|---|
| `DSA_API_KEY` / `LUCAIRN_API_KEY` | Yes | Your Lucairn API key (`lcr_live_...` or legacy `veil_live_...`). Get one at https://lucairn.eu/account/signup. |
| `DSA_GATEWAY_URL` / `LUCAIRN_BASE_URL` | No | Lucairn gateway base URL. Defaults to `https://gateway.lucairn.eu`. Set to a self-hosted gateway URL for Enterprise deployments. |
| `ANTHROPIC_API_KEY` | No | Optional BYOK upstream key for Claude / Anthropic models. If set, forwarded as `X-Upstream-Key` so your Anthropic account is billed directly (gateway does not store it). |
| `OPENAI_API_KEY` | No | Optional BYOK upstream key for GPT / `o1` / `o3` / `o4` models. If set, forwarded as `X-Upstream-Key` so your OpenAI account is billed directly (gateway does not store it). |

## What the tool does

The server registers one MCP tool, `chat_via_lucairn`, which Claude (or any MCP client) can invoke:

- **Input:** `model` (string), `max_tokens` (number), `messages` (array of `{role, content}`), optional `system` (string), optional `temperature` (number).
- **Behavior:** POSTs the request to `${baseUrl}/api/v1/mcp/messages` with `x-api-key: ${apiKey}` and the optional `X-Upstream-Key` header. The gateway runs sanitization (Presidio + QI), forwards the redacted prompt to the upstream LLM, re-links the response, and returns an Anthropic Messages API response shape.
- **Output:** The LLM's text response, returned as the tool result.

The Anthropic-Messages request shape is documented in the gateway's [`MCPPayloadSchema`](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_payload_schema.go).

## How privacy works

- Every message is scanned for PII (names, emails, addresses, medical terms, etc.) before it reaches the LLM.
- Detected PII is replaced with safe placeholders. The LLM never sees raw personal data.
- Responses are re-linked: placeholders are swapped back to the original values before they are returned to the MCP client.
- A Lucairn Certificate is generated for each request — cryptographic proof of what was sanitized. View certificates at https://lucairn.eu/account/audit.

See https://lucairn.eu/developer/mcp for the full setup guide.

## Limitations / known issues

- **Tested with Claude Desktop:** not yet end-to-end verified by the package author. Surface issues at https://github.com/Declade/theveil-sdks/issues.
- **Streaming:** the gateway supports SSE streaming on the underlying endpoint (`stream: true` in the request body), but Claude Desktop's MCP tool-call protocol doesn't yet stream tool output back to the user. The current implementation forces non-streaming.
- **Single tool surface:** the gateway exposes one Anthropic-Messages-compatible endpoint, so this server exposes one tool. Resource and prompt MCP capabilities are not implemented.

## License

MIT — see [LICENSE](../LICENSE).
