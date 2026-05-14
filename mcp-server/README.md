# @lucairn/mcp-server

Model Context Protocol (MCP) server for [Lucairn](https://lucairn.eu) — privacy-preserving AI gateway.

This package lets [Claude Desktop](https://claude.ai/download) (or any MCP-compatible client) send selected `chat_via_lucairn` tool calls through Lucairn's privacy pipeline. It does not proxy normal Claude Desktop chats automatically. PII is detected and replaced with placeholders before reaching the LLM. Developer-tier responses keep placeholders visible; Pro and Enterprise tiers can re-link placeholders before delivery.

## Status

`v1.2.6`. Two transport modes are now supported (see `LUCAIRN_TRANSPORT` below):

- **`direct-http`** (default — recommended for stdio CLI users): the npm package owns the MCP tool catalog locally and forwards each `chat_via_lucairn` call to the gateway's Anthropic-Messages-shape endpoint at `POST /api/v1/mcp/messages` ([gateway source](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_handler.go)). Lowest latency.
- **`stdio-bridge`** (opt-in, new in v1.2): the npm package is a thin stdio↔HTTP bridge. Stdio JSON-RPC frames are forwarded to the gateway's streamable-HTTP MCP endpoint at `POST /mcp` ([gateway source](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_streamable.go), live since 2026-05-06 via PR #135). Tool catalogs come from the gateway, so future tools and tier-aware descriptors land without re-publishing this package.

Upgrading from `v1.1.x` is non-breaking: `LUCAIRN_TRANSPORT` defaults to `direct-http`, which is bit-identical to v1.1.

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
| `LUCAIRN_TRANSPORT` | No | `direct-http` (default) or `stdio-bridge`. See "Transport modes" below. Any other value causes a non-zero exit at startup. |
| `ANTHROPIC_API_KEY` | No | Optional BYOK upstream key for Claude / Anthropic models. If set, forwarded as `X-Upstream-Key` so your Anthropic account is billed directly (gateway does not store it). |
| `OPENAI_API_KEY` | No | Optional BYOK upstream key for OpenAI models. If set, forwarded as `X-Upstream-Key` so your OpenAI account is billed directly (gateway does not store it). |

## Transport modes

`LUCAIRN_TRANSPORT` selects how the npm package talks to the gateway:

### `direct-http` (default)

```jsonc
"env": {
  "LUCAIRN_TRANSPORT": "direct-http",        // optional — this is the default
  "DSA_GATEWAY_URL": "https://gateway.lucairn.eu",
  "DSA_API_KEY": "lcr_live_..."
}
```

The package serves a local MCP server with the single `chat_via_lucairn` tool. Each tool call is converted into an Anthropic Messages API request and POSTed to `${baseUrl}/api/v1/mcp/messages`. Recommended for stdio CLI users — one fewer hop, lowest latency.

### `stdio-bridge` (opt-in, v1.2+)

```jsonc
"env": {
  "LUCAIRN_TRANSPORT": "stdio-bridge",
  "DSA_GATEWAY_URL": "https://gateway.lucairn.eu",
  "DSA_API_KEY": "lcr_live_..."
}
```

The package degenerates into a thin stdio↔HTTP bridge: incoming JSON-RPC 2.0 frames from your local MCP client are forwarded as POSTs to `${baseUrl}/mcp` (the gateway's [streamable-HTTP MCP endpoint](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_streamable.go), live since 2026-05-06). The HTTP response is written back to stdout as the JSON-RPC reply. **Requires gateway support live since 2026-05-06.**

Use this mode when you want:

- The gateway's tool catalog (currently `chat_via_lucairn`; future tools land server-side without a package re-publish).
- Tier-aware tool descriptors that reflect the auth'd account's current plan.
- Centralised, server-emitted protocol-version negotiation.

Trade-off: one extra round-trip vs `direct-http`, since each frame is serialized to HTTP rather than handled locally.

**Out of scope in v1.2:** the gateway's `GET /mcp` SSE channel is not bridged — server-initiated messages (notifications, progress, sampling) are stubbed as a future workstream. Only `POST /mcp` request/response round-trips are bridged.

## What the tool does

The server registers one MCP tool, `chat_via_lucairn`, which Claude (or any MCP client) can invoke:

- **Input:** `model` (string), `max_tokens` (number), `messages` (array of `{role, content}`), optional `system` (string), optional `temperature` (number).
- **Behavior:** POSTs the request to `${baseUrl}/api/v1/mcp/messages` with `x-api-key: ${apiKey}` and the optional `X-Upstream-Key` header. The gateway runs sanitization (Presidio + QI), forwards the redacted prompt to the upstream LLM, and returns an Anthropic Messages API response shape. Developer-tier responses keep placeholders visible; Pro and Enterprise tiers can re-link placeholders before delivery.
- **Output:** The LLM's text response, returned as the tool result.

The Anthropic-Messages request shape is documented in the gateway's [`MCPPayloadSchema`](https://github.com/Declade/dual-sandbox-architecture/blob/main/services/gateway/internal/api/mcp_payload_schema.go).

## How privacy works

- Every message is scanned for PII (names, emails, addresses, medical terms, etc.) before it reaches the LLM.
- Detected PII is replaced with safe placeholders. The LLM never sees raw personal data.
- Response handling is tier-aware: Developer keeps placeholders visible, while Pro and Enterprise can swap placeholders back before returning to the MCP client.
- A Lucairn Certificate is generated for each request — cryptographic proof of what was sanitized. View certificate summaries at https://lucairn.eu/verify or in your account audit trail.

See https://lucairn.eu/developer/mcp for the full setup guide.

## Smithery (URL-based publishing)

The Lucairn gateway can be listed on [Smithery](https://smithery.ai) as a remote MCP server — no install needed for users on Smithery-aware MCP clients. Listing publishes via the smithery.ai web UI (paste the URL `https://gateway.lucairn.eu/mcp` at [smithery.ai/new](https://smithery.ai/new)) or the Smithery CLI: `smithery mcp publish "https://gateway.lucairn.eu/mcp"`. No `smithery.yaml` schema is required — Smithery's URL-only publication path discovers the server's tool catalog directly from the gateway's MCP endpoint.

Once listed, Smithery prompts users for the `lucairnApiKey` (and optional Anthropic / OpenAI BYOK keys) at install time and forwards them on each request. Internally this is the same streamable-HTTP transport the `stdio-bridge` mode uses; either path lands on the gateway's `POST /mcp` endpoint.

## Limitations / known issues

- **Tested with Claude Desktop:** not yet end-to-end verified by the package author. Surface issues at https://github.com/Declade/lucairn-sdks/issues.
- **Streaming:** the gateway supports SSE streaming on the underlying endpoint (`stream: true` in the request body), but Claude Desktop's MCP tool-call protocol doesn't yet stream tool output back to the user. Both transport modes force non-streaming. Server-initiated SSE messages from `GET /mcp` (notifications, progress, sampling) are not bridged in v1.2 — future workstream.
- **Single tool surface in `direct-http`:** in `direct-http` mode the npm package owns a static catalog with one tool (`chat_via_lucairn`). In `stdio-bridge` mode the catalog comes from the gateway and grows automatically as new tools ship server-side.

## License

MIT — see [LICENSE](../LICENSE).
