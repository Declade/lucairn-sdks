# Lucairn SDKs

Official client libraries for **[Lucairn](https://lucairn.eu)** — an EU-based privacy-preserving AI gateway. Lucairn sits between your application (or AI agent) and the upstream LLM (Claude, GPT-4o, o1/o3/o4) and removes personal data from prompts before the model ever sees them. Every response carries a cryptographically signed compliance certificate proving what was redacted, when, and by which sanitizer layer.

This monorepo hosts four packages at parity:

- **`@lucairn/mcp-server`** — Model Context Protocol server (one-line `npx` install for Claude Desktop, Cursor, Cline, Continue, …)
- **`@lucairn/sdk`** — TypeScript / Node SDK
- **`lucairn`** — Python SDK
- **`github.com/declade/lucairn-sdks/go`** — Go SDK

## Quick start (MCP)

For most agent use cases, the fastest path is the MCP server. No build step, no install — `npx` runs it on demand:

```bash
npx -y @lucairn/mcp-server
```

Add it to your MCP client config (Claude Desktop's `claude_desktop_config.json`, Cursor's `mcp.json`, Cline's `cline_mcp_settings.json`, Continue, etc.):

```json
{
  "mcpServers": {
    "lucairn": {
      "command": "npx",
      "args": ["-y", "@lucairn/mcp-server"],
      "env": {
        "LUCAIRN_API_KEY": "<your_lucairn_api_key>",
        "ANTHROPIC_API_KEY": "<optional_byok_anthropic_key>",
        "OPENAI_API_KEY": "<optional_byok_openai_key>"
      }
    }
  }
}
```

Restart your client. The `chat_via_lucairn` tool becomes available immediately. See [`mcp-server/README.md`](mcp-server/README.md) for full details.

## What it does

Each request through any Lucairn SDK follows the same pipeline:

1. **PII detection** runs on every user message in three layers:
   - **Layer 1** — Known-entity matching (your tenant's named entities)
   - **Layer 2** — Presidio NER (names, emails, IBANs, addresses, phone numbers, customer IDs, …)
   - **Layer 3** — GPU-hosted custom-trained PII shield (**Enterprise tier only**, optionally trained on your domain corpus)
2. Detected PII is replaced with placeholders (`[PERSON_1]`, `[EMAIL_2]`, `[IBAN_3]`, …) **before** the request reaches the upstream LLM.
3. The upstream model (Claude or OpenAI) sees only the sanitized text. It never receives raw personal data.
4. The response is returned with a signed compliance certificate (Ed25519 witness signature + RFC 3161 timestamp + Sigstore Rekor inclusion proof).
5. **Response handling depends on tier:**
   - **Developer (free)** — placeholders are returned verbatim. Useful for testing the redaction surface.
   - **Pro / Enterprise** — placeholders are re-linked back to the originals on the gateway before the response reaches your application.

For Lucairn-hosted Developer-tier callers, on-gateway pseudonymization happens before your LLM sees the request. Enterprise self-host deployments can run the entire stack inside the customer environment, in which case no raw identity data leaves that environment at all.

## Provider routing

The gateway picks the upstream provider from the `model` parameter you send:

| Model prefix                                         | Upstream provider | BYOK env var        |
|------------------------------------------------------|-------------------|---------------------|
| `claude-*`, `anthropic-*`                            | Anthropic         | `ANTHROPIC_API_KEY` |
| `gpt-*`, `openai-*`, `o1-*`, `o3-*`, `o4-*`          | OpenAI            | `OPENAI_API_KEY`    |

Cross-provider BYOK shipped in `@lucairn/mcp-server@1.1.0` — set one or both keys in the same MCP config and the server forwards the matching one as `X-Upstream-Key` per request, so your provider account is billed directly.

## Per-language SDKs

| Language       | Package                                   | Version | README                              |
|----------------|-------------------------------------------|---------|-------------------------------------|
| MCP server     | `@lucairn/mcp-server`                     | 1.2.0   | [mcp-server/README.md](mcp-server/README.md) |
| TypeScript     | `@lucairn/sdk`                            | 1.0.0   | [ts/README.md](ts/README.md)        |
| Python         | `lucairn`                                 | 1.0.0   | [python/README.md](python/README.md) |
| Go             | `github.com/declade/lucairn-sdks/go`      | v0.1.0  | [go/README.md](go/README.md)        |

All SDKs are at parity at the observable level. Cross-language byte-equivalence is locked via shared Go-assembler-generated fixtures, so a certificate signed via one SDK verifies identically via the other two.

## Get an API key

Sign up at [https://lucairn.eu/account/signup](https://lucairn.eu/account/signup). Free Developer tier: **500 requests/month, no credit card required.**

Pro adds response re-linking, programmatic certificate JSON access, audit-event export, and higher quota. Enterprise adds self-host, BYOK with provider-side billing isolation, and the optional custom-trained PII shield (priced per scope).

See [https://lucairn.eu/pricing](https://lucairn.eu/pricing) for the full tier comparison.

## Verify a response

Every response through any SDK gets a signed Lucairn certificate. Two surfaces:

- **HTML summary** — DPO-friendly, available on every tier including Developer (free). Use `getCertificateSummary` (TS) / `get_certificate_summary` (Python) / `GetCertificateSummary` (Go), or paste the certificate URL into [https://lucairn.eu/verify](https://lucairn.eu/verify).
- **JSON certificate + local Ed25519 verify** — Pro tier and above. Use `getCertificate` + `verifyCertificate` (and language equivalents). The verifier is in-tree — see [`ts/src/verify-certificate/`](ts/src/verify-certificate/), [`python/src/lucairn/verify_certificate/`](python/src/lucairn/verify_certificate/), and the `internal/verify` package under [`go/`](go/).

External RFC 3161 + Sigstore Rekor anchor verification is currently surfaced as pass-through metadata; full external anchor verification lands in a follow-up release.

## Status

Pre-1.0 monorepo, individual packages tagged per the table above. Cross-language byte-equivalence locked via shared fixtures. Follow [CHANGELOG.md](CHANGELOG.md) for release notes.

## Links

- **Main site**: [https://lucairn.eu](https://lucairn.eu)
- **Sign up (free Developer tier)**: [https://lucairn.eu/account/signup](https://lucairn.eu/account/signup)
- **Pricing**: [https://lucairn.eu/pricing](https://lucairn.eu/pricing)
- **MCP setup guide**: [https://lucairn.eu/developer/mcp](https://lucairn.eu/developer/mcp)
- **OpenAI SDK setup guide**: [https://lucairn.eu/developer/openai](https://lucairn.eu/developer/openai)
- **Verify a certificate**: [https://lucairn.eu/verify](https://lucairn.eu/verify)
- **Glama listing**: [https://glama.ai/mcp/servers/Declade/lucairn-sdks](https://glama.ai/mcp/servers/Declade/lucairn-sdks)
- **npm — `@lucairn/mcp-server`**: [https://www.npmjs.com/package/@lucairn/mcp-server](https://www.npmjs.com/package/@lucairn/mcp-server)
- **npm — `@lucairn/sdk`**: [https://www.npmjs.com/package/@lucairn/sdk](https://www.npmjs.com/package/@lucairn/sdk)
- **PyPI — `lucairn`**: [https://pypi.org/project/lucairn/](https://pypi.org/project/lucairn/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
