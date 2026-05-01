# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **MCP server [1.0.0]** — new `@lucairn/mcp-server` package at
  `mcp-server/`. Stdio-transport Model Context Protocol server that
  wraps the Lucairn gateway's `POST /api/v1/mcp/messages` endpoint
  (Anthropic Messages API-compatible) and exposes it to Claude Desktop
  and any other MCP client as a single tool, `chat_via_lucairn`.
  Pinned to `@modelcontextprotocol/sdk` `^1.29.0`. Supports both
  `DSA_*` and `LUCAIRN_*` env-var prefixes for backward-compat during
  the Stage 3 rebrand. No `@lucairn/sdk` dependency — HTTP-direct to
  the gateway. `dist/` is the published surface; `npx -y
  @lucairn/mcp-server` is the canonical Claude Desktop entry per
  `theveil-website/src/app/[lang]/developer/mcp/page.tsx:9-21`.
- **Python [0.1.0]** — first full implementation. `theveil` on PyPI.
  `TheVeil` client with `messages`, `get_certificate`,
  `verify_certificate`. Six typed exception classes (`TheVeilError`
  base + `TheVeilConfigError` / `TheVeilHttpError` /
  `TheVeilResponseValidationError` / `TheVeilTimeoutError` /
  `TheVeilCertificateError`). `TheVeilResponseValidationError` is
  raised on a 2xx response whose body doesn't fit the declared type
  (wrong shape OR over-cap), distinct from `TheVeilHttpError` which
  is reserved for non-2xx transport failures + the 202 pending
  wrapper. Full `VeilCertificate` + sub-type Pydantic models with
  `extra='ignore'` to match TS thin-transport. `httpx` sync client;
  async client in a later arc. Cross-language byte-equivalence via
  Go-assembler-reference hex fixture + Go-oracle-signed cert fixture.
  155+ tests passing on Python 3.10–3.13.
- **Go [v0.1.0]** — first full implementation. Module
  `github.com/declade/theveil-sdks/go`. `theveil.Client` with
  `Messages`, `GetCertificate`, `VerifyCertificate`. Six typed error
  structs satisfying a `theveil.Error` interface, all with `Unwrap()`
  for `errors.As`/`errors.Is`: `*ConfigError`, `*HTTPError`,
  `*ResponseValidationError`, `*TimeoutError`, `*NetworkError`,
  `*CertificateError`. `*ResponseValidationError` surfaces on a 2xx
  response whose body fails to decode OR fails required-field
  validation (json.Unmarshal is permissive — a body like
  `{"unrelated":"junk"}` would otherwise zero-value the struct), OR
  on a 2xx over-cap body. Functional options pattern (`WithBaseURL`,
  `WithTimeout`, `WithHTTPClient`, `WithMaxResponseBytes`,
  `WithCallTimeout`, `WithCallHeader`). Zero runtime dependencies.
  `context.Context` for cancellation/timeout. Cross-language byte-
  equivalence via the same shared fixtures. 97+ tests passing on
  Go 1.22–1.23; `go vet` and `go test -race` clean.
- Monorepo scaffolding (TypeScript subdir initialized; Python and Go placeholders)
- TypeScript: `TheVeil` client with `apiKey` validation, `baseUrl` normalization,
  per-call timeout composition, and four typed error classes
  (`TheVeilError`, `TheVeilConfigError`, `TheVeilHttpError`,
  `TheVeilTimeoutError`).
- TypeScript: `client.messages(params, options?)` against
  `/api/v1/proxy/messages`, returning a `ProxyResponse` discriminated union
  over sync (200) vs. async-processing (202) gateway results.
- TypeScript [0.2.0]: `client.getCertificate(requestId, options?)` against
  `GET /api/v1/veil/certificate/{request_id}`, returning a narrow
  `Promise<VeilCertificate>`. The gateway's 202 pending wrapper surfaces as
  `TheVeilHttpError{ status: 202, body: { status: "pending",
  retry_after_seconds, ... } }` so the happy-path type stays narrow and
  callers get an explicit retry signal on the error branch. `requestId` is
  `encodeURIComponent`-wrapped before URL interpolation. No auto-verify —
  chain `verifyCertificate()` explicitly.

### Changed
- TypeScript: proxy-specific types now carry a `Proxy` prefix
  (`ProxyMessagesRequest`, `ProxyResponse`, `ProxyPIIAnnotation`) so future
  endpoint families can introduce their own non-conflicting type names.
- **Breaking** — TypeScript: `TheVeil.apiKey` is now a JS private class
  field (`#apiKey`). Reading `client.apiKey` returns `undefined` at runtime
  and is a TS error at compile time. The constructor input shape
  `{ apiKey, baseUrl?, timeoutMs? }` is unchanged.

### Security
- TypeScript: API key storage moved to a JS private class field so the
  credential cannot leak through `JSON.stringify`, `util.inspect`,
  structured-clone, or compile-time property access on the client instance.
