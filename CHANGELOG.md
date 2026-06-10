# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [Go v1.2.0] — 2026-06-10

### Added
- **v3 dual-protocol certificate verification** — `VerifyCertificate` now
  dispatches on `signable_protocol_version_emitted`: certs with value `>= 3`
  are verified against `signable_v3_signature` (13-key signable map); legacy
  certs without that field use the unchanged v2 path (7-key map, byte-identical).
  PRD criterion #7. Source: `go/internal/verify/pipeline.go`,
  `go/internal/verify/v3_signable.go`.
- `VerifyCertificateResult.SignableVersion` — `"v2"` or `"v3"` identifying
  which signable map was verified. PRD criterion #7.
- `DeriveV3SignedBytes` — internal v3 13-key signable reconstruction. Mirrors
  `dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:380-413`
  field-for-field. `go/internal/verify/v3_signable.go`.
- `ExtractSanitizerPayloadHash` — reads `redaction_manifest_hash`,
  `sanitized_fields_hash`, `tms_manifest_hash` from the dsa-sanitizer claim's
  `canonical_payload["payload"]`, surviving the gateway's server-side strip
  pipeline. Strip-surviving discipline from BLOCKER-1 (PR #247).
- `VeilCertificate.APIKeyID` (`*string`, proto field 15) — surfaces the
  gateway API-key metadata field added in Phase B.
- `VeilCertificate.SignableV2Signature`, `SignableV3Signature`,
  `SignableProtocolVersionEmitted` — surfaces the dual-protocol fields from
  v3 certs.
- **`issued_at` RFC3339Nano normalization** (H6 fix, ~10% verify-failure root
  cause) — `normalizeIssuedAt` strips trailing fractional-second zeros before
  placing `issued_at` in signable bytes. Applies to BOTH v2 and v3 paths.
  Protojson zero-padded form (`...878143387000000000Z`) now normalizes to the
  witness-signed form (`...878143387Z`). `go/internal/verify/signable.go`.
- **Real production cert round-trip test** —
  `TestDeriveV3SignedBytes_RealProductionCert_RoundTrip` verifies the full
  real production v3 cert against the production witness public key. Passes
  only if v3 signable reconstruction is byte-exact (Ed25519 verify). Located
  at `go/internal/verify/v3_signable_test.go`; fixture at
  `go/internal/verify/testdata/real-v3-cert.fixture.json`.
- v2 backward-compat test (`TestDeriveV3SignedBytes_V2BackwardCompat_SameRealCert`),
  H6 round-trip test (`TestDeriveV3SignedBytes_TrailingZeroIssuedAt_RoundTrip`),
  13-key freeze test (`TestDeriveV3SignedBytes_SignableContainsExactlyThirteenKeys`),
  and `TestNormalizeIssuedAt_TrailingZerosStripped`.

### Changed (internal, no API break)
- `RawCert` (internal `parse.go`) gains `SignableProtocolVersionEmitted`,
  `SignableV3Signature`, `RawClaims`, `ClientID`, `APIKeyID`, `ByokExempt`
  for v3 dispatch.

## [python 1.2.0] — 2026-06-10

### Added
- **v3 dual-protocol certificate verification** (SDK signable-versioning v3
  chain, criterion #7/#8). `verify_certificate` now dispatches on
  `signable_protocol_version_emitted`: certs with value `>= 3` are verified
  against `signable_v3_signature` using the new 13-key signable map (v2's 7
  keys + `client_id`, `api_key_id`, `byok_exempt`, `redaction_manifest_hash`,
  `sanitized_fields_body_hash`, `tms_manifest_hash`). Certs without the field
  fall back to the legacy 7-key v2 path (backward compat, criterion #8).
- `VerifyCertificateResult.signable_version` field: `'v3'` for new dual-protocol
  certs, `'v2'` for legacy certs (criterion #7).
- New `derive_v3_signed_bytes()` function in `verify_certificate/v3_signable.py`
  implementing the 13-key v3 reconstruction. Hash fields sourced from
  `dsa-sanitizer` claim's `canonical_payload` (strip-surviving; body bytes are
  gateway-stripped but the hashes survive in the sanitizer-signed inner JSON).
  `tms_manifest_hash` is `None`/`null` until TMS rewrite Slice 5 — accepted
  without error.
- `normalize_issued_at()` utility exported from `verify_certificate/signable.py`.

### Fixed
- **issued_at RFC3339Nano trailing-zero mismatch (H6, ~10% verify-failure class)**.
  The witness signs `issued_at` using Go `time.RFC3339Nano` which strips trailing
  zeros (e.g. `.1Z`). The gateway serves via protojson which zero-pads to 9 digits
  (e.g. `.100000000Z`). The SDK now normalizes the served timestamp before placing
  it into the signable bytes. Applied to both v2 and v3 reconstruction paths.
  Round-trip validated against a real production v3 cert (Ed25519 signature verifies
  against the live production witness key).

### Changed
- `VeilCertificate` Pydantic model gains optional fields: `api_key_id` (str|None),
  `signable_v2_signature` (str|None), `signable_v3_signature` (str|None),
  `signable_protocol_version_emitted` (int, default 0). All default-safe; older
  certs without these fields parse cleanly.

## [mcp-server 1.2.6] — 2026-05-14

### Fixed
- MCP tool result now normalizes Lucairn certificate URLs to the
  auth-less `/public-summary` endpoint in BOTH the human-readable
  trailer (already normalized in v1.2.5) AND the
  `structuredContent.compliance` payload (newly closed here).
  v1.2.5 introduced `publicCertificateUrl()` but applied it only to
  the trailer string; the `metadata.dsa_compliance` object that
  crosses the MCP `structuredContent` boundary still carried the
  auth-gated `/summary` URLs and returned 401 to MCP-client
  end-users that followed them. v1.2.6 introduces
  `publicComplianceMetadata()` which re-maps `veil_summary_url`
  AND `veil_certificate_url` on the `dsa_compliance` block before
  it leaves `formatToolResult()`, and the trailer now reads the
  pre-normalized `compliance.veil_summary_url` directly. Source:
  `mcp-server/src/server.ts:270-308`. Trailer-side bug latent from
  v1.0.0 through v1.2.4 (5 versions); structuredContent-side bug
  latent from v1.2.2 (when `structuredContent` was first emitted)
  through v1.2.5 (4 versions).

## [mcp-server 1.2.5] — 2026-05-14

### Added
- `publicCertificateUrl()` helper in `mcp-server/src/server.ts:293`.
  Rewrites a `/summary` path on a Lucairn certificate URL to the
  auth-less `/public-summary` route. Used by the human-readable
  `_Lucairn certificate: …_` trailer emitted by
  `formatToolResult()` so MCP-client end-users following the
  trailer link land on the public, auth-less endpoint rather than
  the auth-gated one that returns 401. See
  `mcp-server/src/server.ts:270-302`.

### Deprecated
- **v1.2.5 still emits auth-gated `/summary` URLs inside
  `structuredContent.compliance`; use v1.2.6.** v1.2.5 is a
  partial fix: the new `publicCertificateUrl()` helper rewrites
  only the trailer string and does NOT touch the
  `metadata.dsa_compliance` object that crosses the MCP
  `structuredContent` boundary. MCP clients that follow
  `structuredContent.compliance.veil_summary_url` or
  `veil_certificate_url` continue to hit the auth-gated route and
  receive 401. v1.2.6 closes the gap via
  `publicComplianceMetadata()`. This version will be marked
  deprecated on npm via `npm deprecate @lucairn/mcp-server@1.2.5
  "use v1.2.6 — partial fix; leaks auth-gated cert URLs in
  structuredContent"`.

## [mcp-server 1.2.4] — 2026-05-14

### Changed
- README + version table copy refreshed across the public SDK
  registry surfaces (`README.md`, `mcp-server/README.md`,
  `python/README.md`, `ts/README.md`, `go/README.md`,
  `python/pyproject.toml`, `python/src/lucairn/types.py`) to
  document the v1.2.x mcp-server lineage in lockstep with the
  TS/Python/Go SDK READMEs. Docs-only release; no code change.
  Cert-URL normalization did NOT ship in this version — that
  landed in v1.2.5 (trailer) and v1.2.6 (full).

## [mcp-server 1.2.3] — 2026-05-07

### Added
- `mcpName: "io.github.Declade/lucairn-mcp-server"` field on
  `mcp-server/package.json`. Required by the Official MCP Registry's
  npm-package verification step (without it,
  `mcp-publisher publish` returns
  `Registry validation failed for package.`).
- New `mcp-server/server.json` at the package root with the
  canonical Lucairn-shaped registry metadata: stdio transport, five
  environment variables (`LUCAIRN_API_KEY` required + optional
  BYOK `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` + optional
  `LUCAIRN_BASE_URL` / `LUCAIRN_TRANSPORT` overrides), repository
  URL, and `websiteUrl` pointing at the developer documentation
  page. Uses the `2025-12-11` server-schema revision.

### Changed
- Version bumped 1.2.2 → 1.2.3 so the `publish-mcp-server.yml`
  GitHub Action republishes with the new `mcpName` field (npm
  would otherwise 409 on a duplicate publish).

## [mcp-server 1.2.2] — 2026-05-07

### Added
- `CHAT_TOOL_DESCRIPTOR.annotations` — declares the canonical MCP
  hint set (`readOnlyHint:false`, `destructiveHint:false`,
  `idempotentHint:false`, `openWorldHint:true`, plus a `title`),
  mirroring the gateway streamable-HTTP descriptor at
  `services/gateway/internal/api/mcp_streamable.go:402-424`
  byte-for-byte.
- `CHAT_TOOL_DESCRIPTOR.outputSchema` — declares the response
  shape (`text`, `model`, `stop_reason`, `usage`, optional
  `compliance` block surfacing `metadata.dsa_compliance`).
- `formatToolResult()` now returns `structuredContent` alongside
  `content[]`. Required by the
  `@modelcontextprotocol/sdk@~1.29.0` type contract when a tool
  declares `outputSchema`; the canonical `content[]` text payload
  is unchanged.

### Changed
- Closes the Capability Quality gap on the Smithery listing
  (84 → 100). All annotation values match the gateway
  streamable-HTTP descriptor, keeping the npm package's
  direct-http path and the gateway's stdio-bridge path in lockstep.

## [mcp-server 1.2.1] — 2026-05-07

### Fixed
- Repository metadata in `mcp-server/package.json` now points at
  `https://github.com/Declade/lucairn-sdks` (the actual public repo
  the package is published from). The 1.2.0 manifest still carried
  the pre-Stage-2 `Declade/theveil-sdks` slug, so the Repository
  link on the npm package page rendered a 404 to visitors and
  Smithery-style listing crawlers. Source code unchanged from 1.2.0.

## [mcp-server 1.2.0] — 2026-05-06

### Added
- Opt-in `LUCAIRN_TRANSPORT=stdio-bridge` mode that turns
  `@lucairn/mcp-server` into a thin stdio↔HTTP bridge against the
  gateway's streamable-HTTP MCP endpoint at `POST /mcp` (live since
  2026-05-06 via dual-sandbox-architecture PR #135). Reads
  JSON-RPC frames from stdio via the SDK's
  `StdioServerTransport`, forwards each frame as
  `POST {baseUrl}/mcp` with `Authorization: Bearer lcr_live_*`, and
  writes the gateway's reply back to stdout. Per-request
  `X-Upstream-Key` selection mirrors the direct-http path's
  `pickUpstreamKey` for `tools/call` frames. Source:
  `mcp-server/src/bridge.ts`.
- Smithery card surface (Smithery web-UI publishing path).
- `LUCAIRN_TRANSPORT` validation: any value other than
  `direct-http` (default) or `stdio-bridge` exits non-zero with a
  clear error message naming the supported set
  (`mcp-server/src/server.ts:64-72`).

### Changed
- Default transport remains `direct-http`, byte-identical to
  v1.1.x. The bridge backend is opt-in only; no change in
  behaviour for callers who do not set `LUCAIRN_TRANSPORT`.

## [Python 1.1.2] — 2026-05-15

### Added
- `redaction_count: int | None = None` field on `ProxySyncResponse`. Mirrors
  the Anthropic-compatible `/v1/messages`
  (`metadata.dsa_compliance.redaction_count`,
  `dual-sandbox-architecture/services/gateway/internal/api/anthropic_types.go:331`)
  and OpenAI-compatible `/v1/chat/completions`
  (`metadata.dsa_compliance.redaction_count`,
  `…/openai_handler.go:944`) emission. The `/api/v1/proxy/messages` path
  does not currently emit the field at the top level — the SDK surface is
  forward-compatible so that callers receive it automatically when the
  gateway promotes it. Until that happens the field stays `None` and
  consumers should treat that as "data not available on this tier/path"
  rather than "zero redactions". Closes the workaround Hannah's example
  app at https://github.com/Declade/lucairn-example-feedback-summarizer
  carries (counting `[TYPE_N]` placeholders by regex).

### Fixed
- `__version__` in `lucairn/__init__.py` was pinned at `1.0.0` and had
  drifted from `pyproject.toml` (last at `1.1.1`). Both now read `1.1.2`.
  Surfaced as friction note #6 in Sim 1 M4
  (`Opus Advisor/specs/sim1-m4-build-app.md`).

## [Python 1.1.0] — 2026-05-08

### Added
- `ISOLATION_PROBE_BYOK_EXEMPT` literal value on `IsolationProbeStatus` and
  the matching probe-status enum surface, mirroring the gateway's
  `ISOLATION_PROBE_BYOK_EXEMPT` proto enum (`dual-sandbox-architecture`
  proto field on `IsolationProbeStatus`).
- `byok_exempt: bool = False` field on `VeilVerificationResult` (proto
  field number 9 on `VerificationResult`). Surfaces the gateway's
  BYOK-exempt verification flag while keeping backward-compat with older
  certs that omit the field.
- BYOK-exempt cert fixture (signed with the existing test keypair) plus
  parse + verify tests asserting end-to-end witness verification on
  byok_exempt certs.
- Backward-compat coverage: `verify_certificate` is now exercised against
  a pre-byok_exempt-shape cert to lock in that the 7-key witness signable
  map has not regressed (DRIFT-002).
- Signable freeze test (`TestSignableFreeze`) — pins
  `derive_witness_signed_bytes(cert_go_signed_reference)` byte-for-byte
  against the new `signable-go-reference.hex` fixture (TOB-001). Catches
  any future change to the 7-key signable map at the byte-identity layer
  rather than only at the signature-verification layer.

## [TypeScript 1.1.0] — 2026-05-08

### Added
- `ISOLATION_PROBE_BYOK_EXEMPT` literal added to the `IsolationProbeStatus`
  union type.
- `byok_exempt?: boolean` optional field on the `VeilVerificationResult`
  interface (proto field number 9). Optional rather than defaulted so the
  wire-absent state remains observable to TS callers.
- New BYOK-exempt cert fixture
  (`ts/src/verify-certificate/__fixtures__/cert-byok-exempt.json`), signed
  with the existing test keypair so SDK verification passes end-to-end.
- Parse + verify tests for the byok_exempt path.
- Backward-compat coverage: `verifyCertificate` is now exercised against
  a pre-byok_exempt-shape cert to lock in that the 7-key witness signable
  map has not regressed (DRIFT-002).
- Signable freeze test
  (`describe('deriveWitnessSignedBytes — signable freeze (TOB-001)')`) —
  pins `deriveWitnessSignedBytes(cert-go-signed-reference)` byte-for-byte
  against the new `signable-go-reference.hex` fixture (TOB-001).

## [Go v1.1.0] — 2026-05-08

### Added
- `ByokExempt bool` field on `VeilVerificationResult` with
  `json:"byok_exempt,omitempty"` (proto field number 9 on
  `VerificationResult`).
- Test asserting the field round-trips through SDK JSON parse and is
  surfaced on the parsed cert.
- Signable freeze test (`TestDeriveSignedBytes_MatchesSignableFreezeHex`
  + `TestDeriveSignedBytes_SignableContainsExactlySevenKeys`) in
  `go/internal/verify/canonical_test.go` — pins `DeriveSignedBytes`
  byte-for-byte against the new `signable-go-reference.hex` fixture
  (TOB-001) and asserts the 7-key invariant structurally.
- Cross-language docstring on the `ByokExempt` field documenting the
  Python / TS / Go absence-vs-false semantic asymmetry (DRIFT-001 /
  TOB-003).

## [Initial releases] — 2026-05-01

Initial public releases of `@lucairn/mcp-server` (1.0.0), `lucairn`
on PyPI (0.1.0), the `github.com/declade/theveil-sdks/go` Go module
(v0.1.0), and the TypeScript surface that preceded the
`@lucairn/sdk` rename. Listed under a single header because the
three language surfaces shipped against the same gateway contract
on the same day; the per-package entries below give the per-surface
detail.

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
