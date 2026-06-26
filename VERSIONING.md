# Versioning policy & compatibility matrix

This monorepo ships **four independently versioned packages**. Despite the
README phrase "four packages at parity", the packages do **not** move in
lockstep — `@lucairn/mcp-server` evolves faster than the three SDKs because it
carries MCP-transport and tool-formatting fixes that the SDKs do not. "Parity"
in the README means **observable behavioural parity** (same pipeline, same
error taxonomy, byte-identical certificate verification), not identical
version numbers.

This document is the authoritative source for:

1. Which version each package is at, and how they relate.
2. How an SDK version maps to the gateway **Veil certificate
   `protocol_version`** it can verify.
3. The independent-versioning rules each package follows.

## Packages

| Package                                   | Ecosystem | SemVer | Source dir   |
|-------------------------------------------|-----------|--------|--------------|
| `@lucairn/mcp-server`                     | npm       | yes    | `mcp-server/`|
| `@lucairn/sdk`                            | npm       | yes    | `ts/`        |
| `lucairn`                                 | PyPI      | yes    | `python/`    |
| `github.com/declade/lucairn-sdks/go`      | Go module | yes    | `go/`        |

The canonical version for each package lives in:

- `mcp-server/package.json` → `version`
- `ts/package.json` → `version`
- `python/pyproject.toml` → `[project].version`
- `go/` → the repo git tag `go/vX.Y.Z` (Go modules version by tag, not by a
  file in-tree)

The single root [`CHANGELOG.md`](CHANGELOG.md) records all four packages, with
each entry headed by the package + version it applies to (e.g.
`## [mcp-server 1.2.6]`, `## [sdk 1.1.1]`). There is one changelog, not four.

## SDK version → gateway certificate `protocol_version`

The Lucairn gateway stamps each Veil certificate with a `protocol_version`.
The certificate-verification pipeline in each SDK accepts exactly **one**
`protocol_version` and rejects any other with the
`unsupported_protocol_version` failure reason. This is a deliberate
fail-closed posture: a certificate signed under a future protocol revision
with a different signing rule must not silently "verify" against an older SDK.

The supported version is pinned in:

- TypeScript — `ts/src/verify-certificate/index.ts` (`SUPPORTED_PROTOCOL_VERSION`)
- Python — `python/src/lucairn/verify_certificate/pipeline.py` (`SUPPORTED_PROTOCOL_VERSION`)
- Go — `go/` (`ReasonUnsupportedProtocolVersion` gate in `errors.go` + verify pipeline)

| SDK package           | SDK version range | Verifiable gateway `protocol_version` |
|-----------------------|-------------------|---------------------------------------|
| `@lucairn/sdk`        | 1.4.x             | 2                                     |
| `lucairn` (Python)    | 1.4.x             | 2                                     |
| `github.com/declade/lucairn-sdks/go` | v1.3.x | 2                                |
| `@lucairn/mcp-server` | 1.2.x             | 2 (delegates verification to the bundled verify pipeline) |

> **Canonical-JSON encoding alignment (sdk 1.4.0 / Python 1.4.0 / Go v1.3.0).**
> These releases align the SDK canonical-JSON verifier to the witness signer's
> exact bytes: every codepoint `>= U+0080` is escaped to a lowercase `\uXXXX`
> (supplementary plane → UTF-16 surrogate pair) and `<` `>` `&` are emitted
> **literally** (the witness does NOT HTML-escape them). This is a
> **backward-compatible** fix, **NOT** a protocol bump — the signable *shape*
> (7-key v2 / 13-key v3) is unchanged, so the verifiable `protocol_version`
> stays `2`. Every existing ASCII certificate produces byte-identical output
> under the old and new encoders (proven by the unchanged ASCII signable-freeze
> fixtures); the only observable change is that a future certificate whose
> signable carries a non-ASCII byte or `<>&` now verifies (it previously failed).
> Publish the aligned encoders before any non-ASCII `org_id` / `client_id` is
> introduced upstream.

All four packages currently verify `protocol_version = 2` only. A future
gateway protocol bump (→ 3) will be a **coordinated** SDK release across all
four packages, because the witness signable reconstruction is schema-locked:
adding or reshaping any field that is part of the canonicalized verify-bytes
breaks every verifier already in the wild. See the project `CLAUDE.md` "Witness
signable map = 7 keys, UNCHANGED" locked decision and the
`verify-certificate/signable` modules in each SDK for the exact reconstruction
paths that must be updated together.

## Independent-versioning rules

1. **Each package versions on its own cadence.** A bug fixed only in the MCP
   transport bumps `@lucairn/mcp-server` alone; the SDKs do not get a courtesy
   bump.
2. **Behavioural-parity changes ship across all SDKs together.** Anything that
   changes the observable contract of the three SDKs (a new method, a changed
   error class, a request/response field) should land in the same release wave
   for `@lucairn/sdk`, `lucairn`, and the Go SDK, even if the version numbers
   differ. Cross-language byte-equivalence is enforced by shared
   Go-assembler-generated fixtures; a parity change that skips one SDK will
   break the cross-language fixture tests.
3. **SemVer applies per package.** A breaking change to a package's public
   surface (e.g. removing the deprecated `TheVeil*` aliases) is a **major**
   bump for that package only.
4. **`protocol_version` changes are coordinated and breaking.** Because the
   signable reconstruction is schema-locked, a gateway `protocol_version` bump
   requires a synchronized release of all four packages and is treated as a
   minor-or-major bump per package depending on whether old certificates remain
   verifiable.
5. **The required-response-field set is intentionally minimal and language-
   asymmetric.** The Go SDK validates a deliberately narrower 2xx required-field
   set than the TypeScript SDK's certificate parser (see the asymmetry note in
   `go/lucairn.go` `validateVeilCertificate`). This asymmetry is a locked
   decision — do not "align" the validators without reopening it.

## Releasing

Before publishing any package, reconcile its in-tree version with what is (or
is about to be) on the registry, and add a `CHANGELOG.md` entry headed by the
package + version. The README per-language version table
([`README.md`](README.md) "Per-language SDKs") should be updated in the same
change so the published version, the in-tree version, and the documented
version all agree.
