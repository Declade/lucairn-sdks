# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [sdk 1.4.1] — 2026-10-11

Patch release of the simple certificate check (`verifyCertificate`, witness
signature only), together with `Python 1.4.2` and `Go v1.3.2` below. The three
SDKs now judge the same certificate the same way in the places listed here.
No change to the v2 / v3 signable bytes, to the reason codes, or to the public
API (T-1322).

### Fixed
- **The simple check applies its own Ed25519 rule before the crypto library
  is called.** Until now the key and signature went straight to the library,
  so the result for some inputs depended on the library build. Refused now,
  on every runtime, as the existing `invalid_signature`:
  - a signature that is not 64 bytes, has `S >= L`, or whose `R` is a
    non-canonical encoding (y >= p) or a small-order point (all 14
    encodings);
  - a public key that is a small-order encoding (all 14) or is not the
    canonical encoding of a curve point.

  Measured before this release, on a certificate whose witness signatures
  were made with nonce 0 (`R` = the identity): accepted on Node 22.23.3
  (OpenSSL 3.6.5) and Node 25.8.0 (OpenSSL 3.5.5), by Python `cryptography`
  42.0.0 and 50.0.2, and by Go 1.26.2 `crypto/ed25519`; refused on Node
  26.11.1 (OpenSSL 4.0.3). The 14 small-order public keys were accepted by
  the same runtimes and refused on Node 26.11.1.

  What this means: with an honestly generated, correctly pinned witness key,
  producing a signature with a small-order `R` needs the witness signing key,
  so that part is not a forgery by an outsider — it removes a result that
  differed by runtime. Separately, if a small-order PUBLIC key (for example
  the identity) was pinned by mistake, anyone could produce a signature the
  affected runtimes accepted for any certificate; the key check closes that.
  A malformed key (wrong length, bad base64) is reported as before.
- **Signature text.** The check first decides, as before, whether each of
  the two signature fields (`witness_signature`, `signable_v3_signature`) is
  blank or present, and from that `witness_signature_missing` and
  `version_downgrade_detected`. After that, every signature field that is
  present must be canonical standard padded base64 (alphabet
  `A-Z a-z 0-9 + /`, `=` padding, nothing else: decode, re-encode, compare),
  otherwise the result is `invalid_signature`. This includes
  `witness_signature` on a v3 certificate, where it is not the signature that
  is verified. Before, TypeScript accepted any text
  `Buffer.from(text, 'base64')` decodes (unpadded, URL-safe, embedded white
  space, trailing characters such as `!`), so a certificate with such a
  signature text verified in TypeScript and was refused in Python and Go.
  Go skipped CR / LF inside the text, and Go and Python accepted non-zero
  padding bits; both are refused now.
- **One white-space set for "is this signature field blank".** All three
  SDKs use the set of Go's `unicode.IsSpace` (U+0009–000D, U+0020, U+0085,
  U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000).
  TypeScript's `trim()` differed on two code points: a field holding only
  U+0085 is now blank (was: present) and a field holding only U+FEFF is now
  present (was: blank). Among signature-field inputs, one verifies now that
  was refused before, in TypeScript only: a legacy v2 certificate whose `signable_v3_signature`
  holds nothing but U+0085 is treated like one with an empty field, as Python
  and Go already did.

### Changed
- One value rule for `protocol_version` and
  `signable_protocol_version_emitted`, in all three SDKs: the value must be a
  JSON number that is an integer from 0 to 2^64 − 1; anything else — a
  fraction, a negative, a string, a boolean, an array, a number too large —
  is `malformed`. An absent or `null` `signable_protocol_version_emitted`
  still means 0. In TypeScript this changes which existing reason some
  garbage input gets: a `protocol_version` of `2.5`, `-2` or a number too
  large for a double was `unsupported_protocol_version` and is `malformed`
  now; a `signable_protocol_version_emitted` given as `"3"`, `[3]` or `3.5`
  was used as if it were 3 and is `malformed` now.

### Unchanged
- v2 / v3 signable reconstruction, verdict names, reason codes, exports.

### Known limits
These apply to the simple check in all three packages after this release.
Items 1 and 4 are input paths on which the three SDKs can still give
different results.
1. Given an already parsed object, the simple check judges values;
   number-token rules apply only where an SDK reads the raw text (Go with raw
   bytes). A number written `2.0000000000000001` in the JSON text is the
   value 2 once parsed, so TypeScript and Go with map input accept it; the
   signed bytes are rebuilt from the value.
2. The base64 form of the PUBLIC KEY argument is not normalised the same way
   in the three SDKs: TypeScript accepts unpadded text and trailing
   characters that Python and Go refuse.
3. The simple check does not validate every claim field the same way in the
   three SDKs. Examples: a claim without `request_id` or `service_id`, a
   `signable_v3_signature` that is not a string, a sanitizer
   `canonical_payload` with trailing characters.
4. A double cannot hold every integer between 2^53 and 2^64, so TypeScript
   and Go with map input do not see such a value as written. A
   `protocol_version` in that range is refused everywhere, but the reason can
   differ (`malformed` or `unsupported_protocol_version`). A
   `signable_protocol_version_emitted` of exactly 2^64 − 1 is read as a v3
   marker by Python and by Go with raw bytes and is `malformed` in TypeScript
   and Go with map input. That field is not signed; it only selects which
   signature must verify.
5. Per-call cost: the key check adds two modular exponentiations to every
   verification (measured about 45 → 219 µs on Node 22 and 35 → 189 µs on
   Python 3.12).
6. The simple check accepts a certificate that carries only the older (v2)
   witness signature. Values that only the newer (v3) signature covers
   (`api_key_id`, `client_id`, `byok_exempt`, the sanitizer hashes) are then
   not vouched for by the result. Callers who need those values vouched for
   pass the require-v3 option — TypeScript `minimumSignableVersion: 'v3'`,
   Python `minimum_signable_version="v3"`, Go
   `VerifyCertificateKeys.MinimumSignableVersion: "v3"` — which refuses a
   certificate verified on the v2 path, or use the chain verifier once it is released.

## [Python 1.4.2] — 2026-10-11

Same release as `sdk 1.4.1` above; see there for the Ed25519 rule, the
measurements and the base64 rule (T-1322).

### Fixed
- `verify_certificate` / `verify_ed25519` apply the same Ed25519 rule before
  `cryptography` is called (small-order or non-canonical `R`, `S >= L`,
  small-order or invalid public key → `invalid_signature`).
- A signature field holding only U+001C–U+001F is no longer treated as blank
  (`str.strip()` strips those four characters; the shared white-space set
  does not contain them). Before, a certificate without the v3 version field
  whose `signable_v3_signature` was just U+001C verified as v2; it is now
  refused as `version_downgrade_detected`, as in TypeScript and Go.
- A signature field that is present must be canonical standard padded
  base64 — also `witness_signature` on a v3 certificate — otherwise
  `invalid_signature`; non-zero base64 padding bits are refused.
- `verify_ed25519` takes the signature and the message through the buffer
  protocol (`bytes`, `bytearray`, `memoryview`, `array.array`, ...) on every
  supported `cryptography` version; anything else raises `TypeError`.

### Changed
- The value rule of `sdk 1.4.1` for `protocol_version` and
  `signable_protocol_version_emitted`: an `int` (not `bool`) from 0 to
  2^64 − 1, otherwise `malformed`. This changes which existing reason some
  garbage input gets: a negative or too large `protocol_version` was
  `unsupported_protocol_version`; a `signable_protocol_version_emitted` given
  as the string `"3"` was used as 3. The same range is applied to a
  `VeilCertificate` instance passed in directly. A `float` is `malformed`
  even when it is integral: a `signable_protocol_version_emitted` written
  `3.0` (some JSON re-serialisers write integers that way) was read as 3
  from a dict and is `malformed` now; write it as `3`. With default interpreter
  settings `json.loads` itself refuses an integer of more than 4,300 digits
  before the SDK is called.

See "Known limits" under `sdk 1.4.1`.

## [Go v1.3.2] — 2026-10-11

Same release as `sdk 1.4.1` above; see there for the Ed25519 rule, the
measurements and the base64 rule (T-1322).

### Fixed
- `VerifyCertificate` applies the same Ed25519 rule before `crypto/ed25519`
  is called (small-order or non-canonical `R`, `S >= L`, small-order or
  invalid public key → `ReasonInvalidSignature`).
- A signature field that is present must be canonical standard padded
  base64 — also `witness_signature` on a v3 certificate — otherwise
  `ReasonInvalidSignature`. `base64.StdEncoding` skipped CR / LF and accepted
  non-zero padding bits.
- The two version fields are no longer converted from `float64` to `int`
  when out of range. That conversion gives different results on arm64 and
  amd64, so a value of 2^63 or more could lead to a different verdict per
  CPU architecture.

### Changed
- With `[]byte` / `json.RawMessage` input, `protocol_version` and
  `signable_protocol_version_emitted` must be written as plain integers
  (digits only — no sign, fraction or exponent — at most 20 digits and at
  most 2^64 − 1), otherwise the result is `ReasonMalformed`. Before, the
  token `2.0` or `2.0000000000000001` was read as 2 and the certificate
  verified. Input given as `map[string]any` or `*VeilCertificate` is judged
  by value: the caller's own decoder has already turned the token into a
  number.
- The value rule of `sdk 1.4.1` for both fields, with raw bytes, map and struct input alike: an
  integer from 0 to 2^64 − 1, otherwise `ReasonMalformed`. This changes
  which existing reason some garbage input gets: a negative
  `protocol_version` was `ReasonUnsupportedProtocolVersion`; a
  `signable_protocol_version_emitted` that was a string, a boolean or an
  array was ignored (treated as 0), and a fraction was truncated. A
  `signable_protocol_version_emitted` from 2^63 up to 2^64 − 1 is now read
  as a v3 marker on every architecture; before, such a value could be read
  as 0 or as a negative number, depending on the CPU architecture and the
  input form, and the certificate was then refused as
  `ReasonVersionDowngradeDetected`. The field is not signed; it only selects
  which signature must verify.

See "Known limits" under `sdk 1.4.1`.

## [Python 1.4.1] — 2026-08-22

### Fixed
- **30s-timeout / 202-receipt race, narrowed (T-702).** `_DEFAULT_TIMEOUT_S`
  (`python/src/lucairn/client.py`) was `30.0`, with a comment citing
  "TS DEFAULT_TIMEOUT_MS = 30_000" — a constant that no longer exists.
  `ts/src/client.ts:40` moved to `DEFAULT_TIMEOUT_MS = 60_000` in the
  CON-07 fix (`f874f0a`, 2026-05-28 hardening audit). 30s is the
  gateway's **default** sync-wait timeout (after which it returns a 202
  processing receipt with a `job_id`); it is configurable
  (`GATEWAY_WAIT_TIMEOUT`), and both hosted compose files already pin it
  to 120s, with the live pilot box running an even higher override. The
  Python SDK's stale 30s default meant a caller against an unconfigured
  gateway on a ~30s turn timed out exactly at the receipt handoff and
  never saw the `job_id` to poll. Bumped `_DEFAULT_TIMEOUT_S` to `60.0`
  and the comment now cites the live TS constant — this restores
  cross-SDK parity with TS and narrows the race, but does **not**
  structurally close it against a gateway configured above 60s; callers
  with long-running turns (e.g. L3) should pass an explicit timeout at or
  above the gateway's configured wait. No API surface change — behavior-
  only default change; callers who don't override the timeout now wait
  up to 60s (was 30s) before a timeout error on a dead/unreachable
  gateway.

## [Go v1.3.1] — 2026-08-22

### Fixed
- **30s-timeout / 202-receipt race, narrowed (T-702).** Same defect and
  fix as `Python 1.4.1` above, in `go/lucairn.go`'s `DefaultTimeout`
  constant (was `30 * time.Second`, citing the same dead TS constant).
  Bumped to `60 * time.Second`, comment now cites the live
  `ts/src/client.ts:40` value and the gateway's **default** (configurable)
  30s sync-wait boundary — see the `Python 1.4.1` entry above for the
  full boundary detail; this bump restores cross-SDK parity with TS and
  narrows the race, it does not structurally close it against a gateway
  configured above 60s. No API surface change; callers who don't override
  the timeout now wait up to 60s (was 30s) before a timeout error on a
  dead/unreachable gateway.

## [mcp-server 1.2.9] — 2026-07-17

### Fixed
- **Broken 1.2.8 publish (missing `dist/`).** `1.2.8` shipped to npm with only
  `LICENSE`, `README.md`, and `package.json` — no compiled code — because
  `dist/` is gitignored and there was no build hook to run it before packing.
  Publishing from a clean checkout (no prior local `npm run build`) packed
  zero code; `1.2.7` only worked because `dist/` happened to already exist in
  the publisher's working directory at the time.
- Added `"prepack": "npm run build"` to `mcp-server/package.json` `scripts`.
  `prepack` runs automatically before both `npm pack` and `npm publish`,
  so publishing now always compiles `dist/` first regardless of the
  publisher's local build state.
- Version bumped 1.2.8 → 1.2.9 (1.2.8's version number is burned on the
  registry with broken content; publish 1.2.9 instead of re-publishing 1.2.8).

## [sdk 1.4.0] — 2026-06-26

### Fixed
- **Canonical-JSON aligned to the witness signer (M3).** The TS canonical-JSON
  verifier (`ts/src/verify-certificate/canonical-json.ts`) now reconstructs the
  witness signer's bytes exactly: every UTF-16 code unit `>= U+0080` is escaped
  to a lowercase `\uXXXX` (a supplementary-plane rune renders as its surrogate
  pair `\uHHHH\uLLLL`), and `<`, `>`, `&` are emitted **literally** (the witness
  does NOT HTML-escape them — the previous `escapeHtmlSafe(JSON.stringify(...))`
  path both HTML-escaped `<>&` and emitted raw UTF-8 for non-ASCII, diverging on
  both axes). `U+2028` / `U+2029` are `>= U+0080` and so escape through the same
  path. The UTF-8 byte-wise key sort (from the prior release) is unchanged.
  **Backward-compatible, NOT a protocol bump:** the signable shape is unchanged
  and existing ASCII certificates produce byte-identical output (the ASCII
  signable-freeze fixtures are untouched). The only behavioural change: a
  certificate whose signable carries a non-ASCII byte or `<>&` now verifies
  (it previously failed `invalid_signature`). Cross-language **golden** test
  added — `canonicalJson` is asserted byte-identical to the witness's
  `pkg/veil/canonical.go` `CanonicalJSON` on a non-ASCII vector (é, à, em-dash,
  unicorn emoji surrogate pair, `<>&`, `U+2028/2029`, control chars, non-ASCII
  keys, nested + array-of-maps), via a fixture shared with the Go and Python
  golden tests. Closes the latent witness↔SDK divergence (M3). Publish before
  any non-ASCII `org_id` / `client_id` is introduced upstream.

## [Python 1.4.0] — 2026-06-26

### Fixed
- **Canonical-JSON aligned to the witness signer (M3).** `canonical_json`
  (`python/src/lucairn/verify_certificate/canonical_json.py`) now serializes
  leaves with `json.dumps(..., ensure_ascii=True)` — byte-identical to the
  witness signer — and the explicit `<>&` HTML-escaping (and the redundant
  `U+2028`/`U+2029` post-processing) has been removed: `ensure_ascii=True`
  escapes every codepoint `>= U+0080` to a lowercase `\uXXXX` (supplementary
  plane → surrogate pair) and emits `<`, `>`, `&` literally, matching the
  witness. Lone / mismatched UTF-16 surrogates are still rejected as a typed
  `TypeError` (now via an explicit pre-serialization guard, since
  `ensure_ascii=True` would otherwise emit them). Backward-compatible, NOT a
  protocol bump — see the `sdk 1.4.0` entry. Shared cross-language golden test
  added.

## [Go v1.3.0] — 2026-06-26

### Fixed
- **Canonical-JSON aligned to the witness signer (M3).** `verify.CanonicalJSON`
  (`go/internal/verify/canonical.go`) replaces the previous `json.Marshal`
  (default `SetEscapeHTML(true)`) leaf encoding — which HTML-escaped `<>&` and
  emitted raw UTF-8 for non-ASCII — with an explicit port of the witness's
  `encodePythonAsciiString`: every rune `>= U+0080` → lowercase `\uXXXX`
  (supplementary plane → UTF-16 surrogate pair), control chars → short escapes
  or `\u00XX`, `U+007F` → ``, and `<`, `>`, `&` emitted literally. Map
  keys are sorted bytewise over their UTF-8 bytes at every nesting level via
  explicit recursion (no longer relying on `json.Marshal`'s key ordering).
  Backward-compatible, NOT a protocol bump — the v2/v3 signable-freeze fixtures
  are byte-identical. Shared cross-language golden test added.

## [ts 1.2.0] — 2026-06-10

### Added
- **v3 dual-protocol certificate verification** (`verifyCertificate`). When
  `cert.signable_protocol_version_emitted >= 3` and `cert.signable_v3_signature`
  is present, the SDK verifies the 13-key v3 signable map (7 v2 keys + 6
  promoted carry-forwards: `client_id`, `api_key_id`, `byok_exempt`,
  `redaction_manifest_hash`, `sanitized_fields_body_hash`, `tms_manifest_hash`)
  and returns `signableVersion: 'v3'` on the result. Legacy certs and dual-
  protocol certs served to v0.5.x callers continue verifying via the 7-key v2
  path and return `signableVersion: 'v2'`. Both paths use the same Ed25519
  witness key — no caller change required. (PRD criterion #7/#8.)
- `signableVersion: 'v2' | 'v3'` field on `VerifyCertificateResult`.
- `api_key_id`, `signable_v2_signature`, `signable_v3_signature`,
  `signable_protocol_version_emitted` optional fields on `VeilCertificate` type.
- `deriveWitnessSignedBytesV3` exported from `verify-certificate/signable.ts`.
- `normalizeIssuedAt` exported from `verify-certificate/signable.ts` (regression-
  test surface; not a primary SDK API).

### Fixed
- **`issued_at` RFC3339Nano normalization (H6)**: the witness signs
  `issuedAt.Format(time.RFC3339Nano)` which strips trailing fractional-second
  zeros (e.g., `.1Z`), but the gateway serves the cert via protojson which
  zero-pads to 9 digits (e.g., `.100000000Z`). The SDK now normalizes the
  protojson form before placing `issued_at` in the signable bytes, fixing
  ~10% of certs that would otherwise fail verify. Applied to both v2 and v3
  signable reconstruction paths.

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
