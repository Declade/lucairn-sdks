# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`lucairn-bundle-verify`: bundle format 2 (audit counter).** Reads the
  `audit/` folder (`events.json`, `proofs.json`, `roots.json`) and checks the
  per-conversation request counter (event hashes recompute, numbers run 1..N,
  every certificate's audit-signed claim names its entry, every counted
  request has its certificate), each counted request's inclusion in the audit
  log, and the audit roots (signature under the pinned `dsa-audit` key, Rekor
  entry made by that key for the root artifact). The tree size is taken from
  the signed root artifact only. A certificate removed together with its
  manifest line is now reported. Printed limits: a cut-off tail and the hour
  before a root is anchored. Format-1 bundles verify as before; older builds
  read format-2 bundles as TAMPERED. Each `audit/*.json` file is one object
  with one named array key and inclusion paths are lowercase hex (any other
  form is TAMPERED); a counter entry is accepted only for a certificate whose
  signed audit claim states that conversation and number, and every signed
  counter claim needs its entry; a format-2 bundle without a certificate is
  TAMPERED.

- **`lucairn-bundle-verify` (Go, `go/cmd/lucairn-bundle-verify`): offline verifier for
  per-conversation evidence bundles (bundle format 1).** Checks the manifest,
  witness and claim signatures (existing SDK verifiers), the signed
  conversation/customer binding, RFC 3161 timestamp tokens against the pinned
  FreeTSA root and Sigstore Rekor entries against the pinned public-good key
  (SET, inclusion proof, checkpoint, witness-made entry); optional `--online`
  Rekor re-fetch that confirms, never replaces, the stored entry. A Rekor
  proof without a signed checkpoint fails; with the built-in pins an
  unanchored certificate is INCOMPLETE (`--allow-unanchored` /
  `--require-anchors`); required files, directory entries and case-variant
  manifest keys are checked; each certificate's own chain verdict and
  `user_unredacted` are printed. The manifest is unsigned in format 1, so the
  reports are reported as not authenticated. Exit 0 VALID / 1 TAMPERED /
  2 INCOMPLETE. Standard library only. Synthetic tamper corpus:
  `go/cmd/lucairn-bundle-verify/scripts/tamper-corpus.sh` (+ `red-proof.sh`).
- **Optional `cert_tier` on the certificate's verification result.**
  TS `VeilVerificationResult.cert_tier?: VeilCertTier` (new exported type:
  `'full_chain' | 'input_shield' | 'input_shield_two_signer' | ''` plus any string), Python
  `VeilVerificationResult.cert_tier: str | None = None`, Go
  `VeilVerificationResult.CertTier string` (`json:"cert_tier,omitempty"`).
  The witness now tags each certificate with the tier its verdict was
  derived for (`input_shield` = the sanitize-only route, whose VERIFIED
  verdict covers sanitizer → gateway → vendor call). The field is OPTIONAL
  (absent on certificates sealed before tier-aware verdicts) and UNSIGNED —
  it is in neither witness signable, `verifyCertificate` never reads it, and an
  unknown value is surfaced verbatim, never an error. Types only: no
  signable change.
- **Every claim checked, not only the witness signature.**
  New `verifyCertificateChain` (TS, also `client.verifyCertificateChain`),
  `verify_certificate_chain` (Python, also `client.verify_certificate_chain`)
  and `VerifyCertificateChain` (Go, also `(*Client).VerifyCertificateChain`).
  The existing witness-only verifier accepts a certificate whose claim body
  was edited under the same claim id, because the witness signs the claim-id
  list, not the claim contents. The new function runs the parity-corpus
  recipe (Declade/dual-sandbox-architecture `tools/parity-corpus/README.md`;
  its check table is vendored as `testdata/parity-corpus/recipe-table.md`):
  each claim's signature against a caller-pinned per-service key, the canonical claim bytes rebuilt
  from the outer fields, claim-id membership and uniqueness, the unsigned
  typed copies against the signed payload, the signed upstream-request
  hashes (`upstream_body_sha256`), the unsigned `cert_tier` against its
  signed copies, and `user_unredacted` read from the signed sanitizer claim
  only. It takes the raw certificate JSON and returns `verdict` (`FAILED` <
  `PARTIAL` < `EGRESS_UNATTESTED` < `VERIFIED`), `reason`,
  `egress_attestation`, `user_unredacted`, `signed_cert_tier`,
  `signable_version`, `request_binding` and `verified` (each verified claim's
  signed canonical bytes plus named values extracted from them). Render and
  decide ONLY from `verified`; nothing else in the certificate is
  authenticated. Pass the expected request id (`expectedRequestId` /
  `expected_request_id` / `ExpectedRequestID`) so a genuine certificate of
  another turn is refused (`request_mismatch`). Pinned keys are checked
  strictly (one encoding, small-order points refused, the public corpus test
  keys refused unless `allowTestKeys`); a refused key raises `PinnedKeyError`
  (Go: `KeyPolicyError`). Policy via the existing minimum-signable-version
  option (`v3` = strict).
- The unsigned `cert_tier` value `input_shield_two_signer` (sanitizer and
  gateway claims, no ai claim) is accepted only beside exactly that signed
  shape and never reaches VERIFIED (EGRESS_UNATTESTED at best).
- The unsigned `cert_tier` value `audit_only` (certificate-only mode: bridge,
  ai and audit claims, the ai claim signing `cert_tier: "audit-only"`) is
  accepted only beside exactly that signed shape (one signed tier copy, from
  the one `dsa-ai` claim, value exactly `audit-only`) and reports
  `signed_cert_tier` `audit_only`. Before, every verifier refused such a
  certificate with `cert_tier_mismatch` (T-1172). The tier is decided by the
  SIGNED claims, never the unsigned label: as soon as any claim signs
  `cert_tier: "audit-only"`, the chain is certificate-only, and a missing
  label or one relabelled `full_chain` / `input_shield` FAILS
  `cert_tier_mismatch` whatever the sealed verdict (VERIFIED or PARTIAL), so
  a certificate-only chain never reports a sanitized tier. A `VERIFIED`
  `audit_only` result attests what was sent, never that anything was
  sanitized.
- **Shared parity corpus** `testdata/parity-corpus/` (98 cases, format v1.2.3,
  re-sync with `sync.sh`). All
  three SDKs run every case under both policies and must match every result
  field; a test fails when the vendored copy drifts from `SOURCE.json`.
- **Rules the corpus does not pin, fixed identically in all three SDKs**
  (found by a cross-SDK fuzz harness): nesting deeper than 256
  arrays/objects is malformed; an unpaired UTF-16 surrogate escape is
  refused as malformed (never read as U+FFFD; corpus v1.2 rule); step 4's "blank" uses Go's `unicode.IsSpace` set; the qi-score
  verdict is upper-cased ASCII-only; the v3 sanitizer-hash lookup uses the
  same strict parser as every other read.

### Changed
- **`protocol_version` and `signable_protocol_version_emitted` in the
  witness-only check: one value rule, `malformed` otherwise (T-1322).**
  `signable_protocol_version_emitted` absent or `null` still means 0. A
  present value, and `protocol_version` always, must be a JSON number whose
  value is an integer from 0 to 2^64 - 1; anything else (a string such as
  `"3"`, an array, a boolean, an object, a fraction, NaN / Infinity, a
  negative number, a value of 2^64 or more) now gets the existing reason
  `malformed` instead of being coerced, ignored, compared as a number or
  reported as `unsupported_protocol_version`. A valid `protocol_version`
  other than 2 is `unsupported_protocol_version` as before. The rule is
  applied by TS, by Python for dict input and for a `VeilCertificate`
  instance (a Python `float` is `malformed` even when integral), and by Go
  for map input; with `[]byte` / `json.RawMessage` input Go applies it to the
  number TOKEN (digits only), so `2.0`, `2e0` and `2.0000000000000001` are
  `malformed` there (parity-corpus cases
  `tamper_protocol_version_oversized_integer` and
  `tamper_protocol_version_float_token`). In Go the decision no longer
  depends on the CPU architecture for values of 2^63 and above. Python's
  default `json.loads` raises on an integer token of more than 4,300 digits
  before the SDK is called.
- **`lucairn-bundle-verify`: the stored Rekor inclusion-proof JSON is read
  strictly** (certificates and audit roots): a duplicate key, a key other than
  `checkpoint` / `hashes` / `logIndex` / `rootHash` / `treeSize`
  (case-sensitive), a non-integer index or size, or data after the object now
  fails the Rekor step. Entries as Rekor returns them are unaffected.
- **`lucairn-bundle-verify`: ASCII-only text output.** The text report, usage
  and error messages no longer contain non-ASCII characters (a default Windows
  console garbled them when piped): step lines read `PASS - detail` instead of
  a long dash, `-> blocks VALID`, `...`; data echoed from a bundle is escaped.
  The Go SDK's certificate-verification error texts lost their long dashes for
  the same reason. `--json` is unchanged.

### Fixed
- **The witness-only check refuses a small-order `R`, a small-order or
  non-canonical public key and `S >= L` by its own code (T-1322).**
  `verifyCertificate` (TS), `verify_certificate` (Python) and
  `VerifyCertificate` (Go) check the witness signature only. Until now they
  handed the key and signature straight to the platform crypto library, so
  the result for a signature whose `R` is a small-order point (for example
  the identity, made with nonce 0) depended on the library version: measured
  on the parity-corpus case `tamper_witness_signature_small_order_r`, Node 22
  and Node 25 (OpenSSL 3.x), Python `cryptography` 46.0.5 and 50.0.2, and Go
  1.26 `crypto/ed25519` accepted it; Node 26 (OpenSSL 4.0.3) refused it. The
  three functions now call the same Ed25519 acceptance rule as the chain
  verifier of the same SDK (one list of the seven small-order values per
  language, no copy): the signature must be 64 bytes with `S < L` and `R` the
  canonical encoding of a point that is not of small order, and the public
  key (after the existing normalisation, on its 32 raw bytes) must be the
  canonical encoding of a curve point that is not of small order. Each
  refusal is reported as the existing invalid-signature result
  (`invalid_signature`); there is no new reason code, error type or export,
  and a malformed key (wrong length, bad base64) is reported as before. The
  chain verifier's refusal of the published parity-corpus test keys is not
  applied to the witness-only functions. What this closes, in two parts:
  with an honestly generated, correctly pinned witness key, producing a
  signature with a small-order `R` that satisfies the equation needs the
  witness signing key, so that part is not a forgery by an outsider; it
  removes a result that differed by runtime. Separately, if a small-order
  PUBLIC KEY was pinned by mistake (for example the identity point), anyone
  could produce a signature the old check accepted on the affected runtimes,
  without any secret; the key check closes that. The Go
  `lucairn-bundle-verify` signature step calls `VerifyCertificate` and
  therefore applies the same rules, including the input rules below. No
  change to the v2 / v3 signable bytes.
- **Measured differences between the three witness-only checks on the same
  certificate are removed (T-1322).** `verifyCertificate` (TS),
  `verify_certificate` (Python) and `VerifyCertificate` (Go) now apply the
  rules below identically. Every change makes a language stricter, with one
  exception named below (TS and U+0085). The limits that remain are listed
  under "Known limits".
  - *Blank or present.* Whether `witness_signature` / `signable_v3_signature`
    is blank is decided with ONE whitespace set, Go's `unicode.IsSpace` (the
    chain verifier's set, same helper). Python used `str.strip()`, which
    also removes U+001C-U+001F: a legacy v2 certificate carrying
    `signable_v3_signature = "\u001c"` verified as v2 in Python and is now
    `version_downgrade_detected`, as in TS and Go (parity-corpus case
    `tamper_signable_v3_signature_control_char`). TS used `.trim()`, which
    does not remove U+0085 (in the set) and removes U+FEFF (not in the set);
    both now follow the set. Among signature-field inputs, the U+0085 case
    is the one certificate that verifies now and did not before: in TS a legacy v2 certificate whose
    `signable_v3_signature` is only U+0085 was `version_downgrade_detected`
    and now verifies as v2, as it already did in Python and Go (the field is
    blank, the same as `""`, and the v2 witness signature is checked as
    before).
  - *Signature text.* `witness_signature_missing` and
    `version_downgrade_detected` are decided first, on blank / present, as
    before. After that, every signature field that is present (non-blank)
    must be canonical standard padded base64 (decode, re-encode, compare;
    the chain verifier's rule and helper), else `invalid_signature`:
    `witness_signature` on every certificate, and `signable_v3_signature` on
    a v3 certificate. This includes `witness_signature` on a v3 certificate,
    where the v3 signature is the one verified. Before: TS decoded with
    Node's permissive decoder and accepted missing padding, the URL-safe
    alphabet, whitespace and any text after the signature (a valid signature
    followed by `!` verified); Go accepted CR / LF inside the text; all three
    accepted non-zero padding bits; and on a v3 certificate the content of
    `witness_signature` was not looked at beyond blank / present.
  - *Python `verify_ed25519` buffers.* Message and signature are read through
    the buffer protocol, as the crypto library did: `bytes`, `bytearray`,
    `memoryview` and `array.array("B")` verify a genuine signature, and a
    non-buffer argument raises `TypeError`. A non-contiguous (strided)
    `memoryview`, which the library refused, is now read as its bytes.
- Python chain verifier: every walk over a signed document (canonical form,
  case-variant keys, surrogate scan, value pointers) is iterative, so a
  legal depth-256 document verifies the same at any caller stack depth (it
  could fail when called from a deep stack). The two-signer tier no longer
  reports the step-8d cap flag, matching TS and Go (no result changes).

### Known limits
These apply to the witness-only check (`verifyCertificate` /
`verify_certificate` / `VerifyCertificate`); the chain verifier reads the raw
text and is not affected by 1 to 3.
1. Given an already parsed object, the simple check judges values, so a
   number written `2.0000000000000001` is the value 2 (TS, and Go with map
   input). Number-token rules apply only where the SDK reads the raw text (Go
   with raw bytes; the chain verifier in all three).
2. The base64 form of the PUBLIC KEY argument is not normalised the same way
   in the three SDKs (TS accepts an unpadded key and trailing characters).
3. The simple check does not validate every claim field the same way in the
   three SDKs. Examples: a claim without `request_id` / `service_id`, a
   non-string `signable_v3_signature`, a sanitizer `canonical_payload` with
   trailing characters.
4. A double cannot hold every integer between 2^53 and 2^64, so TS and Go
   with map input do not see such a value as written. A `protocol_version`
   in that range is refused everywhere, but the reason can differ
   (`malformed` or `unsupported_protocol_version`). A
   `signable_protocol_version_emitted` of exactly 2^64 - 1 is read as a v3
   marker by Python and by Go with raw bytes and is `malformed` in TS and Go
   with map input. That field is not signed; it only selects which signature
   must verify.
5. Per-call cost: the key check adds two modular exponentiations per
   verification (measured ≈ 45 → 219 µs on Node 22, 35 → 189 µs on
   Python 3.12).
6. The simple check accepts a certificate that carries only the older (v2)
   witness signature. Values that only the newer (v3) signature covers
   (`api_key_id`, `client_id`, `byok_exempt`, the sanitizer hashes) are then
   not vouched for by the result. Callers who need those values vouched for
   pass the require-v3 option - TS `minimumSignableVersion: 'v3'`, Python
   `minimum_signable_version="v3"`, Go
   `VerifyCertificateKeys.MinimumSignableVersion: "v3"` - which refuses a
   certificate verified on the v2 path, or use the chain verifier
   (`verifyCertificateChain` and its Python and Go counterparts).
7. Acceptance changes outside the signature fields, both in the unsigned
   `signable_protocol_version_emitted` selector: Go now reads a value from
   2^63 up to 2^64 - 1 as a v3 marker on every architecture (before, such a
   value could be read as 0 or as a negative number depending on the CPU
   architecture and the input form, and the certificate was refused as
   `version_downgrade_detected`); Python refuses a dict whose value is the
   float `3.0` as `malformed` (it was read as 3; some JSON re-serialisers
   write integers that way - write `3`).
8. Python: the value rule sees what it is given. A `VeilCertificate` built
   with `model_validate` has already had `"3"` or `3.0` converted to the
   integer 3 by the model, so such an instance verifies where the same dict
   is `malformed`; the range check still applies to the instance.

### Unchanged
- The v2 / v3 witness signable reconstructions are byte-for-byte unchanged,
  and the chain verifier is an additive layer. `verifyCertificate` /
  `verify_certificate` / `VerifyCertificate` keep their signature, result and
  reason codes; their behaviour changes are the Ed25519 rule and the input
  rules under Fixed and Changed above.

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
