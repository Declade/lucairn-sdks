# lucairn — Go SDK

Client for **Lucairn** — privacy-preserving AI infrastructure.

## Status

`v1.1.1`. Ships alongside the TypeScript and Python SDKs and behaves
identically at the observable level. See the [monorepo
README](../README.md) for the full SDK index.

## Install

```bash
go get github.com/declade/lucairn-sdks/go@latest
```

Requires Go 1.22+.

The canonical module path is `github.com/declade/lucairn-sdks/go`.

## Quickstart

```go
package main

import (
	"context"
	"fmt"

	lucairn "github.com/declade/lucairn-sdks/go"
)

func main() {
	client, err := lucairn.New("lcr_live_...")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Proxy a prompt through the Lucairn gateway (split-knowledge routing).
	maxTokens := 256
	resp, err := client.Messages(ctx, lucairn.MessagesRequest{
		PromptTemplate: "Summarize the following: {text}",
		Context:        map[string]string{"text": "Long input..."},
		Model:          "claude-sonnet-4-6",
		MaxTokens:      &maxTokens,
	})
	if err != nil {
		panic(err)
	}
	switch r := resp.(type) {
	case *lucairn.ProxySyncResponse:
		fmt.Println("sync result:", r.Status, r.ModelUsed)
	case *lucairn.ProxyAcceptedResponse:
		fmt.Println("async — poll:", r.StatusURL)
	}
}
```

## Privacy receipts: free vs Pro tier paths

Every `Messages()` call generates a privacy receipt witnessed by the
gateway. Two surfaces exist for that receipt, and which one your code
should consume depends on your tier:

- **`GetCertificateSummary(ctx, requestID)`** — returns a human-readable
  HTML summary (DPO-friendly). **Available on every tier including
  Developer (free).**
- **`GetCertificate(ctx, requestID)` + `VerifyCertificate(cert, keys)`** —
  fetches the raw JSON certificate and verifies the witness's Ed25519
  signature over its canonical signed subset. **Pro tier and above.**

If a Developer-tier key calls `GetCertificate`, the gateway returns
HTTP 403 with `{"error":"tier_insufficient","hint":"Contact sales to
upgrade."}`, surfaced by the SDK as `*HTTPError` with `Status == 403`.

### Developer tier (free) — render the HTML summary

```go
package main

import (
	"context"
	"errors"
	"fmt"

	lucairn "github.com/declade/lucairn-sdks/go"
)

func main() {
	client, err := lucairn.New("lcr_live_...")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	maxTokens := 1024
	resp, err := client.Messages(ctx, lucairn.MessagesRequest{
		PromptTemplate: "Hello {name}",
		Context:        map[string]string{"name": "Example Person"},
		Model:          "claude-sonnet-4-6",
		MaxTokens:      &maxTokens,
	})
	if err != nil {
		panic(err)
	}

	// resp.RequestID is populated on every tier (Developer / Pro / Enterprise).
	// Pro/Enterprise responses additionally expose resp.Veil.SummaryURL if you
	// want the summary URL directly without an extra fetch.
	var requestID string
	if sync, ok := resp.(*lucairn.ProxySyncResponse); ok {
		requestID = sync.RequestID
	}

	html, err := client.GetCertificateSummary(ctx, requestID)
	if err != nil {
		var httpErr *lucairn.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == 503 {
			// Veil Witness temporarily unavailable; retry later.
			return
		}
		panic(err)
	}
	fmt.Println("summary html bytes:", len(html))
	// Display html in a sandboxed iframe or save for the DPO.
}
```

### Pro tier and above — fetch + verify the JSON certificate

On Pro and Enterprise tier responses the gateway adds a `Veil` block
(`*ProxyVeilReceipt` on `ProxySyncResponse.Veil`) carrying `SummaryURL`
and `CertificateURL`. Pro and Enterprise keys can also fetch the raw
certificate and verify the witness Ed25519 signature locally for a
programmatic audit trail.

```go
package main

import (
	"context"
	"errors"
	"fmt"

	lucairn "github.com/declade/lucairn-sdks/go"
)

func main() {
	client, err := lucairn.New("lcr_live_...")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Fetch a Veil Certificate for a known requestID (Pro/Enterprise).
	cert, err := client.GetCertificate(ctx, "req_abc123")
	if err != nil {
		var httpErr *lucairn.HTTPError
		if errors.As(err, &httpErr) {
			switch httpErr.Status {
			case 202:
				// Pending; retry after httpErr.Body["retry_after_seconds"].
				return
			case 403:
				// Developer (free) tier — use GetCertificateSummary instead.
				return
			}
		}
		panic(err)
	}

	// Verify the witness Ed25519 signature against pinned trust-root keys.
	result, err := client.VerifyCertificate(cert, lucairn.VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: "<base64 of raw 32-byte Ed25519 public key>",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.OverallVerdict, result.AnchorStatus)
}
```

## Public API

### `lucairn.New(apiKey string, opts ...Option) (*Client, error)`

Constructor validates every input up front:

- `apiKey` must be a Lucairn key (`lcr_live_...`) or a legacy `dsa_...` key.
- `WithBaseURL(url)` must be `http://` or `https://`; default is
  `https://gateway.lucairn.eu`.
- `WithTimeout(d)` must be a positive `time.Duration`; default `60s`.
- `WithHTTPClient(c)` lets you substitute a custom `*http.Client` (for
  mTLS, corporate proxies, custom transports).

### `(*Client).Messages(ctx, req, ...CallOption) (MessagesResponse, error)`

POST to `/api/v1/proxy/messages`. Returns the `MessagesResponse` tagged
union — discriminate via a type switch:

```go
switch r := resp.(type) {
case *lucairn.ProxySyncResponse:
	// 200 terminal result — inspect r.Status for COMPLETED / FAILED
case *lucairn.ProxyAcceptedResponse:
	// 202 processing receipt — poll r.StatusURL until completion
}
```

### `(*Client).GetCertificate(ctx, requestID, ...CallOption) (*VeilCertificate, error)`

GET `/api/v1/veil/certificate/{requestID}`. **Pro tier or above** —
Developer (free) tier returns HTTP 403 `tier_insufficient`, surfaced as
`*HTTPError` with `Status == 403`.

Happy-path returns `*VeilCertificate`. Gateway-side pending (certificate
not yet assembled, or unknown requestID — the gateway does not
distinguish) surfaces as `*HTTPError` with `Status=202` and `Body`
holding the pending wrapper:

```go
cert, err := client.GetCertificate(ctx, "req_abc")
var httpErr *lucairn.HTTPError
if errors.As(err, &httpErr) && httpErr.Status == 202 {
	body := httpErr.Body.(map[string]any)
	retryAfter := body["retry_after_seconds"]
	// poll later
}
```

No auto-verification — chain `VerifyCertificate` explicitly.

### `(*Client).GetCertificateSummary(ctx, requestID, ...CallOption) (string, error)`

GET `/api/v1/veil/certificate/{requestID}/summary`. **Available on every
tier including Developer (free).** Returns the gateway's text/html
DPO-friendly summary view as a raw string. Both pending and assembled
states return HTTP 200 with HTML — pending shows a `PENDING` banner
instructing the caller to retry in ~30s — so callers who want to
distinguish should chain `GetCertificate` first or pattern-match the
HTML. 503 surfaces as `*HTTPError` with `Status=503`.

```go
html, err := client.GetCertificateSummary(ctx, "req_abc")
if err != nil {
	// 503 → witness unavailable; 401/403 → auth/tier; transport errors
	// surface as *TimeoutError / *NetworkError as usual.
}
// html is the raw template output; render or display as needed.
```

### `(*Client).ListAuditEvents(ctx, opts, ...CallOption) (*AuditExportResponse, error)`

GET `/api/v1/audit/export`. Pro/Enterprise tier (Developer tier returns 403).
Returns the typed `*AuditExportResponse` carrying `Events []AuditEntry`,
`TotalEvents int`, and metadata.

```go
resp, err := client.ListAuditEvents(ctx, lucairn.AuditExportOptions{
	Days:      30,
	EventType: "veil.certificate.issued",
})
if err != nil {
	// *HTTPError Status=403  → Developer tier, upgrade to Pro/Enterprise
	// *HTTPError Status=400  → days outside [1,90]
	// *HTTPError Status=503  → audit export unavailable
	return
}
for _, evt := range resp.Events {
	fmt.Println(evt.Timestamp, evt.EventType, evt.RequestID)
}
```

`Days = 0` lets the gateway apply its default lookback (30 days at the
time of writing). `EventType = ""` returns events of every type.

### `lucairn.VerifyCertificate(cert, keys)` / `(*Client).VerifyCertificate(cert, keys)`

Verify a certificate's witness Ed25519 signature. Accepts cert as
`*VeilCertificate`, `map[string]any`, `[]byte`, or `json.RawMessage`.
Returns `*VerifyCertificateResult` on success, `*CertificateError` on
failure with one of five reasons:

| Reason                                    | Condition                                                |
|-------------------------------------------|----------------------------------------------------------|
| `ReasonMalformed`                         | cert shape invalid / gateway invariant / unknown verdict |
| `ReasonUnsupportedProtocolVersion`        | `ProtocolVersion != 2`                                   |
| `ReasonWitnessMismatch`                   | key ID mismatch                                          |
| `ReasonWitnessSignatureMissing`           | empty or whitespace-only signature                       |
| `ReasonInvalidSignature`                  | Ed25519 verify failed, or key input malformed            |

External RFC 3161 timestamp + Sigstore Rekor transparency-log
verification are out of scope for this release (pending upstream gateway
fixes).

### `lucairn.VerifyCertificateChain(certificate, keys)` / `(*Client).VerifyCertificateChain(certificate, keys)`

`VerifyCertificate` above checks the witness signatures only. The witness
signs the LIST of claim ids, not the claim contents, so a certificate whose
claim body was edited under the same claim id still passes it.
`VerifyCertificateChain` runs the full check: every claim's own signature
against the key you pin for its service, the claim bytes rebuilt from the
outer fields, claim-id membership, the unsigned typed copies against the
signed payload, the signed upstream-request hashes, the unsigned
`cert_tier` against its signed copies, and (when you pass it) the request
the certificate must belong to. It is additive: `VerifyCertificate` is
unchanged.

It takes the **raw certificate JSON bytes**, not a re-marshalled struct,
because number lexemes, duplicate keys and trailing bytes are part of the
checks (inputs above 32 MiB are malformed). A bad certificate is never an
error: it returns a `*CertificateChainResult` with a `Verdict` and the
`Reason` of the check that decided (JSON tags carry the corpus field names).
The error is a `*KeyPolicyError` when a pinned key is refused (below), or a
`*ConfigError` for another programmer error (an empty key id or service id,
an unknown policy).

**Input size.** The 32 MiB limit is a format limit, not a memory budget: a
pathological document (for example millions of tiny values) can take many times
its size in memory while it is parsed. If you verify certificates from an
untrusted relay or upload, cap the input yourself before calling the verifier
(8 MiB is ample for a real certificate) and treat anything larger as unverified.

```go
reqID := turn.RequestID // the request id of the turn you are showing
result, err := lucairn.VerifyCertificateChain(rawBody, lucairn.CertificateChainKeys{
	WitnessKeyID:     "witness_v1",
	WitnessPublicKey: witnessKeyB64,
	// one key per claim-emitting service in your deployment;
	// a claim from an unpinned service FAILS the certificate
	ServicePublicKeys: map[string]any{
		"dsa-sanitizer":  sanitizerKeyB64,
		"dsa-ai":         aiKeyB64,
		"dsa-gateway":    gatewayKeyB64,
		"dsa-bridge":     bridgeKeyB64,
		"dsa-audit":      auditKeyB64,
		"dsa-reid-guard": reidGuardKeyB64, // where deployed
	},
	MinimumSignableVersion: "v3", // "" for the legacy-tolerant default
	ExpectedRequestID:      &reqID,
})
if err != nil {
	return err // key-set problem, not a certificate problem
}
if result.Verdict != "VERIFIED" {
	log.Printf("%s: %s", result.Verdict, result.Reason)
}
if result.UserUnredacted == "true" {
	showSentUnredactedMark()
}
if result.Verified != nil {
	if c, ok := result.Verified.Certificate["client_id"].(string); ok {
		showClient(c) // signed (v3 only); absent under v2
	}
}
```

**Which keys to pin.** Pin the per-service public keys your Lucairn operator publishes for your deployment, the same way you pin the witness key, and pin every service that emits claims there (including, where present, `dsa-reid-guard` and `dsa-sanitizer-streaming`): a claim from an unpinned service FAILS the certificate. A published key endpoint is planned; this release does not fetch keys.

**Pinned-key policy.** Every key is checked when it is loaded, and a refused key is a `*KeyPolicyError` (the Go equivalent of `PinnedKeyError` in the TypeScript and Python SDKs; `Key` names the refused key: `"witness"` or the service id) whose `Code` is, in this order: `key_malformed` (a string key must be the canonical standard padded base64 of exactly 32 bytes: no hex, no URL-safe alphabet, no missing padding, no whitespace or line break, no set trailing bits; a `[]byte` key must be exactly 32 bytes), `key_small_order` (one of the Ed25519 small-order encodings, which would let one forged signature verify over many messages), `key_invalid_point` (not the canonical encoding of a curve point), or `key_test_key`. **Never pin the keys of the parity corpus** vendored in this repository: their private keys follow from a public seed, so the SDK refuses them unless `AllowTestKeys` is set, and only a parity test harness sets it. Signatures are accepted under one strict Ed25519 rule (64 bytes, canonical `S`, canonical and not small-order `R`, the cofactorless equation), so the three SDKs accept exactly the same signatures.

**Always pass the expected request id.** `ExpectedRequestID` (and optionally `ExpectedCertificateID`) must equal the witness-signed value, else the result is FAILED `request_mismatch`; `RequestBinding` then says `matched`. Without it, a genuine certificate of ANOTHER turn, swapped in by a store, a fetch path or a relay, verifies. It does not stop a compromised gateway or local proxy: the gateway issues the request id you compare against. A pointer to `""` is a supplied value.

**What the result means.**

| `verdict` | meaning |
|---|---|
| `VERIFIED` | every check passed, and exactly one claim signs a list of upstream-request SHA-256 hashes (one per request attempt the inference sandbox recorded) with the pinned `dsa-ai` key. A witness export that carries the request bytes inline has them checked against the signed hashes here. Certificates without signed hashes end at `EGRESS_UNATTESTED`. |
| `EGRESS_UNATTESTED` | every check passed, but no signed upstream-request hash exists (older certificates, the input-shield lane today). Never treat it as green. |
| `PARTIAL` | the signatures hold, but the certificate itself says something is missing, unfinished or opted out (`reason` says which, e.g. `user_sent_unredacted`). |
| `FAILED` | an integrity, binding or policy check broke, or the witness itself sealed FAILED. |

Only `VERIFIED` is green. The result also carries `signed_cert_tier` (show this, never the unsigned `verification.cert_tier`; besides the corpus values it can be `input_shield_two_signer`, an input-shield chain with only sanitizer and gateway claims (exactly one signed tier copy, from the gateway; at least one `dsa-sanitizer` claim; no `dsa-ai` claim), which has no signed upstream hashes and so ends at `EGRESS_UNATTESTED` or below, or `audit_only`, a certificate-only chain whose one `dsa-ai` claim signs `cert_tier: "audit-only"` — the sanitizer was skipped by design and the content was NOT sanitized, so never show a `VERIFIED` `audit_only` result as a sanitized certificate), `request_binding`, and `user_unredacted`, a **string** (`"true"` / `"false"` / `"unknown"`) read from the signed sanitizer claim only. Compare it to `"true"`; `"false"` is a non-empty string.

**Render and decide only from `Verified`.** `result.Verified` (JSON `verified`, `nil` on every FAILED result) is built only from signed bytes:

- `Verified.Certificate` is the witness-signed map that verified, key for key: the 7 v2 keys (`certificate_id`, `claim_ids`, `issued_at`, `overall_verdict`, `protocol_version`, `request_id`, `witness_key_id`), plus `api_key_id`, `byok_exempt`, `client_id`, `redaction_manifest_hash`, `sanitized_fields_body_hash`, `tms_manifest_hash` when `SignableVersion` is `v3`. Under `v2` those six are absent: show no client, API key or BYOK mark then.
- `Verified.Claims` has one entry per claim, keyed `"<index>:<service_id>:<claim_type>"` (split at the first and the last `:`; order claims by the parsed index, not by key). `Canonical` is the claim's signed bytes exactly; `Values` maps the JSON Pointer of every string, boolean and integer leaf of those bytes (`/payload/model_used`, `/data_seen/0`) to its value. Integers are `json.Number` (up to 2^64-1: keep the text). Floats, negative numbers and `null` are not in `Values`: read them from `Canonical`.

Everything a caller displays or decides on (a "sent unredacted" or BYOK mark, a client or API-key attribution, a model name) comes from `Verified` plus `Verdict`, `Reason`, `EgressAttestation`, `SignedCertTier`, `UserUnredacted` and `RequestBinding`. Never read it from the raw certificate or from a second parse of it: `json.Unmarshal` into `VeilCertificate` matches field names case-insensitively and reads unsigned copies (the typed claim objects, `upstream_model`, `verification.*`, the outer claim timestamps) that no signature covers. What is not in `Verified` is not verified. Also:

- The verdict to display is `Verdict`. `Verified.Certificate["overall_verdict"]` is what the witness sealed, a signed value but not the result.
- The egress claim is the one whose `Values` carry `/payload/upstream_body_sha256/0`, never "the first `dsa-ai` claim".
- Show an upstream request body only after hashing its exact bytes with SHA-256 and finding the lowercase hex digest at `/payload/upstream_body_sha256/<i>` of that claim, `i` = the body's position.

Limits: this is the signature of the bytes Lucairn sent. It does not tell you what the model provider received or did. A `VERIFIED` result means "signed with the pinned `dsa-ai` key"; it does not say which Lucairn component held that key. A certificate that carries only the older v2 witness signature verifies under the default policy with only the v2 keys in `Verified.Certificate`; strict callers pass minimum signable version `v3`, which fails every such certificate. The full rules (document grammar, timestamp grammar, canonical JSON and base64, typed-field binding) are implemented in this SDK's source with comments. The 98-case test corpus, its pinned-key vectors and the ordered check table are vendored at [`testdata/parity-corpus/`](https://github.com/Declade/lucairn-sdks/tree/main/testdata/parity-corpus); the TypeScript, Python and Go SDKs return identical results on every case under both policies.

## Offline evidence-bundle verifier: `lucairn-bundle-verify`

`go/cmd/lucairn-bundle-verify` checks a Lucairn evidence bundle (the per-conversation
`.zip` downloaded from the Lucairn account pages) without contacting Lucairn.
It is one static binary with no runtime.

### Download

Ready-to-run downloads are on the release page
<https://github.com/Declade/lucairn-sdks/releases/tag/bundle-verify-v1.0.0>
(Windows, macOS and Linux; Intel/AMD and ARM; one file each, no installer).
Check the download before you run it: the release carries `SHA256SUMS` and
`SHA256SUMS.sig`. The signature verifies with the Lucairn public key at
<https://lucairn.eu/.well-known/lucairn-cosign.pub>:

```bash
cosign verify-blob --key lucairn-cosign.pub --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing   # on macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

The signature is recorded in the Sigstore Rekor transparency log. The binaries
are reproducible from source (the build command is in the release notes). The
macOS binaries are not notarised by Apple.

### Build from source

```bash
cd go
CGO_ENABLED=0 go build -trimpath -o lucairn-bundle-verify ./cmd/lucairn-bundle-verify
./lucairn-bundle-verify bundle.zip            # offline (default)
./lucairn-bundle-verify --online bundle.zip   # also re-fetches every Rekor entry from rekor.sigstore.dev
./lucairn-bundle-verify --json bundle.zip     # machine-readable report
./lucairn-bundle-verify --print-trust-roots   # the keys built into this binary
```

Every step prints `PASS`, `FAIL` or `SKIPPED(reason)`. Exit codes: `0` VALID ·
`1` TAMPERED (a check failed) · `2` INCOMPLETE (nothing failed, but a required
check could not run; also unreadable input and usage errors).

The text report, the usage text and error messages are ASCII-only, so they
survive a pipe or a redirect in a default Windows console (a step line reads
`structure        PASS - 7 files, all in the v1 layout`). Anything else the
tool has to echo, such as a file name taken from the bundle, is printed
escaped (`\u2014`). `--json` is UTF-8 JSON and is not escaped.

What it recomputes, from the bundle's files and keys built into the binary
(never from the bundle):

- every file against `manifest.json` (SHA-256, nothing unlisted, v1 layout
  only; `manifest.json`, `README.txt`, `report-external.pdf` and at least one
  certificate are required; a directory entry or any other name in the zip,
  and any manifest key that is not exactly a v1 key, is TAMPERED — verify the
  zip as downloaded, not a re-zipped folder);
- each certificate's witness signature (`VerifyCertificate`) and every claim
  signature (`VerifyCertificateChain`) under the pinned keys published at
  `https://lucairn.eu/.well-known/lucairn-service-keys.json`;
- that the signed claim payloads name the bundle's conversation and customer;
- each RFC 3161 timestamp token: CMS signature, ESS signing-certificate, chain
  to the pinned FreeTSA root with a critical time-stamping EKU, and a message
  imprint equal to the expected digest (see anchor binding below);
- each Sigstore Rekor entry: signed entry timestamp under the pinned
  public-good key, the RFC 6962 inclusion proof and its signed checkpoint
  (required: a proof without one is FAIL), a proof index no higher than the
  signed log index, and that the witness key made the entry (Ed25519ph over
  the logged SHA-512 digest). The stored inclusion-proof JSON is read as one
  strict document: a duplicate key, a key that is not one of Rekor's five
  (`checkpoint`, `hashes`, `logIndex`, `rootHash`, `treeSize`, case-sensitive)
  or data after the object is FAIL. `--online` fetches the log's current copy
  to CONFIRM the stored entry; the stored proof is still the one verified.

**Anchor binding.** Certificates anchored with *anchor binding v1* (marked
`attestation.timestamp.hash_algorithm = "lucairn.anchor-binding/v1"`) have
both anchors over
`H = sha256("lucairn.anchor-binding/v1\n" || cert_hash || sha256(signed signable))`:
the RFC 3161 imprint is `H` and the Rekor entry logs `sha512(H)`. The tool
recomputes `H` from the recorded `cert_hash` and the canonical bytes the
verified witness signature covers, so a passing step is printed as
`PASS (content-bound)` (JSON `PASS_CONTENT_BOUND`): the anchor commits to this
certificate's signed content plus its recorded `cert_hash`, and anchors copied
from another certificate FAIL. Only when at least one anchor step passed this
way does the result add a `CONTENT-BOUND:` line (JSON
`content_bound_anchor_steps`).

Older anchors (without binding v1) cover the certificate as stored by
Lucairn. A passing step is then printed as `PASS (genuine anchor, not
content-bound)` — never a bare `PASS` — with this line under it and in the
result summary: "The timestamp and log entry cover the certificate as stored
by Lucairn, which contains original data and is not exported, so this tool
cannot tie them to this exact certificate." (JSON status
`PASS_NOT_CONTENT_BOUND`; it does not block VALID.)

Downgrade guard: with the built-in pins, a certificate whose **signed**
`issued_at` is after the hosted binding cutover **2026-11-01T00:00:00Z**
(`anchor.BindingV1Cutover`, printed by `--print-trust-roots`) must declare
binding v1; without the marker (removed, or anchors of another certificate) it
is TAMPERED, and that holds with or without anchors and with
`--allow-unanchored`: removing the anchors together with the marker is
TAMPERED, not "not anchored". The witness records `cert_hash` and the marker
when an anchoring run starts and keeps them when both rails fail. Only
`hash_algorithm` values `"lucairn.anchor-binding/v1"`, `"SHA-256"` and empty
are known (the witness's set); any other spelling is an unknown marker and
TAMPERED. If the signed `issued_at` cannot be recovered after the signature
check while a cutover is set, the step `anchor-binding` is SKIPPED and blocks
VALID. A custom `--witness-key` clears the hosted cutover and the banner says
"anchor-binding cutover not enforced"; `--require-binding-after RFC3339` sets
one for another deployment. Bundles of certificates issued after
the cutover need this version of the tool: older builds report their
content-bound anchors as FAIL.

A binding-v1 certificate whose timestamp rail failed keeps `cert_hash` and the
marker on its timestamp half, without a token: its Rekor entry is still checked
`PASS (content-bound)`, and the missing timestamp is `SKIPPED(not anchored)`
(INCOMPLETE with the built-in pins, which require both anchors). A timestamp
that declares the legacy form while the certificate's Rekor entry logs
`sha512(cert_hash)` is TAMPERED: a legacy entry logs a digest of the stored
certificate bytes, so that entry can only be another certificate's binding-v1
anchor relabelled as legacy.

Every certificate's own chain verdict and its `user_unredacted` value are
printed on their own `INFO` lines. VALID is a statement about the bundle's
integrity (intact, signed by the pinned keys, this conversation and account);
it does not mean every turn was sanitized — read the chain-verdict lines.

With the built-in pins every certificate must be anchored: a missing
timestamp or Rekor entry is INCOMPLETE, whatever the certificate's own
`anchor_status` says (it is never read as evidence). Self-hosted deployments
pass their own keys with `--witness-key`, `--service-key`, `--tsa-root` and
`--rekor-key`; the report then says the trust roots are custom, and with a
custom witness key an unanchored certificate is `SKIPPED(not anchored)`
without blocking VALID unless `--require-anchors` is given; the banner then says
"unanchored certificates allowed" and the summary adds a `LIMITATION` line saying
anchors were not required. The timestamp line names only the TSA signer's common
name; `--json` keeps the full distinguished name as `signer_dn`.
`--allow-unanchored` relaxes the rule explicitly.

### Bundle format 2: the audit counter

A format-2 bundle (`"format_version": 2`) is a format-1 bundle plus three
required files, `audit/events.json`, `audit/proofs.json` and
`audit/roots.json`. They hold, for the conversation: one entry per counted
request (the audit service numbers the requests of a conversation 1, 2, 3...),
an inclusion path per entry into the audit log's Merkle tree, and the audit
roots those paths lead to. Each file is one JSON object with exactly one key
holding an array — `{"events":[...]}`, `{"proofs":[...]}`, `{"roots":[...]}`
(an empty list is `[]`) — and every inclusion path element is 64 lowercase hex
characters. The exact shape is documented in
[`internal/bundle/audit.go`](internal/bundle/audit.go); a bare array, any
other key, a number written as a string, or a hash in another spelling (base64,
upper-case hex) is TAMPERED. Format-1 bundles are checked exactly as before. A
format-2 bundle without any certificate is TAMPERED, as in format 1 (a bundle
holds at least one certificate), whatever its `audit/` folder says.

Nothing in `audit/` is trusted as such. An entry counts because of two
signatures the tool checks under pinned keys:

- every certificate carries an `EVENTS_RECORDED` claim signed by the audit
  service (`dsa-audit`). It signs the audit row's `event_hash`, and for a
  counted request also `conversation_id` and `conv_seq` themselves;
- the audit service signs the root of its log (Ed25519ph over
  `"lucairn.audit-root/v1\n" + tree_size + "\n" + hex(root) + "\n"`) and logs
  that signature in Rekor.

The steps (each `PASS`, `FAIL` or `SKIPPED(reason)`):

| Step | What it checks | If not |
|---|---|---|
| `audit-files` | the three files have the documented shape and reference each other consistently | TAMPERED |
| `audit-binding` | every counter entry names the bundle's conversation | TAMPERED |
| `audit-event-hash` | each entry's `event_hash` recomputes from its fields: `sha256(previous_event_hash + "lucairn.audit-event/v2\n" + L(event_id) L(event_type) L(source_service) L(actor) L(payload_sha256) L(request_id) L(conversation_id) L(conv_seq))`, `L(x)` = byte length, `:`, `x` | TAMPERED |
| `audit-continuity` | the numbers are exactly 1..N: no gap, no duplicate, in order | TAMPERED, e.g. `seq gap at 2` |
| `audit-root` | each root: canonical artifact, signature under the pinned `dsa-audit` key, Rekor entry (signed entry timestamp, inclusion proof, signed checkpoint) made by that key for exactly this artifact | TAMPERED |
| `audit-counter` (per certificate) | every signed audit claim of the certificate that carries a counter names the certificate's one counter entry: same request, `event_hash`, conversation and number | TAMPERED on any mismatch, when a claim says "counted, seq k" but the bundle has no entry for it (also when another claim of the same certificate matches), and when an entry gives a number to a request whose claim carries no counter and names another `event_hash`; INCOMPLETE "not tracked" when no claim carries a counter (the request was recorded before counting started) — also when the bundle lists an entry with the claim's `event_hash` |
| `audit-inclusion` (per counted request) | the entry's `event_hash` is leaf `leaf_index` of the tree whose size and root the signed root artifact states | TAMPERED; INCOMPLETE "not yet anchored" for a request newer than the latest anchored root (a root covering new rows is published hourly: export the bundle again) |
| `audit-certs` | every counted request has its certificate in the bundle | INCOMPLETE `request seq 3 has no certificate` |

Two rules worth knowing:

- **The tree size comes from the signed root artifact only**, after its
  signature and Rekor entry verified. An inclusion path does not pin the tree
  size (several sizes share one path shape), so the `tree_size` copies in
  `audit/proofs.json` and `audit/roots.json` must equal the signed value and
  are never used in its place. Paths carry no left/right flags: index and size
  decide the side (RFC 9162 section 2.1.3.2).
- **Whether a request was counted is what its certificate's signed claim
  says**, not a date in the tool and not the `audit/` folder. A counter entry
  is accepted only for a certificate whose claim signs that conversation and
  number; an entry that merely carries the `event_hash` of a claim without a
  counter leaves the certificate "not tracked" (INCOMPLETE). A format-1 bundle
  whose certificates say "counted" (a format-2 bundle with `audit/` removed
  and the version rewritten, or an export that could not fetch the counter) is
  INCOMPLETE.

A certificate removed together with its manifest line — invisible in format 1
— now shows as `audit-certs` INCOMPLETE, or as `seq gap at N` if its counter
entry was removed too.

A self-hosted deployment that publishes no audit root writes empty `proofs` and
`roots`. With a custom `--witness-key` or `--allow-unanchored` the counter
steps still run, `audit-root` and `audit-inclusion` are `SKIPPED(not
anchored)` and do not block VALID; with the built-in pins a counted request
without an anchored root is INCOMPLETE. Pass the deployment's audit key as
`--service-key dsa-audit=BASE64`. `--online` also re-fetches the audit roots'
Rekor entries.

What the counter cannot show is printed as `LIMITATION` lines on every
format-2 run:

- *Counter tail.* The counter shows there is no hole between request 1 and
  request N. It cannot show that N is the last request: a bundle cut off after
  request N, with the last certificates and their counter entries removed
  together, is not detected.
- *Hour before anchoring.* The operator holds the audit signing key. Until a
  root covering a row is logged in Rekor, the operator could still rewrite and
  re-sign that row; afterwards it cannot. A run that verified no anchored root
  says so instead.

Not checked: the hash chain from one audit row to the next (the neighbouring
rows are not in the bundle), consistency between two anchored roots, and
whether a row's root is the earliest one that covers it. Older builds of the
tool, including the `bundle-verify-v1.0.0` release, read every format-2 bundle
as TAMPERED (`audit/events.json is not part of the v1 bundle format`): use a
build with format-2 support.

What a version-1 bundle cannot show is printed on every run: a certificate
removed together with its manifest entry (closed by the planned audit counter),
for certificates anchored before binding v1 the binding of an anchor to the
certificate (it covers the stored bytes, which are not exported), and the
reports themselves: `manifest.json` is unsigned in format 1,
so `report-external.pdf`, `report-internal.pdf`, `verification.json` and
`README.txt` match the manifest but are **not authenticated** by any signature
("report content not authenticated"); only the certificates are signed. The
tool is a technical integrity check, not a certification or legal opinion.

The synthetic tamper corpus runs against the built binary:

```bash
go/cmd/lucairn-bundle-verify/scripts/tamper-corpus.sh
# side by side with an older build of the tool as the independent reference:
go/cmd/lucairn-bundle-verify/scripts/red-proof.sh /path/to/older/lucairn-bundle-verify
```

## Per-call options

Options compose; last-write-wins on conflict:

```go
client.GetCertificate(ctx, "req_abc",
	lucairn.WithCallTimeout(5*time.Second),
	lucairn.WithCallHeader("x-correlation-id", "corr_xyz"),
)
```

SDK-owned headers (`x-api-key`, `content-type`) always win over
caller-supplied values with the same key.

## Error taxonomy

All SDK errors satisfy the `lucairn.Error` interface. Concrete types:

- `*ConfigError` — caller input invalid.
- `*HTTPError` — gateway returned non-2xx (or 202 from `GetCertificate`);
  fields `Status int`, `Body any`, `Message string`, `Err error` (wrapped).
- `*ResponseValidationError` — gateway returned 2xx but the body couldn't
  be deserialized into the declared response type (typically a gateway
  bug or version skew); fields `Body []byte`, `Message string`,
  `Err error` (wrapped decode error). **Distinct from `*HTTPError`** so
  callers can branch cleanly on "transport failed" vs "body shape
  wrong."
- `*TimeoutError` — request exceeded timeout; wraps `context.DeadlineExceeded`.
- `*NetworkError` — connection failures, caller-cancel, transport errors;
  wraps the underlying error (use `errors.Is(err, context.Canceled)` to
  detect caller cancel specifically).
- `*CertificateError` — `VerifyCertificate` failed; fields `Reason`,
  `CertificateID`, `Message`, `Err`.

Use `errors.As(err, &concreteType)` to inspect typed fields. Error
strings prefix with `lucairn: ` for source attribution.

## Behavioural parity with TS / Python

This SDK is cross-language byte-equivalent to the TS and Python SDKs for
canonical JSON and `VerifyCertificate`. The Go-assembler-signed cert
fixture (`cert-go-signed-reference.json`) verifies identically in all
three. The `internal/verify` canonical serializer uses Go's native
`encoding/json` with default HTML-escape on — which produces the exact
bytes the TS/Python ports build with explicit escape passes.

Intentional idiomatic divergences from the other two SDKs:

- **Cancellation via `context.Context`**, not `AbortSignal` / cancel
  tokens. Pass a `ctx` with deadline / cancel; caller-cancel produces
  a `*NetworkError` wrapping `context.Canceled`.
- **Error taxonomy** satisfies the `lucairn.Error` interface. No deep
  inheritance chain.
- **Functional options** (`WithBaseURL`, `WithTimeout`, `WithHTTPClient`,
  `WithCallTimeout`, `WithCallHeader`, `WithMaxResponseBytes`) for
  constructor + per-call config.
- **PascalCase exports** per Go convention: `GetCertificate`, `Messages`,
  `VerifyCertificate`, `GetCertificateSummary`, `ListAuditEvents`.
- **Malformed 2xx body**: TS passes through as raw bytes typed as
  `VeilCertificate` (thin transport); Go follows Go-SDK precedent
  (aws-sdk-go-v2's `*smithy.DeserializationError`,
  kubernetes/client-go's runtime-decode errors) and returns
  `(nil, *ResponseValidationError)` on any decode failure. `*HTTPError`
  is reserved for non-2xx transport failures — an HTTP 200 is not an
  HTTP error. The same applies uniformly across `GetCertificate`,
  `Messages`, `ListAuditEvents`, and any other 2xx-decode path.
  A 2xx JSON object whose shape is structurally valid but whose
  required fields are missing (Go's `json.Unmarshal` zero-values them
  permissively) is also rejected with `*ResponseValidationError` — the
  per-type `validateVeilCertificate` / `validateProxySyncResponse` /
  `validateProxyAcceptedResponse` helpers guard against silent "apparent
  success with zero-valued struct."
- **Error `.Body` type on over-cap**: Go stores the preserved prefix
  as `[]byte` — idiomatic for Go callers used to `resp.Body`-style
  byte-slice access. The Python SDK stores `.body` as `str`
  (UTF-8-decoded with `errors='replace'`) — idiomatic for Python
  callers used to `httpx.Response.text` / `.json()`. Behaviour parity
  holds at the "the prefix is preserved, bounded, and
  diagnostic-readable" level; the representation is intentionally
  language-idiomatic, not byte-identical.
- **Literal JSON null body**: when the gateway returns a 2xx with the
  literal `null` payload, `json.Unmarshal` produces Go `nil`; the SDK's
  `rawBodyBytes` re-marshals through `json.Marshal(nil)` to emit
  `[]byte("null")` on `*ResponseValidationError.Body`, preserving the
  "gateway sent null" signal so callers can distinguish it from "SDK
  forgot to populate `.Body`."

## Release

Versions are tagged as a pair against the same commit (see
`publish-go.yml`):

- `v0.1.0` — canonical monorepo tag (shared with TS + Python).
- `go/v0.1.0` — Go submodule tag required by Go's module path
  conventions for subdirectory modules. Publishing = pushing the
  `go/v*` tag and warming `proxy.golang.org`; no registry credentials.

## Development

```bash
cd go
go test ./... -race
go vet ./...
```

Tests include a byte-for-byte cross-check of Go canonical-JSON output
against the Go assembler's reference hex, and end-to-end verification
of a real Go-assembler-signed certificate. If either fails, the SDK's
Ed25519 verify will silently produce `invalid_signature` on valid
certs — do not skip or soft-fail those tests.

## License

MIT — see [LICENSE](../LICENSE).
