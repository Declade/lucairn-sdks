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
