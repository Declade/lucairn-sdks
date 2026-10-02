# lucairn — Python SDK

Client for **Lucairn** — privacy-preserving AI gateway.

## Status

`1.1.1`. Ships alongside the TypeScript SDK and behaves identically at the
observable level. See the [monorepo README](../README.md) for the full SDK
index.

Migration from the previous release: the package was previously
published under a different name (pre-1.0). For one minor-version cycle,
an in-tree compatibility shim re-exports every public symbol under its
previous name and emits a `DeprecationWarning` on import. To migrate,
change your imports to the new top-level names — the rename map and an
example are below.

```python
# old (still works for one minor cycle, with DeprecationWarning):
from theveil import TheVeil, TheVeilConfig

# new:
from lucairn import Lucairn, LucairnConfig
```

## Install

```bash
pip install lucairn
```

Requires Python 3.10+.

## Quickstart

```python
from lucairn import Lucairn, LucairnConfig

client = Lucairn(LucairnConfig(api_key="lcr_live_..."))

# Proxy a prompt through the Lucairn gateway (split-knowledge routing).
response = client.messages({
    "prompt_template": "Summarize the following in one sentence: {text}",
    "context": {"text": "Long input..."},
    "model": "claude-sonnet-4-6",
    "max_tokens": 256,
})
```

## Privacy receipts: free vs Pro tier paths

Every `messages()` call generates a privacy receipt witnessed by the
gateway. Two surfaces exist for that receipt, and which one your code
should consume depends on your tier:

- **`get_certificate_summary(request_id)`** — returns a human-readable
  HTML summary (DPO-friendly). **Available on every tier including
  Developer (free).**
- **`get_certificate(request_id)` + `verify_certificate(cert, keys)`** —
  fetches the raw JSON certificate and verifies the witness's Ed25519
  signature over its canonical signed subset. **Pro tier and above.**

If a Developer-tier key calls `get_certificate()`, the gateway returns
HTTP 403 with `{"error":"tier_insufficient","hint":"Contact sales to
upgrade."}`, surfaced by the SDK as `LucairnHttpError` with
`err.status == 403`.

### Developer tier (free) — render the HTML summary

```python
from lucairn import Lucairn, LucairnConfig, LucairnHttpError

client = Lucairn(LucairnConfig(api_key="lcr_live_..."))

response = client.messages({
    "prompt_template": "Hello {name}",
    "context": {"name": "Example Person"},
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
})

# `response.request_id` is populated on every tier (Developer / Pro / Enterprise).
# Pro/Enterprise responses additionally expose `response.veil.summary_url` if you
# want the summary URL directly without an extra fetch.
request_id = response.request_id

try:
    summary_html = client.get_certificate_summary(request_id)
except LucairnHttpError as err:
    if err.status == 503:
        # Veil Witness temporarily unavailable; retry later.
        return
    raise
# Display summary_html in a sandboxed iframe or save for the DPO.
```

### Pro tier and above — fetch + verify the JSON certificate

On Pro and Enterprise tier responses the gateway adds a `veil` block
(accessible as `response.veil.summary_url` and
`response.veil.certificate_url`). Pro and Enterprise keys can also fetch
the raw certificate and verify the witness Ed25519
signature locally for a programmatic audit trail.

```python
from lucairn import Lucairn, LucairnConfig, VerifyCertificateKeys, LucairnHttpError

client = Lucairn(LucairnConfig(api_key="lcr_live_..."))

try:
    cert = client.get_certificate(request_id)  # 200 on Pro/Enterprise; 403 on Developer (free)
except LucairnHttpError as err:
    if err.status == 202:
        # Certificate not yet assembled; retry after err.body["retry_after_seconds"].
        return
    if err.status == 403:
        # Developer (free) tier — use get_certificate_summary() instead.
        return
    raise

keys = VerifyCertificateKeys(
    witness_key_id="witness_v1",
    witness_public_key="<base64 of raw 32-byte Ed25519 public key>",
)
result = client.verify_certificate(cert, keys)
print(result.overall_verdict, result.anchor_status)
```

> **Witness key format.** `witness_public_key` must be the **raw 32-byte**
> Ed25519 public key, supplied as `bytes` or a base64 string. The pilot's
> `/.well-known/veil-keys.json` discovery endpoint, however, serves the key
> as a **hex** string. Decode hex → bytes before passing it in, otherwise
> verification fails with `must be 32 bytes, got 48`:
>
> ```python
> # hex (e.g. from /.well-known/veil-keys.json) -> raw 32 bytes
> witness_public_key = bytes.fromhex(hex_string)
> keys = VerifyCertificateKeys(
>     witness_key_id="witness_v1",
>     witness_public_key=witness_public_key,
> )
> ```

## Public API

### `Lucairn(config: LucairnConfig)`

Constructor validates every input up front:

- `api_key` must be a Lucairn key (`lcr_live_...`) or a legacy `dsa_...` key.
- `base_url` must be `http://` or `https://`; defaults to
  `https://gateway.lucairn.eu`.
- `timeout` must be a positive finite number of **seconds** (default `60.0`).
  TS SDK equivalent is `timeoutMs` (milliseconds) — Python uses seconds to
  match `httpx` / `requests` / `openai-python` / `anthropic-python`.

### `client.messages(params, options=None)`

POST to `/api/v1/proxy/messages`. Returns a discriminated union:

- `ProxySyncResponse` — terminal result (gateway returned 200).
- `ProxyAcceptedResponse` — async processing receipt (gateway returned 202,
  body `status: "processing"`). Poll the `status_url` until completion.

### `client.get_certificate(request_id, options=None)`

GET `/api/v1/veil/certificate/{request_id}`. **Pro tier or above** —
Developer (free) tier returns HTTP 403 `tier_insufficient`, surfaced as
`LucairnHttpError` with `err.status == 403`.

Happy-path returns a `VeilCertificate`. Gateway-side pending
(certificate not yet assembled, or unknown request_id — the gateway does
not distinguish) surfaces as `LucairnHttpError` with `status=202` and a
body `{"status": "pending", "retry_after_seconds": 30, ...}` so the
happy-path return stays narrow. Inspect `err.body["retry_after_seconds"]`
for the retry signal.

No auto-verification — chain `client.verify_certificate()` explicitly.

### `client.get_certificate_summary(request_id, options=None)`

GET `/api/v1/veil/certificate/{request_id}/summary`. **Available on
every tier including Developer (free).** Returns the DPO-friendly HTML
summary as a UTF-8 `str`. Per the gateway source the pending case
renders an HTML body at HTTP 200 (not a 202 wrapper), so the SDK passes
the rendered HTML straight back to the caller.

### `client.list_audit_events(opts=None)`

GET `/api/v1/audit/export`. Returns an `AuditExportResponse` with the
customer's audit events for the requested lookback window:

```python
from lucairn import AuditExportOptions

resp = client.list_audit_events(AuditExportOptions(days=7, type="proxy.completed"))
print(resp.tier, resp.total_events)
for e in resp.events:
    print(e.timestamp, e.event_type, e.request_id)
```

- `days`: int 1..90 (gateway default 30, max 90).
- `type`: optional event-type filter.
- 503 `audit_export_unavailable` (tier-gated; not enabled for the calling
  customer) raises `LucairnHttpError` with `err.status == 503` and
  `err.body["code"] == "audit_export_unavailable"`.

### `client.verify_certificate(cert, keys)`

Verify a certificate's witness Ed25519 signature against the certificate's
canonical-JSON signed subset. Returns `VerifyCertificateResult` on success.
Raises `LucairnCertificateError` with one of five reasons on failure:

| reason                            | condition                                                            |
|-----------------------------------|----------------------------------------------------------------------|
| `malformed`                       | cert shape invalid, gateway invariant broken, or unknown verdict     |
| `unsupported_protocol_version`    | `protocol_version != 2`                                              |
| `witness_mismatch`                | `keys.witness_key_id != cert.witness_key_id`                         |
| `witness_signature_missing`       | empty or whitespace-only `witness_signature`                         |
| `invalid_signature`               | Ed25519 verify failed, or key input malformed                        |

External RFC 3161 timestamp + Sigstore Rekor transparency-log verification
are out of scope for this release (pending upstream gateway fixes).

### `verify_certificate_chain(certificate, keys, *, minimum_signable_version=None, expected_request_id=None, expected_certificate_id=None)`

`verify_certificate()` above checks the witness signatures only. The witness
signs the LIST of claim ids, not the claim contents, so a certificate whose
claim body was edited under the same claim id still passes it.
`lucairn.verify_certificate_chain()` (also `client.verify_certificate_chain()`)
runs the full check: every claim's own signature against the key you pin for
its service, the claim bytes rebuilt from the outer fields, claim-id
membership, the unsigned typed copies against the signed payload, the signed
upstream-request hashes, the unsigned `cert_tier` against its signed copies,
and (when you pass it) the request the certificate belongs to. It is
additive: `verify_certificate()` is unchanged.

It takes the **raw certificate JSON** (`bytes` or `str`, at most 32 MiB), not
a parsed `dict`, because number lexemes, duplicate keys and trailing bytes are
part of the checks. It never raises on a bad certificate: it returns a
`CertificateChainResult` with a `verdict` and the `reason` of the check that
decided (`.to_dict()` gives the plain mapping). It raises only for programmer
errors: `PinnedKeyError` (a `ValueError`) when a pinned key is refused, and
`TypeError` / `ValueError` for a malformed key set, an unknown policy or a
non-string expected id.

**Input size.** The 32 MiB limit is a format limit, not a memory budget: a
pathological document (for example millions of tiny values) can take many times
its size in memory while it is parsed. If you verify certificates from an
untrusted relay or upload, cap the input yourself before calling the verifier
(8 MiB is ample for a real certificate) and treat anything larger as unverified.

```python
from lucairn import CertificateChainKeys, verify_certificate_chain

raw = httpx.get(f"{gateway}/api/v1/veil/certificate/{request_id}", headers=headers).content

result = verify_certificate_chain(
    raw,
    CertificateChainKeys(
        witness_key_id="witness_v1",
        witness_public_key=witness_key_b64,
        # one key per claim-emitting service in your deployment;
        # a claim from an unpinned service FAILS the certificate
        service_public_keys={
            "dsa-sanitizer": sanitizer_key_b64,
            "dsa-ai": ai_key_b64,
            "dsa-gateway": gateway_key_b64,
            "dsa-bridge": bridge_key_b64,
            "dsa-audit": audit_key_b64,
            "dsa-reid-guard": reid_guard_key_b64,  # where deployed
        },
    ),
    expected_request_id=request_id,  # always: the turn you are showing
    minimum_signable_version="v3",   # omit for the legacy-tolerant default
)
if result.verdict != "VERIFIED":
    print(result.verdict, result.reason)
if result.user_unredacted == "true":
    show_sent_unredacted_mark()
if result.verified is not None:
    cert = result.verified["certificate"]          # the witness-signed values
    client = cert.get("client_id")                 # absent unless the v3 signature verified
    for key, claim in result.verified["claims"].items():
        index, rest = key.split(":", 1)
        service_id, claim_type = rest.rsplit(":", 1)
        model = claim["values"].get("/payload/model_used")  # signed value, or None
```

**Which keys to pin.** Pin the per-service public keys your Lucairn operator publishes for your deployment, the same way you pin the witness key, and pin every service that emits claims there (including, where present, `dsa-reid-guard` and `dsa-sanitizer-streaming`): a claim from an unpinned service FAILS the certificate. A published key endpoint is planned; this release does not fetch keys. Keys are raw 32 bytes or their canonical standard padded base64 (no hex, no URL-safe alphabet, no missing padding, no whitespace). Every key passes a pinned-key policy each time the key set is loaded, and `PinnedKeyError.code` says why one was refused: `key_malformed`, `key_small_order` (a small-order point would let one forged signature verify over many messages), `key_invalid_point`, or `key_test_key`. The TypeScript SDK raises the same `PinnedKeyError`; the Go SDK's equivalent is `KeyPolicyError`, with the same codes in its `Code` field.

**Never pin the parity-corpus keys.** The keys in [`testdata/parity-corpus/`](https://github.com/Declade/lucairn-sdks/tree/main/testdata/parity-corpus) are test keys derived from a public seed, so anyone can sign with them. The verifier refuses them (`key_test_key`) unless `CertificateChainKeys(allow_test_keys=True)`; only a parity test harness sets that, never a product.

**Always pass the expected request id.** When you show a certificate for a turn you know, pass that turn's `expected_request_id` (and, if you have it, `expected_certificate_id`). A supplied value must equal the witness-signed one exactly, or the result is `FAILED` / `request_mismatch`; an empty string counts as supplied. `request_binding` reports `matched`, `not_checked` (nothing supplied) or `not_evaluated` (every `FAILED` result). This stops a genuine certificate of ANOTHER turn being served for this one by a store, fetch path or relay. It does not stop a compromised gateway or local proxy: the gateway issues the request id, so it could hand out an earlier clean turn's id together with that turn's certificate.

**What the result means.**

| `verdict` | meaning |
|---|---|
| `VERIFIED` | every check passed, and exactly one claim signs a list of upstream-request SHA-256 hashes (one per request attempt the inference sandbox recorded) with the pinned `dsa-ai` key. |
| `EGRESS_UNATTESTED` | every check passed, but no signed upstream-request hash exists (older certificates, the input-shield lane today). Never treat it as green. |
| `PARTIAL` | the signatures hold, but the certificate itself says something is missing, unfinished or opted out (`reason` says which, e.g. `user_sent_unredacted`). |
| `FAILED` | an integrity, binding or policy check broke, or the witness itself sealed FAILED. |

Only `VERIFIED` is green, and the verdict to display is `result.verdict` — never `verified["certificate"]["overall_verdict"]`, which is only what the witness sealed (every legacy certificate says `VERIFIED` there and ends at `EGRESS_UNATTESTED` here). The result also carries `signed_cert_tier` (`absent`, `input_shield`, `inconsistent`, `input_shield_two_signer` for an input-shield chain sealed with only the sanitizer and gateway claims, `audit_only` for a certificate-only chain — the sanitizer skipped by design, the content NOT sanitized, so never show a `VERIFIED` `audit_only` result as a sanitized certificate — or `not_evaluated`; show this, never the unsigned `verification.cert_tier`), `signable_version` (`v3` / `v2` / `none`) and `user_unredacted`, a **string** (`"true"` / `"false"` / `"unknown"`) read from the signed sanitizer claim only. Compare it to `"true"`; `"false"` is a non-empty string.

**Render and decide only from `verified`.** `result.verified` is `None` on every `FAILED` result; otherwise it is built only from signed bytes:

- `verified["certificate"]` is the witness signable map that verified: the 7 v2 keys (`certificate_id`, `claim_ids`, `issued_at`, `overall_verdict`, `protocol_version`, `request_id`, `witness_key_id`), plus `api_key_id`, `byok_exempt`, `client_id`, `redaction_manifest_hash`, `sanitized_fields_body_hash`, `tms_manifest_hash` only when the v3 witness signature verified. Under v2 those six keys are simply absent — never show them.
- `verified["claims"]` has one entry per claim, keyed `"<index>:<service_id>:<claim_type>"` (the claim type is the SIGNED one and may be `""`; it never contains `:`, so split at the first and the last `:`, and order by the parsed index, not the key). Each entry has `canonical`, the claim's signed canonical JSON as an exact string, and `values`, every string, boolean and integer leaf of that signed document under its RFC 6901 JSON Pointer (`/payload/model_used`, `/data_seen/0`). `null`, non-integer numbers and empty containers have no `values` entry; read them from `canonical`.
- More than one claim can share a service and type: pick the egress claim as the one whose `values` carry `/payload/upstream_body_sha256/0`.

Everything else in the certificate is unverified, and a list of it could never be complete. Do not read the raw certificate, and do not parse it a second time (a second parser can read a field no signature covers: a case-insensitive decoder, a duplicate key, a typed copy, `upstream_model`, `verification.*`). A "sent unredacted" mark, a BYOK badge or policy, a client or API-key attribution, a model or encryption claim: if it is not in `verified` (or the result's own fields), do not show it. Strict callers pass `minimum_signable_version="v3"`, which fails every certificate that only carries the v2 witness signature.

**Showing an upstream request body.** The stored request bodies are not signed and not copied into `verified`. Before you display one, hash its exact bytes with SHA-256 and require the lowercase hex digest to equal the verified value at `/payload/upstream_body_sha256/<i>` of the egress claim, `i` being the body's position.

Limits: this is the signature of the bytes Lucairn sent. It does not tell you what the model provider received or did. A `VERIFIED` result means "signed with the pinned `dsa-ai` key"; it does not say which Lucairn component held that key. The full rules (input grammar, timestamp grammar, canonical JSON and base64, Ed25519 acceptance, typed-field binding) are implemented in this SDK's source with comments. The 84-case test corpus, the pinned-key vectors and the ordered check table are vendored at [`testdata/parity-corpus/`](https://github.com/Declade/lucairn-sdks/tree/main/testdata/parity-corpus); the TypeScript, Python and Go SDKs return identical results on every case under both policies.

### `lucairn.get_client_id(cert)`

Module-level helper returning `cert.client_id` (the org-scoped
correlation field added by W2A-B1) or `None` if the certificate predates
the change. The field is unsigned metadata at the witness signable
layer — tamper evidence flows indirectly through the bridge claim's
bridge-signed `canonical_payload`.

## Error hierarchy

All SDK errors inherit from `LucairnError`:

- `LucairnConfigError` — bad constructor input or per-call option.
- `LucairnHttpError` — gateway returned non-2xx (or 202 from
  `get_certificate`); exposes `.status` and `.body`.
- `LucairnResponseValidationError` — gateway returned 2xx but the body
  doesn't fit the declared response type (typically a gateway bug or
  version skew); exposes `.body` (raw response). The underlying
  `pydantic.ValidationError` or `ValueError` is preserved on
  `__cause__` for field-level inspection.
- `LucairnTimeoutError` — request exceeded timeout.
- `LucairnCertificateError` — `verify_certificate` failed; exposes
  `.reason` and (when available) `.certificate_id`.

Catch `LucairnError` to handle all SDK errors uniformly.

## Behavioural parity with TS

This SDK is cross-language byte-equivalent to the TS SDK for
`canonical_json` and `verify_certificate`. The Go-assembler-signed cert
fixture (`cert-go-signed-reference.json`) verifies identically in both.

Intentional divergences where TS semantics don't port cleanly to Python:

- **Timeout**: seconds (Python) vs. milliseconds (TS). Validator shape
  identical (positive finite).
- **Abort/cancel**: v1 sync Python has timeout only; no `signal` analogue.
  Cancellation arrives with the async client in a later arc.
- **Malformed 2xx body**: TS passes through as raw text typed as
  `VeilCertificate` (thin transport); Python calls
  `VeilCertificate.model_validate` and, on a shape mismatch, raises
  the dedicated `LucairnResponseValidationError` — NOT
  `LucairnHttpError`. The Python class follows the established
  Python-SDK precedent (`openai.APIResponseValidationError`,
  `anthropic.APIResponseValidationError`): an HTTP 200 is not an HTTP
  error, and callers benefit from being able to catch "transport
  failed" separately from "body doesn't fit the declared type." TS's
  pass-through model remains the authoritative behaviour for the TS
  surface; Python fails earlier (at fetch) because Pydantic validates
  at deserialize-time, and the failure class names the reason
  precisely instead of lying via `status=200`.
- **Error `.body` type on over-cap**: Python stores the preserved
  prefix as `str` (UTF-8-decoded with `errors='replace'`) — idiomatic
  for Python SDK callers used to `httpx.Response.text` / `.json()`.
  The Go SDK stores `.Body` as `[]byte` for the same case — idiomatic
  for Go callers used to `resp.Body`-style byte-slice access. Behaviour
  parity holds at the "the prefix is preserved, bounded, and
  diagnostic-readable" level; the representation is intentionally
  language-idiomatic, not byte-identical.
- **Literal JSON null body**: when the gateway returns a 2xx with the
  literal `null` payload, the parsed body is Python `None`; the SDK
  falls back to the raw pre-parse text (`"null"`) for
  `LucairnResponseValidationError.body` so callers can distinguish
  "gateway sent null" from "SDK forgot to populate the error body."

## Development

```bash
cd python
pip install -e ".[dev]"
pytest
```

Tests include a byte-for-byte cross-check of Python canonical-JSON output
against the Go assembler's reference hex, and end-to-end verification of
a real Go-assembler-signed certificate. If either fails, the SDK's Ed25519
verify will silently produce `invalid_signature` on valid certs — do not
skip or soft-fail those tests.

## License

MIT — see [LICENSE](../LICENSE).
