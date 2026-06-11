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
- `timeout` must be a positive finite number of **seconds** (default `30.0`).
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
