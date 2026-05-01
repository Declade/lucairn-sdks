# theveil — Python SDK

Client for **The Veil** — privacy-preserving AI infrastructure.

## Status

Pre-1.0 (0.1.0). Ships alongside the TypeScript SDK's `0.2.0` and behaves
identically at the observable level. See the [monorepo
README](../README.md) for the full SDK index.

## Install

```bash
pip install lucairn
```

Requires Python 3.10+.

## Quickstart

```python
from theveil import TheVeil, TheVeilConfig, VerifyCertificateKeys

client = TheVeil(TheVeilConfig(api_key="dsa_..."))

# Proxy a prompt through the Veil gateway (split-knowledge routing).
response = client.messages({
    "prompt_template": "Summarize the following in one sentence: {text}",
    "context": {"text": "Long input..."},
    "model": "claude-opus-4-7",
    "max_tokens": 256,
})

# Fetch the Veil Certificate for a known request_id (Pro+/Enterprise tier).
cert = client.get_certificate("req_abc123")

# Verify the witness Ed25519 signature against pinned trust-root keys.
keys = VerifyCertificateKeys(
    witness_key_id="witness_v1",
    witness_public_key="<base64 of raw 32-byte Ed25519 public key>",
)
result = client.verify_certificate(cert, keys)
print(result.overall_verdict, result.anchor_status)
```

## Public API

### `TheVeil(config: TheVeilConfig)`

Constructor validates every input up front:

- `api_key` must match `^dsa_[0-9a-f]{32}$`.
- `base_url` must be `http://` or `https://`; defaults to
  `https://gateway.dsaveil.io`.
- `timeout` must be a positive finite number of **seconds** (default `30.0`).
  TS SDK equivalent is `timeoutMs` (milliseconds) — Python uses seconds to
  match `httpx` / `requests` / `openai-python` / `anthropic-python`.

### `client.messages(params, options=None)`

POST to `/api/v1/proxy/messages`. Returns a discriminated union:

- `ProxySyncResponse` — terminal result (gateway returned 200).
- `ProxyAcceptedResponse` — async processing receipt (gateway returned 202,
  body `status: "processing"`). Poll the `status_url` until completion.

### `client.get_certificate(request_id, options=None)`

GET `/api/v1/veil/certificate/{request_id}`. Happy-path returns a
`VeilCertificate`. Gateway-side pending (certificate not yet assembled, or
unknown request_id — the gateway does not distinguish) surfaces as
`TheVeilHttpError` with `status=202` and a body
`{"status": "pending", "retry_after_seconds": 30, ...}` so the happy-path
return stays narrow. Inspect `err.body["retry_after_seconds"]` for the
retry signal.

No auto-verification — chain `client.verify_certificate()` explicitly.

### `client.verify_certificate(cert, keys)`

Verify a certificate's witness Ed25519 signature against the certificate's
canonical-JSON signed subset. Returns `VerifyCertificateResult` on success.
Raises `TheVeilCertificateError` with one of five reasons on failure:

| reason                            | condition                                                            |
|-----------------------------------|----------------------------------------------------------------------|
| `malformed`                       | cert shape invalid, gateway invariant broken, or unknown verdict     |
| `unsupported_protocol_version`    | `protocol_version != 2`                                              |
| `witness_mismatch`                | `keys.witness_key_id != cert.witness_key_id`                         |
| `witness_signature_missing`       | empty or whitespace-only `witness_signature`                         |
| `invalid_signature`               | Ed25519 verify failed, or key input malformed                        |

External RFC 3161 timestamp + Sigstore Rekor transparency-log verification
are out of scope for this release (pending upstream gateway fixes).

## Error hierarchy

All SDK errors inherit from `TheVeilError`:

- `TheVeilConfigError` — bad constructor input or per-call option.
- `TheVeilHttpError` — gateway returned non-2xx (or 202 from
  `get_certificate`); exposes `.status` and `.body`.
- `TheVeilResponseValidationError` — gateway returned 2xx but the body
  doesn't fit the declared response type (typically a gateway bug or
  version skew); exposes `.body` (raw response). The underlying
  `pydantic.ValidationError` or `ValueError` is preserved on
  `__cause__` for field-level inspection.
- `TheVeilTimeoutError` — request exceeded timeout.
- `TheVeilCertificateError` — `verify_certificate` failed; exposes
  `.reason` and (when available) `.certificate_id`.

Catch `TheVeilError` to handle all SDK errors uniformly.

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
  the dedicated `TheVeilResponseValidationError` — NOT
  `TheVeilHttpError`. The Python class follows the established
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
  `TheVeilResponseValidationError.body` so callers can distinguish
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
