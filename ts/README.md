# @lucairn/sdk

## Status

The `Lucairn` client ships construction-time `apiKey` validation,
`baseUrl` normalization with scheme guards, per-call timeout composition,
the `client.messages()` proxy endpoint, `client.getCertificate()` and
`client.getCertificateSummary()` fetch helpers, `client.listAuditEvents()`
audit-export helper, `client.verifyCertificate()` for witness-signature
verification, and five typed error classes. See [CHANGELOG](../CHANGELOG.md)
for the rebrand from `@dsaveil/theveil`.

Node-first. Browser use requires gateway CORS configuration (not covered
by this release).

## Install

```sh
npm install @lucairn/sdk
```

## Construct a client

```ts
import { Lucairn } from '@lucairn/sdk';

const client = new Lucairn({ apiKey: process.env.LUCAIRN_API_KEY! });
```

The default `baseUrl` is `https://gateway.lucairn.eu` (the hosted Lucairn
gateway). Enterprise self-host deployments must pass `baseUrl` explicitly.

## Send a request through the privacy-preserving proxy

```ts
const response = await client.messages({
  prompt_template: 'Hello {name}',
  context: { name: 'Example Person' },
  model: 'claude-sonnet-4-6',
  max_tokens: 1024,
});
```

## Privacy receipts: free vs Pro tier paths

Every `messages()` call generates a privacy receipt witnessed by the
gateway. Two surfaces exist for that receipt, and which one your code
should consume depends on your tier:

- **`getCertificateSummary(requestId)`** — returns a human-readable HTML
  summary (DPO-friendly). **Available on every tier including Developer
  (free).**
- **`getCertificate(requestId)` + `verifyCertificate(cert, keys)`** —
  fetches the raw JSON certificate and verifies the witness's Ed25519
  signature over its canonical signed subset. **Pro tier and above.**

If a Developer-tier key calls `getCertificate()`, the gateway returns
HTTP 403 with `{"error":"tier_insufficient","hint":"Contact sales to
upgrade."}`, surfaced by the SDK as `LucairnHttpError` with `status === 403`.

### Developer tier (free) — render the HTML summary

```ts
import { Lucairn, LucairnHttpError } from '@lucairn/sdk';

const client = new Lucairn({ apiKey: process.env.LUCAIRN_API_KEY! });

const response = await client.messages({
  prompt_template: 'Hello {name}',
  context: { name: 'Example Person' },
  model: 'claude-sonnet-4-6',
  max_tokens: 1024,
});

// `response.request_id` is populated on every tier (Developer / Pro / Enterprise).
// Pro/Enterprise responses additionally expose `response.veil.summary_url` if you
// want the summary URL directly without an extra fetch.
const requestId = response.request_id;

let summaryHtml: string;
try {
  summaryHtml = await client.getCertificateSummary(requestId);
} catch (err) {
  if (err instanceof LucairnHttpError && err.status === 202) {
    // Pending; the body is the gateway's "pending" HTML view.
    return;
  }
  throw err;
}
// Display summaryHtml in a sandboxed iframe or save for the DPO.
```

### Pro tier and above — fetch + verify the JSON certificate

On Pro and Enterprise tier responses the gateway adds a `veil` block with
`summary_url` and `certificate_url`. Pro and Enterprise keys can also fetch the raw
certificate and verify the witness Ed25519 signature locally for a
programmatic audit trail.

`client.getCertificate(requestId)` returns the raw `VeilCertificate`.
Pair it with `client.verifyCertificate(cert, keys)` to prove the
witness's Ed25519 signature over the certificate's canonical JSON
signed subset. The two calls are deliberately separate: the SDK never
fetches or bakes in witness keys, and the caller supplies the witness
identity (expected `witnessKeyId` label and raw 32-byte
`witnessPublicKey`) out of band.

External RFC 3161 timestamp verification and Sigstore Rekor transparency-
log verification are **not** performed by this release. They land in a
follow-up release pending gateway work. Until then, `anchorStatus` and
`overallVerdict` are surfaced as pass-through metadata for observability,
not independently verified.

Quota behaviour for certificate reads is a gateway-side concern; see the
gateway documentation for current tier limits.

```ts
import {
  Lucairn,
  LucairnCertificateError,
  LucairnHttpError,
} from '@lucairn/sdk';

const client = new Lucairn({ apiKey: process.env.LUCAIRN_API_KEY! });

let cert;
try {
  cert = await client.getCertificate(requestId); // 200 on Pro/Enterprise; 403 on Developer (free)
} catch (err) {
  if (err instanceof LucairnHttpError && err.status === 202) {
    // Certificate not yet assembled — retry after the indicated delay.
    const body = err.body as { retry_after_seconds?: number };
    const retryAfter = body.retry_after_seconds ?? 30;
    console.log(`pending; retry in ${retryAfter}s`);
    return;
  }
  if (err instanceof LucairnHttpError && err.status === 403) {
    // Developer (free) tier — use getCertificateSummary() instead.
    console.log('certificate JSON requires Pro tier or above');
    return;
  }
  throw err;
}

try {
  const result = await client.verifyCertificate(cert, {
    witnessKeyId: 'witness_v1',
    witnessPublicKey: process.env.VEIL_WITNESS_PUBLIC_KEY_BASE64!,
  });
  // result.witnessAssertedIssuedAtIso preserves full nanosecond precision;
  // result.witnessAssertedIssuedAt is the millisecond-truncated Date form.
  console.log('verified', result.certificateId, result.witnessAssertedIssuedAtIso);
} catch (err) {
  if (err instanceof LucairnCertificateError) {
    switch (err.reason) {
      case 'malformed':
      case 'unsupported_protocol_version':
      case 'witness_mismatch':
      case 'witness_signature_missing':
      case 'invalid_signature':
        console.error(`verify failed (${err.reason}):`, err.message);
        break;
    }
    return;
  }
  throw err;
}
```

> **Witness key format.** `witnessPublicKey` must be the **raw 32-byte**
> Ed25519 public key, supplied as a `Uint8Array` or a base64 string. The
> pilot's `/.well-known/veil-keys.json` discovery endpoint, however, serves
> the key as a **hex** string. Decode hex → bytes before passing it in,
> otherwise verification fails with `must be 32 bytes, got 48`:
>
> ```ts
> // hex (e.g. from /.well-known/veil-keys.json) -> raw 32 bytes
> const witnessPublicKey = Uint8Array.from(
>   hexString.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
> );
> // ...then pass witnessPublicKey to verifyCertificate({ witnessKeyId, witnessPublicKey })
> ```

### Check every claim: `verifyCertificateChain(certificate, keys, options?)`

`verifyCertificate()` above checks the witness signatures only. The witness
signs the LIST of claim ids, not the claim contents, so a certificate whose
claim body was edited under the same claim id still passes it.
`verifyCertificateChain()` (also `client.verifyCertificateChain()`) runs the
full check: every claim's own signature against the key you pin for its
service, the claim bytes rebuilt from the outer fields, claim-id membership,
the unsigned typed copies against the signed payload, the signed
upstream-request hashes, the unsigned `cert_tier` against its signed copies,
and (when you pass one) the request id of the turn. It is additive:
`verifyCertificate()` is unchanged.

It takes the **raw certificate bytes** (a `Uint8Array`, or a string), not a
`JSON.parse` result, because number lexemes, duplicate keys and trailing bytes
are part of the checks. Read the HTTP body with `arrayBuffer()`, not `text()`:
`text()` silently drops a byte-order mark and replaces invalid UTF-8, which
turns an input the verifier must refuse into one it would accept. The input
is at most 32 MiB. It never throws on a bad certificate: it returns a result
with a `verdict` and the `reason` of the check that decided. It throws a
`TypeError` only for programmer errors: a malformed key set or option, or a
pinned key the key policy refuses (a `PinnedKeyError` with a `code`, below; the Go SDK's equivalent is `KeyPolicyError`).

**Input size.** The 32 MiB limit is a format limit, not a memory budget: a
pathological document (for example millions of tiny values) can take many times
its size in memory while it is parsed (in this SDK, up to several gigabytes). If you verify certificates from an
untrusted relay or upload, cap the input yourself before calling the verifier
(8 MiB is ample for a real certificate) and treat anything larger as unverified.

```ts
import { verifyCertificateChain } from '@lucairn/sdk';

const res = await fetch(`${gateway}/api/v1/veil/certificate/${requestId}`, { headers });
const raw = new Uint8Array(await res.arrayBuffer()); // the exact bytes, not res.text() / res.json()

const result = await verifyCertificateChain(raw, {
  witnessKeyId: 'witness_v1',
  witnessPublicKey: witnessKeyBase64,
  servicePublicKeys: {
    // one key per claim-emitting service in your deployment;
    // a claim from an unpinned service FAILS the certificate
    'dsa-sanitizer': sanitizerKeyBase64,
    'dsa-ai': aiKeyBase64,
    'dsa-gateway': gatewayKeyBase64,
    'dsa-bridge': bridgeKeyBase64,
    'dsa-audit': auditKeyBase64,
    'dsa-reid-guard': reidGuardKeyBase64, // where deployed
  },
}, {
  expectedRequestId: requestId,     // ALWAYS pass the id of the turn you show
  minimumSignableVersion: 'v3',     // omit for the legacy-tolerant default
});

if (result.verdict !== 'VERIFIED') console.warn(result.verdict, result.reason);
if (result.user_unredacted === 'true') showSentUnredactedMark();
const v = result.verified; // null on every FAILED result
if (v) showClient(v.certificate.client_id); // absent (undefined) on a v2-only certificate: show nothing
```

**Render and decide only from `verified`.** Besides `verdict`, `reason`,
`egress_attestation`, `signed_cert_tier`, `user_unredacted` and
`request_binding`, the result carries `verified`, built ONLY from signed
bytes; it is `null` on every FAILED result:

- `verified.certificate` is exactly the witness signable map whose signature
  verified: the 7 v2 keys, plus `api_key_id`, `byok_exempt`, `client_id`,
  `redaction_manifest_hash`, `sanitized_fields_body_hash` and
  `tms_manifest_hash` when the v3 signature verified. On a certificate that
  carries only the v2 signature those v3 keys are ABSENT: never show a
  client, API key or BYOK value then.
- `verified.claims` has one entry per claim, keyed
  `<index>:<service_id>:<claim_type>` (e.g. `2:dsa-ai:INFERENCE_COMPLETED`):
  `canonical` is the claim's signed bytes as a string, exactly, and `values`
  maps each string, boolean and integer leaf of the signed document to its
  JSON Pointer (`/payload/model_used`, `/data_seen/0`). Integers are
  `bigint` (they can exceed 2^53), so `JSON.stringify(result.verified)` throws;
  serialize with `canonicalVerifiedJson`. A path missing from `values` (a float,
  `null`) may still be in `canonical`. Order claims by the parsed index,
  never by key order.

Never read a value from the raw certificate or from a second parse of it
(`JSON.parse`, a typed model): anything outside `verified` is covered by no
signature — the typed claim copies, `upstream_model`, every `verification.*`
field, the outer claim timestamps. What is not in `verified` is not verified:
not a BYOK badge, not a "sent unredacted" mark, not a client or API-key
attribution, not a model claim. Show the verdict from `result.verdict`, never
`verified.certificate.overall_verdict` (that is what the witness sealed). An
upstream request body (from a witness export or the gateway's
`/upstream-request` endpoint) is unsigned: before you display it, hash its
exact bytes with SHA-256 and require the lowercase hex to equal
`values['/payload/upstream_body_sha256/<i>']` of the claim that carries that
key, `i` = the body's position. `canonicalVerifiedJson(result.verified)`
gives the canonical JSON form every Lucairn verifier is compared in.

**Request binding.** Pass `expectedRequestId` (and, if you have it,
`expectedCertificateId`) whenever you verify a certificate for a turn you
know. Each supplied value must equal the witness-signed one, or the result is
FAILED `request_mismatch`; `request_binding` then says `matched`, or
`not_checked` when you supplied none. This stops a genuine certificate of
ANOTHER turn being served for this one by a store, a fetch path or a relay.
It does not stop a compromised gateway or local proxy: the gateway issues the
request id, so it can hand out an earlier clean turn's id together with that
turn's genuine certificate.

**Which keys to pin.** Pin the per-service public keys your Lucairn operator publishes for your deployment, the same way you pin the witness key, and pin every service that emits claims there (including, where present, `dsa-reid-guard` and `dsa-sanitizer-streaming`): a claim from an unpinned service FAILS the certificate. A published key endpoint is planned; this release does not fetch keys. Every key must be canonical standard padded base64 of exactly 32 bytes (or exactly 32 raw bytes); hex, URL-safe base64, missing padding or whitespace are refused (`key_malformed`), as are the small-order points (`key_small_order`) and encodings that are not a point on the curve (`key_invalid_point`). If your key source serves hex, decode it to 32 raw bytes first.

**Never pin the test-corpus keys.** The keys in the vendored parity corpus are test keys whose private keys follow from a public seed. The verifier refuses them (`key_test_key`) unless `allowTestKeys: true` is set, which only a parity test harness does; never set it in a product.

**What the result means.**

| `verdict` | meaning |
|---|---|
| `VERIFIED` | every check passed, and exactly one claim signs a list of upstream-request SHA-256 hashes (one per request attempt the inference sandbox recorded) with the pinned `dsa-ai` key. A witness export that carries the request bodies inline has them checked against the signed hashes here; bodies fetched separately must be hashed by you before display (above). Certificates without signed hashes end at `EGRESS_UNATTESTED`. |
| `EGRESS_UNATTESTED` | every check passed, but no signed upstream-request hash exists (older certificates, the input-shield lane today). Never treat it as green. |
| `PARTIAL` | the signatures hold, but the certificate itself says something is missing, unfinished or opted out (`reason` says which, e.g. `user_sent_unredacted`). |
| `FAILED` | an integrity, binding or policy check broke, or the witness itself sealed FAILED. |

Only `VERIFIED` is green. Show `signed_cert_tier`, never the unsigned `verification.cert_tier`. `signed_cert_tier` is `absent`, `input_shield`, `input_shield_two_signer` (the certificate is labelled `input_shield_two_signer`, only the gateway signs an input-shield tier, and the chain has a `dsa-sanitizer` claim and no `dsa-ai` claim; it never reaches `VERIFIED`), `audit_only` (a certificate-only chain: the one `dsa-ai` claim signs `cert_tier: "audit-only"`, the sanitizer was skipped by design — the content was NOT sanitized, so a `VERIFIED` `audit_only` result must never be shown as a sanitized certificate), `inconsistent`, or `not_evaluated` on a FAILED result. `user_unredacted` is a **string** (`"true"` / `"false"` / `"unknown"`) read from the signed sanitizer claim only: compare it to `"true"`; `"false"` is a non-empty string. The default policy accepts certificates that carry only the older v2 witness signature; that is safe only because you render from `verified`, where their v3 values are absent. Strict callers pass `minimumSignableVersion: 'v3'`, which FAILS every such certificate.

Limits: this is the signature of the bytes Lucairn sent. It does not tell you what the model provider received or did. A `VERIFIED` result means "signed with the pinned `dsa-ai` key"; it does not say which Lucairn component held that key. The full rules (timestamp grammar, canonical JSON and base64, typed-field binding, key policy) are implemented in this SDK's source with comments. The 84-case test corpus, its key-policy vectors and the ordered check table are vendored at [`testdata/parity-corpus/`](https://github.com/Declade/lucairn-sdks/tree/main/testdata/parity-corpus); the TypeScript, Python and Go SDKs return identical results on every case under both policies.

## New helpers (1.0)

### `getCertificateSummary(requestId, options?): Promise<string>`

Returns a DPO-friendly HTML summary of a Veil Certificate. **Available on
every tier including Developer (free).** The endpoint returns text/html;
the helper returns the raw HTML string. When the certificate is not yet
assembled, the gateway responds 202 Accepted with a pending-summary HTML
body, surfaced as `LucairnHttpError({ status: 202, body: '<html>...</html>' })`.

```ts
let summaryHtml: string;
try {
  summaryHtml = await client.getCertificateSummary(requestId);
} catch (err) {
  if (err instanceof LucairnHttpError && err.status === 202) {
    // Pending; the body is the gateway's "pending" HTML view.
    return;
  }
  throw err;
}
```

### `getClientId(cert): string | null`

Reads the optional `client_id` (org_id metadata) from a Veil Certificate.
Returns the value, or `null` when missing or `null` on the wire.

```ts
import { getClientId } from '@lucairn/sdk';

const orgId = getClientId(cert);
```

`client_id` is unsigned metadata for client-side correlation. For
tamper-evident proof of the issuing org, walk the bridge claim's
`canonical_payload` (which IS in the witness signable map).

### `listAuditEvents(opts?): Promise<AuditExportResponse>`

Lists the calling customer's recent audit events. Tier-gated server-side
(403 `tier_insufficient` if the customer's tier doesn't include audit
export). `days` defaults to 30 and is capped at 90 by the gateway.

```ts
const result = await client.listAuditEvents({ days: 7, eventType: 'request_recorded' });
console.log(`${result.total_events} events from ${result.source}`);
for (const ev of result.events) {
  console.log(ev.timestamp, ev.event_type, ev.request_id);
}
```

## Migrating from `@dsaveil/theveil`

The pre-1.0 package name `@dsaveil/theveil` and class name `TheVeil` are
re-exported as legacy aliases for one minor-version cycle so existing
imports keep compiling:

```ts
// Both of these import the same constructor.
import { TheVeil } from '@lucairn/sdk';   // legacy alias
import { Lucairn } from '@lucairn/sdk';   // new name
```

The legacy aliases (`TheVeil`, `TheVeilError`, `TheVeilConfigError`,
`TheVeilHttpError`, `TheVeilTimeoutError`, `TheVeilCertificateError`,
`TheVeilConfig`) will be removed in the next minor bump. Migrate before
upgrading past `1.x.0`.

## Back to root

See the [monorepo README](../README.md) for the full SDK index.
