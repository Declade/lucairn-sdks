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
upstream-request hashes, and the unsigned `cert_tier` against its signed
copies. It is additive: `verifyCertificate()` is unchanged.

It takes the **raw certificate JSON text** (string or UTF-8 bytes), not a
`JSON.parse` result, because number lexemes and trailing bytes are part of
the checks. It never throws on a bad certificate: it returns a result with a
`verdict` and the `reason` of the check that decided. It throws `TypeError`
only for programmer errors (a malformed key set).

```ts
import { verifyCertificateChain } from '@lucairn/sdk';

const res = await fetch(`${gateway}/api/v1/veil/certificate/${requestId}`, { headers });
const raw = await res.text(); // the raw body, not res.json()

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
}, { minimumSignableVersion: 'v3' }); // omit for the legacy-tolerant default

if (result.verdict !== 'VERIFIED') console.warn(result.verdict, result.reason);
if (result.user_unredacted === 'true') showSentUnredactedMark();
for (const f of result.unauthenticated_fields) markUnverified(f);
```

**Which keys to pin.** Pin the per-service public keys your Lucairn operator publishes for your deployment, the same way you pin the witness key, and pin every service that emits claims there (including, where present, `dsa-reid-guard` and `dsa-sanitizer-streaming`): a claim from an unpinned service FAILS the certificate. A published key endpoint is planned; this release does not fetch keys.

**What the result means.**

| `verdict` | meaning |
|---|---|
| `VERIFIED` | every check passed, and exactly one claim signs a list of upstream-request SHA-256 hashes (one per request attempt the inference sandbox recorded) with the pinned `dsa-ai` key. The bytes Lucairn sent are signed and you can recompute them: the stored request bytes are served by the gateway's `/upstream-request` endpoint once the signed-hash producer change is deployed (this SDK does not fetch them), and a witness export that carries them inline has them checked against the signed hashes here. Certificates without signed hashes end at `EGRESS_UNATTESTED`. |
| `EGRESS_UNATTESTED` | every check passed, but no signed upstream-request hash exists (older certificates, the input-shield lane today). Never treat it as green. |
| `PARTIAL` | the signatures hold, but the certificate itself says something is missing, unfinished or opted out (`reason` says which, e.g. `user_sent_unredacted`). |
| `FAILED` | an integrity, binding or policy check broke, or the witness itself sealed FAILED. |

Only `VERIFIED` is green. The result also carries `signed_cert_tier` (show this, never the unsigned `verification.cert_tier`) and `user_unredacted`, a **string** (`"true"` / `"false"` / `"unknown"`) read from the signed sanitizer claim only. Compare it to `"true"`; `"false"` is a non-empty string.

> **`unauthenticated_fields` MUST be shown as unverified and MUST NEVER drive a decision.** Every entry (for example `client_id`, `api_key_id`, `byok_exempt` on a certificate that only carries the older v2 witness signature, or `claims[1].inference.model_used` when no claim signs a model) is covered by no signature. Label it unverified wherever you display it, and never base a BYOK badge, a "sent unredacted" mark, a client or API-key attribution, or a model claim on it. Read the value from a signed source instead, or show nothing. Strict callers pass minimum signable version `v3`, which fails every certificate that only carries the v2 witness signature.

Limits: this is the signature of the bytes Lucairn sent. It does not tell you what the model provider received or did. A `VERIFIED` result means "signed with the pinned `dsa-ai` key"; it does not say which Lucairn component held that key. The full rules (timestamp grammar, canonical JSON and base64, typed-field binding) are implemented in this SDK's source with comments. The 54-case test corpus and the ordered check table are vendored at [`testdata/parity-corpus/`](https://github.com/Declade/lucairn-sdks/tree/main/testdata/parity-corpus); the TypeScript, Python and Go SDKs return identical results on every case under both policies. The keys in that corpus are test keys; never pin them in a product.

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
