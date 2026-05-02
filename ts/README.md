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
  model: 'claude-sonnet-4-5',
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
  model: 'claude-sonnet-4-5',
  max_tokens: 1024,
});

// Hold the requestId from your own correlation ID, request log, or
// (on Pro/Enterprise responses) `response.veil.summary_url`.
const requestId = response.request_id; // populated once gateway emits it top-level

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
