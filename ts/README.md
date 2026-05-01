# @dsaveil/theveil

## Status

Pre-1.0. The `TheVeil` client ships construction-time `apiKey` validation,
`baseUrl` normalization with scheme guards, per-call timeout composition,
the `client.messages()` proxy endpoint, `client.getCertificate()` fetch
helper, `client.verifyCertificate()` for witness-signature verification,
and five typed error classes. The public API surface is still in flux —
see [CHANGELOG](../CHANGELOG.md).

Node-first. Browser use requires gateway CORS configuration (not covered
by this release).

## Install

```sh
npm install @lucairn/sdk
```

(not yet published)

## Fetch + verify a Veil Certificate

`client.getCertificate(requestId)` returns the raw `VeilCertificate` from
the gateway. Pair it with `client.verifyCertificate(cert, keys)` to prove
the witness's Ed25519 signature over the certificate's canonical JSON core
fields. The two calls are deliberately separate: the SDK never fetches or
bakes in witness keys, and the caller supplies the witness identity
(expected `witnessKeyId` label and raw 32-byte `witnessPublicKey`) out of
band.

External RFC 3161 timestamp verification and Sigstore Rekor transparency-
log verification are **not** performed by this release. They land in a
follow-up release pending gateway work. Until then, `anchorStatus` and
`overallVerdict` are surfaced as pass-through metadata for observability,
not independently verified.

Quota behaviour for certificate reads is a gateway-side concern; see the
gateway documentation for current tier limits.

```ts
import {
  TheVeil,
  TheVeilCertificateError,
  TheVeilHttpError,
} from '@dsaveil/theveil';

const client = new TheVeil({ apiKey: process.env.THEVEIL_API_KEY! });

let cert;
try {
  cert = await client.getCertificate(requestId);
} catch (err) {
  if (err instanceof TheVeilHttpError && err.status === 202) {
    // Certificate not yet assembled — retry after the indicated delay.
    const body = err.body as { retry_after_seconds?: number };
    const retryAfter = body.retry_after_seconds ?? 30;
    console.log(`pending; retry in ${retryAfter}s`);
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
  if (err instanceof TheVeilCertificateError) {
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

## Back to root

See the [monorepo README](../README.md) for the full SDK index.
