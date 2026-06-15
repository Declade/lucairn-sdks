"""Derive the exact byte sequence the witness signs.

Port of
  dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132

Keep the 7-key set, the Go short-form enum mapping, and the string-vs-number
encoding of each field in lockstep with the Go source. Any change to the
assembler's signable construction must land here in the same arc.

Gateway invariant enforced defensively:
  cert.request_id == cert.claims[0].request_id
The Go assembler reads claims[0].RequestId for the signed subset; this
port adds a guard so drift surfaces loudly (``malformed``) rather than
silently failing as ``invalid_signature`` on a cert with a valid
signature computed over a different request_id.

CRITICAL ENCODING NOTE (resolved 2026-04-20 after contract-drift-detector
caught it):
  The Go assembler signs ``vr.OverallVerdict`` (verifier.go:56 — type
  ``string``) DIRECTLY. vr.OverallVerdict holds short-form strings like
  "VERIFIED", NOT the proto enum integer and NOT the full-name protojson
  form "VERDICT_VERIFIED". The signable emits a JSON string (quoted) via
  canonical JSON's default string path — NOT an integer.

Protojson → Go short-form mapping: the gateway emits full-name VERDICT_*
literals on the wire (UseProtoNames + default enum serialization); the
witness signs the short-form. The SDK must convert.

ISSUED_AT NORMALIZATION (H6 fix, 1.2.0):
  The witness signs ``issuedAt.Format(time.RFC3339Nano)`` which strips
  trailing zeros from the fractional-seconds component — Go's
  time.RFC3339Nano contract. The gateway serves the timestamp via
  protojson which zero-pads the fractional part to 9 digits (e.g.
  ``.100000000Z`` instead of ``.1Z``). On ~10% of certs the served
  string has trailing zeros that the signed bytes lack, causing false
  ``invalid_signature`` failures. Fix: normalize the served issued_at
  to RFC3339Nano form (strip trailing zeros; drop the dot when the
  fractional part is entirely zeros) before placing it into the signable
  bytes. Applied to BOTH the v2 and v3 reconstruction paths.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from lucairn.errors import LucairnCertificateError
from lucairn.types import VeilCertificate, VeilVerdict
from lucairn.verify_certificate.canonical_json import canonical_json

__all__ = [
    "derive_witness_signed_bytes",
    "normalize_issued_at",
    "SIGNABLE_PROTOCOL_VERSION",
]


# Mirrors pipeline.SUPPORTED_PROTOCOL_VERSION. The two must update in
# lockstep; importing from pipeline would create a circular import, so
# this module declares its own constant and the pipeline module asserts
# the values agree at import time.
SIGNABLE_PROTOCOL_VERSION = 2


_VERDICT_FULL_TO_SHORT: dict[VeilVerdict, str] = {
    "VERDICT_UNSPECIFIED": "UNSPECIFIED",
    "VERDICT_VERIFIED": "VERIFIED",
    "VERDICT_PARTIAL": "PARTIAL",
    "VERDICT_FAILED": "FAILED",
}


def normalize_issued_at(issued_at: str) -> str:
    """Normalize a protojson-serialized RFC 3339 timestamp to Go RFC3339Nano form.

    Mirrors the Go witness assembler's
    ``time.Parse(time.RFC3339Nano, s)`` → ``t.UTC().Format(time.RFC3339Nano)``.
    This (a) converts any non-UTC offset to the equivalent UTC ``Z`` time and
    (b) strips trailing fractional-second zeros (dropping the dot entirely
    when the whole fraction is zero) so the SDK reconstructs the exact bytes
    the witness signed.

    Applies to BOTH the v2 and v3 reconstruction paths.

    Parity note (this fix, 2026-06-15): the previous Python implementation
    returned non-``Z`` timestamps UNCHANGED; Go re-emits in UTC.  The witness
    ALWAYS signs Zulu (UTC) timestamps, so on every real cert this is
    byte-equivalent to the old behaviour.  The change only affects the latent
    never-emitted shape of a non-Zulu offset timestamp, bringing Python into
    exact parity with Go (and TS).

    On parse failure the original string is returned unchanged (fail-open) —
    matching Go's ``if err != nil { return s }``.

    Examples::

        '2026-06-10T00:01:59.100000000Z' → '2026-06-10T00:01:59.1Z'
        '2026-06-10T00:01:59.000000000Z' → '2026-06-10T00:01:59Z'
        '2026-06-10T00:01:59.878143387Z' → '2026-06-10T00:01:59.878143387Z'  (no change)
        '2026-06-10T00:01:59Z'           → '2026-06-10T00:01:59Z'  (no change)
        '2026-05-01T12:00:00.5+02:00'    → '2026-05-01T10:00:00.5Z'  (UTC-normalized)
    """
    # Parse the RFC3339 components. The fractional part is offset-invariant, so
    # it is preserved verbatim (modulo trailing-zero stripping) across the UTC
    # conversion. Group 1 = date+time-to-second, group 2 = optional ".NNN"
    # fraction (dot captured), group 3 = timezone designator (Z or ±HH:MM).
    m = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$",
        issued_at,
    )
    if m is None:
        # Not a parseable RFC3339 timestamp — fail-open (Go returns s on err).
        return issued_at
    seconds_part = m.group(1)
    frac_raw = m.group(2) or ""  # includes leading dot, or "" if no fraction
    tz = m.group(3)

    # Strip trailing zeros from the fractional part (Go time.RFC3339Nano does
    # this); drop the dot entirely if nothing remains.
    frac = frac_raw
    if frac:
        frac = frac.rstrip("0")
        if frac == ".":
            frac = ""

    if tz == "Z":
        # Already UTC — just emit the (zero-stripped) seconds + Z.
        return seconds_part + frac + "Z"

    # Non-UTC offset: convert the wall-clock seconds to UTC exactly like Go's
    # t.UTC(), then re-attach the preserved (offset-invariant) fraction.
    try:
        dt = datetime.strptime(seconds_part, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return issued_at  # fail-open on an unparseable wall-clock
    sign = -1 if tz[0] == "-" else 1
    off_minutes = sign * (int(tz[1:3]) * 60 + int(tz[4:6]))
    utc_dt = dt - timedelta(minutes=off_minutes)
    utc_seconds = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
    return utc_seconds + frac + "Z"


def _validate_claims(cert: VeilCertificate) -> list[str]:
    """Validate cert.claims and return the list of claim IDs.

    Shared by the v2 and v3 reconstruction paths.  Raises
    ``LucairnCertificateError(reason='malformed')`` on structural drift.
    """
    if len(cert.claims) == 0:
        raise LucairnCertificateError(
            "cert.claims is empty — certificate must contain at least one claim",
            reason="malformed",
            certificate_id=cert.certificate_id,
        )

    # Gateway invariant: cert.request_id must equal cert.claims[0].request_id.
    if cert.claims[0].request_id != cert.request_id:
        raise LucairnCertificateError(
            "cert.request_id does not match cert.claims[0].request_id (gateway invariant violated)",
            reason="malformed",
            certificate_id=cert.certificate_id,
        )

    # Validate each claim carries a string claim_id. Pydantic already enforces
    # this at parse time via VeilClaim.claim_id: str, so this is defence-in-
    # depth against future model drift (e.g. a parse path that skips Pydantic).
    claim_ids: list[str] = []
    for i, c in enumerate(cert.claims):
        if not isinstance(c.claim_id, str):
            raise LucairnCertificateError(
                f"cert.claims[{i}].claim_id must be a string",
                reason="malformed",
                certificate_id=cert.certificate_id,
            )
        claim_ids.append(c.claim_id)
    return claim_ids


def derive_witness_signed_bytes(cert: VeilCertificate) -> bytes:
    """Build the exact byte sequence the witness Ed25519-signs (v2 path).

    This is the LOCKED 7-key v2 signable.  It is BYTE-IDENTICAL to the
    pre-1.2.0 output for certs where ``issued_at`` has no protojson
    trailing zeros.  The issued_at normalization (H6) is the only change
    to the v2 path in 1.2.0 — it fixes ~10% of certs that previously
    produced false ``invalid_signature`` failures.

    For v3 certs (``signable_protocol_version_emitted >= 3``) the
    pipeline dispatches to :func:`derive_v3_signed_bytes` instead.
    This function is intentionally kept for the v2 path and for callers
    that need the raw v2 bytes directly (e.g. the signable-freeze tests).

    Raises:
        LucairnCertificateError: with ``reason="malformed"`` on any
            structural / invariant drift (empty claims, request-id
            mismatch, unknown verdict literal, non-string claim_id).
    """
    claim_ids = _validate_claims(cert)

    full_name = cert.verification.overall_verdict
    if full_name not in _VERDICT_FULL_TO_SHORT:
        raise LucairnCertificateError(
            f"Unknown verification.overall_verdict literal: {full_name} — SDK may be out of date",
            reason="malformed",
            certificate_id=cert.certificate_id,
        )
    go_short_form = _VERDICT_FULL_TO_SHORT[full_name]

    # The signable mirrors assembler.go:319-328 field-for-field.
    # protocol_version: Go int → JSON integer.
    # overall_verdict: Go short string → JSON quoted string (default path).
    # issued_at: normalized to RFC3339Nano (strip trailing zeros — H6 fix).
    # All other fields are strings or string arrays, pass-through.
    signable = {
        "certificate_id": cert.certificate_id,
        "request_id": cert.request_id,
        "protocol_version": SIGNABLE_PROTOCOL_VERSION,
        "claim_ids": claim_ids,
        "issued_at": normalize_issued_at(cert.issued_at),
        "overall_verdict": go_short_form,
        "witness_key_id": cert.witness_key_id,
    }
    return canonical_json(signable)
