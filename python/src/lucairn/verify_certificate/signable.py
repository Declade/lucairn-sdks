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
"""

from __future__ import annotations

from lucairn.errors import LucairnCertificateError
from lucairn.types import VeilCertificate, VeilVerdict
from lucairn.verify_certificate.canonical_json import canonical_json

__all__ = ["derive_witness_signed_bytes", "SIGNABLE_PROTOCOL_VERSION"]


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


def derive_witness_signed_bytes(cert: VeilCertificate) -> bytes:
    """Build the exact byte sequence the witness Ed25519-signs.

    Raises:
        LucairnCertificateError: with ``reason="malformed"`` on any
            structural / invariant drift (empty claims, request-id
            mismatch, unknown verdict literal, non-string claim_id).
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

    full_name = cert.verification.overall_verdict
    if full_name not in _VERDICT_FULL_TO_SHORT:
        raise LucairnCertificateError(
            f"Unknown verification.overall_verdict literal: {full_name} — SDK may be out of date",
            reason="malformed",
            certificate_id=cert.certificate_id,
        )
    go_short_form = _VERDICT_FULL_TO_SHORT[full_name]

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

    # The signable mirrors assembler.go:117-125 field-for-field.
    # protocol_version: Go int → JSON integer.
    # overall_verdict: Go short string → JSON quoted string (default path).
    # All other fields are strings or string arrays, pass-through.
    signable = {
        "certificate_id": cert.certificate_id,
        "request_id": cert.request_id,
        "protocol_version": SIGNABLE_PROTOCOL_VERSION,
        "claim_ids": claim_ids,
        "issued_at": cert.issued_at,
        "overall_verdict": go_short_form,
        "witness_key_id": cert.witness_key_id,
    }
    return canonical_json(signable)
