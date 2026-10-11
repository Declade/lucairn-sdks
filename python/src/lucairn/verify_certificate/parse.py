"""Structural parse of a raw Veil Certificate body."""

from __future__ import annotations

from typing import Any

from lucairn.errors import LucairnCertificateError
from lucairn.types import VeilCertificate

__all__ = ["parse_certificate"]

_U64_MAX = 2**64 - 1


def parse_certificate(raw: Any) -> VeilCertificate:
    """Structurally validate ``raw`` and return a :class:`VeilCertificate`.

    Asserts the shape this arc reads. Does NOT validate enum literal
    membership beyond "string" here — the signable derivation layer throws
    ``malformed`` on unknown verdict literals, which is where that check
    belongs semantically.

    Raises:
        LucairnCertificateError: with ``reason="malformed"`` on bad shape
            or missing required fields.
    """

    if not isinstance(raw, dict):
        raise LucairnCertificateError(
            "Certificate is not a JSON object",
            reason="malformed",
        )

    cert_id_raw = raw.get("certificate_id")
    cert_id = cert_id_raw if isinstance(cert_id_raw, str) else None

    required_str_fields = (
        "certificate_id",
        "request_id",
        "witness_key_id",
        "witness_signature",
        "issued_at",
    )
    for field_name in required_str_fields:
        if not isinstance(raw.get(field_name), str):
            raise LucairnCertificateError(
                "Certificate missing required fields",
                reason="malformed",
                certificate_id=cert_id,
            )
    if not isinstance(raw.get("protocol_version"), int) or isinstance(
        raw.get("protocol_version"), bool
    ):
        # bool subclasses int in Python; exclude it so True/False never
        # passes as a protocol version.
        raise LucairnCertificateError(
            "Certificate missing required fields",
            reason="malformed",
            certificate_id=cert_id,
        )
    # The two integers this check reads must be integers in [0, 2^64 - 1].
    # Anything else is garbage input, not a newer protocol.
    if not 0 <= raw["protocol_version"] <= _U64_MAX:
        raise LucairnCertificateError(
            "protocol_version must be an integer in [0, 2^64 - 1]",
            reason="malformed",
            certificate_id=cert_id,
        )
    emitted = raw.get("signable_protocol_version_emitted")
    if isinstance(emitted, float) or (
        isinstance(emitted, int) and not isinstance(emitted, bool) and not 0 <= emitted <= _U64_MAX
    ):
        raise LucairnCertificateError(
            "signable_protocol_version_emitted must be an integer in [0, 2^64 - 1]",
            reason="malformed",
            certificate_id=cert_id,
        )
    if not isinstance(raw.get("claims"), list):
        raise LucairnCertificateError(
            "Certificate missing required fields",
            reason="malformed",
            certificate_id=cert_id,
        )
    verification = raw.get("verification")
    if not isinstance(verification, dict):
        raise LucairnCertificateError(
            "Certificate missing required fields",
            reason="malformed",
            certificate_id=cert_id,
        )
    if not isinstance(verification.get("overall_verdict"), str):
        raise LucairnCertificateError(
            "verification.overall_verdict must be a string enum literal",
            reason="malformed",
            certificate_id=cert_id,
        )

    try:
        return VeilCertificate.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError etc.
        # Any Pydantic-level coercion failure on the declared fields
        # (e.g. claim with non-int nested field) surfaces as malformed.
        raise LucairnCertificateError(
            f"Certificate validation failed: {exc}",
            reason="malformed",
            certificate_id=cert_id,
        ) from exc
