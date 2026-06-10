"""Verify-certificate pipeline — parse → canonical → signature → result.

Version dispatch (SDK 1.2.0, dual-protocol v3 chain):
  - If ``cert.signable_protocol_version_emitted >= 3``: use the v3
    13-key signable (``derive_v3_signed_bytes``) and verify against
    ``cert.signable_v3_signature``.  Result carries ``signable_version='v3'``.
  - Otherwise (older certs, or certs without the field): use the legacy
    7-key v2 signable (``derive_witness_signed_bytes``) and verify against
    ``cert.witness_signature`` (which mirrors ``signable_v2_signature``
    byte-for-byte).  Result carries ``signable_version='v2'``.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from lucairn.errors import LucairnCertificateError
from lucairn.types import (
    VeilCertificate,
    VerifyCertificateKeys,
    VerifyCertificateResult,
)
from lucairn.verify_certificate.parse import parse_certificate
from lucairn.verify_certificate.signable import (
    SIGNABLE_PROTOCOL_VERSION,
    derive_witness_signed_bytes,
)
from lucairn.verify_certificate.v3_signable import derive_v3_signed_bytes
from lucairn.verify_certificate.signature import verify_ed25519

__all__ = ["verify_certificate"]


SUPPORTED_PROTOCOL_VERSION = SIGNABLE_PROTOCOL_VERSION

# The minimum value of ``signable_protocol_version_emitted`` that triggers the
# v3 verification path.  Certs with a lower value (or absent field, which
# defaults to 0) are verified via the legacy v2 path.
_V3_SIGNABLE_MIN_VERSION = 3


def verify_certificate(
    raw_cert: Any,
    keys: VerifyCertificateKeys,
) -> VerifyCertificateResult:
    """Verify a Veil Certificate's witness Ed25519 signature.

    Dispatches to v2 or v3 verification based on
    ``cert.signable_protocol_version_emitted``:

    - ``>= 3`` → v3 13-key signable + ``signable_v3_signature``
    - ``< 3`` (or field absent) → v2 7-key signable + ``witness_signature``

    External RFC 3161 timestamp verification and Sigstore Rekor
    transparency-log verification are OUT OF SCOPE for this SDK release;
    they land in a follow-up arc (2b-cert-strong) pending gateway fixes.
    The result surfaces ``anchor_status`` and ``overall_verdict`` as
    pass-through metadata — the SDK does NOT independently verify them.

    Args:
        raw_cert: protojson-shaped certificate body as returned by
            ``GET /api/v1/veil/certificate/{request_id}``. Either a
            ``dict`` or an already-parsed :class:`VeilCertificate`.
        keys: trust-root keys (:class:`VerifyCertificateKeys`).

    Returns:
        :class:`VerifyCertificateResult` on success.  ``signable_version``
        is ``'v3'`` for new dual-protocol certs, ``'v2'`` for legacy certs.

    Raises:
        LucairnCertificateError: with ``reason`` in one of:

          * ``malformed`` — cert shape invalid or gateway invariant broken
          * ``unsupported_protocol_version`` — ``protocol_version != 2``
          * ``witness_mismatch`` — ``keys.witness_key_id`` mismatch
          * ``witness_signature_missing`` — empty/whitespace-only signature
          * ``invalid_signature`` — Ed25519 verification failed or key
            input is malformed (wrong length, non-base64, etc.)
        TypeError: if ``keys`` is not a :class:`VerifyCertificateKeys`
            (programmer error, not a cert-verification failure).
    """

    if not isinstance(keys, VerifyCertificateKeys):
        raise TypeError(
            "verify_certificate: keys must be a VerifyCertificateKeys instance"
        )

    cert: VeilCertificate = (
        raw_cert if isinstance(raw_cert, VeilCertificate) else parse_certificate(raw_cert)
    )

    if cert.protocol_version != SUPPORTED_PROTOCOL_VERSION:
        raise LucairnCertificateError(
            f"Unsupported Veil protocol version: {cert.protocol_version} "
            f"(SDK supports {SUPPORTED_PROTOCOL_VERSION})",
            reason="unsupported_protocol_version",
            certificate_id=cert.certificate_id,
        )

    if cert.witness_key_id != keys.witness_key_id:
        raise LucairnCertificateError(
            f'Witness key ID mismatch: cert has "{cert.witness_key_id}", '
            f'expected "{keys.witness_key_id}"',
            reason="witness_mismatch",
            certificate_id=cert.certificate_id,
        )

    # ``strip()`` routes "" AND whitespace-only signatures to the same reason
    # — "   " base64-decodes to empty bytes which would otherwise surface as
    # a confusing invalid_signature.
    if cert.witness_signature.strip() == "":
        raise LucairnCertificateError(
            "Certificate has no witness signature",
            reason="witness_signature_missing",
            certificate_id=cert.certificate_id,
        )

    # --- Version dispatch ---
    use_v3 = cert.signable_protocol_version_emitted >= _V3_SIGNABLE_MIN_VERSION

    if use_v3:
        # v3 path: reconstruct 13-key signable + verify signable_v3_signature.
        try:
            signed_bytes = derive_v3_signed_bytes(cert)
        except LucairnCertificateError:
            raise
        except TypeError as exc:
            raise LucairnCertificateError(
                f"Failed to derive v3 signed payload: {exc}",
                reason="malformed",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        # v3 certs carry signable_v3_signature; fall back to witness_signature
        # if the field is absent (should not happen for v3 certs, but be defensive).
        sig_field = cert.signable_v3_signature or cert.witness_signature
        if not sig_field or sig_field.strip() == "":
            raise LucairnCertificateError(
                "v3 certificate has no signable_v3_signature",
                reason="witness_signature_missing",
                certificate_id=cert.certificate_id,
            )

        try:
            signature_bytes = base64.b64decode(sig_field, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise LucairnCertificateError(
                f"signable_v3_signature base64 decode failed: {exc}",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        try:
            valid = verify_ed25519(signed_bytes, signature_bytes, keys.witness_public_key)
        except TypeError as exc:
            raise LucairnCertificateError(
                f"Invalid witness_public_key: {exc}",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        if not valid:
            raise LucairnCertificateError(
                "Witness Ed25519 v3 signature verification failed",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
            )

        return _build_result(cert, signable_version="v3")

    else:
        # v2 path: legacy 7-key signable + witness_signature.
        try:
            signed_bytes = derive_witness_signed_bytes(cert)
        except LucairnCertificateError:
            raise
        except TypeError as exc:
            raise LucairnCertificateError(
                f"Failed to derive signed payload: {exc}",
                reason="malformed",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        try:
            signature_bytes = base64.b64decode(cert.witness_signature, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise LucairnCertificateError(
                f"Witness signature base64 decode failed: {exc}",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        try:
            valid = verify_ed25519(signed_bytes, signature_bytes, keys.witness_public_key)
        except TypeError as exc:
            raise LucairnCertificateError(
                f"Invalid witness_public_key: {exc}",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
                cause=exc,
            ) from exc

        if not valid:
            raise LucairnCertificateError(
                "Witness Ed25519 signature verification failed",
                reason="invalid_signature",
                certificate_id=cert.certificate_id,
            )

        return _build_result(cert, signable_version="v2")


def _build_result(cert: VeilCertificate, signable_version: str = "v2") -> VerifyCertificateResult:
    try:
        issued_at = _parse_iso(cert.issued_at)
    except ValueError as exc:
        # Signature has already verified at this point, so the witness signed
        # over whatever bytes cert.issued_at contains — but the public contract
        # of verify_certificate is that only LucairnCertificateError / TypeError
        # escape. A malformed-but-signed timestamp surfaces as malformed
        # (gateway delivered a bad field under a valid signature). Callers who
        # only need the raw ISO string can read
        # ``witness_asserted_issued_at_iso`` on the result on the success path.
        raise LucairnCertificateError(
            f"cert.issued_at is not a valid RFC 3339 timestamp: {cert.issued_at!r}",
            reason="malformed",
            certificate_id=cert.certificate_id,
            cause=exc,
        ) from exc
    return VerifyCertificateResult(
        certificate_id=cert.certificate_id,
        request_id=cert.request_id,
        witness_key_id=cert.witness_key_id,
        witness_asserted_issued_at=issued_at,
        witness_asserted_issued_at_iso=cert.issued_at,
        anchor_status=(
            cert.anchor_status.status if cert.anchor_status is not None
            else "ANCHOR_STATUS_UNSPECIFIED"
        ),
        overall_verdict=cert.verification.overall_verdict,
        signable_version=signable_version,
    )


def _parse_iso(iso: str) -> datetime:
    """Parse an RFC 3339 timestamp into ``datetime`` with microsecond precision.

    Raises ValueError on non-RFC-3339 input. The witness-asserted issued-at
    may carry nanosecond precision; Python ``datetime`` is microsecond-
    resolution, so sub-microsecond digits are dropped. Callers requiring
    full precision should read the ``witness_asserted_issued_at_iso``
    field (raw string, unchanged).
    """

    # datetime.fromisoformat in 3.11+ accepts the "Z" suffix and nanoseconds
    # (nanoseconds since 3.12; "Z" since 3.11). For 3.10 compatibility,
    # substitute "Z" → "+00:00" and truncate fractional seconds beyond 6 digits.
    s = iso
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Truncate fractional seconds to microsecond resolution (6 digits).
    dot = s.find(".")
    if dot != -1:
        end = dot + 1
        while end < len(s) and s[end].isdigit():
            end += 1
        frac = s[dot + 1 : end]
        if len(frac) > 6:
            s = s[:dot] + "." + frac[:6] + s[end:]
    # Let ValueError propagate; the caller in _build_result wraps it as
    # LucairnCertificateError(reason="malformed") to preserve the public
    # contract of verify_certificate.
    return datetime.fromisoformat(s)
