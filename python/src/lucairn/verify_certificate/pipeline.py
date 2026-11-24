"""Verify-certificate pipeline — parse → canonical → signature → result.

Version dispatch (SDK 1.2.0, dual-protocol v3 chain):
  - If ``cert.signable_protocol_version_emitted >= 3``: use the v3
    13-key signable (``derive_v3_signed_bytes``) and verify against
    ``cert.signable_v3_signature``.  Result carries ``signable_version='v3'``.
  - Otherwise (older certs, or certs without the field): use the legacy
    7-key v2 signable (``derive_witness_signed_bytes``) and verify against
    ``cert.witness_signature`` (which mirrors ``signable_v2_signature``
    byte-for-byte).  Result carries ``signable_version='v2'``.

Downgrade protection (canonical, both tampering directions rejected):
  - If ``emitted >= 3`` but ``signable_v3_signature`` is absent or blank,
    the v3 sig was stripped from a real v3 cert.  Raises
    ``LucairnCertificateError(reason='version_downgrade_detected')``.
  - If ``signable_v3_signature`` is present and non-empty but ``emitted < 3``,
    the version field was stripped from a real v3 cert.  Raises
    ``LucairnCertificateError(reason='version_downgrade_detected')``.
  Legitimate v3 certs always carry BOTH (the assembler sets them atomically).
  Legitimate legacy v2 certs carry NEITHER.  No false-rejects for either.
  The ``minimum_signable_version='v3'`` strict-mode parameter lets callers
  in a v3 deployment fail-closed on any downgrade (including a fully-stripped
  v3 cert that presents as a clean legacy v2 cert).
"""

from __future__ import annotations

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
from lucairn.verify_certificate.chain import (
    _b64,
    _outer_fields_match_signed,
    _rfc3339nano_utc,
    _signed_claim_document,
    _trim_space,
)
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
    *,
    minimum_signable_version: str | None = None,
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

    Given an already parsed object, the simple check judges VALUES:
    number-token rules apply only where the SDK reads the raw text (Go with
    raw bytes; the chain verifier in all three SDKs). ``protocol_version``
    and ``signable_protocol_version_emitted`` must be integers in
    ``[0, 2**64 - 1]`` (a ``float`` such as ``2.0`` is ``malformed``). Note
    that Python's default ``json.loads`` raises on an integer token of more
    than 4,300 digits before this function is called.

    SECURITY NOTE: when ``signable_version == 'v2'`` on the returned result,
    the fields ``api_key_id``, ``client_id``, ``byok_exempt``, and the
    sanitizer hash fields (``redaction_manifest_hash``,
    ``sanitized_fields_body_hash``, ``tms_manifest_hash``) are NOT covered
    by the witness signature.  Callers relying on those fields for security
    decisions MUST require ``signable_version == 'v3'`` — e.g. pass
    ``minimum_signable_version='v3'``.

    Args:
        raw_cert: protojson-shaped certificate body as returned by
            ``GET /api/v1/veil/certificate/{request_id}``. Either a
            ``dict`` or an already-parsed :class:`VeilCertificate`.
        keys: trust-root keys (:class:`VerifyCertificateKeys`). The witness
            signature covers only the list of claim ids; supply
            ``keys.service_public_keys`` to also verify each claim's own
            signature over its ``canonical_payload`` AND that the claim's outer
            fields (claim_id, request_id, service_id, claim_type, data_seen,
            data_not_seen, timestamp) match those signed bytes
            (``result.claim_signatures_verified`` is then ``True``). Without
            them a claim whose contents or outer fields were changed after
            signing is NOT detected. The typed claim objects, egress digests
            and ``cert_tier`` are checked only by
            ``verify_certificate_chain``.
        minimum_signable_version: Optional strict-mode floor. When set to
            ``'v3'``, raises
            :class:`~lucairn.errors.LucairnCertificateError` with
            ``reason='signable_version_insufficient'`` if the resolved
            signable version is not ``'v3'``.  This lets callers in a v3
            deployment fail-closed on any downgrade — including a cert that
            presents as a clean legacy v2 cert (fully stripped) and one that
            carries a v3 signature but a stripped version field (caught
            earlier as ``'version_downgrade_detected'``).  Default ``None``
            preserves the current backward-compatible behaviour.

    Returns:
        :class:`VerifyCertificateResult` on success.  ``signable_version``
        is ``'v3'`` for new dual-protocol certs, ``'v2'`` for legacy certs.
        ``v3_signature_stripped`` is reserved; always ``False`` under the
        current reject-on-downgrade policy (downgrades raise before the v2
        path is taken — the flag is kept for forward-compatibility).

    Raises:
        LucairnCertificateError: with ``reason`` in one of:

          * ``malformed`` — cert shape invalid or gateway invariant broken
          * ``unsupported_protocol_version`` — ``protocol_version != 2``
          * ``witness_mismatch`` — ``keys.witness_key_id`` mismatch
          * ``witness_signature_missing`` — ``witness_signature`` field is
            empty/whitespace-only (checked before version dispatch)
          * ``invalid_signature`` — Ed25519 verification failed or key
            input is malformed (wrong length, non-base64, etc.); with
            ``keys.service_public_keys`` also a claim's own signature failed,
            a claim's service has no supplied key, the signed bytes are not one
            strict JSON object, a signed payload names another claim_id, or
            an outer claim field differs from the signed bytes
          * ``version_downgrade_detected`` — EITHER the version field is
            absent or < 3 while a non-empty ``signable_v3_signature`` is
            present (version stripped from a real v3 cert), OR the version
            field is >= 3 while ``signable_v3_signature`` is absent or blank
            (v3 sig stripped from a real v3 cert).  Both tampering directions
            raise this reason.
          * ``signable_version_insufficient`` — ``minimum_signable_version``
            constraint was not met (strict-mode callers only).
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
    # The same domain for model input as parse_certificate enforces for a dict,
    # so both give the same outcome.
    for _field in ("protocol_version", "signable_protocol_version_emitted"):
        _value = getattr(cert, _field)
        if isinstance(_value, bool) or not isinstance(_value, int) or not 0 <= _value <= _U64_MAX:
            raise LucairnCertificateError(
                f"{_field} must be an integer in [0, 2^64 - 1]",
                reason="malformed",
                certificate_id=cert.certificate_id,
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

    # "" AND whitespace-only signatures get the same reason. "Whitespace" is
    # the chain verifier's ONE whitespace set (Go's unicode.IsSpace) — not
    # ``str.strip()``, which also removes U+001C-U+001F.
    if _trim_space(cert.witness_signature) == "":
        raise LucairnCertificateError(
            "Certificate has no witness signature",
            reason="witness_signature_missing",
            certificate_id=cert.certificate_id,
        )

    # --- Version dispatch ---
    use_v3 = cert.signable_protocol_version_emitted >= _V3_SIGNABLE_MIN_VERSION

    # TOB-SDK-PY-01(a): downgrade-detection guard.
    # A genuine v2-only cert carries NO signable_v3_signature.  If the version
    # field is absent/< 3 but the cert still carries a non-empty v3 signature,
    # the version field was stripped from a real v3 cert — reject immediately.
    if not use_v3 and cert.signable_v3_signature and _trim_space(cert.signable_v3_signature):
        raise LucairnCertificateError(
            "Certificate carries a signable_v3_signature but "
            f"signable_protocol_version_emitted={cert.signable_protocol_version_emitted!r} "
            "(expected >= 3). The version field appears to have been stripped from a "
            "genuine v3 cert. Verification rejected to prevent downgrade attack.",
            reason="version_downgrade_detected",
            certificate_id=cert.certificate_id,
        )

    if use_v3:
        # v3 path: reconstruct 13-key signable + verify signable_v3_signature.

        # Canonical downgrade check: a legitimate v3 cert ALWAYS carries a non-empty
        # signable_v3_signature — the assembler sets them atomically.  If the version
        # field says >=3 but the v3 signature is absent or blank, the sig was stripped
        # from a real v3 cert (the other direction of a downgrade attack from the
        # TOB-SDK-PY-01a guard above).  Raise the same reason so both tampering
        # directions surface identically to the caller.
        if not cert.signable_v3_signature or _trim_space(cert.signable_v3_signature) == "":
            raise LucairnCertificateError(
                f"Certificate has signable_protocol_version_emitted="
                f"{cert.signable_protocol_version_emitted!r} (>= 3) but "
                "signable_v3_signature is absent or blank. A legitimate v3 cert "
                "always carries the v3 signature — it appears to have been stripped. "
                "Verification rejected to prevent downgrade attack.",
                reason="version_downgrade_detected",
                certificate_id=cert.certificate_id,
            )

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

        # Every signature field that is PRESENT is text-checked, not only the
        # one selected for verification: witness_signature is non-blank here.
        _decode_signature_text(cert.witness_signature, "witness_signature", cert.certificate_id)
        signature_bytes = _decode_signature_text(
            cert.signable_v3_signature, "signable_v3_signature", cert.certificate_id
        )

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

        claims_ok = _verify_claim_signatures(cert, keys)

        # TOB-SDK-PY-01(b): strict-mode check after successful v3 verification.
        if minimum_signable_version == "v3":
            pass  # already on v3 path — constraint satisfied

        return _build_result(cert, signable_version="v3", claim_signatures_verified=claims_ok)

    else:
        # v2 path: legacy 7-key signable + witness_signature.
        #
        # NOTE (cross-language parity, 2026-06-15): the strict-mode
        # minimum_signable_version=='v3' check is deliberately performed AFTER
        # Ed25519 verification (further down), NOT before. This matches TS
        # (index.ts verifyV2) and Go (pipeline.go Run) which both run the
        # signature check first and only then enforce the version floor. The
        # effect: a TAMPERED v2 cert returns reason='invalid_signature' (the
        # security-relevant verdict) rather than 'signable_version_insufficient'
        # (a policy verdict that would mask the tamper). A genuine, signature-
        # valid v2 cert still surfaces 'signable_version_insufficient'.

        # TOB-SDK-PY-01(c): surface whether a v3 sig was present but ignored.
        # (Downgrade-detected certs never reach here; this covers non-strict
        # callers on legitimately-missing-version-field certs from unusual
        # gateway configurations where a v3 sig could theoretically be present
        # but the guard above would have raised already.  In practice this flag
        # is always False on the v2 path because the guard already rejected any
        # cert with a non-empty v3 sig.  Kept as an explicit field on the
        # result for forward-compatibility if the guard semantics ever relax.)
        v3_sig_stripped = bool(
            cert.signable_v3_signature and _trim_space(cert.signable_v3_signature)
        )

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

        signature_bytes = _decode_signature_text(
            cert.witness_signature, "witness_signature", cert.certificate_id
        )

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

        # Claim signatures BEFORE the version floor, so a tampered claim
        # surfaces as 'invalid_signature' rather than a policy verdict.
        claims_ok = _verify_claim_signatures(cert, keys)

        # TOB-SDK-PY-01(b): strict-mode floor — enforced AFTER signature
        # verification so a tampered v2 cert surfaces as 'invalid_signature'
        # (matching TS verifyV2 and Go Run). Only a genuine, signature-valid
        # v2 cert reaches here and is rejected as 'signable_version_insufficient'
        # when the caller requires v3.
        if minimum_signable_version == "v3":
            raise LucairnCertificateError(
                "minimum_signable_version='v3' required but cert resolved to the v2 "
                f"path (signable_protocol_version_emitted="
                f"{cert.signable_protocol_version_emitted!r}). "
                "The v3-only fields (api_key_id, client_id, byok_exempt, and the "
                "sanitizer hash fields) are not covered by the v2 witness signature.",
                reason="signable_version_insufficient",
                certificate_id=cert.certificate_id,
            )

        return _build_result(
            cert,
            signable_version="v2",
            v3_signature_stripped=v3_sig_stripped,
            claim_signatures_verified=claims_ok,
        )


_U64_MAX = 2**64 - 1


def _decode_signature_text(text: str, field: str, certificate_id: str) -> bytes:
    """A signature text must be CANONICAL standard padded base64 (decode,
    re-encode, compare) — the chain verifier's rule for the same fields."""
    raw = _b64(text)
    if raw is None:
        raise LucairnCertificateError(
            f"{field} is not canonical standard padded base64",
            reason="invalid_signature",
            certificate_id=certificate_id,
        )
    return raw


def _verify_claim_signatures(cert: VeilCertificate, keys: VerifyCertificateKeys) -> bool:
    """Verify every claim's own Ed25519 signature over its canonical_payload
    with the caller-supplied key of its service_id, that the signed payload
    names the same claim_id as the (witness-signed) outer claim, and that it
    agrees with every outer claim field (the chain verifier's steps 7e-7h).

    The witness signature covers only the claim ids, so without this a claim
    whose contents were changed after signing still verified (level-3 review,
    entry 5). Returns False when no service keys were supplied (nothing
    checked).
    """

    service_keys = keys.service_public_keys
    if service_keys is None:
        return False
    if not isinstance(service_keys, dict):
        raise TypeError("verify_certificate: keys.service_public_keys must be a dict")
    cid = cert.certificate_id

    def fail(message: str, cause: BaseException | None = None) -> LucairnCertificateError:
        return LucairnCertificateError(
            message, reason="invalid_signature", certificate_id=cid, cause=cause
        )

    for i, claim in enumerate(cert.claims):
        svc = claim.service_id
        if not isinstance(svc, str) or svc not in service_keys:
            raise fail(f"claims[{i}]: no service public key supplied for service_id {svc!r}")
        payload = _b64(claim.canonical_payload)
        signature = _b64(claim.signature)
        if payload is None or signature is None:
            raise fail(
                f"claims[{i}]: canonical_payload and signature must be canonical "
                "standard padded base64"
            )
        try:
            valid = verify_ed25519(payload, signature, service_keys[svc])
        except TypeError as exc:
            raise fail(f"Invalid service_public_keys[{svc!r}]: {exc}", exc) from exc
        if not valid:
            raise fail(f"claims[{i}] ({svc}): claim Ed25519 signature verification failed")
        # The chain verifier's steps 7e-7h, shared code: the signed bytes are
        # ONE strict JSON object (a duplicate or case-variant key is refused),
        # name this claim_id, rebuild byte-for-byte from the OUTER fields, and
        # carry the certificate's request_id.
        doc = _signed_claim_document(payload)
        if doc is None:
            raise fail(
                f"claims[{i}] ({svc}): signed canonical_payload is not one strict JSON "
                "object (duplicate or case-variant key, or bad grammar)"
            )
        signed_id = doc.get("claim_id")
        if not isinstance(signed_id, str) or signed_id != claim.claim_id:
            raise fail(
                f"claims[{i}] ({svc}): signed canonical_payload does not name "
                f"claim_id {claim.claim_id!r}"
            )
        outer = {
            "claim_id": claim.claim_id,
            "request_id": claim.request_id,
            "service_id": claim.service_id,
            "claim_type": claim.claim_type,
            "data_seen": claim.data_seen,
            "data_not_seen": claim.data_not_seen,
        }
        if _outer_fields_match_signed(outer, doc, payload) is None:
            raise fail(
                f"claims[{i}] ({svc}): an outer field (claim_id, request_id, service_id, "
                "claim_type, data_seen, data_not_seen) differs from the signed canonical_payload"
            )
        # The outer timestamp is written in another textual form than the
        # signed one (protojson pads fractions to 3/6/9 digits), so it is
        # compared as an instant with the chain's ONE timestamp grammar.
        signed_ts = doc.get("timestamp")
        a = _rfc3339nano_utc(claim.timestamp) if isinstance(claim.timestamp, str) else None
        b = _rfc3339nano_utc(signed_ts) if isinstance(signed_ts, str) else None
        if a is None or b is None or a != b:
            raise fail(f"claims[{i}] ({svc}): outer timestamp differs from the signed canonical_payload")
        if doc.get("request_id") != cert.request_id:
            raise fail(
                f"claims[{i}] ({svc}): signed canonical_payload names another request_id "
                "than the certificate"
            )
    return True


def _build_result(
    cert: VeilCertificate,
    signable_version: str = "v2",
    v3_signature_stripped: bool = False,
    claim_signatures_verified: bool = False,
) -> VerifyCertificateResult:
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
        v3_signature_stripped=v3_signature_stripped,
        claim_signatures_verified=claim_signatures_verified,
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
