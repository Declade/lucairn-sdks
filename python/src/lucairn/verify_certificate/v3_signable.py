"""Derive the v3 (13-key) byte sequence the witness signs.

Port of dual-sandbox-architecture/services/veil-witness/internal/assembler/
assembler.go:380-414 (v3Map construction).

The v3 signable extends the locked 7-key v2 surface with 6 carry-forward
fields promoted from the witness metadata layer.  The SAME witness Ed25519
key signs both the v2 and v3 maps; they produce separate signatures stored
at ``signable_v2_signature`` and ``signable_v3_signature`` on the cert.

--- v3 key set (13 total) ---

v2 keys (UNCHANGED, byte-identical):
  certificate_id  request_id  protocol_version  claim_ids  issued_at
  overall_verdict  witness_key_id

v3-only promoted carry-forwards:
  client_id               ← cert.client_id (None when absent/None; "" preserved as "")
  api_key_id              ← cert.api_key_id (None when absent/None; "" preserved as "")
  byok_exempt             ← cert.verification.byok_exempt (bool, default False)
  redaction_manifest_hash ← dsa-sanitizer canonical_payload["redaction_manifest_hash"]
  sanitized_fields_body_hash ← dsa-sanitizer canonical_payload["sanitized_fields_hash"]
  tms_manifest_hash       ← dsa-sanitizer canonical_payload["tms_manifest_hash"]
                            (None / absent until Slice 5 of the TMS rewrite)

--- Strip-surviving discipline ---

The gateway server-side strip pipeline nils out
SanitizerClaim.RedactionManifestBody and SanitizedFieldsBody before
the cert is marshalled to the SDK.  The three hash values survive
because they live in the SANITIZER CLAIM'S canonical_payload (the
sanitizer-signed inner JSON blob), NOT in top-level proto fields.
The SDK reconstruction reads from the same place — see
``_sanitizer_canonical_payload_string``.

--- Null/empty handling ---

``client_id`` and ``api_key_id`` map None/absent → canonical JSON ``null``,
and the empty string ``""`` → canonical JSON ``""``.  This matches Go's
``optionalStringForSignable``: a nil pointer produces ``null`` and a
present pointer (even to an empty string) produces the string value.
Pydantic gives ``None`` for a JSON-null or absent field and ``""`` for an
explicit empty string; only ``None`` maps to ``null`` in the signable.

The four hash fields (``redaction_manifest_hash``,
``sanitized_fields_body_hash``, ``tms_manifest_hash``, ``byok_exempt``)
carry None (→ ``null``) when the underlying source is absent or empty,
matching ``sanitizerCanonicalPayloadStringForSignable`` returning ``nil``.
``tms_manifest_hash`` is always None until the TMS rewrite Slice 5 ships;
v3 SDK reconstruction must accept this without error.

--- Encoding ---

SAME canonical JSON serialiser as v2 (sorted keys, HTML-escape, no whitespace,
UTF-8 bytes).  ``byok_exempt`` is a Go ``bool`` field → canonical JSON
``false``/``true`` via the ``bool`` branch in ``_marshal_sorted``.

--- issued_at normalization ---

Applied in both v2 and v3 paths: see ``normalize_issued_at`` in signable.py.
"""

from __future__ import annotations

import base64
import json

from lucairn.errors import LucairnCertificateError
from lucairn.types import VeilCertificate
from lucairn.verify_certificate.canonical_json import canonical_json
from lucairn.verify_certificate.signable import (
    SIGNABLE_PROTOCOL_VERSION,
    _VERDICT_FULL_TO_SHORT,
    _validate_claims,
    normalize_issued_at,
)

__all__ = ["derive_v3_signed_bytes"]


def _sanitizer_canonical_payload_string(cert: VeilCertificate, key: str) -> object:
    """Read a string value from the dsa-sanitizer claim's inner canonical payload.

    Mirrors ``sanitizerCanonicalPayloadStringForSignable`` in
    ``services/veil-witness/internal/assembler/assembler.go:487-511``.

    The sanitizer claim's ``canonical_payload`` field is base64-encoded
    proto field carrying the sanitizer's signed inner JSON.  That JSON has
    the shape ``{"payload": {...}, ...}``; the hash keys live at
    ``payload["redaction_manifest_hash"]``, ``payload["sanitized_fields_hash"]``,
    and ``payload["tms_manifest_hash"]``.

    Returns ``None`` when:
    - no dsa-sanitizer claim present
    - canonical_payload is absent or fails to parse
    - the requested key is absent or the empty string

    Returns the string value otherwise.  ``canonical_json`` will emit
    ``None`` as JSON ``null``.
    """
    for claim in cert.claims:
        if claim.service_id != "dsa-sanitizer":
            continue
        raw_b64 = claim.canonical_payload
        if not raw_b64:
            return None
        try:
            raw_json = base64.b64decode(raw_b64)
            outer: dict = json.loads(raw_json)
        except Exception:
            return None
        # The canonical_payload JSON has an outer wrapper: {payload: {...}, ...}.
        # Fall back to the flat structure if "payload" key is absent.
        inner = outer.get("payload")
        if not isinstance(inner, dict):
            inner = outer
        v = inner.get(key)
        if not isinstance(v, str) or v == "":
            return None
        return v
    return None


def derive_v3_signed_bytes(cert: VeilCertificate) -> bytes:
    """Build the exact byte sequence the witness Ed25519-signs for v3 certs.

    The v3 signable is the 13-key map defined at assembler.go:380-414.
    BYTE-IDENTICAL to the Go output when the same field values are present.

    Args:
        cert: Parsed :class:`VeilCertificate`.

    Returns:
        Raw bytes ready for Ed25519 signature verification against
        ``cert.signable_v3_signature``.

    Raises:
        LucairnCertificateError: with ``reason="malformed"`` on structural
            drift (empty claims, request-id mismatch, unknown verdict literal,
            non-string claim_id).
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

    # --- v3-only carry-forward fields ---
    # client_id: None (null) ONLY when absent/None — preserve "" when present.
    # Matches Go optionalStringForSignable: nil pointer → null, present pointer
    # → the string value INCLUDING "".  Pydantic gives None for absent/JSON-null
    # and "" for an explicit empty string; only None maps to null.
    client_id: object = cert.client_id if cert.client_id is not None else None
    # api_key_id: same rule — None → null, "" → "" (preserves distinction).
    api_key_id: object = cert.api_key_id if cert.api_key_id is not None else None
    # byok_exempt: bool, default False.
    byok_exempt: bool = cert.verification.byok_exempt

    # Hash fields: read from dsa-sanitizer canonical_payload, NOT from top-level
    # proto body fields (which may be stripped by the gateway).
    # Strip-surviving discipline per assembler.go:338-378 comment block.
    redaction_manifest_hash = _sanitizer_canonical_payload_string(
        cert, "redaction_manifest_hash"
    )
    sanitized_fields_body_hash = _sanitizer_canonical_payload_string(
        cert, "sanitized_fields_hash"
    )
    # tms_manifest_hash: None until TMS rewrite Slice 5; v3 accepts null.
    tms_manifest_hash = _sanitizer_canonical_payload_string(cert, "tms_manifest_hash")

    # Build the 13-key v3 signable map.
    #
    # IMPORTANT: protocol_version is the CERT-shape version (still 2), NOT
    # the SDK-signable-shape version (3).  The assembler comment at
    # assembler.go:386-389 explains why: a future maintainer who changes this
    # literal to 3 will break v3 SDK byte-identity for every install.
    v3_map: dict = {
        "certificate_id": cert.certificate_id,
        "request_id": cert.request_id,
        "protocol_version": SIGNABLE_PROTOCOL_VERSION,  # = 2, intentional
        "claim_ids": claim_ids,
        "issued_at": normalize_issued_at(cert.issued_at),
        "overall_verdict": go_short_form,
        "witness_key_id": cert.witness_key_id,
        # --- v3-only promoted carry-forwards ---
        "client_id": client_id,
        "api_key_id": api_key_id,
        "byok_exempt": byok_exempt,
        "redaction_manifest_hash": redaction_manifest_hash,
        "sanitized_fields_body_hash": sanitized_fields_body_hash,
        "tms_manifest_hash": tms_manifest_hash,
    }
    return canonical_json(v3_map)
