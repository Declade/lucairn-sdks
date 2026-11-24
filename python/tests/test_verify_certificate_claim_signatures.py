"""Claim-signature check of the simple verify_certificate (security fix stream
T-1474, slice F16; level-3 review entry 5: "the SDK's certificate check
reports valid for a certificate whose claim contents were changed").

The witness signature covers only the list of claim ids. With
``keys.service_public_keys`` supplied, verify_certificate must also verify
each claim's own Ed25519 signature over its canonical_payload. Synthetic keys
and data only.
"""

from __future__ import annotations

import base64
import copy
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import verify_certificate
from lucairn.verify_certificate.parse import parse_certificate
from lucairn.verify_certificate.signable import derive_witness_signed_bytes
from lucairn.verify_certificate.v3_signable import derive_v3_signed_bytes


def _pair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(pub).decode()


WITNESS = _pair()
BRIDGE = _pair()
SANITIZER = _pair()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _canon(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _signed_claim(pair, claim_id: str, service_id: str, claim_type: str, payload: dict) -> dict:
    # The gateway signs the short claim-type name in canonical JSON (the
    # chain recipe's step 7g).
    doc = {
        "claim_id": claim_id,
        "claim_type": claim_type.removeprefix("CLAIM_TYPE_"),
        "data_not_seen": [],
        "data_seen": [],
        "payload": payload,
        "request_id": "req_f16_0001",
        "service_id": service_id,
        "timestamp": "2026-11-21T08:00:00Z",
    }
    cp = _canon(doc)
    return {
        "claim_id": claim_id,
        "request_id": "req_f16_0001",
        "service_id": service_id,
        "claim_type": claim_type,
        "data_seen": [],
        "data_not_seen": [],
        "canonical_payload": _b64(cp),
        "timestamp": "2026-11-21T08:00:00Z",
        "signature": _b64(pair[0].sign(cp)),
    }


def _cert(v3: bool) -> dict:
    raw = {
        "certificate_id": "veil_f16_0001",
        "request_id": "req_f16_0001",
        "protocol_version": 2,
        "claims": [
            _signed_claim(BRIDGE, "clm_f16_bridge", "dsa-bridge", "CLAIM_TYPE_TOKEN_GENERATED",
                          {"org_id": "org_synthetic"}),
            _signed_claim(SANITIZER, "clm_f16_sanitizer", "dsa-sanitizer", "CLAIM_TYPE_PII_SANITIZED",
                          {"entities_found": 3, "redaction_manifest_hash": "aGFzaA=="}),
        ],
        "verification": {
            "signatures_valid": True,
            "completeness": "COMPLETENESS_FULL",
            "missing_services": [],
            "temporal_consistent": True,
            "data_visibility_consistent": True,
            "isolation_verified": True,
            "qi_score": None,
            "overall_verdict": "VERDICT_VERIFIED",
        },
        "issued_at": "2026-11-21T08:00:01Z",
        "witness_signature": "AAAA",
        "witness_key_id": "witness_f16",
    }
    raw["witness_signature"] = _b64(WITNESS[0].sign(derive_witness_signed_bytes(parse_certificate(raw))))
    if v3:
        raw["signable_protocol_version_emitted"] = 3
        raw["signable_v3_signature"] = "AAAA"
        raw["signable_v3_signature"] = _b64(WITNESS[0].sign(derive_v3_signed_bytes(parse_certificate(raw))))
    return raw


def _tamper(raw: dict) -> dict:
    """The level-3 case: change what a claim says after signing (the sanitizer
    claim's entity count), leaving the witness-signed claim ids intact."""
    out = copy.deepcopy(raw)
    c = out["claims"][1]
    doc = json.loads(base64.b64decode(c["canonical_payload"]))
    doc["payload"]["entities_found"] = 0
    c["canonical_payload"] = _b64(_canon(doc))
    return out


WITNESS_ONLY = VerifyCertificateKeys(witness_key_id="witness_f16", witness_public_key=WITNESS[1])
WITH_SERVICES = VerifyCertificateKeys(
    witness_key_id="witness_f16",
    witness_public_key=WITNESS[1],
    service_public_keys={"dsa-bridge": BRIDGE[1], "dsa-sanitizer": SANITIZER[1]},
)


def _reason(raw: dict, keys: VerifyCertificateKeys, **kw) -> str:
    try:
        verify_certificate(raw, keys, **kw)
    except LucairnCertificateError as exc:
        return exc.reason
    return "valid"


@pytest.mark.parametrize("v3", [False, True], ids=["v2", "v3"])
def test_genuine_cert_verifies_with_service_keys(v3: bool) -> None:
    r = verify_certificate(_cert(v3), WITH_SERVICES)
    assert r.signable_version == ("v3" if v3 else "v2")
    assert r.claim_signatures_verified is True


@pytest.mark.parametrize("v3", [False, True], ids=["v2", "v3"])
def test_claim_changed_after_signing_is_not_valid(v3: bool) -> None:
    tampered = _tamper(_cert(v3))
    # The witness signature alone still verifies (it covers only claim ids) ...
    assert verify_certificate(tampered, WITNESS_ONLY).claim_signatures_verified is False
    # ... the claim-signature check catches the change.
    assert _reason(tampered, WITH_SERVICES) == "invalid_signature"


@pytest.mark.parametrize("v3", [False, True], ids=["v2", "v3"])
def test_tampered_claim_is_invalid_signature_before_v3_floor(v3: bool) -> None:
    assert _reason(_tamper(_cert(v3)), WITH_SERVICES, minimum_signable_version="v3") == "invalid_signature"


def test_claim_without_supplied_service_key_fails() -> None:
    keys = VerifyCertificateKeys("witness_f16", WITNESS[1], {"dsa-bridge": BRIDGE[1]})
    assert _reason(_cert(False), keys) == "invalid_signature"


def test_claim_signed_by_other_service_key_fails() -> None:
    keys = VerifyCertificateKeys("witness_f16", WITNESS[1],
                                 {"dsa-bridge": SANITIZER[1], "dsa-sanitizer": SANITIZER[1]})
    assert _reason(_cert(False), keys) == "invalid_signature"


def test_signed_payload_naming_other_claim_id_fails() -> None:
    raw = _cert(False)
    other = _signed_claim(SANITIZER, "clm_other_cert", "dsa-sanitizer", "CLAIM_TYPE_PII_SANITIZED",
                          {"entities_found": 0})
    raw["claims"][1]["canonical_payload"] = other["canonical_payload"]
    raw["claims"][1]["signature"] = other["signature"]
    assert _reason(raw, WITH_SERVICES) == "invalid_signature"


def test_non_canonical_base64_claim_signature_fails() -> None:
    raw = _cert(False)
    raw["claims"][0]["signature"] = raw["claims"][0]["signature"].rstrip("=")
    assert _reason(raw, WITH_SERVICES) == "invalid_signature"


# Review round 1, finding 1: with service keys, every OUTER claim field must
# agree with the signed canonical_payload (the chain verifier's step 7g
# rebuild, shared code). Each edit leaves every signature valid. The
# service_id case edits the bridge claim (the v3 witness signable reads the
# sanitizer hashes by service_id); its twin name carries the bridge key.
_OUTER_EDITS = [
    ("data_seen", 1, ["raw_prompt"]),
    ("data_not_seen", 1, ["pii_values"]),
    ("claim_type", 1, "CLAIM_TYPE_EVENTS_RECORDED"),
    ("request_id", 1, "req_f16_other"),
    ("timestamp", 1, "2026-11-21T09:00:00Z"),
    ("service_id", 0, "dsa-bridge-twin"),
]


@pytest.mark.parametrize("v3", [False, True], ids=["v2", "v3"])
@pytest.mark.parametrize(("field", "idx", "value"), _OUTER_EDITS, ids=[e[0] for e in _OUTER_EDITS])
def test_edited_outer_field_with_valid_signatures_is_not_valid(v3: bool, field: str, idx: int, value) -> None:
    raw = _cert(v3)
    raw["claims"][idx][field] = value
    keys = VerifyCertificateKeys(
        "witness_f16", WITNESS[1],
        {"dsa-bridge": BRIDGE[1], "dsa-sanitizer": SANITIZER[1], "dsa-bridge-twin": BRIDGE[1]},
    )
    assert verify_certificate(raw, WITNESS_ONLY).claim_signatures_verified is False
    assert _reason(raw, keys) == "invalid_signature"


def test_outer_timestamp_compared_as_instant_not_text() -> None:
    raw = _cert(False)
    raw["claims"][1]["timestamp"] = "2026-11-21T08:00:00.000Z"
    assert verify_certificate(raw, WITH_SERVICES).claim_signatures_verified is True


def test_signed_payload_with_duplicate_claim_id_key_fails() -> None:
    raw = _cert(False)
    c = raw["claims"][1]
    text = base64.b64decode(c["canonical_payload"]).decode()
    dup = text.replace('{"claim_id":', '{"claim_id":"clm_other","claim_id":', 1).encode()
    c["canonical_payload"] = _b64(dup)
    c["signature"] = _b64(SANITIZER[0].sign(dup))
    assert _reason(raw, WITH_SERVICES) == "invalid_signature"

