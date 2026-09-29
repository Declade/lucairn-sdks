"""Optional, UNSIGNED ``verification.cert_tier`` on the type.

Types only, no verifier or signable change. The field parses when present,
absent or unknown (never a validation error), and the offline verifier's
outcome does not depend on it — the real production v3 certificate verifies
identically with or without a tier, because neither witness signable
carries it.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from lucairn.types import VeilCertificate, VeilVerificationResult, VerifyCertificateKeys
from lucairn.verify_certificate import verify_certificate

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def real_v3_cert() -> dict:
    return json.loads((_FIXTURES_DIR / "real-v3-cert.fixture.json").read_text())


@pytest.fixture(scope="module")
def production_keys() -> VerifyCertificateKeys:
    hex_str = (_FIXTURES_DIR / "production-witness-pubkey.hex").read_text().strip()
    return VerifyCertificateKeys(witness_key_id="witness_v1", witness_public_key=bytes.fromhex(hex_str))


def _with_tier(cert: dict, tier: object) -> dict:
    out = copy.deepcopy(cert)
    out["verification"]["cert_tier"] = tier
    return out


def test_cert_tier_absent_parses_as_none(real_v3_cert: dict) -> None:
    assert "cert_tier" not in real_v3_cert["verification"]
    assert VeilVerificationResult.model_validate(real_v3_cert["verification"]).cert_tier is None
    assert VeilCertificate.model_validate(real_v3_cert).verification.cert_tier is None


@pytest.mark.parametrize("tier", ["full_chain", "input_shield", "input_shield_two_signer", "", "input-shield", "some_future_tier"])
def test_cert_tier_present_or_unknown_parses_verbatim(real_v3_cert: dict, tier: str) -> None:
    cert = VeilCertificate.model_validate(_with_tier(real_v3_cert, tier))
    assert cert.verification.cert_tier == tier


@pytest.mark.parametrize("tier", [None, "full_chain", "input_shield", "input_shield_two_signer", "", "some_future_tier"])
def test_verifier_outcome_does_not_depend_on_cert_tier(
    real_v3_cert: dict, production_keys: VerifyCertificateKeys, tier: object
) -> None:
    """cert_tier is outside both signables: adding or changing it never changes the result."""
    cert = real_v3_cert if tier is None else _with_tier(real_v3_cert, tier)
    result = verify_certificate(cert, production_keys)
    assert result.signable_version == "v3"
    assert result.overall_verdict == real_v3_cert["verification"]["overall_verdict"]
