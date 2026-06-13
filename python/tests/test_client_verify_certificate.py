"""client.verify_certificate() — minimum_signable_version parity tests.

Mirrors the standalone verify_certificate(minimum_signable_version=...)
tests in test_verify_certificate_v3.py at the client-method level.
Goal: confirm the new keyword arg threads through to the pipeline
unchanged, and that the default (None) preserves backward compat.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from lucairn import Lucairn, LucairnConfig
from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys

_FIXTURES_PY = Path(__file__).parent / "fixtures"
_FIXTURES_TS = (
    Path(__file__).resolve().parent.parent.parent
    / "ts"
    / "src"
    / "verify-certificate"
    / "__fixtures__"
)

VALID_KEY = "dsa_0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="session")
def production_witness_pubkey() -> bytes:
    hex_str = (_FIXTURES_PY / "production-witness-pubkey.hex").read_text().strip()
    return bytes.fromhex(hex_str)


@pytest.fixture(scope="session")
def production_keys(production_witness_pubkey: bytes) -> VerifyCertificateKeys:
    return VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=production_witness_pubkey,
    )


@pytest.fixture(scope="session")
def test_witness_keypair() -> dict:
    for name in ("test-witness-keypair.json", "witness-keypair.json"):
        p = _FIXTURES_TS / name
        if p.is_file():
            return json.loads(p.read_text())
    pytest.fail("No witness keypair fixture found in TS fixtures dir")


@pytest.fixture(scope="session")
def test_keys(test_witness_keypair: dict) -> VerifyCertificateKeys:
    return VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=test_witness_keypair["publicKey"],
    )


@pytest.fixture(scope="session")
def real_v3_cert() -> dict:
    return json.loads((_FIXTURES_PY / "real-v3-cert.fixture.json").read_text())


@pytest.fixture(scope="session")
def legacy_v2_cert() -> dict:
    return json.loads((_FIXTURES_TS / "cert-valid-anchored.json").read_text())


@pytest.fixture
def client() -> Lucairn:
    return Lucairn(LucairnConfig(api_key=VALID_KEY))


class TestClientVerifyCertificateMinimumSignableVersion:
    """client.verify_certificate forwards minimum_signable_version to the pipeline."""

    def test_v2_cert_minimum_v3_raises_signable_version_insufficient(
        self,
        client: Lucairn,
        legacy_v2_cert: dict,
        test_keys: VerifyCertificateKeys,
    ) -> None:
        """client.verify_certificate(v2_cert, keys, minimum_signable_version='v3')
        raises LucairnCertificateError(reason='signable_version_insufficient').

        Mirrors test_verify_certificate_v3.py::
            test_minimum_signable_version_v3_on_legacy_v2_cert_raises
        """
        assert not legacy_v2_cert.get("signable_v3_signature"), (
            "Fixture must be a pure v2 cert — no v3 sig"
        )
        assert not legacy_v2_cert.get("signable_protocol_version_emitted"), (
            "Fixture must be a pure v2 cert — no version field"
        )

        with pytest.raises(LucairnCertificateError) as exc_info:
            client.verify_certificate(
                legacy_v2_cert,
                test_keys,
                minimum_signable_version="v3",
            )

        assert exc_info.value.reason == "signable_version_insufficient", (
            f"Expected reason='signable_version_insufficient', "
            f"got {exc_info.value.reason!r}"
        )

    def test_v3_cert_minimum_v3_passes(
        self,
        client: Lucairn,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """client.verify_certificate(v3_cert, keys, minimum_signable_version='v3')
        returns a result with signable_version='v3'.

        Mirrors test_verify_certificate_v3.py::
            test_genuine_v3_cert_with_minimum_signable_version_v3_passes
        """
        result = client.verify_certificate(
            real_v3_cert,
            production_keys,
            minimum_signable_version="v3",
        )
        assert result.signable_version == "v3", (
            f"Expected signable_version='v3', got {result.signable_version!r}"
        )
        assert not result.v3_signature_stripped

    def test_v2_cert_default_args_unchanged(
        self,
        client: Lucairn,
        legacy_v2_cert: dict,
        test_keys: VerifyCertificateKeys,
    ) -> None:
        """client.verify_certificate(cert, keys) with no minimum_signable_version
        still verifies a v2 cert successfully — backward compat unchanged.

        Mirrors test_verify_certificate_v3.py::
            test_genuine_legacy_v2_cert_default_args_still_passes
        """
        result = client.verify_certificate(legacy_v2_cert, test_keys)
        assert result.signable_version == "v2"
        assert result.overall_verdict == "VERDICT_VERIFIED"
        assert not result.v3_signature_stripped
