"""Fixture-driven verify_certificate tests.

Port of theveil-sdks/ts/src/verifyCertificate.test.ts at the observable
level. Some JS-specific hazards (sparse arrays, ``__proto__`` pollution)
do not translate 1:1; Python equivalents reach the same ``malformed``
verdict via Pydantic parse. See inline notes where the divergence matters.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import (
    normalize_ed25519_public_key,
    verify_certificate,
    verify_ed25519,
)


# -- normalize_ed25519_public_key ------------------------------------------


class TestNormalizeEd25519PublicKey:
    def test_passes_32_byte_bytes_through(self) -> None:
        key = bytes([0xAA] * 32)
        assert normalize_ed25519_public_key(key) == key

    def test_decodes_base64_string(self) -> None:
        bytes_in = bytes([0xBB] * 32)
        b64 = base64.b64encode(bytes_in).decode("ascii")
        assert normalize_ed25519_public_key(b64) == bytes_in

    def test_rejects_too_short(self) -> None:
        with pytest.raises(TypeError, match="32 bytes"):
            normalize_ed25519_public_key(bytes(16))

    def test_rejects_too_long(self) -> None:
        with pytest.raises(TypeError, match="32 bytes"):
            normalize_ed25519_public_key(bytes(64))

    def test_rejects_int_input(self) -> None:
        with pytest.raises(TypeError):
            normalize_ed25519_public_key(42)  # type: ignore[arg-type]

    def test_rejects_none(self) -> None:
        with pytest.raises(TypeError):
            normalize_ed25519_public_key(None)  # type: ignore[arg-type]

    def test_rejects_invalid_base64(self) -> None:
        with pytest.raises(TypeError, match="base64"):
            normalize_ed25519_public_key("not valid base64!!!")


# -- verify_ed25519 ---------------------------------------------------------


class TestVerifyEd25519:
    """Exercise verify_ed25519 against a freshly-generated keypair."""

    @staticmethod
    def _generate_keypair() -> tuple[bytes, Any]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        raw_pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw_pub, priv

    def test_verifies_valid_signature(self) -> None:
        raw_pub, priv = self._generate_keypair()
        message = b"the quick brown fox"
        signature = priv.sign(message)
        assert verify_ed25519(message, signature, raw_pub) is True

    def test_returns_false_on_tampered_signature(self) -> None:
        raw_pub, priv = self._generate_keypair()
        message = b"the quick brown fox"
        sig = bytearray(priv.sign(message))
        sig[0] ^= 0x01
        assert verify_ed25519(message, bytes(sig), raw_pub) is False

    def test_returns_false_on_tampered_message(self) -> None:
        raw_pub, priv = self._generate_keypair()
        signature = priv.sign(b"the quick brown fox")
        assert verify_ed25519(b"the quick brown foz", signature, raw_pub) is False

    def test_accepts_base64_public_key(self) -> None:
        raw_pub, priv = self._generate_keypair()
        message = b"hello"
        signature = priv.sign(message)
        b64 = base64.b64encode(raw_pub).decode("ascii")
        assert verify_ed25519(message, signature, b64) is True

    def test_rejects_wrong_length_public_key(self) -> None:
        with pytest.raises(TypeError, match="32 bytes"):
            verify_ed25519(b"hello", bytes(64), bytes(16))


# -- Cert fixture shape sanity --------------------------------------------


class TestCertFixturesLoadable:
    def test_valid_anchored_shape(self, cert_valid_anchored: dict[str, Any]) -> None:
        assert cert_valid_anchored["protocol_version"] == 2
        assert cert_valid_anchored["anchor_status"]["status"] == "ANCHOR_STATUS_ANCHORED"
        assert (
            cert_valid_anchored["verification"]["overall_verdict"] == "VERDICT_VERIFIED"
        )
        assert cert_valid_anchored["witness_signature"]
        assert cert_valid_anchored["witness_key_id"] == "witness_v1"

    def test_issued_at_terminates_in_Z(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        # Locks the protojson-UTC assumption. If the gateway ever emits
        # +00:00 instead of Z, this fails loudly so signable reconstruction
        # doesn't silently produce invalid_signature.
        assert cert_valid_anchored["issued_at"].endswith("Z")

    def test_pending_and_failed_variants_parse(
        self,
        cert_valid_pending: dict[str, Any],
        cert_valid_failed: dict[str, Any],
        ts_fixtures_dir: Path,
    ) -> None:
        assert cert_valid_pending["anchor_status"]["status"] == "ANCHOR_STATUS_PENDING"
        assert cert_valid_failed["anchor_status"]["status"] == "ANCHOR_STATUS_FAILED"
        tampered = json.loads(
            (ts_fixtures_dir / "cert-tampered-payload.json").read_text()
        )
        assert tampered["claims"][0]["claim_id"].endswith("TAMPERED")

    def test_no_signature_and_whitespace_signature_variants(
        self, ts_fixtures_dir: Path
    ) -> None:
        no_sig = json.loads(
            (ts_fixtures_dir / "cert-no-signature.json").read_text()
        )
        ws_sig = json.loads(
            (ts_fixtures_dir / "cert-whitespace-signature.json").read_text()
        )
        assert no_sig["witness_signature"] == ""
        assert ws_sig["witness_signature"].strip() == ""
        assert len(ws_sig["witness_signature"]) > 0

    def test_protocol_version_mismatch_variant(self, ts_fixtures_dir: Path) -> None:
        m = json.loads(
            (ts_fixtures_dir / "cert-protocol-version-mismatch.json").read_text()
        )
        assert m["protocol_version"] == 999


# -- verify_certificate — failure reasons ---------------------------------


def _keys(witness_keypair: dict[str, str]) -> VerifyCertificateKeys:
    return VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=witness_keypair["publicKey"],
    )


class TestVerifyCertificateFailureReasons:
    def test_malformed_on_non_object(
        self, witness_keypair: dict[str, str]
    ) -> None:
        keys = _keys(witness_keypair)
        for bad in (None, "string", [], 42, 1.5):
            with pytest.raises(LucairnCertificateError) as exc_info:
                verify_certificate(bad, keys)
            assert exc_info.value.reason == "malformed"

    def test_malformed_on_missing_required_fields(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-malformed-truncated.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_malformed_on_request_id_mismatch(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["request_id"] = "req_different_from_claims"
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_malformed_on_unknown_verdict_literal(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["verification"]["overall_verdict"] = "VERDICT_FUTURE_VALUE"
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_unsupported_protocol_version(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-protocol-version-mismatch.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "unsupported_protocol_version"

    def test_witness_mismatch(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        keys = VerifyCertificateKeys(
            witness_key_id="different-label",
            witness_public_key=witness_keypair["publicKey"],
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert_valid_anchored, keys)
        assert exc_info.value.reason == "witness_mismatch"

    def test_witness_signature_missing_on_empty(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads((ts_fixtures_dir / "cert-no-signature.json").read_text())
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "witness_signature_missing"

    def test_witness_signature_missing_on_whitespace(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-whitespace-signature.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "witness_signature_missing"

    def test_invalid_signature_on_tampered_payload(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-tampered-payload.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "invalid_signature"

    def test_invalid_signature_on_malformed_public_key_preserves_cause(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        bad_keys = VerifyCertificateKeys(
            witness_key_id="witness_v1",
            witness_public_key=bytes(16),  # wrong length
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert_valid_anchored, bad_keys)
        err = exc_info.value
        assert err.reason == "invalid_signature"
        assert isinstance(err.__cause__, TypeError)


# -- verify_certificate — happy paths -------------------------------------


class TestVerifyCertificateHappyPaths:
    def test_returns_result_on_valid_anchored(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        result = verify_certificate(cert_valid_anchored, _keys(witness_keypair))
        assert result.certificate_id == cert_valid_anchored["certificate_id"]
        assert result.request_id == cert_valid_anchored["request_id"]
        assert result.witness_key_id == "witness_v1"
        assert result.witness_asserted_issued_at_iso == cert_valid_anchored["issued_at"]
        assert result.anchor_status == "ANCHOR_STATUS_ANCHORED"
        assert result.overall_verdict == "VERDICT_VERIFIED"

    def test_passes_pending_anchor_status_through(
        self, cert_valid_pending: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        result = verify_certificate(cert_valid_pending, _keys(witness_keypair))
        assert result.anchor_status == "ANCHOR_STATUS_PENDING"

    def test_passes_failed_anchor_status_through(
        self, cert_valid_failed: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        result = verify_certificate(cert_valid_failed, _keys(witness_keypair))
        assert result.anchor_status == "ANCHOR_STATUS_FAILED"


# -- verify_certificate — ordering + error shape --------------------------


class TestVerifyCertificateOrdering:
    def test_malformed_before_protocol_version(
        self, ts_fixtures_dir: Path
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-malformed-truncated.json").read_text()
        )
        keys = VerifyCertificateKeys(
            witness_key_id="any", witness_public_key=bytes(32)
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, keys)
        assert exc_info.value.reason == "malformed"

    def test_malformed_before_unsupported_protocol_version(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        # Cert is both malformed AND has wrong protocol_version.
        raw = json.loads(
            (ts_fixtures_dir / "cert-malformed-plus-bad-version.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_unsupported_protocol_version_before_witness_check(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-protocol-version-mismatch.json").read_text()
        )
        keys = VerifyCertificateKeys(
            witness_key_id="wrong-label",
            witness_public_key=witness_keypair["publicKey"],
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, keys)
        assert exc_info.value.reason == "unsupported_protocol_version"

    def test_certificate_id_populated_on_typed_failure(
        self, ts_fixtures_dir: Path, witness_keypair: dict[str, str]
    ) -> None:
        raw = json.loads(
            (ts_fixtures_dir / "cert-tampered-payload.json").read_text()
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(raw, _keys(witness_keypair))
        err = exc_info.value
        assert err.reason == "invalid_signature"
        assert err.certificate_id == raw["certificate_id"]

    def test_certificate_id_none_on_structural_parse_failure(
        self, witness_keypair: dict[str, str]
    ) -> None:
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate("garbage", _keys(witness_keypair))
        assert exc_info.value.certificate_id is None


# -- Go-oracle cross-check (end-to-end) -----------------------------------


class TestGoOracleCrossCheck:
    """Authoritative test: the Python port verifies a cert signed by the
    real Go assembler. If this ever fails after a gateway change, the Go
    side changed its signable-field encoding and the Python port must
    match. Do NOT paper over by regenerating both."""

    def test_python_verify_accepts_go_oracle_signed_cert(
        self,
        cert_go_signed_reference: dict[str, Any],
        ts_fixtures_dir: Path,
    ) -> None:
        oracle_kp = json.loads(
            (ts_fixtures_dir / "test-witness-keypair.json").read_text()
        )
        keys = VerifyCertificateKeys(
            witness_key_id="witness_v1",
            witness_public_key=oracle_kp["publicKey"],
        )
        result = verify_certificate(cert_go_signed_reference, keys)
        assert result.certificate_id == "veil_oracle_0000000000000001"
        assert result.request_id == "req_oracle_0000000000000001"
        assert result.witness_key_id == "witness_v1"
        assert result.overall_verdict == "VERDICT_VERIFIED"
        assert result.anchor_status == "ANCHOR_STATUS_ANCHORED"


# -- Gap fills (bug-hunter C1–C5 equivalents) -----------------------------


class TestVerifyCertificateBadTimestamp:
    """A cert with a non-RFC-3339 issued_at that still signs + verifies must
    surface as LucairnCertificateError(malformed), not a raw ValueError.

    The contract is: only LucairnCertificateError / TypeError escape
    verify_certificate. A gateway delivering a bad timestamp under a valid
    signature is the one path that could violate this before the fix.
    """

    def test_malformed_issued_at_raises_typed_error(
        self, witness_keypair: dict[str, str]
    ) -> None:
        # We can't sign a real Ed25519 signature without the private key on
        # the wire, but the contract-violation scenario happens even before
        # signature verification if parse accepts the string as structurally
        # valid. So we construct the cert, skip signature verification by
        # stubbing signable+verify via the ValidCert happy path first, then
        # mutate issued_at on the parsed VeilCertificate, call _build_result
        # directly — the unit under test.
        from lucairn.verify_certificate.pipeline import _build_result
        from lucairn.types import VeilCertificate

        cert = VeilCertificate(
            certificate_id="veil_x",
            request_id="req_x",
            protocol_version=2,
            claims=[],
            verification={
                "signatures_valid": True,
                "completeness": "COMPLETENESS_FULL",
                "missing_services": [],
                "temporal_consistent": True,
                "data_visibility_consistent": True,
                "isolation_verified": True,
                "overall_verdict": "VERDICT_VERIFIED",
            },
            issued_at="not a valid timestamp",
            witness_signature="AAAA",
            witness_key_id="witness_v1",
        )
        with pytest.raises(LucairnCertificateError) as exc_info:
            _build_result(cert)
        assert exc_info.value.reason == "malformed"
        assert exc_info.value.certificate_id == "veil_x"
        # Ensure the original ValueError is preserved via __cause__.
        assert isinstance(exc_info.value.__cause__, ValueError)


class TestVerifyCertificateGapFills:
    def test_empty_claims_raises_malformed_with_correct_message(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["claims"] = []
        with pytest.raises(LucairnCertificateError, match="claims is empty") as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_empty_string_overall_verdict_is_malformed(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["verification"]["overall_verdict"] = ""
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_non_string_claim_id_is_malformed(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["claims"][0]["claim_id"] = 42  # not a string
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_none_claim_element_is_malformed(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        cert = copy.deepcopy(cert_valid_anchored)
        cert["claims"].append(None)
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"

    def test_rejects_non_keys_argument_with_type_error(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        # TypeError (programmer error), not LucairnCertificateError.
        with pytest.raises(TypeError):
            verify_certificate(cert_valid_anchored, None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            verify_certificate(
                cert_valid_anchored, {"witness_key_id": "w", "witness_public_key": bytes(32)}  # type: ignore[arg-type]
            )

    def test_unknown_verdict_including_proto_name_as_literal(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        # Python has no Object.prototype pollution concern; we still verify
        # that the defensive lookup rejects arbitrary strings, including
        # ones that might accidentally match a dict dunder on a
        # less-carefully-implemented map.
        cert = copy.deepcopy(cert_valid_anchored)
        cert["verification"]["overall_verdict"] = "__class__"
        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert, _keys(witness_keypair))
        assert exc_info.value.reason == "malformed"


# -- Client delegation -----------------------------------------------------


class TestLucairnVerifyCertificateDelegation:
    def test_delegates_to_pipeline_and_returns_same_shape(
        self, cert_valid_anchored: dict[str, Any], witness_keypair: dict[str, str]
    ) -> None:
        from lucairn import Lucairn, LucairnConfig

        client = Lucairn(LucairnConfig(api_key="dsa_" + "0" * 32))
        result = client.verify_certificate(cert_valid_anchored, _keys(witness_keypair))
        assert result.witness_key_id == "witness_v1"
        assert result.anchor_status == "ANCHOR_STATUS_ANCHORED"
        assert result.overall_verdict == "VERDICT_VERIFIED"
