"""v3 dual-protocol certificate verification tests.

SDK signable-versioning v3 chain (PR #247 + Python SDK 1.2.0).

Tests:
  (a) Real-cert round-trip: verify_certificate(real_v3_cert) returns
      valid=True, signable_version='v3'.  PASSES ONLY if the v3
      reconstruction produces the exact bytes the witness signed.
      Do NOT weaken this test if it fails — fix the reconstruction.

  (b) v2 backward-compat: the same real cert also verifies as v2 when
      the v2 path is forced (it carries both signatures) → valid=True
      against signable_v2_signature.  Proves v2 stays byte-identical.

  (c) issued_at RFC3339Nano normalization: a cert with trailing zeros
      in its protojson-served issued_at verifies correctly after
      normalization.  Demonstrates the H6 fix (~10% false-failure class).

  (d) Structural: v3 signable contains exactly 13 keys.
  (e) tms_manifest_hash absent → null in v3 signable (no failure).
  (f) signable_version='v2' on legacy certs (no signable_protocol_version_emitted).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import (
    derive_v3_signed_bytes,
    derive_witness_signed_bytes,
    normalize_issued_at,
    verify_certificate,
)
from lucairn.verify_certificate.parse import parse_certificate

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TS_FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "ts"
    / "src"
    / "verify-certificate"
    / "__fixtures__"
)


@pytest.fixture(scope="session")
def production_witness_pubkey() -> bytes:
    """Production Ed25519 witness public key (raw 32 bytes, from hex file)."""
    hex_str = (_FIXTURES_DIR / "production-witness-pubkey.hex").read_text().strip()
    return bytes.fromhex(hex_str)


@pytest.fixture(scope="session")
def real_v3_cert() -> dict:
    """Real production v3 certificate (signable_protocol_version_emitted=3)."""
    return json.loads((_FIXTURES_DIR / "real-v3-cert.fixture.json").read_text())


@pytest.fixture(scope="session")
def production_keys(production_witness_pubkey: bytes) -> VerifyCertificateKeys:
    return VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=production_witness_pubkey,
    )


@pytest.fixture(scope="session")
def test_witness_keypair() -> dict:
    for name in ("test-witness-keypair.json", "witness-keypair.json"):
        p = _TS_FIXTURES / name
        if p.is_file():
            return json.loads(p.read_text())
    pytest.fail("No witness keypair fixture found in TS fixtures dir")


@pytest.fixture(scope="session")
def test_keys(test_witness_keypair: dict) -> VerifyCertificateKeys:
    return VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=test_witness_keypair["publicKey"],
    )


# ---------------------------------------------------------------------------
# (a) ANTI-GAMING REAL-CERT ROUND-TRIP — test (a)
#
# This is the mandatory acceptance test.  It passes ONLY if the v3
# canonical-byte reconstruction exactly matches what the witness signed.
# The Ed25519 signature is real; no mocking.
# ---------------------------------------------------------------------------


class TestRealCertV3RoundTrip:
    def test_real_v3_cert_verifies_with_production_key(
        self, real_v3_cert: dict, production_keys: VerifyCertificateKeys
    ) -> None:
        """TEST (a): verify_certificate(real_v3_cert) → valid=True, signable_version='v3'.

        PASSES ONLY if the v3 byte-reconstruction is exact.  If this test
        fails, the reconstruction is wrong — fix the reconstruction, do NOT
        weaken the test.
        """
        # Sanity: confirm the fixture is a v3 cert
        assert real_v3_cert["signable_protocol_version_emitted"] == 3
        assert real_v3_cert["signable_v3_signature"]
        assert real_v3_cert["signable_v2_signature"] == real_v3_cert["witness_signature"], (
            "Fixture invariant: witness_signature must mirror signable_v2_signature byte-for-byte"
        )

        result = verify_certificate(real_v3_cert, production_keys)

        assert result.certificate_id == real_v3_cert["certificate_id"]
        assert result.request_id == real_v3_cert["request_id"]
        assert result.witness_key_id == "witness_v1"
        assert result.overall_verdict == real_v3_cert["verification"]["overall_verdict"]
        # Criterion #7: signable_version must be 'v3' for a v3 cert
        assert result.signable_version == "v3", (
            f"Expected signable_version='v3', got {result.signable_version!r}"
        )

    def test_real_v3_cert_v3_signature_verifies_directly(
        self, real_v3_cert: dict, production_witness_pubkey: bytes
    ) -> None:
        """Direct byte-level check: derive_v3_signed_bytes + Ed25519 verify."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)

        sig = base64.b64decode(real_v3_cert["signable_v3_signature"])
        key = Ed25519PublicKey.from_public_bytes(production_witness_pubkey)
        try:
            key.verify(sig, v3_bytes)
            verified = True
        except InvalidSignature:
            verified = False

        assert verified, (
            "v3 signature verification FAILED against production witness key.\n"
            f"v3 canonical bytes: {v3_bytes.decode()!r}\n"
            "The reconstruction is wrong — the v3 signable map does not match "
            "what the witness signed.  Do NOT skip or weaken this test."
        )


# ---------------------------------------------------------------------------
# (b) BACKWARD COMPAT — v2 path stays byte-identical — test (b)
# ---------------------------------------------------------------------------


class TestV2BackwardCompat:
    def test_real_v3_cert_also_verifies_on_v2_path(
        self, real_v3_cert: dict, production_witness_pubkey: bytes
    ) -> None:
        """TEST (b): same cert verifies on forced v2 path → byte-identical v2.

        The real cert carries both signable_v2_signature and witness_signature
        (they are the same bytes).  Forcing the v2 path and verifying against
        signable_v2_signature proves v2 reconstruction is byte-identical.
        Criterion #8.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        cert = parse_certificate(real_v3_cert)
        v2_bytes = derive_witness_signed_bytes(cert)

        # Verify against signable_v2_signature (= witness_signature)
        sig_v2 = base64.b64decode(real_v3_cert["signable_v2_signature"])
        key = Ed25519PublicKey.from_public_bytes(production_witness_pubkey)
        try:
            key.verify(sig_v2, v2_bytes)
            verified = True
        except InvalidSignature:
            verified = False

        assert verified, (
            "v2 path FAILED on a real v3 cert.  The v2 reconstruction is no longer "
            "byte-identical to what the witness signed.  Criterion #8 is broken."
        )

    def test_v2_signable_has_exactly_seven_keys(
        self, real_v3_cert: dict
    ) -> None:
        """v2 signable must contain exactly the 7 locked keys (regression guard)."""
        cert = parse_certificate(real_v3_cert)
        v2_bytes = derive_witness_signed_bytes(cert)
        decoded = json.loads(v2_bytes.decode())

        assert sorted(decoded.keys()) == [
            "certificate_id",
            "claim_ids",
            "issued_at",
            "overall_verdict",
            "protocol_version",
            "request_id",
            "witness_key_id",
        ], f"v2 signable has wrong keys: {sorted(decoded.keys())}"
        # v3-only fields must NOT leak into v2
        for v3_only in (
            "api_key_id", "byok_exempt", "client_id",
            "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash",
        ):
            assert v3_only not in decoded, (
                f"v3-only field '{v3_only}' leaked into the v2 signable — "
                "this breaks every v0.5.x SDK verifier in the field."
            )

    def test_legacy_cert_returns_signable_version_v2(
        self, test_keys: VerifyCertificateKeys
    ) -> None:
        """TEST (b) extension: a cert without signable_protocol_version_emitted
        returns signable_version='v2'.  Criterion #8 backward compat."""
        cert_dict = json.loads(
            (_TS_FIXTURES / "cert-valid-anchored.json").read_text()
        )
        # Confirm it's a legacy cert: no signable_protocol_version_emitted
        assert "signable_protocol_version_emitted" not in cert_dict

        result = verify_certificate(cert_dict, test_keys)
        assert result.signable_version == "v2"

    @property  # type: ignore[misc]
    def _TS_FIXTURES(self) -> Path:
        return _TS_FIXTURES


# ---------------------------------------------------------------------------
# (c) issued_at RFC3339Nano normalization — H6 fix — test (c)
# ---------------------------------------------------------------------------


class TestIssuedAtNormalization:
    """H6 due-diligence fix: protojson zero-pads fractional seconds;
    Go RFC3339Nano strips trailing zeros.  ~10% of real certs have a
    mismatch that caused false invalid_signature before SDK 1.2.0."""

    def test_strips_trailing_zeros(self) -> None:
        assert normalize_issued_at("2026-06-10T00:01:59.100000000Z") == "2026-06-10T00:01:59.1Z"

    def test_drops_dot_when_all_zeros(self) -> None:
        assert normalize_issued_at("2026-06-10T00:01:59.000000000Z") == "2026-06-10T00:01:59Z"

    def test_unchanged_when_no_trailing_zeros(self) -> None:
        assert (
            normalize_issued_at("2026-06-10T00:01:59.878143387Z")
            == "2026-06-10T00:01:59.878143387Z"
        )

    def test_unchanged_when_no_fractional_part(self) -> None:
        assert normalize_issued_at("2026-06-10T00:01:59Z") == "2026-06-10T00:01:59Z"

    def test_unchanged_when_not_utc_z_suffix(self) -> None:
        # Non-Z timestamps pass through unchanged (witness always emits UTC).
        assert (
            normalize_issued_at("2026-06-10T00:01:59.100000000+00:00")
            == "2026-06-10T00:01:59.100000000+00:00"
        )

    def test_partial_trailing_zeros_stripped(self) -> None:
        assert normalize_issued_at("2026-06-10T00:01:59.500Z") == "2026-06-10T00:01:59.5Z"
        assert normalize_issued_at("2026-06-10T00:01:59.120000000Z") == "2026-06-10T00:01:59.12Z"

    def test_cert_with_trailing_zero_issued_at_verifies(
        self, real_v3_cert: dict, production_keys: VerifyCertificateKeys
    ) -> None:
        """TEST (c): a cert whose issued_at has trailing zeros (artificially
        injected) verifies correctly after normalization.

        We manufacture the scenario by replacing the real cert's issued_at with
        a zero-padded version, then re-sign the v2 and v3 signables using the
        NORMALIZED form (to simulate what the witness does), and verify that
        normalize_issued_at in the SDK closes the gap.
        """
        import copy
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        from lucairn.verify_certificate.canonical_json import canonical_json

        # Generate a fresh keypair for this synthetic test
        priv = Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Use the real v3 cert as the template, inject trailing-zero issued_at
        cert_dict = copy.deepcopy(real_v3_cert)
        original_issued_at = cert_dict["issued_at"]  # e.g. "...878143387Z"
        # Create a trailing-zero version (simulate protojson padding)
        # We strip last digits and pad to 9 with zeros
        dot = original_issued_at.rfind(".")
        if dot == -1:
            # No fractional part: inject .100000000Z
            padded_issued_at = original_issued_at[:-1] + ".100000000Z"
        else:
            frac = original_issued_at[dot + 1 : -1]
            # Re-pad to 9 digits with zeros
            padded_issued_at = original_issued_at[:dot + 1] + frac.ljust(9, "0") + "Z"

        cert_dict["issued_at"] = padded_issued_at
        # Remove the signable_protocol_version_emitted to force v2 path (simpler)
        cert_dict.pop("signable_protocol_version_emitted", None)
        cert_dict.pop("signable_v3_signature", None)

        # Build v2 signable with NORMALIZED issued_at (what witness signs)
        normalized = normalize_issued_at(padded_issued_at)
        claim_ids = [c["claim_id"] for c in cert_dict["claims"]]

        # Map verdict to short form
        full_to_short = {
            "VERDICT_UNSPECIFIED": "UNSPECIFIED",
            "VERDICT_VERIFIED": "VERIFIED",
            "VERDICT_PARTIAL": "PARTIAL",
            "VERDICT_FAILED": "FAILED",
        }
        verdict = full_to_short[cert_dict["verification"]["overall_verdict"]]

        signable_v2 = {
            "certificate_id": cert_dict["certificate_id"],
            "request_id": cert_dict["request_id"],
            "protocol_version": 2,
            "claim_ids": claim_ids,
            "issued_at": normalized,  # normalized form (what witness signed)
            "overall_verdict": verdict,
            "witness_key_id": cert_dict["witness_key_id"],
        }
        v2_bytes = canonical_json(signable_v2)
        sig_v2 = priv.sign(v2_bytes)
        cert_dict["witness_signature"] = base64.b64encode(sig_v2).decode()

        # Verify: SDK should normalize issued_at and arrive at the same bytes
        synthetic_keys = VerifyCertificateKeys(
            witness_key_id="witness_v1",
            witness_public_key=pub_raw,
        )
        result = verify_certificate(cert_dict, synthetic_keys)
        assert result.signable_version == "v2"
        assert result.certificate_id == cert_dict["certificate_id"]


# ---------------------------------------------------------------------------
# (d) v3 signable structural checks
# ---------------------------------------------------------------------------


class TestV3SignableStructure:
    def test_v3_signable_has_exactly_thirteen_keys(
        self, real_v3_cert: dict
    ) -> None:
        """TEST (d): v3 signable contains exactly 13 keys (7 v2 + 6 carry-forwards)."""
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())

        assert len(decoded) == 13, (
            f"v3 signable has {len(decoded)} keys, expected 13: {sorted(decoded.keys())}"
        )
        expected_keys = sorted([
            "certificate_id", "request_id", "protocol_version", "claim_ids",
            "issued_at", "overall_verdict", "witness_key_id",
            "client_id", "api_key_id", "byok_exempt",
            "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash",
        ])
        assert sorted(decoded.keys()) == expected_keys

    def test_v3_protocol_version_is_two_not_three(
        self, real_v3_cert: dict
    ) -> None:
        """protocol_version in the v3 signable is the CERT-shape version (2),
        not the signable-shape version (3).  Assembler comment at
        assembler.go:386-389: changing this to 3 breaks byte-identity."""
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["protocol_version"] == 2, (
            f"v3 signable protocol_version must be 2 (cert-shape), got {decoded['protocol_version']}"
        )

    def test_v3_tms_manifest_hash_is_null_when_absent(
        self, real_v3_cert: dict
    ) -> None:
        """TEST (e): tms_manifest_hash absent in sanitizer payload → null in v3 signable."""
        # The real v3 cert was minted pre-Slice-5, so tms_manifest_hash is absent.
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["tms_manifest_hash"] is None, (
            f"tms_manifest_hash should be null (pre-Slice-5), got {decoded['tms_manifest_hash']!r}"
        )

    def test_v3_byok_exempt_is_bool(
        self, real_v3_cert: dict
    ) -> None:
        """byok_exempt in the v3 signable is a JSON bool, not a string."""
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert isinstance(decoded["byok_exempt"], bool), (
            f"byok_exempt must be a bool in the v3 signable, got {type(decoded['byok_exempt'])}"
        )

    def test_v3_api_key_id_populated_from_cert(
        self, real_v3_cert: dict
    ) -> None:
        """api_key_id is read from cert.api_key_id (top-level field)."""
        assert real_v3_cert.get("api_key_id"), "Real v3 cert must carry api_key_id"
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["api_key_id"] == real_v3_cert["api_key_id"]

    def test_v3_client_id_null_when_absent(
        self, real_v3_cert: dict
    ) -> None:
        """client_id is null when the cert carries no org_id."""
        # Real cert: client_id is None (empty org_id from bridge)
        assert real_v3_cert.get("client_id") is None
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["client_id"] is None

    def test_v3_redaction_hashes_from_sanitizer_canonical_payload(
        self, real_v3_cert: dict
    ) -> None:
        """Hash fields come from dsa-sanitizer canonical_payload, not top-level fields."""
        cert = parse_certificate(real_v3_cert)
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())

        # Extract expected values directly from the sanitizer claim
        for claim in real_v3_cert["claims"]:
            if claim["service_id"] == "dsa-sanitizer":
                cp = json.loads(base64.b64decode(claim["canonical_payload"]))
                inner = cp.get("payload", cp)
                assert decoded["redaction_manifest_hash"] == inner.get("redaction_manifest_hash")
                assert decoded["sanitized_fields_body_hash"] == inner.get("sanitized_fields_hash")
                break


# ---------------------------------------------------------------------------
# (f) signable_version='v2' on legacy certs
# ---------------------------------------------------------------------------


class TestSignableVersionOnLegacyCerts:
    def test_valid_anchored_cert_returns_v2(
        self, test_keys: VerifyCertificateKeys
    ) -> None:
        """TEST (f): legacy cert (no signable_protocol_version_emitted) → signable_version='v2'."""
        cert_dict = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
        result = verify_certificate(cert_dict, test_keys)
        assert result.signable_version == "v2"
        assert result.overall_verdict == "VERDICT_VERIFIED"

    def test_signable_version_field_present_on_result(
        self, test_keys: VerifyCertificateKeys
    ) -> None:
        """VerifyCertificateResult always carries signable_version (default 'v2')."""
        cert_dict = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
        result = verify_certificate(cert_dict, test_keys)
        assert hasattr(result, "signable_version")
        assert result.signable_version in ("v2", "v3")


# ---------------------------------------------------------------------------
# TestDowngradeDetection — TOB-SDK-PY-01 + TOB-SDK-PY-02
# ---------------------------------------------------------------------------


class TestDowngradeDetection:
    """Trail-of-Bits findings TOB-SDK-PY-01 (MEDIUM) and TOB-SDK-PY-02 (LOW).

    (a) v3 cert with version field stripped but v3 sig present
        → raises version_downgrade_detected (TOB-SDK-PY-01a).
    (b) minimum_signable_version='v3' on a genuine v2 cert (no v3 sig)
        → raises signable_version_insufficient (TOB-SDK-PY-01b).
    (c) genuine v3 cert with minimum_signable_version='v3'
        → passes with signable_version='v3' (no regression).
    (d) genuine legacy v2 cert with default args
        → still passes signable_version='v2' (no regression).
    (e) v3 path with missing signable_v3_signature
        → raises witness_signature_missing with honest error (TOB-SDK-PY-02).
    """

    def test_version_stripped_with_v3_sig_raises_downgrade_detected(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (a) TOB-SDK-PY-01a: strip version field but leave v3 sig → version_downgrade_detected."""
        import copy

        tampered = copy.deepcopy(real_v3_cert)
        # Confirm fixture is a v3 cert
        assert tampered.get("signable_protocol_version_emitted") == 3
        assert tampered.get("signable_v3_signature")

        # Strip the version field (attacker removes it to force the v2 path)
        del tampered["signable_protocol_version_emitted"]
        # v3 signature left intact — this is the downgrade-attempt shape

        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(tampered, production_keys)

        assert exc_info.value.reason == "version_downgrade_detected", (
            f"Expected reason='version_downgrade_detected', got {exc_info.value.reason!r}"
        )

    def test_version_set_to_zero_with_v3_sig_raises_downgrade_detected(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (a) variant: version field set to 0 (< 3) but v3 sig present → version_downgrade_detected."""
        import copy

        tampered = copy.deepcopy(real_v3_cert)
        tampered["signable_protocol_version_emitted"] = 0  # force v2 dispatch
        assert tampered.get("signable_v3_signature")  # v3 sig still present

        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(tampered, production_keys)

        assert exc_info.value.reason == "version_downgrade_detected"

    def test_minimum_signable_version_v3_on_legacy_v2_cert_raises(
        self,
        test_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (b) TOB-SDK-PY-01b: minimum_signable_version='v3' on legacy cert → signable_version_insufficient."""
        cert_dict = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
        # Confirm it's a genuine legacy v2 cert (no v3 sig)
        assert not cert_dict.get("signable_v3_signature")
        assert not cert_dict.get("signable_protocol_version_emitted")

        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(cert_dict, test_keys, minimum_signable_version="v3")

        assert exc_info.value.reason == "signable_version_insufficient", (
            f"Expected reason='signable_version_insufficient', got {exc_info.value.reason!r}"
        )

    def test_genuine_v3_cert_with_minimum_signable_version_v3_passes(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (c): genuine v3 cert + minimum_signable_version='v3' → passes, signable_version='v3'."""
        result = verify_certificate(
            real_v3_cert, production_keys, minimum_signable_version="v3"
        )
        assert result.signable_version == "v3", (
            f"Expected signable_version='v3', got {result.signable_version!r}"
        )
        assert result.certificate_id == real_v3_cert["certificate_id"]
        assert not result.v3_signature_stripped

    def test_genuine_legacy_v2_cert_default_args_still_passes(
        self,
        test_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (d): genuine legacy v2 cert with default args → passes, signable_version='v2' (no regression)."""
        cert_dict = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
        result = verify_certificate(cert_dict, test_keys)
        assert result.signable_version == "v2"
        assert result.overall_verdict == "VERDICT_VERIFIED"
        assert not result.v3_signature_stripped

    def test_v3_path_missing_v3_signature_raises_version_downgrade_detected(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """TEST (e) canonical downgrade dispatch: emitted>=3 but signable_v3_signature
        is empty → version_downgrade_detected (NOT witness_signature_missing).

        A legitimate v3 cert ALWAYS carries both the version field and the v3 sig —
        the witness assembler sets them atomically.  A missing v3 sig on a v3-versioned
        cert means the sig was stripped.  Raises version_downgrade_detected to match
        the other tampering direction (version stripped, sig present).
        """
        import copy

        tampered = copy.deepcopy(real_v3_cert)
        # Keep the version field (so v3 dispatch is triggered) but strip the v3 sig.
        assert tampered.get("signable_protocol_version_emitted") == 3
        tampered["signable_v3_signature"] = ""  # stripped — downgrade attack direction 2

        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(tampered, production_keys)

        assert exc_info.value.reason == "version_downgrade_detected", (
            f"Expected reason='version_downgrade_detected', got {exc_info.value.reason!r}\n"
            "Canonical downgrade-detection: emitted>=3 with absent/empty v3 sig is a "
            "stripping attack — must raise version_downgrade_detected, not "
            "witness_signature_missing."
        )

    def test_v3_path_absent_v3_signature_field_raises_version_downgrade_detected(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """Variant of (e): signable_v3_signature key absent entirely → version_downgrade_detected."""
        import copy

        tampered = copy.deepcopy(real_v3_cert)
        assert tampered.get("signable_protocol_version_emitted") == 3
        tampered.pop("signable_v3_signature", None)

        with pytest.raises(LucairnCertificateError) as exc_info:
            verify_certificate(tampered, production_keys)

        assert exc_info.value.reason == "version_downgrade_detected"

    def test_v3_signature_stripped_flag_false_on_genuine_v3(
        self,
        real_v3_cert: dict,
        production_keys: VerifyCertificateKeys,
    ) -> None:
        """v3_signature_stripped is False on a genuine v3 cert (happy path)."""
        result = verify_certificate(real_v3_cert, production_keys)
        assert result.v3_signature_stripped is False

    def test_v3_signature_stripped_flag_false_on_clean_legacy_v2(
        self,
        test_keys: VerifyCertificateKeys,
    ) -> None:
        """v3_signature_stripped is False on a clean legacy v2 cert (no v3 sig present)."""
        cert_dict = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
        result = verify_certificate(cert_dict, test_keys)
        assert result.v3_signature_stripped is False


# ---------------------------------------------------------------------------
# TestEmptyOptionalPreservation — CODEX-SDKPY-01 regression
#
# client_id and api_key_id must preserve "" (empty string) in the v3 signable,
# not coerce it to null.  Matches Go optionalStringForSignable behaviour: a nil
# pointer → null; a present pointer (even to "") → the string value.
# ---------------------------------------------------------------------------


class TestEmptyOptionalPreservation:
    """CODEX-SDKPY-01 (MED): empty-string optionals preserved in v3 signable."""

    def _make_cert(
        self,
        real_v3_cert: dict,
        *,
        client_id: "str | None",
        api_key_id: "str | None",
    ):  # type: ignore[return]
        import copy

        d = copy.deepcopy(real_v3_cert)
        if client_id is None:
            d.pop("client_id", None)
        else:
            d["client_id"] = client_id
        if api_key_id is None:
            d.pop("api_key_id", None)
        else:
            d["api_key_id"] = api_key_id
        return parse_certificate(d)

    def test_client_id_empty_string_preserved_as_empty_string(
        self, real_v3_cert: dict
    ) -> None:
        """CODEX-SDKPY-01: client_id='' in cert → '' in v3 signable (NOT null).

        Matches Go assembler optionalStringForSignable: a present pointer to ""
        produces the JSON string "", not null.
        """
        cert = self._make_cert(real_v3_cert, client_id="", api_key_id="k_abc123")
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["client_id"] == "", (
            f"client_id='' must appear as '' in the v3 signable, got {decoded['client_id']!r}. "
            "CODEX-SDKPY-01: truthiness check was coercing empty string to null."
        )

    def test_api_key_id_empty_string_preserved_as_empty_string(
        self, real_v3_cert: dict
    ) -> None:
        """CODEX-SDKPY-01: api_key_id='' in cert → '' in v3 signable (NOT null)."""
        cert = self._make_cert(real_v3_cert, client_id=None, api_key_id="")
        v3_bytes = derive_v3_signed_bytes(cert)
        decoded = json.loads(v3_bytes.decode())
        assert decoded["api_key_id"] == "", (
            f"api_key_id='' must appear as '' in the v3 signable, got {decoded['api_key_id']!r}. "
            "CODEX-SDKPY-01: truthiness check was coercing empty string to null."
        )

    def test_client_id_absent_produces_null(self, real_v3_cert: dict) -> None:
        """Absent client_id (None / JSON-null) still produces null in v3 signable."""
        cert = self._make_cert(real_v3_cert, client_id=None, api_key_id="k_abc")
        decoded = json.loads(derive_v3_signed_bytes(cert).decode())
        assert decoded["client_id"] is None

    def test_api_key_id_absent_produces_null(self, real_v3_cert: dict) -> None:
        """Absent api_key_id (None / JSON-null) still produces null in v3 signable."""
        cert = self._make_cert(real_v3_cert, client_id="org_xyz", api_key_id=None)
        decoded = json.loads(derive_v3_signed_bytes(cert).decode())
        assert decoded["api_key_id"] is None

    def test_client_id_non_empty_string_preserved(self, real_v3_cert: dict) -> None:
        """A normal non-empty client_id passes through unchanged."""
        cert = self._make_cert(real_v3_cert, client_id="org_abc123", api_key_id=None)
        decoded = json.loads(derive_v3_signed_bytes(cert).decode())
        assert decoded["client_id"] == "org_abc123"


_TS_FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "ts"
    / "src"
    / "verify-certificate"
    / "__fixtures__"
)
