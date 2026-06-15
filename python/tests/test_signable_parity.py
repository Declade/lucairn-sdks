"""Cross-language signable-reconstruction PARITY tests (2026-06-15).

These tests lock the Python signable reconstruction against a SHARED golden
hex that lives BYTE-IDENTICALLY in all three SDK fixture directories:

    go/internal/verify/testdata/real-v{2,3}-signable-go-reference.hex
    ts/src/verify-certificate/__fixtures__/real-v{2,3}-signable-go-reference.hex
    python/tests/fixtures/real-v{2,3}-signable-go-reference.hex

The hex is the canonical signable bytes derived from the SHARED real cert
fixture (real-v3-cert.fixture.json, also byte-identical across all three dirs).
Each language asserts it reproduces this exact hex; because the same hex is
pinned in every tree, byte-identity in each language is a transitive proof of
cross-language byte-equivalence.

HARD GATE: these bytes are UNCHANGED from origin/main — the signable
reconstruction parity fixes (issued_at UTC normalization here in Python; the TS
flat-fallback / bytewise-UTF-8 key sort) are byte-equivalent on every real cert
(which only ever carries the wrapped canonical_payload shape and Zulu timestamps
with ASCII keys). If this test fails, the reconstruction drifted — fix the
reconstruction, do NOT regenerate the hex.

It ALSO pins the parity SHAPE behaviour for the previously-divergent edge cases
(flat canonical_payload, offset timestamp, non-ASCII key, null version) so the
Python output matches the Go reference (TestParity_* in
go/internal/verify/parity_test.go) byte-for-byte.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from lucairn.errors import LucairnCertificateError
from lucairn.types import VeilCertificate, VerifyCertificateKeys
from lucairn.verify_certificate import verify_certificate
from lucairn.verify_certificate.canonical_json import canonical_json
from lucairn.verify_certificate.parse import parse_certificate
from lucairn.verify_certificate.signable import (
    derive_witness_signed_bytes,
    normalize_issued_at,
)
from lucairn.verify_certificate.v3_signable import derive_v3_signed_bytes

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_TS_FIXTURES = (
    Path(__file__).resolve().parent.parent.parent
    / "ts"
    / "src"
    / "verify-certificate"
    / "__fixtures__"
)


def _real_cert() -> VeilCertificate:
    raw = json.loads((_FIXTURES_DIR / "real-v3-cert.fixture.json").read_text())
    return parse_certificate(raw)


def _shared_hex(name: str) -> str:
    return (_FIXTURES_DIR / name).read_text().strip()


# ---------------------------------------------------------------------------
# Shared golden-hex anchors — the cross-language byte-equivalence proof.
# ---------------------------------------------------------------------------


def test_real_cert_v2_signable_matches_shared_golden_hex() -> None:
    out = derive_witness_signed_bytes(_real_cert())
    got = out.hex()
    want = _shared_hex("real-v2-signable-go-reference.hex")
    assert got == want, (
        "v2 signable drifted from the shared cross-language golden hex.\n"
        f"  got:  {got}\n  want: {want}\n  got-json: {out.decode()}"
    )


def test_real_cert_v3_signable_matches_shared_golden_hex() -> None:
    out = derive_v3_signed_bytes(_real_cert())
    got = out.hex()
    want = _shared_hex("real-v3-signable-go-reference.hex")
    assert got == want, (
        "v3 signable drifted from the shared cross-language golden hex.\n"
        f"  got:  {got}\n  want: {want}\n  got-json: {out.decode()}"
    )


# ---------------------------------------------------------------------------
# Parity SHAPE tests — match the Go reference (TestParity_* in
# go/internal/verify/parity_test.go) on the previously-divergent shapes.
# ---------------------------------------------------------------------------


def _raw_real_cert() -> dict:
    return json.loads((_FIXTURES_DIR / "real-v3-cert.fixture.json").read_text())


def _sanitizer_claim_cert(canonical_payload_json: str) -> VeilCertificate:
    """Derive a cert from the real fixture but replace the dsa-sanitizer claim's
    canonical_payload with the given JSON, so we exercise the v3 hash extraction
    path on both the flat and wrapped canonical_payload shapes. Deriving from
    the real fixture keeps every other required field valid under Pydantic."""
    import copy

    cp_b64 = base64.b64encode(canonical_payload_json.encode()).decode()
    raw = copy.deepcopy(_raw_real_cert())
    replaced = False
    for claim in raw["claims"]:
        if claim.get("service_id") == "dsa-sanitizer":
            claim["canonical_payload"] = cp_b64
            replaced = True
            break
    assert replaced, "real fixture has no dsa-sanitizer claim to mutate"
    return parse_certificate(raw)


def test_flat_canonical_payload_hash_read() -> None:
    """FLAT canonical_payload (hash at top level, no 'payload' wrapper) — the
    flat fallback must read it (matches Go + the now-fixed TS port)."""
    cert = _sanitizer_claim_cert('{"redaction_manifest_hash":"abc123"}')
    out_json = json.loads(derive_v3_signed_bytes(cert).decode())
    assert out_json["redaction_manifest_hash"] == "abc123"


def test_wrapped_canonical_payload_hash_read() -> None:
    """WRAPPED canonical_payload (hash under 'payload') — the normal shape;
    flat and wrapped must read identically."""
    cert = _sanitizer_claim_cert(
        '{"payload":{"redaction_manifest_hash":"abc123"}}'
    )
    out_json = json.loads(derive_v3_signed_bytes(cert).decode())
    assert out_json["redaction_manifest_hash"] == "abc123"


def test_offset_timestamp_normalized_to_utc() -> None:
    """OFFSET timestamp → equivalent UTC Z time (trailing zeros stripped),
    byte-identical to Go's time.Parse(RFC3339Nano).UTC().Format(RFC3339Nano).
    These exact input/output pairs are pinned in the Go reference test."""
    cases = [
        ("2026-05-01T14:00:00.100000000+02:00", "2026-05-01T12:00:00.1Z"),
        ("2026-05-01T08:00:00-03:00", "2026-05-01T11:00:00Z"),
        ("2026-06-10T00:01:59.100000000+00:00", "2026-06-10T00:01:59.1Z"),
        ("2026-06-10T00:01:59.878143387Z", "2026-06-10T00:01:59.878143387Z"),
        ("2026-06-10T00:01:59.000000000Z", "2026-06-10T00:01:59Z"),
        ("2026-06-10T00:01:59Z", "2026-06-10T00:01:59Z"),
        ("not-a-timestamp", "not-a-timestamp"),  # fail-open
    ]
    for src, want in cases:
        assert normalize_issued_at(src) == want, src


def test_non_ascii_key_sort() -> None:
    """NON-ASCII key sort — bytewise UTF-8, byte-identical to the Go reference.

    bmpKey    = U+E000 (BMP)   -> UTF-8 ee 80 80
    astralKey = U+1F600 (emoji) -> UTF-8 f0 9f 98 80
    UTF-16 would order astralKey before bmpKey (surrogate D83D < E000); UTF-8
    orders bmpKey before astralKey (ee < f0). Python sorts by k.encode('utf-8')
    so it matches Go's encoding/json. ASCII 'a' (0x61) sorts first."""
    bmp_key = ""
    astral_key = "\U0001f600"
    out = canonical_json({bmp_key: "bmp", astral_key: "astral", "a": "ascii"})
    want = (
        '{"a":"ascii","' + bmp_key + '":"bmp","' + astral_key + '":"astral"}'
    ).encode("utf-8")
    assert out == want, f"\n  got:  {out!r}\n  want: {want!r}"


def test_null_signable_protocol_version_tolerated() -> None:
    """NULL version field — an explicit JSON null for
    signable_protocol_version_emitted is coerced to 0 (matches TS `?? 0` and
    Go nil→0), instead of raising a Pydantic validation error."""
    import copy

    raw = copy.deepcopy(_raw_real_cert())
    raw["signable_protocol_version_emitted"] = None  # explicit JSON null
    cert = parse_certificate(raw)
    assert cert.signable_protocol_version_emitted == 0


def test_non_null_signable_protocol_version_still_validates() -> None:
    """A non-null value still passes through normal int validation — the null
    coercion does not swallow type errors (a bad type still raises)."""
    import copy

    from lucairn.errors import LucairnCertificateError

    raw = copy.deepcopy(_raw_real_cert())
    raw["signable_protocol_version_emitted"] = "not-an-int"
    try:
        parse_certificate(raw)
    except LucairnCertificateError:
        pass  # expected: bad type rejected as malformed
    else:
        raise AssertionError("expected a malformed error for a non-int version")


def _witness_keypair() -> dict:
    """Load the TS test witness keypair (shared cross-language fixture)."""
    for name in ("test-witness-keypair.json", "witness-keypair.json"):
        p = _TS_FIXTURES / name
        if p.is_file():
            return json.loads(p.read_text())
    pytest.fail("No witness keypair fixture found in TS fixtures dir")


def test_tampered_v2_cert_with_min_v3_returns_invalid_signature() -> None:
    """ORDERING PARITY (fix 3): a TAMPERED v2 cert verified with
    minimum_signable_version='v3' must surface reason='invalid_signature'
    (the security-relevant verdict), NOT 'signable_version_insufficient'.

    Before the fix Python checked the version floor BEFORE signature
    verification on the v2 path, masking the tamper as a policy failure. TS
    (index.ts verifyV2) and Go (pipeline.go Run) both verify the signature
    first, then enforce the floor. This pins Python to the same order so all
    three languages agree on a tampered cert."""
    keys = VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=_witness_keypair()["publicKey"],
    )
    tampered = json.loads((_TS_FIXTURES / "cert-tampered-payload.json").read_text())
    # Sanity: a genuine v2 cert (no v3 sig / version) with a bad signature.
    assert not tampered.get("signable_protocol_version_emitted")
    assert not tampered.get("signable_v3_signature")

    with pytest.raises(LucairnCertificateError) as exc_info:
        verify_certificate(tampered, keys, minimum_signable_version="v3")
    assert exc_info.value.reason == "invalid_signature", (
        "tampered v2 cert + min='v3' must return 'invalid_signature' "
        f"(parity with TS/Go), got {exc_info.value.reason!r}"
    )


def test_genuine_v2_cert_with_min_v3_returns_version_insufficient() -> None:
    """The other side of fix 3: a GENUINE, signature-valid v2 cert verified
    with minimum_signable_version='v3' still surfaces
    'signable_version_insufficient' — the version floor is enforced AFTER a
    successful signature check, so valid-cert behaviour is unchanged."""
    keys = VerifyCertificateKeys(
        witness_key_id="witness_v1",
        witness_public_key=_witness_keypair()["publicKey"],
    )
    valid_v2 = json.loads((_TS_FIXTURES / "cert-valid-anchored.json").read_text())
    assert not valid_v2.get("signable_protocol_version_emitted")
    assert not valid_v2.get("signable_v3_signature")

    with pytest.raises(LucairnCertificateError) as exc_info:
        verify_certificate(valid_v2, keys, minimum_signable_version="v3")
    assert exc_info.value.reason == "signable_version_insufficient", (
        f"genuine v2 cert + min='v3' must return 'signable_version_insufficient', "
        f"got {exc_info.value.reason!r}"
    )
