"""The witness-only verifier (verify_certificate -> verify_ed25519) applies its
own Ed25519 acceptance rule before the bytes reach ``cryptography``: a
small-order R, a small-order or non-canonical public key and S >= L are
refused whatever library build sits behind the runtime (T-1322).

Every assertion here is a refusal, or an honest signature verifying — so the
file passes on a runtime whose library already refuses these inputs and on
one whose library accepts them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import lucairn
from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import signature as signature_mod
from lucairn.verify_certificate import verify_certificate, verify_ed25519

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

# The shared vector file: the SAME bytes sit in
#   ts/src/verify-certificate/__fixtures__/ed25519-rule-vectors.json
#   python/tests/fixtures/ed25519-rule-vectors.json
#   go/internal/verify/testdata/ed25519-rule-vectors.json
# and each SDK's test pins this sha256, so the three copies of the rule are
# held to one set of inputs and expected results.
VECTORS_SHA256 = "f7bd4f8122c91078a705a480a929b8e832d8f205cf52525d35438d50f53a5818"
VECTORS_FILE = _FIXTURES_DIR / "ed25519-rule-vectors.json"

# Parity-corpus case ``tamper_witness_signature_small_order_r`` (corpus
# v1.2.3), copied verbatim; the same bytes sit in the TypeScript and Go test
# folders. Its witness key is the published corpus TEST key below.
CORPUS_CASE_SHA256 = "2fc78fe50a778c53d421f4af4e85c9d5a39a1e0b25c37bcd1aa4203465e89db6"
CORPUS_CASE_FILE = _FIXTURES_DIR / "corpus-tamper_witness_signature_small_order_r.json"
CORPUS_WITNESS = VerifyCertificateKeys(
    witness_key_id="witness_parity_v1",
    witness_public_key="DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc=",
)

VECTORS: list[dict[str, str]] = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))["vectors"]
SMALL_ORDER = [bytes.fromhex(v["public_key_hex"]) for v in VECTORS if v["group"] == "small_order_key"]

L = 2**252 + 27742317777372353535851937790883648493
MESSAGE = b"witness-only signature rule"


def _fresh_key() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, raw


def _corpus_case() -> Any:
    return json.loads(CORPUS_CASE_FILE.read_text(encoding="utf-8"))


# --- the corpus case through verify_certificate --------------------------------


def test_corpus_fixture_is_the_corpus_file_byte_for_byte() -> None:
    assert hashlib.sha256(CORPUS_CASE_FILE.read_bytes()).hexdigest() == CORPUS_CASE_SHA256
    want = _corpus_case()["expected"]["default"]
    assert (want["verdict"], want["reason"]) == ("FAILED", "witness_signature_invalid")


def test_corpus_small_order_r_is_refused_as_invalid_signature() -> None:
    with pytest.raises(LucairnCertificateError) as exc:
        verify_certificate(_corpus_case()["certificate"], CORPUS_WITNESS)
    assert exc.value.reason == "invalid_signature"


def test_corpus_small_order_r_is_refused_under_minimum_v3() -> None:
    with pytest.raises(LucairnCertificateError) as exc:
        verify_certificate(_corpus_case()["certificate"], CORPUS_WITNESS, minimum_signable_version="v3")
    assert exc.value.reason == "invalid_signature"


# --- shared cross-language vectors -----------------------------------------------


def test_vector_file_is_the_shared_one() -> None:
    assert hashlib.sha256(VECTORS_FILE.read_bytes()).hexdigest() == VECTORS_SHA256


def test_vector_file_coverage() -> None:
    def group(g: str) -> list[dict[str, str]]:
        return [v for v in VECTORS if v["group"] == g]

    assert len({v["signature_hex"][:64] for v in group("small_order_r")}) == 14
    assert len(set(SMALL_ORDER)) == 14
    assert len(group("invalid_point_key")) >= 3
    assert len(group("noncanonical_s")) >= 1
    assert len(group("noncanonical_r")) >= 1
    assert len([v for v in VECTORS if v["expected"] == "accept"]) >= 5
    assert len(VECTORS) == 48


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["id"])
def test_shared_vector(vector: dict[str, str]) -> None:
    want = vector["expected"] == "accept"
    key = bytes.fromhex(vector["public_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    sig = bytes.fromhex(vector["signature_hex"])
    assert verify_ed25519(message, sig, key) is want
    # the base64 form of the key takes the same path
    assert verify_ed25519(message, sig, base64.b64encode(key).decode("ascii")) is want


# --- fresh keys made in the test (no false refusal) ---------------------------------


def test_genuine_signatures_of_fresh_keys_verify_with_either_key_sign_bit() -> None:
    clear = sign_set = 0
    for _ in range(400):
        if clear >= 4 and sign_set >= 4:
            break
        private, raw = _fresh_key()
        sig = private.sign(MESSAGE)
        assert verify_ed25519(MESSAGE, sig, raw) is True
        assert verify_ed25519(MESSAGE, sig, base64.b64encode(raw).decode("ascii")) is True
        if raw[31] & 0x80:
            sign_set += 1
        else:
            clear += 1
    assert clear >= 4 and sign_set >= 4


def test_fresh_signature_with_s_plus_l_is_refused() -> None:
    private, raw = _fresh_key()
    sig = private.sign(MESSAGE)
    assert verify_ed25519(MESSAGE, sig, raw) is True
    s_plus_l = int.from_bytes(sig[32:], "little") + L
    assert s_plus_l < 2**256
    assert verify_ed25519(MESSAGE, sig[:32] + s_plus_l.to_bytes(32, "little"), raw) is False


def test_every_small_order_encoding_is_refused_as_r_and_as_key_for_a_fresh_key() -> None:
    private, raw = _fresh_key()
    sig = private.sign(MESSAGE)
    assert len(SMALL_ORDER) == 14
    for enc in SMALL_ORDER:
        assert verify_ed25519(MESSAGE, enc + sig[32:], raw) is False
        assert verify_ed25519(MESSAGE, sig, enc) is False


def test_malformed_key_still_raises_type_error() -> None:
    for bad in (bytes(31), bytes(33), "not base64!", 7, None):
        with pytest.raises(TypeError):
            verify_ed25519(MESSAGE, bytes(64), bad)  # type: ignore[arg-type]


def test_bytearray_inputs_behave_like_bytes() -> None:
    private, raw = _fresh_key()
    sig = private.sign(MESSAGE)
    assert verify_ed25519(bytearray(MESSAGE), bytearray(sig), bytearray(raw)) is True
    assert verify_ed25519(MESSAGE, bytearray(SMALL_ORDER[2] + sig[32:]), bytearray(raw)) is False


# --- nothing new became public ------------------------------------------------------


def test_no_new_public_name() -> None:
    assert signature_mod.__all__ == ["verify_ed25519"]
    assert not [n for n in lucairn.__all__ if "small_order" in n.lower() or "acceptable" in n.lower()]
    from lucairn.verify_certificate import _ed25519_rule

    assert _ed25519_rule.__all__ == []
