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
from lucairn.verify_certificate import _ed25519_rule, _text_rule
from lucairn.verify_certificate import signature as signature_mod
from lucairn.verify_certificate import verify_certificate, verify_ed25519

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

# The shared vector file: the SAME bytes sit in
#   ts/src/verify-certificate/__fixtures__/ed25519-rule-vectors.json
#   python/tests/fixtures/ed25519-rule-vectors.json
#   go/internal/verify/testdata/ed25519-rule-vectors.json
# and each SDK's test pins this sha256, so the three copies of the rule are
# held to one set of inputs and expected results.
VECTORS_SHA256 = "26033d6336fd735dc5c4db068fbcb682cbd6385f8167b8afbb5d44769062fd20"
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

_VECTOR_DOC = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
VECTORS: list[dict[str, str]] = _VECTOR_DOC["vectors"]
FIELD_VECTORS: list[dict[str, str]] = _VECTOR_DOC["certificate_field_vectors"]
_TS_FIXTURES = Path(__file__).resolve().parent.parent.parent / "ts" / "src" / "verify-certificate" / "__fixtures__"
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


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview], ids=lambda w: w.__name__)
def test_signature_and_message_buffer_forms_verify(wrap: Any) -> None:
    """bytes, bytearray and memoryview signatures / messages verified at
    runtime before this rule existed; they still do."""
    private, raw = _fresh_key()
    sig = private.sign(MESSAGE)
    assert verify_ed25519(MESSAGE, wrap(sig), raw) is True
    assert verify_ed25519(wrap(MESSAGE), sig, raw) is True
    assert verify_ed25519(wrap(MESSAGE), wrap(sig), raw) is True
    # and the refusals do not depend on the buffer type either
    assert verify_ed25519(MESSAGE, wrap(SMALL_ORDER[2] + sig[32:]), raw) is False
    assert verify_ed25519(MESSAGE, wrap(sig), SMALL_ORDER[0]) is False


def test_key_buffer_forms() -> None:
    """Key forms are the normaliser's, unchanged: bytes, bytearray and a
    base64 string are accepted; a memoryview key raises TypeError as before."""
    private, raw = _fresh_key()
    sig = private.sign(MESSAGE)
    assert verify_ed25519(MESSAGE, sig, bytearray(raw)) is True
    assert verify_ed25519(MESSAGE, sig, bytearray(SMALL_ORDER[0])) is False
    with pytest.raises(TypeError):
        verify_ed25519(MESSAGE, sig, memoryview(raw))  # type: ignore[arg-type]


def test_caller_buffers_are_not_modified() -> None:
    private, raw = _fresh_key()
    sig = bytearray(private.sign(MESSAGE))
    key = bytearray(raw)
    key[31] |= 0x80
    sig_copy, key_copy = bytes(sig), bytes(key)
    verify_ed25519(MESSAGE, sig, key)
    _ed25519_rule.key_acceptable(key)
    _ed25519_rule.signature_encoding_acceptable(sig)
    assert bytes(sig) == sig_copy and bytes(key) == key_copy


# --- the helpers, every small-order encoding one by one ---------------------------------


def test_the_14_encodings_are_7_values_with_either_sign_bit() -> None:
    assert len({e[:31] + bytes([e[31] & 0x7F]) for e in SMALL_ORDER}) == 7


@pytest.mark.parametrize("enc", SMALL_ORDER, ids=lambda e: e.hex())
def test_small_order_encoding_is_on_the_list_and_refused_as_key_and_as_r(enc: bytes) -> None:
    s_one = (1).to_bytes(32, "little")  # S = 1 is below L, so only R decides
    assert _ed25519_rule._is_small_order(enc) is True
    assert _ed25519_rule.key_acceptable(enc) is False
    assert _ed25519_rule.signature_encoding_acceptable(enc + s_one) is False
    for wrap in (bytearray, memoryview):
        assert _ed25519_rule._is_small_order(wrap(enc)) is True
        assert _ed25519_rule.signature_encoding_acceptable(wrap(enc + s_one)) is False


def test_an_ordinary_point_is_not_on_the_list() -> None:
    _, raw = _fresh_key()
    assert _ed25519_rule._is_small_order(raw) is False
    assert _ed25519_rule.key_acceptable(raw) is True
    assert _ed25519_rule.signature_encoding_acceptable(raw + (1).to_bytes(32, "little")) is True


# --- signature text rules (shared with the TypeScript and Go SDKs) ----------------------


def _outcome(cert: Any, keys: VerifyCertificateKeys) -> str:
    """verify_certificate as one comparable string."""
    try:
        return "accept:" + str(verify_certificate(cert, keys).signable_version)
    except LucairnCertificateError as exc:
        return "refuse:" + exc.reason


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(which: str) -> tuple[Any, VerifyCertificateKeys]:
    if which == "v2":
        cert = _load(_TS_FIXTURES / "cert-valid-anchored.json")
        key = _load(_TS_FIXTURES / "witness-keypair.json")["publicKey"]
        return cert, VerifyCertificateKeys(witness_key_id="witness_v1", witness_public_key=key)
    cert = _load(_FIXTURES_DIR / "real-v3-cert.fixture.json")
    key_hex = (_FIXTURES_DIR / "production-witness-pubkey.hex").read_text().strip()
    return cert, VerifyCertificateKeys(witness_key_id="witness_v1", witness_public_key=bytes.fromhex(key_hex))


def test_white_space_is_the_go_unicode_isspace_set() -> None:
    blank = _text_rule.is_blank_signature_text
    assert blank("") and blank(None) and blank(chr(0x85))
    assert blank("".join(chr(c) for c in (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2000, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000)))
    for c in (0x1C, 0x1D, 0x1E, 0x1F, 0xFEFF, 0x200B, 0x180E, 0x00, 0x41):
        assert not blank(chr(c))
        assert not blank(" " + chr(c) + " ")


def test_signature_text_must_be_canonical_standard_padded_base64() -> None:
    text = base64.b64encode(bytes([7]) * 64).decode("ascii")
    assert _text_rule.decode_signature_text(text) == bytes([7]) * 64
    assert text.endswith("Bw==")
    nonzero_padding = text[:-3] + "x=="
    assert base64.b64decode(nonzero_padding, validate=True) == bytes([7]) * 64
    for bad in (text[:-2], text + "!", " " + text, text + chr(10), nonzero_padding, chr(0xFEFF)):
        with pytest.raises(ValueError):
            _text_rule.decode_signature_text(bad)


def test_field_vector_coverage() -> None:
    assert len(FIELD_VECTORS) == 76
    ids = {v["id"] for v in FIELD_VECTORS}
    assert {
        "v2_signable_v3_signature_only_u0085",
        "v2_signable_v3_signature_only_ufeff",
        "v2_signable_v3_signature_only_u001c",
        "v3_signable_v3_signature_trailing_bang",
        "v3_signable_v3_signature_nonzero_padding_bits",
    } <= ids


@pytest.mark.parametrize("vector", FIELD_VECTORS, ids=lambda v: v["id"])
def test_shared_certificate_field_vector(vector: dict[str, str]) -> None:
    cert, keys = _base(vector["base"])
    cert[vector["field"]] = vector["text"]
    assert _outcome(cert, keys) == vector["expected"]


# --- corpus cases of the parse layer (copied verbatim; same bytes in the TS and Go folders) ---

_CORPUS_SHA256 = {
    "corpus-tamper_signable_v3_signature_control_char.json": "f2deec7b3549ab30e42a67a29a70c2b566b42528ea6d1c43ffd2da16e4c35bb2",
    "corpus-tamper_protocol_version_float_token.json": "e9a576edf871084cf187832b5e7d9506dc8df26641182f78343cf20517c5b69f",
    "corpus-tamper_protocol_version_oversized_integer.json": "0920687b2cd9b01a68689dd2903045fceebcd06ea9186c19635ef8b6056e2bfb",
}


def test_parse_layer_fixtures_are_the_corpus_files_byte_for_byte() -> None:
    for name, want in _CORPUS_SHA256.items():
        assert hashlib.sha256((_FIXTURES_DIR / name).read_bytes()).hexdigest() == want


def test_v3_signature_holding_only_u001c_is_present_version_downgrade_detected() -> None:
    """``str.strip()`` would strip U+001C and let this certificate verify as
    v2; the shared white-space set does not contain it."""
    case = _load(_FIXTURES_DIR / "corpus-tamper_signable_v3_signature_control_char.json")
    assert case["certificate"]["signable_v3_signature"] == chr(0x1C)
    assert case["expected"]["default"]["reason"] == "version_downgrade_detected"
    assert _outcome(case["certificate"], CORPUS_WITNESS) == "refuse:version_downgrade_detected"


def test_float_token_protocol_version_is_malformed() -> None:
    case = _load(_FIXTURES_DIR / "corpus-tamper_protocol_version_float_token.json")
    assert isinstance(case["certificate"]["protocol_version"], float)
    assert _outcome(case["certificate"], CORPUS_WITNESS) == "refuse:malformed"


def test_oversized_integer_protocol_version() -> None:
    """With default settings the caller's own ``json.loads`` refuses the
    5,000-digit integer before the SDK is called (Python >= 3.11, and the
    3.10 security releases). A caller who raised the integer-digits limit
    gets ``malformed`` from the SDK (was ``unsupported_protocol_version``)."""
    import sys

    text = (_FIXTURES_DIR / "corpus-tamper_protocol_version_oversized_integer.json").read_text(encoding="utf-8")
    if not hasattr(sys, "set_int_max_str_digits"):
        case = json.loads(text)
    else:
        with pytest.raises(ValueError):
            json.loads(text)
        previous = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(0)
        try:
            case = json.loads(text)
        finally:
            sys.set_int_max_str_digits(previous)
    assert case["certificate"]["protocol_version"] > 2**64 - 1
    assert case["expected"]["default"]["reason"] == "malformed"
    assert _outcome(case["certificate"], CORPUS_WITNESS) == "refuse:malformed"


def test_protocol_version_range() -> None:
    cert, keys = _base("v3")
    for bad in (2**64, -1, -2):
        assert _outcome({**cert, "protocol_version": bad}, keys) == "refuse:malformed"
    for other in (0, 3, 2**64 - 1):
        assert _outcome({**cert, "protocol_version": other}, keys) == "refuse:unsupported_protocol_version"


def test_genuine_certificates_with_protocol_version_2_still_verify() -> None:
    for which in ("v2", "v3"):
        cert, keys = _base(which)
        assert cert["protocol_version"] == 2
        assert _outcome(cert, keys) == "accept:" + which


# --- nothing new became public ------------------------------------------------------


def test_no_new_public_name() -> None:
    assert signature_mod.__all__ == ["verify_ed25519"]
    assert not [n for n in lucairn.__all__ if "small_order" in n.lower() or "acceptable" in n.lower()]
    assert _ed25519_rule.__all__ == [] and _text_rule.__all__ == []
