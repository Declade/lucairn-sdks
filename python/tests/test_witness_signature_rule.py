"""The witness-only verifier (verify_certificate -> verify_ed25519) applies the
chain verifier's Ed25519 acceptance rule by its own code: a small-order R, a
small-order or non-canonical public key and S >= L are refused whatever
OpenSSL build sits behind ``cryptography``.

Every assertion here is a refusal (or an honest signature verifying), so the
file passes on a runtime whose library already refuses these inputs and on one
whose library accepts them.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import chain as chain_mod
from lucairn.verify_certificate import signature as signature_mod
from lucairn.verify_certificate import verify_certificate, verify_ed25519

CORPUS = Path(__file__).resolve().parents[2] / "testdata" / "parity-corpus" / "v1"
KEYS = json.loads((CORPUS / "keys.json").read_text())
KEY_POLICY = json.loads((CORPUS / "key-policy.json").read_text())
WITNESS = VerifyCertificateKeys(
    witness_key_id=KEYS["witness"]["key_id"],
    witness_public_key=KEYS["witness"]["public_key_base64"],
)

# The 14 small-order encodings, from the vendored key-policy vectors (not from
# the code under test).
SMALL_ORDER = [
    base64.b64decode(v["public_key"]) for v in KEY_POLICY["vectors"] if re.match(r"small_order_\d\d_", v["id"])
]
INVALID_POINTS = [
    base64.b64decode(v["public_key"])
    for v in KEY_POLICY["vectors"]
    if v["id"].startswith("invalid_point_") and v["expected"] == "key_invalid_point"
]

L = 2**252 + 27742317777372353535851937790883648493
BASE_POINT = bytes.fromhex("58" + "66" * 31)

# A fixed TEST key (seed = sha256 of a label), with its secret scalar.
SEED = hashlib.sha256(b"lucairn-sdks python witness-only signature rule").digest()
PRIVATE = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = PRIVATE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_h = bytearray(hashlib.sha512(SEED).digest()[:32])
_h[0] &= 248
_h[31] &= 127
_h[31] |= 64
SCALAR = int.from_bytes(_h, "little")
MESSAGE = b"witness-only signature rule"
HONEST = PRIVATE.sign(MESSAGE)


def _challenge(r: bytes, a: bytes, m: bytes) -> int:
    """k = SHA-512(R || A || M) mod L."""
    return int.from_bytes(hashlib.sha512(r + a + m).digest(), "little") % L


def _case(case_id: str) -> Any:
    return json.loads((CORPUS / "cases" / f"{case_id}.json").read_text(encoding="utf-8"))


def _chain_key(raw: bytes):
    return chain_mod._pinned_key(raw, True, "k")


# --- the corpus case through verify_certificate --------------------------------


def test_corpus_small_order_r_is_refused_as_invalid_signature() -> None:
    honest = verify_certificate(_case("honest_full_chain_egress")["certificate"], WITNESS)
    assert honest.overall_verdict == "VERDICT_VERIFIED"

    case = _case("tamper_witness_signature_small_order_r")
    want = case["expected"]["default"]
    assert (want["verdict"], want["reason"]) == ("FAILED", "witness_signature_invalid")
    with pytest.raises(LucairnCertificateError) as exc:
        verify_certificate(case["certificate"], WITNESS)
    assert exc.value.reason == "invalid_signature"
    with pytest.raises(LucairnCertificateError) as exc:
        verify_certificate(case["certificate"], WITNESS, minimum_signable_version="v3")
    assert exc.value.reason == "invalid_signature"


# --- public-key hardening --------------------------------------------------------


def test_vendored_vectors_hold_the_14_small_order_encodings() -> None:
    assert len(SMALL_ORDER) == len(set(SMALL_ORDER)) == 14
    assert len(INVALID_POINTS) >= 3


@pytest.mark.parametrize("key", SMALL_ORDER, ids=lambda k: k.hex()[:8] + k.hex()[-2:])
def test_small_order_key_is_refused(key: bytes) -> None:
    """R = the base point, S = 1: [S]B = R + [k]A holds for a small-order A
    whenever k is a multiple of 8 — a signature the cofactorless equation
    accepts. Search a message with such a k."""
    sig = BASE_POINT + (1).to_bytes(32, "little")
    msg = next(
        m for m in (b"small-order key %d" % n for n in range(4096)) if _challenge(BASE_POINT, key, m) % 8 == 0
    )
    assert verify_ed25519(msg, sig, key) is False
    assert verify_ed25519(msg, sig, base64.b64encode(key).decode("ascii")) is False
    # the chain verifier refuses the same key when it loads the key set
    with pytest.raises(chain_mod.PinnedKeyError) as exc:
        _chain_key(key)
    assert exc.value.code == "key_small_order"


@pytest.mark.parametrize("key", INVALID_POINTS, ids=lambda k: k.hex()[:8] + k.hex()[-2:])
def test_non_canonical_or_off_curve_key_is_an_invalid_signature(key: bytes) -> None:
    assert verify_ed25519(MESSAGE, HONEST, key) is False
    with pytest.raises(chain_mod.PinnedKeyError) as exc:
        _chain_key(key)
    assert exc.value.code == "key_invalid_point"


def test_malformed_key_still_raises_type_error() -> None:
    for bad in (bytes(31), bytes(33), "not base64!", 7, None):
        with pytest.raises(TypeError):
            verify_ed25519(MESSAGE, bytes(64), bad)  # type: ignore[arg-type]


def test_test_key_refusal_of_the_chain_verifier_is_not_applied() -> None:
    """verify_certificate with the published corpus witness key still verifies
    (the chain verifier refuses that key unless allow_test_keys is set)."""
    assert KEYS["witness"]["public_key_base64"] in chain_mod.CORPUS_TEST_PUBLIC_KEYS
    got = verify_certificate(_case("honest_full_chain_egress")["certificate"], WITNESS)
    assert got.signable_version == "v3"


# --- signature encoding ----------------------------------------------------------


def test_honest_signature_verifies() -> None:
    assert verify_ed25519(MESSAGE, HONEST, PUBLIC) is True
    assert chain_mod._ed25519_ok(_chain_key(PUBLIC), MESSAGE, HONEST) is True


def test_s_not_below_l_is_refused() -> None:
    s_plus_l = int.from_bytes(HONEST[32:], "little") + L
    assert s_plus_l < 2**256
    bad = HONEST[:32] + s_plus_l.to_bytes(32, "little")
    assert verify_ed25519(MESSAGE, bad, PUBLIC) is False
    assert chain_mod._ed25519_ok(_chain_key(PUBLIC), MESSAGE, bad) is False


def test_signature_not_64_bytes_is_refused() -> None:
    for bad in (HONEST[:63], HONEST + b"\x00", b""):
        assert verify_ed25519(MESSAGE, bad, PUBLIC) is False


def test_non_canonical_r_is_refused() -> None:
    # y = p + 3, the encoding of a curve point that is not of small order.
    bad = bytes.fromhex("f0" + "ff" * 30 + "7f") + HONEST[32:]
    assert verify_ed25519(MESSAGE, bad, PUBLIC) is False
    assert chain_mod._ed25519_ok(_chain_key(PUBLIC), MESSAGE, bad) is False


# --- byte containers ---------------------------------------------------------------


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview], ids=["bytes", "bytearray", "memoryview"])
def test_genuine_signature_verifies_in_every_buffer_type(wrap) -> None:
    """A genuine signature given as bytes, bytearray or memoryview verifies
    (the annotation says bytes; the other two worked at runtime before and
    must keep working). The same for the message; the key normaliser takes
    bytes and bytearray."""
    assert verify_ed25519(MESSAGE, wrap(HONEST), PUBLIC) is True
    assert verify_ed25519(wrap(MESSAGE), HONEST, PUBLIC) is True
    assert verify_ed25519(wrap(MESSAGE), wrap(HONEST), PUBLIC) is True
    # and a tampered one is still False, not an exception
    bad = bytearray(HONEST)
    bad[40] ^= 1
    assert verify_ed25519(MESSAGE, wrap(bytes(bad)), PUBLIC) is False
    # a small-order R in any buffer type is refused, not an exception
    assert verify_ed25519(MESSAGE, wrap(SMALL_ORDER[2] + HONEST[32:]), PUBLIC) is False


def test_key_buffer_types_are_unchanged() -> None:
    assert verify_ed25519(MESSAGE, HONEST, bytearray(PUBLIC)) is True
    with pytest.raises(TypeError):
        verify_ed25519(MESSAGE, HONEST, memoryview(PUBLIC))  # type: ignore[arg-type]


def test_chain_rule_takes_every_buffer_type() -> None:
    for wrap in (bytes, bytearray, memoryview):
        assert chain_mod._ed25519_ok(_chain_key(PUBLIC), wrap(MESSAGE), wrap(HONEST)) is True
        assert chain_mod._masked(wrap(SMALL_ORDER[3])) in chain_mod._SMALL_ORDER_Y


# --- drift: ONE rule for the witness-only path and the chain path ------------------


def test_shared_list_is_exactly_the_seven_values_of_the_14_encodings() -> None:
    """Exact list equality against the vendored vectors, and the primitive
    refuses each encoding as R whatever S is. Removing any one of the seven
    entries turns this red (the nonce-0 test below only notices the identity
    entry, because the other constructions fail the equation)."""
    want = {k[:31] + bytes([k[31] & 0x7F]) for k in SMALL_ORDER}
    assert len(want) == 7
    assert chain_mod._SMALL_ORDER_Y == want
    assert signature_mod._SMALL_ORDER_Y == want
    for r in SMALL_ORDER:
        assert chain_mod._masked(r) in signature_mod._SMALL_ORDER_Y
        assert verify_ed25519(MESSAGE, r + HONEST[32:], PUBLIC) is False
    for good in (BASE_POINT, PUBLIC, HONEST[:32]):
        assert chain_mod._masked(good) not in signature_mod._SMALL_ORDER_Y



@pytest.mark.parametrize("r", SMALL_ORDER, ids=lambda k: k.hex()[:8] + k.hex()[-2:])
def test_both_paths_refuse_every_small_order_r(r: bytes) -> None:
    """S = k*a mod L with R the small-order encoding (the nonce-0
    construction): for R = the identity this is the signature a library that
    only checks the equation accepts."""
    s = _challenge(r, PUBLIC, MESSAGE) * SCALAR % L
    sig = r + s.to_bytes(32, "little")
    assert verify_ed25519(MESSAGE, sig, PUBLIC) is False
    assert chain_mod._ed25519_ok(_chain_key(PUBLIC), MESSAGE, sig) is False


def test_witness_only_primitive_uses_the_chain_rule_objects() -> None:
    """Identity, not a copy: the same list, the same point check, the same
    acceptance function — and no library call or list of its own."""
    assert signature_mod._SMALL_ORDER_Y is chain_mod._SMALL_ORDER_Y
    assert signature_mod._canonical_curve_point is chain_mod._canonical_curve_point
    assert signature_mod._ed25519_ok is chain_mod._ed25519_ok
    assert signature_mod._masked is chain_mod._masked
    src = inspect.getsource(signature_mod)
    assert ".verify(" not in src
    assert not re.search(r"[0-9a-f]{64}", src)
    # nothing new became public
    assert signature_mod.__all__ == ["verify_ed25519"]
