"""Input rules of the witness-only verify_certificate that all three SDKs
share (the parity corpus is the reference):

- ONE whitespace set (Go's unicode.IsSpace) for every blank / present test;
- a signature text is canonical standard padded base64, else invalid_signature;
- protocol_version / signable_protocol_version_emitted are integers in
  [0, 2**64 - 1], else malformed.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from lucairn.errors import LucairnCertificateError
from lucairn.types import VerifyCertificateKeys
from lucairn.verify_certificate import chain as chain_mod
from lucairn.verify_certificate import pipeline as pipeline_mod
from lucairn.verify_certificate import (
    derive_v3_signed_bytes,
    derive_witness_signed_bytes,
    parse_certificate,
    verify_certificate,
)

CORPUS = Path(__file__).resolve().parents[2] / "testdata" / "parity-corpus" / "v1"
KEYS = json.loads((CORPUS / "keys.json").read_text())
WITNESS = VerifyCertificateKeys(
    witness_key_id=KEYS["witness"]["key_id"],
    witness_public_key=KEYS["witness"]["public_key_base64"],
)


def _case_text(case_id: str) -> str:
    return (CORPUS / "cases" / f"{case_id}.json").read_text(encoding="utf-8")


def _v3() -> dict[str, Any]:
    return json.loads(_case_text("honest_full_chain_egress"))["certificate"]


def _v2() -> dict[str, Any]:
    return json.loads(_case_text("legacy_v2_signable_only"))["certificate"]


def _outcome(cert: Any) -> str:
    """'ACCEPT:<signable version>' or the refusal reason."""
    try:
        return f"ACCEPT:{verify_certificate(cert, WITNESS).signable_version}"
    except LucairnCertificateError as exc:
        return exc.reason


def _with(cert: dict[str, Any], **fields: Any) -> dict[str, Any]:
    out = copy.deepcopy(cert)
    out.update(fields)
    return out


def test_controls() -> None:
    assert _outcome(_v3()) == "ACCEPT:v3"
    assert _outcome(_v2()) == "ACCEPT:v2"


# --- ONE whitespace set ------------------------------------------------------------


def test_corpus_control_char_case_is_version_downgrade_detected() -> None:
    case = json.loads(_case_text("tamper_signable_v3_signature_control_char"))
    assert case["expected"]["default"]["reason"] == "version_downgrade_detected"
    assert case["certificate"]["signable_v3_signature"] == "\u001c"
    assert _outcome(case["certificate"]) == "version_downgrade_detected"


@pytest.mark.parametrize(
    ("ch", "blank"),
    [
        ("\u001c", False),
        ("\u001d", False),
        ("\u001e", False),
        ("\u001f", False),
        ("\u0085", True),
        ("\ufeff", False),
        ("\u00a0", True),
        ("\u2028", True),
        ("\u200b", False),
        (" ", True),
    ],
    ids=lambda v: f"U+{ord(v):04X}" if isinstance(v, str) else str(v),
)
def test_blank_and_present_use_the_one_whitespace_set(ch: str, blank: bool) -> None:
    # signable_v3_signature on a legacy v2 certificate: blank -> the v2
    # certificate verifies; present -> a v3 signature without the version.
    assert _outcome(_with(_v2(), signable_v3_signature=ch)) == ("ACCEPT:v2" if blank else "version_downgrade_detected")
    # on a v3 certificate: blank -> the v3 signature was stripped; present ->
    # it is decoded and is not a signature.
    assert _outcome(_with(_v3(), signable_v3_signature=ch)) == (
        "version_downgrade_detected" if blank else "invalid_signature"
    )
    # witness_signature: blank -> missing; present -> not a signature.
    assert _outcome(_with(_v2(), witness_signature=ch)) == ("witness_signature_missing" if blank else "invalid_signature")


def test_pipeline_uses_the_chain_whitespace_helper_only() -> None:
    import inspect

    assert pipeline_mod._trim_space is chain_mod._trim_space
    assert pipeline_mod._b64 is chain_mod._b64
    assert "_signature.strip(" not in inspect.getsource(pipeline_mod)


# --- signature text ----------------------------------------------------------------


def _bump_padding_bits(s: str) -> str:
    al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    i = al.index(s[-3])
    assert i % 16 == 0  # 64 bytes: the last data character carries 4 zero bits
    return s[:-3] + al[i + 1] + "=="


def _variants(s: str) -> list[tuple[str, str]]:
    return [
        ("unpadded", s.rstrip("=")),
        ("one pad character removed", s[:-1]),
        ("URL-safe alphabet", s.replace("+", "-").replace("/", "_")),
        ("embedded space", s[:40] + " " + s[40:]),
        ("embedded LF", s[:40] + "\n" + s[40:]),
        ("embedded CR", s[:40] + "\r" + s[40:]),
        ("leading space", " " + s),
        ("trailing space", s + " "),
        ("trailing LF", s + "\n"),
        ("non-zero padding bits", _bump_padding_bits(s)),
        ("trailing '!'", s + "!"),
        ("trailing 'AAAA'", s + "AAAA"),
        ("trailing '===='", s + "===="),
        ("embedded '!'", s[:40] + "!" + s[40:]),
    ]


def test_v3_signature_text_must_be_canonical_base64() -> None:
    base = _v3()
    sig = base["signable_v3_signature"]
    assert "+" in sig or "/" in sig
    for name, text in _variants(sig):
        assert text != sig, name
        assert _outcome(_with(base, signable_v3_signature=text)) == "invalid_signature", name


def test_v2_signature_text_must_be_canonical_base64() -> None:
    base = _v2()
    sig = base["witness_signature"]
    assert "+" in sig or "/" in sig
    for name, text in _variants(sig):
        assert text != sig, name
        assert _outcome(_with(base, witness_signature=text)) == "invalid_signature", name


# --- integers ----------------------------------------------------------------------


def test_corpus_oversized_protocol_version_is_malformed() -> None:
    """Python's default json.loads refuses an integer token of more than 4,300
    digits before the SDK is called; with that limit lifted the SDK itself
    returns malformed."""
    text = _case_text("tamper_protocol_version_oversized_integer")
    old = sys.get_int_max_str_digits()
    if old:
        with pytest.raises(ValueError):
            json.loads(text)
    sys.set_int_max_str_digits(0)
    try:
        case = json.loads(text)
    finally:
        sys.set_int_max_str_digits(old)
    assert case["expected"]["default"]["reason"] == "malformed"
    assert case["certificate"]["protocol_version"] == 10**4999
    assert _outcome(case["certificate"]) == "malformed"


def test_protocol_version_garbage_is_malformed_other_integers_unsupported() -> None:
    for bad in (-1, -2, 2**64, 10**30, 2.0, 2.5, float("inf"), float("nan"), "2", True, None, []):
        assert _outcome(_with(_v3(), protocol_version=bad)) == "malformed", repr(bad)
    for other in (0, 1, 3, 2**32 - 1, 2**53 - 1, 2**64 - 1):
        assert _outcome(_with(_v3(), protocol_version=other)) == "unsupported_protocol_version", other


def test_emitted_number_outside_the_integer_range_is_malformed() -> None:
    for bad in (-1, 2**64, 10**30, 2.5, 3.5, 3.0, 2.0, float("inf"), float("nan")):
        assert _outcome(_with(_v3(), signable_protocol_version_emitted=bad)) == "malformed", repr(bad)
        assert _outcome(_with(_v2(), signable_protocol_version_emitted=bad)) == "malformed", repr(bad)
    # in range: unchanged dispatch
    assert _outcome(_with(_v3(), signable_protocol_version_emitted=4)) == "ACCEPT:v3"
    assert _outcome(_with(_v3(), signable_protocol_version_emitted=2**64 - 1)) == "ACCEPT:v3"
    assert _outcome(_with(_v3(), signable_protocol_version_emitted=2)) == "version_downgrade_detected"
    assert _outcome(_with(_v2(), signable_protocol_version_emitted=3)) == "version_downgrade_detected"
    absent = _v2()
    del absent["signable_protocol_version_emitted"]
    assert _outcome(absent) == "ACCEPT:v2"


def test_corpus_float_token_protocol_version_is_malformed() -> None:
    """json.loads keeps the token 2.0000000000000001 as a float, so Python sees
    that protocol_version was not written as an integer. The signable bytes of
    the parent certificate are untouched by this rule."""
    case = json.loads(_case_text("tamper_protocol_version_float_token"))
    assert case["expected"]["default"]["reason"] == "malformed"
    assert isinstance(case["certificate"]["protocol_version"], float)
    assert _outcome(case["certificate"]) == "malformed"
    parent = parse_certificate(_v3())
    fixed = parse_certificate(_with(case["certificate"], protocol_version=2))
    assert derive_v3_signed_bytes(fixed) == derive_v3_signed_bytes(parent)
    assert derive_witness_signed_bytes(fixed) == derive_witness_signed_bytes(parent)


# --- every present signature field is text-checked ----------------------------------


@pytest.mark.parametrize(
    "text",
    ["\ufeff", "\u001c", "\u001d", "\u001e", "\u001f", "!"],
    ids=lambda v: "+".join(f"U+{ord(c):04X}" for c in v),
)
def test_v3_certificate_witness_signature_must_be_canonical_too(text: str) -> None:
    assert _outcome(_with(_v3(), witness_signature=text)) == "invalid_signature"


def test_v3_certificate_witness_signature_with_trailing_text() -> None:
    base = _v3()
    assert _outcome(_with(base, witness_signature=base["witness_signature"] + "!")) == "invalid_signature"


def test_missing_and_downgrade_are_decided_before_any_text_check() -> None:
    assert _outcome(_with(_v3(), witness_signature="")) == "witness_signature_missing"
    assert _outcome(_with(_v3(), witness_signature="\u0085")) == "witness_signature_missing"
    assert _outcome(_with(_v2(), signable_v3_signature="\u0085")) == "ACCEPT:v2"
    assert _outcome(_with(_v2(), signable_v3_signature="\u001c")) == "version_downgrade_detected"
    assert _outcome(_with(_v2(), signable_v3_signature="!")) == "version_downgrade_detected"
    assert _outcome(_with(_v3(), signable_v3_signature="", witness_signature="!")) == "version_downgrade_detected"


# --- the two version fields: one value rule, before any coercion ---------------------

_EMITTED = [
    # (value, outcome on the v3 certificate, outcome on the legacy v2 certificate)
    (3.5, "malformed", "malformed"),
    ("3", "malformed", "malformed"),
    ([3], "malformed", "malformed"),
    (True, "malformed", "malformed"),
    ("garbage", "malformed", "malformed"),
    ({}, "malformed", "malformed"),
    (-1, "malformed", "malformed"),
    (3.0, "malformed", "malformed"),
    (float("nan"), "malformed", "malformed"),
    (float("inf"), "malformed", "malformed"),
    (2**64, "malformed", "malformed"),
    (None, "version_downgrade_detected", "ACCEPT:v2"),
    (3, "ACCEPT:v3", "version_downgrade_detected"),
    (2, "version_downgrade_detected", "ACCEPT:v2"),
    (0, "version_downgrade_detected", "ACCEPT:v2"),
    (2**53, "ACCEPT:v3", "version_downgrade_detected"),
    (2**64 - 1, "ACCEPT:v3", "version_downgrade_detected"),
]


@pytest.mark.parametrize(("value", "on_v3", "on_v2"), _EMITTED, ids=lambda v: repr(v)[:24])
def test_emitted_value_rule(value: Any, on_v3: str, on_v2: str) -> None:
    assert _outcome(_with(_v3(), signable_protocol_version_emitted=value)) == on_v3
    assert _outcome(_with(_v2(), signable_protocol_version_emitted=value)) == on_v2


def test_emitted_absent() -> None:
    a = _v3()
    del a["signable_protocol_version_emitted"]
    assert _outcome(a) == "version_downgrade_detected"


def test_protocol_version_value_rule() -> None:
    for bad in (-1, -2, 2**64, 3.5, 2.0, "2", [2], True, None):
        assert _outcome(_with(_v3(), protocol_version=bad)) == "malformed", repr(bad)
    assert _outcome(_with(_v3(), protocol_version=3)) == "unsupported_protocol_version"
    assert _outcome(_with(_v3(), protocol_version=0)) == "unsupported_protocol_version"
    assert _outcome(_with(_v3(), protocol_version=2**64 - 1)) == "unsupported_protocol_version"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", -2),
        ("protocol_version", 2**64),
        ("signable_protocol_version_emitted", -1),
        ("signable_protocol_version_emitted", 2**64),
    ],
)
def test_model_input_gets_the_same_domain_check_as_dict_input(field: str, value: int) -> None:
    """A VeilCertificate instance passed directly must not bypass the domain
    check the dict path applies."""
    from lucairn.types import VeilCertificate

    for base in (_v3(), _v2()):
        data = _with(base, **{field: value})
        assert _outcome(data) == "malformed"
        assert _outcome(VeilCertificate.model_validate(data)) == "malformed"
    # in-range values: dict and model agree
    for base in (_v3(), _v2()):
        assert _outcome(VeilCertificate.model_validate(base)) == _outcome(base)
