"""Certificate chain verification — every inner claim.

:func:`verify_certificate` checks the witness signatures only: a certificate
whose claim body was edited while its claim id stayed the same still passes it,
because the witness signs the claim-id LIST, not the claim content. This module
adds the layer on top: every claim's own Ed25519 signature against a PINNED
per-service key, the claim's canonical bytes rebuilt from its outer fields,
claim-id membership in the witness-signed list, the typed (unsigned) mirrors
against the signed payload, the signed egress digests, the unsigned
``cert_tier`` against its signed copies, the ``user_unredacted_segment`` token
read from the SIGNED sanitizer payload only, and (optionally) the binding of
the certificate to the request the caller expects.

The specification is the Lucairn certificate verifier parity corpus, format
``lucairn-parity-corpus/v1.2`` (its ordered check table is vendored at
``testdata/parity-corpus/recipe-table.md``, its cases at
``testdata/parity-corpus/v1``). The steps below carry the table's step ids;
the TS and Go SDKs implement the same table and all three are held to the
same 79-case corpus under both policies (``python/tests/test_parity_corpus.py``).

Consumer rule: render and decide ONLY from ``CertificateChainResult.verified``
plus ``verdict``, ``reason``, ``egress_attestation``, ``signed_cert_tier``,
``user_unredacted`` and ``request_binding`` — never from the raw certificate
and never from a second parse of it. What is not in ``verified`` is not
verified. Only ``verdict == "VERIFIED"`` is green; ``EGRESS_UNATTESTED``
never is.
"""

from __future__ import annotations

import base64
import binascii
import copy
import datetime as _dt
import hashlib
import json
import math
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "CORPUS_TEST_PUBLIC_KEYS",
    "CertificateChainKeys",
    "CertificateChainResult",
    "MAX_INPUT_BYTES",
    "PinnedKeyError",
    "verify_certificate_chain",
]


# ---------------------------------------------------------------------------
# Public types.
# ---------------------------------------------------------------------------


class PinnedKeyError(ValueError):
    """A pinned key was refused by the pinned-key policy.

    A refused key is a CALLER error, never a certificate verdict.
    :attr:`code` is one of ``key_malformed``, ``key_small_order``,
    ``key_invalid_point``, ``key_test_key`` (checked in that order).
    """

    def __init__(self, code: str, which: str = "") -> None:
        super().__init__(f"pinned key refused ({code})" + (f": {which}" if which else ""))
        self.code = code
        self.which = which


@dataclass
class CertificateChainKeys:
    """The pinned trust roots for :func:`verify_certificate_chain`.

    Every key passes the pinned-key policy when the key set is loaded (each
    call of :func:`verify_certificate_chain`); a refused key raises
    :class:`PinnedKeyError`.

    Attributes:
        witness_key_id: the witness ``key_id`` the certificate must name.
        witness_public_key: the raw 32-byte Ed25519 key, or its canonical
            standard padded base64 (no hex, no URL-safe alphabet, no missing
            padding, no whitespace).
        service_public_keys: ``{service_id: key}``, same key forms, one per
            service that emits claims in the deployment (e.g.
            ``dsa-sanitizer``, ``dsa-ai``, ``dsa-gateway``, ``dsa-bridge``,
            ``dsa-audit``, ``dsa-reid-guard``). A claim from a service with no
            pinned key FAILS the certificate (``unknown_service``); it is
            never skipped.
        allow_test_keys: accept the public parity-corpus TEST keys
            (:data:`CORPUS_TEST_PUBLIC_KEYS`). Their private keys follow from
            a public seed, so a product must never set this; only a parity
            test harness does. Default ``False``.
    """

    witness_key_id: str
    witness_public_key: bytes | str
    service_public_keys: Mapping[str, bytes | str] = field(default_factory=dict)
    allow_test_keys: bool = False


@dataclass(frozen=True)
class CertificateChainResult:
    """The verification result — field names and values are the corpus's.

    Attributes:
        verdict: ``FAILED`` < ``PARTIAL`` < ``EGRESS_UNATTESTED`` <
            ``VERIFIED``; only ``VERIFIED`` is green. This is the verdict to
            display (never ``verified["certificate"]["overall_verdict"]``,
            which is only what the witness sealed).
        reason: the reason of the recipe step that decided.
        egress_attestation: ``signed_digests`` | ``unattested`` |
            ``not_evaluated`` (every FAILED result).
        user_unredacted: the STRING ``"true"`` | ``"false"`` | ``"unknown"``
            (every FAILED result). Compare to ``"true"``, never by truthiness.
            Read from the verified, signed sanitizer payload only.
        signed_cert_tier: ``absent`` | ``input_shield`` | ``inconsistent`` |
            ``input_shield_two_signer`` | ``not_evaluated``. Show THIS tier,
            never the unsigned ``verification.cert_tier``.
            ``input_shield_two_signer`` (an input-shield chain sealed with a
            sanitizer claim and no dsa-ai claim: only the gateway claim signs
            the tier) is an
            SDK-local extension beyond corpus v1.2; it always ends at
            ``EGRESS_UNATTESTED``.
        signable_version: ``v3`` | ``v2`` | ``none``.
        request_binding: ``matched`` (an expected request / certificate id was
            supplied and every supplied value equals the witness-signed one),
            ``not_checked`` (none supplied) or ``not_evaluated`` (every FAILED
            result; a mismatch is FAILED ``request_mismatch``).
        verified: ``None`` on every FAILED result; otherwise the values built
            ONLY from signed bytes::

                {"certificate": {<the witness signable map that verified>},
                 "claims": {"<index>:<service_id>:<claim_type>":
                                {"canonical": "<signed canonical bytes>",
                                 "values": {"<JSON Pointer>": str | bool | int}}}}

            ``certificate`` holds the 7 v2 keys, plus the 6 v3 keys
            (``api_key_id``, ``byok_exempt``, ``client_id``,
            ``redaction_manifest_hash``, ``sanitized_fields_body_hash``,
            ``tms_manifest_hash``) only when the v3 signature verified.
            ``values`` extracts every string, boolean and integer leaf of the
            signed claim document under its RFC 6901 pointer (``null``,
            non-integer numbers and empty containers contribute no entry —
            read those from ``canonical``). Render and decide only from here.
    """

    verdict: str
    reason: str
    egress_attestation: str
    user_unredacted: str
    signed_cert_tier: str
    signable_version: str
    request_binding: str
    verified: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "egress_attestation": self.egress_attestation,
            "user_unredacted": self.user_unredacted,
            "signed_cert_tier": self.signed_cert_tier,
            "signable_version": self.signable_version,
            "request_binding": self.request_binding,
            "verified": copy.deepcopy(self.verified),
        }


# ---------------------------------------------------------------------------
# The ordered check list (recipe table).
# ---------------------------------------------------------------------------

STEPS: tuple[tuple[str, str, str], ...] = (
    ("1", "FAILED", "malformed"),
    ("2", "FAILED", "unsupported_protocol_version"),
    ("3", "FAILED", "witness_key_mismatch"),
    ("4", "FAILED", "version_downgrade_detected"),
    ("5a", "FAILED", "malformed"),
    ("5b", "FAILED", "witness_signature_invalid"),
    ("5c", "FAILED", "witness_signature_invalid"),
    ("5d", "FAILED", "signable_version_insufficient"),
    ("5e", "FAILED", "request_mismatch"),
    ("6a", "FAILED", "sealed_failed"),
    ("6b", "FAILED", "malformed"),
    ("6c", "FAILED", "duplicate_claim_id"),
    ("7a", "FAILED", "unknown_service"),
    ("7b", "FAILED", "malformed"),
    ("7c", "FAILED", "service_key_mismatch"),
    ("7d", "FAILED", "claim_signature_invalid"),
    ("7e", "FAILED", "claim_canonical_mismatch"),
    ("7f", "FAILED", "claim_not_witness_listed"),
    ("7g", "FAILED", "claim_canonical_mismatch"),
    ("7h", "FAILED", "request_id_splice"),
    ("7i", "FAILED", "typed_payload_mismatch"),
    ("8a", "FAILED", "egress_digest_malformed"),
    ("8b", "FAILED", "egress_body_unbound"),
    ("8c", "FAILED", "egress_body_hash_mismatch"),
    ("8d", "FAILED", "cert_tier_mismatch"),
    ("9a", "PARTIAL", "inference_unfinished"),
    ("9b", "PARTIAL", "user_sent_unredacted"),
    ("9c", "PARTIAL", "sealed_partial"),
    ("9d", "EGRESS_UNATTESTED", "egress_unattested"),
    ("9e", "VERIFIED", "ok"),
)
_STEP = {sid: (verdict, reason) for sid, verdict, reason in STEPS}

# Input bounds (corpus manifest `max_input_bytes`, `max_depth`,
# `max_values_pointer_bytes`).
MAX_INPUT_BYTES = 32 << 20  # the certificate input, checked before parsing
MAX_DEPTH = 256  # every array / object counts one; brackets in strings do not
MAX_VALUES_POINTER_BYTES = 64 << 20  # all `values` pointers of one result together

_TOKEN = "user_unredacted_segment"
# Step 8d: the unsigned label a witness writes for an input-shield chain
# sealed with only the sanitizer and gateway claims (no dsa-ai claim). Not in
# corpus v1.2; see _cert_tier_check.
_TWO_SIGNER_TIER = "input_shield_two_signer"
_CLAIM_TYPES = {
    "CLAIM_TYPE_TOKEN_GENERATED": "TOKEN_GENERATED",
    "CLAIM_TYPE_PII_SANITIZED": "PII_SANITIZED",
    "CLAIM_TYPE_INFERENCE_COMPLETED": "INFERENCE_COMPLETED",
    "CLAIM_TYPE_EVENTS_RECORDED": "EVENTS_RECORDED",
}
# Step 7i: the typed object each named claim type carries, and the SIGNED keys
# whose presence requires it.
_TYPED_KINDS = {
    "TOKEN_GENERATED": ("bridge", ("token_hash", "encryption_enabled")),
    "PII_SANITIZED": ("sanitizer", ("pii_entities_found", "layers_active", "qi_score")),
    "INFERENCE_COMPLETED": ("inference", ("response_hash", "isolation_probe", "model_used", "inference_outcome")),
    "EVENTS_RECORDED": ("audit", ("chain_head_hash", "chain_length")),
}
_PROBE = {
    "VERIFIED": "ISOLATION_PROBE_VERIFIED",
    "BREACHED": "ISOLATION_PROBE_BREACHED",
    "LOCKED": "ISOLATION_PROBE_LOCKED",
    "BYOK_EXEMPT": "ISOLATION_PROBE_BYOK_EXEMPT",
}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_INT_TOKEN = re.compile(r"0|[1-9][0-9]*")
_INT_MAX_DIGITS = 20  # len(str(2**64 - 1)); decided BEFORE int()
_TIMESTAMP = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|([+-])(\d\d):(\d\d))",
    re.ASCII,
)
# The ONE whitespace set (Go's unicode.IsSpace): step 4's "non-blank" and the
# step-7i qi_score verdict trim. Not U+001C-U+001F (which str.strip() would
# also remove), not U+200B.
_RECIPE_SPACE = "".join(
    map(
        chr,
        [
            0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x85, 0xA0, 0x1680,
            0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
            0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        ],
    )
)
_SURROGATE = re.compile("[" + chr(0xD800) + "-" + chr(0xDFFF) + "]")
# A JSON string (skipped whole) or one bracket: the depth scan.
_DEPTH_TOKEN = re.compile(r'"(?:[^"\\]+|\\.)*"?|[\[\]{}]', re.DOTALL)
_U32 = 2**32 - 1
_U64 = 2**64 - 1

# The case-variant key rule: every key the recipe reads anywhere in the
# certificate document or in the signed bytes.
_SPEC_KEYS = frozenset(
    [
        # certificate
        "certificate_id", "request_id", "witness_key_id", "issued_at", "protocol_version", "claims",
        "verification", "signable_protocol_version_emitted", "witness_signature", "signable_v3_signature",
        "client_id", "api_key_id",
        # verification
        "overall_verdict", "cert_tier", "byok_exempt",
        # claims[]
        "claim_id", "service_id", "claim_type", "canonical_payload", "signature", "data_seen", "data_not_seen",
        "bridge", "sanitizer", "inference", "audit",
        # typed objects
        "isolation_probe", "model_used", "response_hash", "upstream_request_bodies",
        "pii_entities_found", "layers_active", "qi_score",
        "k_anonymity", "l_diversity", "risk_score", "threshold", "verdict", "fields_generalized",
        "token_hash", "encryption_enabled", "chain_head_hash", "chain_length",
        # signed bytes (steps 5c, 7e-7i, 8, 9)
        "payload", "timestamp", "upstream_body_sha256", "inference_outcome",
        "redaction_manifest_hash", "sanitized_fields_hash", "tms_manifest_hash",
    ]
)
# Fold: ASCII A-Z -> a-z, U+212A KELVIN SIGN -> k, U+017F LATIN SMALL LETTER
# LONG S -> s (the only non-ASCII letters whose Unicode simple case folding
# reaches an ASCII letter; Go's encoding/json matches struct fields that way).
_FOLD = {**{c: c + 32 for c in range(0x41, 0x5B)}, 0x212A: ord("k"), 0x017F: ord("s")}
_ASCII_UPPER = {c: c - 32 for c in range(0x61, 0x7B)}


def _proto_json_name(name: str) -> str:
    """The protojson JSON name protoc derives from a field name: every ``_``
    dropped and the lower-case ASCII letter after it upper-cased."""
    out, under = [], False
    for c in name:
        if c != "_":
            out.append(c.upper() if under and "a" <= c <= "z" else c)
        under = c == "_"
    return "".join(out)


# Each spec key and its protojson JSON name, folded: a key that folds to one
# of these without being a spec key is refused.
_SPEC_FOLDED = frozenset(
    [k.translate(_FOLD) for k in _SPEC_KEYS] + [_proto_json_name(k).translate(_FOLD) for k in _SPEC_KEYS]
)

# Ed25519 curve constants.
_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
# The small-order y values (little-endian, top bit of byte 31 cleared) — the
# libsodium blocklist: 0, 1, p-1, p, p+1 and the two order-8 values. With the
# sign bit either way: the 8 canonical small-order encodings plus 6
# non-canonical ones.
_SMALL_ORDER_Y = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)

#: The public keys of the verifier parity corpus (witness, the seven service
#: keys and the two keys that sign tamper cases). They are TEST keys derived
#: from a public seed, so anyone can sign with them: a key set that pins one
#: is refused (``key_test_key``) unless ``allow_test_keys`` is set.
CORPUS_TEST_PUBLIC_KEYS: frozenset[str] = frozenset(
    [
        "DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc=",  # witness
        "CEYOK2jlNGFq+qO34Lsv1J683D6o0xP7/zh8CExSEPw=",  # dsa-ai
        "g34bEFHw7VjKYrRbblIGfjR7vktJDyqrf5xJfLHTyJE=",  # dsa-audit
        "l4pxgBHACNYoETbJISAgKf2GFv32LsF44RZ+5CXsbmk=",  # dsa-bridge
        "QfwIjbzb5aYQsBsrp+1dhyh5XeO/wRokwWcQxfgvSc8=",  # dsa-gateway
        "ufi3DjW9XlboFkOiQiDHRFZpDFpvPgxZCw516lNr7Kg=",  # dsa-reid-guard
        "tS+sf+14i1H/qJLJcrNvIvg2B5iJQ2KMXQhirCKsKLs=",  # dsa-sanitizer
        "XF4RayFQtg/k+NkMnsSnlrA/mEgv63vRzi6GKrSSQzY=",  # dsa-sanitizer-streaming
        "/eReR5ZWs84YMcnJkk7lNr1iOetpZXTaPIy/EERjio0=",  # not pinned (unknown-service case)
        "9oGMdHYHc5/aVzMjYZkLNdXqKsNR1A5aNp8bmSdd1Aw=",  # not pinned (rogue signer)
    ]
)
_CORPUS_TEST_KEY_BYTES = frozenset(base64.b64decode(k) for k in CORPUS_TEST_PUBLIC_KEYS)


# ---------------------------------------------------------------------------
# JSON with number lexemes kept (canonical JSON: numbers keep their lexeme).
# ---------------------------------------------------------------------------


class _Num:
    """A JSON number kept as its source lexeme (``0.0`` stays ``0.0``)."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Num) and other.text == self.text

    def __hash__(self) -> int:
        return hash(self.text)

    def __repr__(self) -> str:
        return f"_Num({self.text})"


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")  # NaN / Infinity / -Infinity


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Objects: a key that repeats — compared AFTER escape decoding, code
    point for code point, no normalisation or case folding — is refused."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _depth_ok(text: str) -> bool:
    """At most MAX_DEPTH nested arrays/objects (brackets inside strings skipped)."""
    depth = 0
    for m in _DEPTH_TOKEN.finditer(text):
        t = m.group()
        if t == "[" or t == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif t == "]" or t == "}":
            depth -= 1
    return True


def _has_surrogate(v: Any) -> bool:
    """json joins every escaped high + low pair; any surrogate code point left
    in a key or string was escaped unpaired (strict UTF-8 decoding refuses raw
    ones)."""
    stack = [v]  # explicit stack: never depends on the caller's stack depth
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            if _SURROGATE.search(x) is not None:
                return True
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            for k, y in x.items():
                if _SURROGATE.search(k) is not None:
                    return True
                stack.append(y)
    return False


def _loads(data: bytes | bytearray | memoryview | str) -> Any:
    """The ONE strict document parser (certificate, signed bytes, v3
    sanitizer-hash lookup): UTF-8 without BOM, at most MAX_DEPTH levels,
    exactly one JSON value followed only by JSON whitespace, no NaN /
    Infinity, no duplicate key (after escape decoding), no unpaired surrogate
    escape (refused, never repaired). Raises ValueError."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data).decode("utf-8")  # strict: invalid UTF-8 raises
    if not _depth_ok(data):
        raise ValueError("nesting too deep")
    v = json.loads(
        data,
        parse_int=_Num,
        parse_float=_Num,
        parse_constant=_no_constant,
        object_pairs_hook=_unique_pairs,
    )
    if _has_surrogate(v):
        raise ValueError("unpaired surrogate escape")
    return v


def _case_variant_key(v: Any) -> bool:
    """A key, at any depth, that is not a spec key but folds to a spec key or
    to a spec key's protojson JSON name."""
    stack = [v]  # explicit stack: never depends on the caller's stack depth
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            for k, y in x.items():
                if k not in _SPEC_KEYS and k.translate(_FOLD) in _SPEC_FOLDED:
                    return True
                stack.append(y)
        elif isinstance(x, list):
            stack.extend(x)
    return False


def _load_certificate(data: bytes) -> Any:
    """Step 1's document rule: the size bound (before any parsing), the
    document grammar, the case-variant key rule."""
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input larger than MAX_INPUT_BYTES")
    v = _loads(data)
    if _case_variant_key(v):
        raise ValueError("a key differs from a spec key only in case or spelling")
    return v


def _canonical(v: Any) -> str:
    """Python ``json.dumps(sort_keys=True, separators=(",", ":"),
    ensure_ascii=True)`` with number lexemes kept. Iterative (an explicit
    stack), so the result never depends on the caller's stack depth."""
    out: list[str] = []
    # Work items: (True, literal text) or (False, value still to render).
    stack: list[tuple[bool, Any]] = [(False, v)]
    while stack:
        lit, x = stack.pop()
        if lit:
            out.append(x)
        elif isinstance(x, _Num):
            out.append(x.text)
        elif x is None:
            out.append("null")
        elif x is True:
            out.append("true")
        elif x is False:
            out.append("false")
        elif isinstance(x, int):
            out.append(str(x))
        elif isinstance(x, str):
            out.append(json.dumps(x, ensure_ascii=True))
        elif isinstance(x, list):
            out.append("[")
            stack.append((True, "]"))
            for i in range(len(x) - 1, -1, -1):
                stack.append((False, x[i]))
                if i:
                    stack.append((True, ","))
        elif isinstance(x, dict):
            out.append("{")
            stack.append((True, "}"))
            keys = sorted(x)
            for i in range(len(keys) - 1, -1, -1):
                stack.append((False, x[keys[i]]))
                stack.append((True, ("," if i else "") + json.dumps(keys[i], ensure_ascii=True) + ":"))
        else:
            raise TypeError(type(x))
    return "".join(out)


def _b64(v: Any) -> bytes | None:
    """CANONICAL standard padded base64 (step 7b); absent/null → b''."""
    if v is None:
        return b""
    if not isinstance(v, str) or not _B64.fullmatch(v):
        return None
    try:
        raw = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw).decode("ascii") == v else None


def _str_list(v: Any) -> list[str] | None:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        return None
    return v


def _opt_str(v: Any) -> tuple[str, bool]:
    if v is None:
        return "", True
    return (v, True) if isinstance(v, str) else ("", False)


def _uint_token(text: str, maximum: int) -> int | None:
    """An integer TOKEN (digits only) in [0, maximum]; the digit count is
    bounded BEFORE conversion, so an oversized token is out of range, never an
    exception."""
    if len(text) > _INT_MAX_DIGITS or not _INT_TOKEN.fullmatch(text):
        return None
    n = int(text)
    return n if n <= maximum else None


def _integer(v: Any, maximum: int) -> int | None:
    """A JSON number written as an integer TOKEN (digits only), in [0, maximum]."""
    return _uint_token(v.text, maximum) if isinstance(v, _Num) else None


def _typed_uint(v: Any) -> int | None:
    """A typed proto integer: a JSON number or (protojson uint64) a decimal
    string; absent/null → 0."""
    if v is None:
        return 0
    if isinstance(v, str):
        return _uint_token(v, _U64)
    return _integer(v, _U64)


def _f32(v: Any, zero_if_absent: bool) -> float | None:
    """A JSON number rounded to float32; out of range never matches."""
    if v is None and zero_if_absent:
        return 0.0
    if not isinstance(v, _Num):
        return None
    try:
        d = float(v.text)
        if math.isinf(d):  # beyond float64 (1e400): out of range, not +Inf
            return None
        return struct.unpack("<f", struct.pack("<f", d))[0]  # OverflowError beyond float32
    except (OverflowError, ValueError):
        return None


def _trim_space(s: str) -> str:
    return s.strip(_RECIPE_SPACE)


def _ascii_upper(s: str) -> str:
    """a-z only: never str.upper() (``"ß".upper()`` is ``"SS"``)."""
    return s.translate(_ASCII_UPPER)


def _rfc3339nano_utc(s: str) -> str | None:
    """Step 5a: the ONE timestamp grammar, then the UTC RFC3339Nano form (the
    only normalisation: offset applied, trailing fraction zeros trimmed)."""
    m = _TIMESTAMP.fullmatch(s)
    if not m:
        return None
    year, month, day, hour, minute, second, frac, _tz, sign, oh, om = m.groups()
    if sign and (int(oh) > 23 or int(om) > 59):
        return None
    try:  # a real date in 0001-9999; hour <= 23, minute and second <= 59
        dt = _dt.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        if sign:
            dt -= (1 if sign == "+" else -1) * _dt.timedelta(hours=int(oh), minutes=int(om))
    except (ValueError, OverflowError):  # OverflowError: the UTC instant leaves 0001-9999
        return None
    frac = (frac or "").rstrip("0")
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        + ("." + frac if frac else "")
        + "Z"
    )


# ---------------------------------------------------------------------------
# Ed25519: the pinned-key policy and the ONE signature acceptance rule.
# ---------------------------------------------------------------------------


def _masked(enc: bytes) -> bytes:
    return enc[:31] + bytes([enc[31] & 0x7F])


def _canonical_curve_point(enc: bytes) -> bool:
    """y (the low 255 bits) < p, some x satisfies -x^2 + y^2 = 1 + d x^2 y^2,
    and the sign bit is clear when that x is 0."""
    y = int.from_bytes(_masked(enc), "little")
    if y >= _ED_P:
        return False
    y2 = y * y % _ED_P
    x2 = (y2 - 1) * pow(_ED_D * y2 + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return not enc[31] & 0x80
    return pow(x2, (_ED_P - 1) // 2, _ED_P) == 1


def _pinned_key(key: Any, allow_test_keys: bool, which: str) -> Ed25519PublicKey:
    """One pinned key through the policy, in order: key_malformed (canonical
    standard padded base64 of exactly 32 bytes, or exactly 32 raw bytes),
    key_small_order, key_invalid_point, key_test_key."""
    if isinstance(key, (bytes, bytearray)):
        raw: bytes | None = bytes(key)
    elif isinstance(key, str):
        raw = _b64(key) if key != "" else None
    else:
        raise TypeError(f"{which}: an Ed25519 public key must be bytes or a base64 string, got {type(key).__name__}")
    if raw is None or len(raw) != 32:
        raise PinnedKeyError("key_malformed", which)
    if _masked(raw) in _SMALL_ORDER_Y:
        raise PinnedKeyError("key_small_order", which)
    if not _canonical_curve_point(raw):
        raise PinnedKeyError("key_invalid_point", which)
    if not allow_test_keys and raw in _CORPUS_TEST_KEY_BYTES:
        raise PinnedKeyError("key_test_key", which)
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:  # pragma: no cover - the checks above are stricter
        raise PinnedKeyError("key_invalid_point", which) from exc


def _ed25519_ok(pub: Ed25519PublicKey, msg: bytes, sig: bytes) -> bool:
    """The ONE acceptance rule: a 64-byte R || S with S < L, R the canonical
    encoding (y < p) of a point not of small order, and the cofactorless
    equation (the library compares the encoding of R)."""
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= _ED_L:
        return False
    r = _masked(sig[:32])
    if int.from_bytes(r, "little") >= _ED_P or r in _SMALL_ORDER_Y:
        return False
    try:
        pub.verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Recipe helpers.
# ---------------------------------------------------------------------------


def _outcome(
    step: str,
    egress: str = "",
    sv: str = "none",
    user_unredacted: str = "unknown",
    tier: str = "not_evaluated",
    binding: str = "not_evaluated",
    verified: dict[str, Any] | None = None,
) -> CertificateChainResult:
    verdict, reason = _STEP[step]
    if verdict == "FAILED":
        return CertificateChainResult(
            verdict="FAILED",
            reason=reason,
            egress_attestation="not_evaluated",
            user_unredacted="unknown",
            signed_cert_tier="not_evaluated",
            signable_version="none",
            request_binding="not_evaluated",
            verified=None,
        )
    return CertificateChainResult(
        verdict=verdict,
        reason=reason,
        egress_attestation=egress,
        user_unredacted=user_unredacted,
        signed_cert_tier=tier,
        signable_version=sv,
        request_binding=binding,
        verified=verified,
    )


def _sanitizer_hash(claims: list[dict[str, Any]], key: str) -> Any:
    """Step 5c: the FIRST dsa-sanitizer claim's signed ``payload[key]`` as a
    non-empty string, else None — parsed with the SAME strict document parser
    as every other read; bytes it refuses give None."""
    for c in claims:
        if c.get("service_id") != "dsa-sanitizer":
            continue
        cp = _b64(c.get("canonical_payload"))
        if not cp:
            return None
        try:
            outer = _loads(cp)
        except (ValueError, RecursionError):
            return None
        if not isinstance(outer, dict):
            return None
        inner = outer.get("payload") if isinstance(outer.get("payload"), dict) else outer
        val = inner.get(key)
        return val if isinstance(val, str) and val != "" else None
    return None


def _qi_verdict(s: str) -> str:
    v = _ascii_upper(_trim_space(s))
    return "QI_VERDICT_" + v if v in ("PASS", "GENERALIZED", "BLOCKED") else "QI_VERDICT_UNKNOWN"


def _qi_bound(signed: Any, typed: Any) -> bool:
    if not isinstance(signed, dict):
        return typed is None
    if not isinstance(typed, dict):
        return False
    ka, tka = _integer(signed.get("k_anonymity"), _U32), _typed_uint(typed.get("k_anonymity"))
    if ka is None or tka is None or ka != tka:
        return False
    for k in ("l_diversity", "risk_score", "threshold"):
        sf, tf = _f32(signed.get(k), False), _f32(typed.get(k), True)
        if sf is None or tf is None or sf != tf:
            return False
    sv = signed.get("verdict")
    tv, ok = _opt_str(typed.get("verdict"))
    if not isinstance(sv, str) or not ok or _qi_verdict(sv) != (tv or "QI_VERDICT_UNKNOWN"):
        return False
    sfg = signed.get("fields_generalized")
    if not isinstance(sfg, list):
        return False
    a, b = _str_list(sfg), _str_list(typed.get("fields_generalized"))
    return a is not None and b is not None and a == b


def _typed_bound(c: dict[str, Any], claim_type: str, p: dict[str, Any]) -> bool:
    """Step 7i: the typed (unsigned) mirror agrees with the signed payload."""
    present = ""
    for k in ("bridge", "sanitizer", "inference", "audit"):
        if c.get(k) is None:
            continue
        if not isinstance(c[k], dict) or present:
            return False
        present = k
    kind = _TYPED_KINDS.get(claim_type)
    if present and (kind is None or present != kind[0]):
        return False
    if kind is not None and not present and any(k in p for k in kind[1]):
        return False
    signed_layers = p.get("layers_active")
    if isinstance(signed_layers, list) and _TOKEN in signed_layers and present != "sanitizer":
        return False
    if not present:
        return True
    t = c[present]
    if present == "inference":
        probe, ok = _opt_str(t.get("isolation_probe"))
        if not ok:
            return False
        probe = probe or "ISOLATION_PROBE_UNKNOWN"
        sp = p.get("isolation_probe")
        if isinstance(sp, str):
            if probe != _PROBE.get(sp, "ISOLATION_PROBE_UNKNOWN"):
                return False
        elif probe in ("ISOLATION_PROBE_VERIFIED", "ISOLATION_PROBE_BYOK_EXEMPT"):
            return False
        model, ok = _opt_str(t.get("model_used"))
        if not ok or (isinstance(p.get("model_used"), str) and model != p["model_used"]):
            return False
        rh = _b64(t.get("response_hash"))
        if rh is None:
            return False
        srh = p.get("response_hash")
        if bool(rh) != isinstance(srh, str) or (rh and rh.hex() != srh):
            return False
    elif present == "sanitizer":
        if isinstance(p.get("pii_entities_found"), _Num):
            want, got = _integer(p["pii_entities_found"], _U32), _typed_uint(t.get("pii_entities_found"))
            if want is None or got is None or want != got:
                return False
        typed_layers, signed_list = _str_list(t.get("layers_active")), _str_list(p.get("layers_active"))
        if typed_layers is None or signed_list is None or typed_layers != signed_list:
            return False
        if not _qi_bound(p.get("qi_score"), t.get("qi_score")):
            return False
    elif present == "bridge":
        if isinstance(p.get("encryption_enabled"), bool):
            te = t.get("encryption_enabled")
            if te is not None and not isinstance(te, bool):
                return False
            if bool(te) != p["encryption_enabled"]:
                return False
        if isinstance(p.get("token_hash"), str):
            th = _b64(t.get("token_hash"))
            if th is None or th.hex() != p["token_hash"]:
                return False
    elif present == "audit":
        if isinstance(p.get("chain_head_hash"), str):
            h = _b64(t.get("chain_head_hash"))
            if h is None or h.hex() != p["chain_head_hash"]:
                return False
        if isinstance(p.get("chain_length"), _Num):
            want, got = _integer(p["chain_length"], _U64), _typed_uint(t.get("chain_length"))
            if want is None or got is None or want != got:
                return False
    return True


def _cert_tier_check(
    claims: list[dict[str, Any]], canon: list[dict[str, Any]], unsigned: str, sealed: str
) -> tuple[str, bool, bool]:
    """Step 8d → (signed tier, the unsigned label passes, capped at
    EGRESS_UNATTESTED by fix A)."""
    carriers = [(c["service_id"], p["cert_tier"]) for c, p in zip(claims, canon) if "cert_tier" in p]
    if unsigned == _TWO_SIGNER_TIER:
        # SDK-local extension beyond corpus v1.2 (additive: no corpus case
        # carries this label, so every corpus result is unchanged). An
        # input-shield chain sealed without any dsa-ai claim: exactly ONE
        # signed tier copy, from the gateway claim, a dsa-sanitizer claim
        # (every claim reaching this step passed step 7, so present = valid)
        # and no dsa-ai claim at all. Any other shape with this label is a
        # mismatch. It carries no signed egress digests, so the result is
        # capped at EGRESS_UNATTESTED (never green).
        services = [c["service_id"] for c in claims]
        two_signer = (
            carriers == [("dsa-gateway", "input-shield")]
            and "dsa-sanitizer" in services
            and "dsa-ai" not in services
        )
        if two_signer:
            return _TWO_SIGNER_TIER, True, False
        return "not_evaluated", False, False  # FAILED cert_tier_mismatch reports no tier
    if not carriers:
        signed = "absent"
    elif sorted(carriers, key=lambda x: x[0]) == [("dsa-ai", "input-shield"), ("dsa-gateway", "input-shield")]:
        signed = "input_shield"
    else:
        signed = "inconsistent"
    if unsigned not in ("", "full_chain", "input_shield"):
        return signed, False, False
    if (signed == "absent" and unsigned in ("", "full_chain")) or (signed == "input_shield" and unsigned == "input_shield"):
        return signed, True, False
    if signed == "input_shield" and unsigned == "":
        return signed, True, True
    return signed, sealed == "VERDICT_PARTIAL", False


def _pointer(k: str) -> str:
    """RFC 6901 escaping of one reference token."""
    return k.replace("~", "~0").replace("/", "~1")


def _is_value_leaf(v: Any) -> bool:
    return isinstance(v, (str, bool)) or (isinstance(v, _Num) and _uint_token(v.text, _U64) is not None)


def _values_bytes(v: Any, ptr_len: int, budget: int) -> int:
    """The UTF-8 byte total of the pointers _flatten would write for v (each
    ptr_len bytes so far); stops once the total passes budget, so a document
    built to blow up is never flattened. Iterative (explicit stack)."""
    n = 0
    stack: list[tuple[Any, int]] = [(v, ptr_len)]
    while stack:
        x, pl = stack.pop()
        if isinstance(x, dict):
            for k, y in x.items():
                stack.append((y, pl + 1 + len(_pointer(k).encode("utf-8"))))
        elif isinstance(x, list):
            for i, y in enumerate(x):
                stack.append((y, pl + 1 + len(str(i))))
        elif _is_value_leaf(x):
            n += pl
            if n > budget:
                return n
    return n


def _flatten(v: Any, path: str, out: dict[str, Any]) -> None:
    """``values``: the string / boolean / integer-token leaves of a signed
    document by JSON Pointer (integers as Python ``int``); null, other numbers
    and empty containers contribute nothing. Iterative (explicit stack); the
    result is a dict, so visit order does not matter."""
    stack: list[tuple[Any, str]] = [(v, path)]
    while stack:
        x, p = stack.pop()
        if isinstance(x, dict):
            for k, y in x.items():
                stack.append((y, p + "/" + _pointer(k)))
        elif isinstance(x, list):
            for i, y in enumerate(x):
                stack.append((y, f"{p}/{i}"))
        elif isinstance(x, (str, bool)):
            out[p] = x
        elif isinstance(x, _Num):
            n = _uint_token(x.text, _U64)
            if n is not None:
                out[p] = n


def _plain(v: Any) -> Any:
    """A signable map value with number lexemes turned into Python ints (the
    signable carries only the integer ``protocol_version``)."""
    if isinstance(v, _Num):
        n = _uint_token(v.text, _U64)
        if n is None:  # pragma: no cover - the signable never carries other numbers
            raise TypeError("non-integer number in a signable map")
        return n
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    return v


# ---------------------------------------------------------------------------
# The recipe.
# ---------------------------------------------------------------------------


class _PinnedKeys:
    def __init__(self, keys: CertificateChainKeys) -> None:
        if not isinstance(keys, CertificateChainKeys):
            raise TypeError(
                f"keys must be a CertificateChainKeys instance, got {type(keys).__name__}"
            )
        if not isinstance(keys.witness_key_id, str) or keys.witness_key_id == "":
            raise TypeError("CertificateChainKeys.witness_key_id must be a non-empty string")
        if not isinstance(keys.allow_test_keys, bool):
            raise TypeError("CertificateChainKeys.allow_test_keys must be a bool")
        allow = keys.allow_test_keys
        self.witness_key_id = keys.witness_key_id
        self.witness = _pinned_key(keys.witness_public_key, allow, "witness_public_key")
        if not isinstance(keys.service_public_keys, Mapping):
            raise TypeError("CertificateChainKeys.service_public_keys must be a mapping {service_id: key}")
        self.services: dict[str, Ed25519PublicKey] = {}
        for svc, key in keys.service_public_keys.items():
            if not isinstance(svc, str) or svc == "":
                raise TypeError("service_public_keys keys must be non-empty service_id strings")
            self.services[svc] = _pinned_key(key, allow, f"service_public_keys[{svc!r}]")


def verify_certificate_chain(
    certificate: bytes | str,
    keys: CertificateChainKeys,
    *,
    minimum_signable_version: str | None = None,
    expected_request_id: str | None = None,
    expected_certificate_id: str | None = None,
) -> CertificateChainResult:
    """Verify a Lucairn certificate AND every claim inside it.

    Runs the parity corpus verification recipe (steps 1–9e) and returns a
    :class:`CertificateChainResult`. Certificate problems never raise: they
    are a ``FAILED`` verdict with the deciding step's reason.

    Args:
        certificate: the certificate JSON exactly as received — the raw body
            of ``GET /api/v1/veil/certificate/{id}`` (or a witness export), as
            UTF-8 ``bytes`` or ``str``, at most :data:`MAX_INPUT_BYTES`. Pass
            the raw text, not a parsed ``dict``: integer tokens, float
            lexemes, duplicate keys and trailing data are part of the checks.
        keys: the pinned witness key and per-service claim keys. Every key
            passes the pinned-key policy first (:class:`PinnedKeyError`).
        minimum_signable_version: ``None`` / ``"v2"`` (policy ``default``,
            accepts legacy certificates that carry only the v2 witness
            signature — ``verified["certificate"]`` then holds only the 7 v2
            keys) or ``"v3"`` (policy ``minimum_v3``: a certificate that
            authenticates only through the v2 signable FAILS
            ``signable_version_insufficient``).
        expected_request_id: the request id of the turn this certificate is
            shown for. When supplied it must equal the witness-signed
            ``request_id`` exactly, else FAILED ``request_mismatch``. Always
            pass it when you know the turn: it stops a genuine certificate of
            ANOTHER turn being served for this one (an empty string is a
            supplied value).
        expected_certificate_id: optionally, the certificate id you expect;
            same rule against the witness-signed ``certificate_id``.

    Raises:
        PinnedKeyError: a pinned key was refused (``.code`` says why).
        TypeError / ValueError: other programmer errors — a malformed key
            set, an unknown ``minimum_signable_version``, a non-string
            expected id.
    """

    if minimum_signable_version not in (None, "v2", "v3"):
        raise ValueError(f"minimum_signable_version must be None, 'v2' or 'v3', got {minimum_signable_version!r}")
    if not isinstance(certificate, (bytes, bytearray, memoryview, str)):
        raise TypeError(
            "certificate must be the raw certificate JSON as bytes or str, got "
            f"{type(certificate).__name__}"
        )
    for name, val in (("expected_request_id", expected_request_id), ("expected_certificate_id", expected_certificate_id)):
        if val is not None and not isinstance(val, str):
            raise TypeError(f"{name} must be a string or None, got {type(val).__name__}")
    pinned = _PinnedKeys(keys)
    return _verify(certificate, pinned, minimum_signable_version == "v3", expected_request_id, expected_certificate_id)


def _verify(
    cert_json: bytes | bytearray | memoryview | str,
    keys: _PinnedKeys,
    min_v3: bool,
    exp_req: str | None,
    exp_cert: str | None,
) -> CertificateChainResult:
    # 1. Shape (the input bound, the document grammar, the case-variant rule).
    try:
        if isinstance(cert_json, str):
            if len(cert_json) > MAX_INPUT_BYTES:  # every character is at least one UTF-8 byte
                return _outcome("1")
            data = cert_json.encode("utf-8")  # a lone surrogate: UnicodeEncodeError, a ValueError
        else:
            data = bytes(cert_json)
        cert = _load_certificate(data)
    except (ValueError, RecursionError):
        return _outcome("1")
    if not isinstance(cert, dict):
        return _outcome("1")
    ver = cert.get("verification")
    claims = cert.get("claims")
    pv = _integer(cert.get("protocol_version"), _U32)
    if (
        not all(isinstance(cert.get(k), str) for k in ("certificate_id", "request_id", "witness_key_id", "issued_at"))
        or pv is None
        or not isinstance(claims, list)
        or not claims
        or not isinstance(ver, dict)
        or not isinstance(ver.get("overall_verdict"), str)
    ):
        return _outcome("1")
    unsigned_tier, ok_t = _opt_str(ver.get("cert_tier"))
    byok = ver.get("byok_exempt")
    ok_b = byok is None or isinstance(byok, bool)
    emitted_raw = cert.get("signable_protocol_version_emitted")
    emitted = 0 if emitted_raw is None else _integer(emitted_raw, 2**31 - 1)
    v3sig, ok_v3 = _opt_str(cert.get("signable_v3_signature"))
    ok_rest = all(_opt_str(cert.get(k))[1] for k in ("witness_signature", "client_id", "api_key_id"))
    if not (ok_t and ok_b and emitted is not None and ok_v3 and ok_rest):
        return _outcome("1")
    if not all(
        isinstance(c, dict) and isinstance(c.get("claim_id"), str) and isinstance(c.get("service_id"), str)
        for c in claims
    ):
        return _outcome("1")
    sealed = ver["overall_verdict"]
    claim_ids = [c["claim_id"] for c in claims]

    # 2. Protocol version.
    if pv != 2:
        return _outcome("2")
    # 3. Witness identity.
    if cert["witness_key_id"] != keys.witness_key_id:
        return _outcome("3")
    # 4. Signable-version tri-state ("non-blank" over the ONE whitespace set).
    v3present = _trim_space(v3sig) != ""
    if (emitted >= 3) != v3present:
        return _outcome("4")
    # 5a. issued_at grammar.
    issued = _rfc3339nano_utc(cert["issued_at"])
    if issued is None:
        return _outcome("5a")
    # 5b. v2 witness signature.
    v2 = {
        "certificate_id": cert["certificate_id"],
        "request_id": cert["request_id"],
        "protocol_version": _Num("2"),
        "claim_ids": claim_ids,
        "issued_at": issued,
        "overall_verdict": sealed.removeprefix("VERDICT_"),
        "witness_key_id": cert["witness_key_id"],
    }
    wsig = _b64(cert.get("witness_signature"))
    if not wsig or not _ed25519_ok(keys.witness, _canonical(v2).encode(), wsig):
        return _outcome("5b")
    signable: dict[str, Any] = v2
    # 5c. v3 witness signature.
    sv = "v2"
    if v3present:
        v3 = dict(
            v2,
            client_id=cert.get("client_id"),
            api_key_id=cert.get("api_key_id"),
            byok_exempt=bool(byok),
            redaction_manifest_hash=_sanitizer_hash(claims, "redaction_manifest_hash"),
            sanitized_fields_body_hash=_sanitizer_hash(claims, "sanitized_fields_hash"),
            tms_manifest_hash=_sanitizer_hash(claims, "tms_manifest_hash"),
        )
        sig = _b64(v3sig)
        if sig is None or not _ed25519_ok(keys.witness, _canonical(v3).encode(), sig):
            return _outcome("5c")
        sv = "v3"
        signable = v3
    # 5d. Policy.
    if min_v3 and sv != "v3":
        return _outcome("5d")
    # 5e. Request binding against the witness-signed ids.
    binding = "not_checked"
    if exp_req is not None or exp_cert is not None:
        if (exp_req is not None and exp_req != cert["request_id"]) or (
            exp_cert is not None and exp_cert != cert["certificate_id"]
        ):
            return _outcome("5e")
        binding = "matched"
    # 6. Sealed verdict + claim-id uniqueness.
    if sealed == "VERDICT_FAILED":
        return _outcome("6a")
    if sealed not in ("VERDICT_VERIFIED", "VERDICT_PARTIAL"):
        return _outcome("6b")
    if len(set(claim_ids)) != len(claim_ids):
        return _outcome("6c")
    listed = set(claim_ids)

    # 7. Every claim, in array order.
    canon: list[dict[str, Any]] = []
    verified_claims: dict[str, Any] = {}
    values_total = 0
    for i, c in enumerate(claims):
        svc = c["service_id"]
        # 7a. A pinned key for the service.
        pub = keys.services.get(svc)
        if pub is None:
            return _outcome("7a")
        # 7b. Canonical base64.
        cp, sig = _b64(c.get("canonical_payload")), _b64(c.get("signature"))
        if cp is None or sig is None:
            return _outcome("7b")
        # 7c / 7d. The claim signature under its own service key.
        own = _ed25519_ok(pub, cp, sig)
        if not own and any(_ed25519_ok(k, cp, sig) for s, k in keys.services.items() if s != svc):
            return _outcome("7c")
        if not own:
            return _outcome("7d")
        # 7e. The signed bytes are one strict JSON object, no case-variant
        # spec key, and their values stay within the running pointer bound.
        try:
            cm = _loads(cp)
        except (ValueError, RecursionError):
            return _outcome("7e")
        if not isinstance(cm, dict) or _case_variant_key(cm):
            return _outcome("7e")
        values_total += _values_bytes(cm, 0, MAX_VALUES_POINTER_BYTES - values_total + 1)
        if values_total > MAX_VALUES_POINTER_BYTES:
            return _outcome("7e")
        # 7f. Witness-listed claim id.
        if not isinstance(cm.get("claim_id"), str) or cm["claim_id"] not in listed:
            return _outcome("7f")
        # 7g. Rebuild from the outer fields.
        ds, dns = _str_list(c.get("data_seen")), _str_list(c.get("data_not_seen"))
        outer_req, ok_req = _opt_str(c.get("request_id"))
        if ds is None or dns is None or not ok_req:
            return _outcome("7g")
        claim_type = _CLAIM_TYPES.get(c.get("claim_type"), "") if isinstance(c.get("claim_type"), str) else ""
        try:
            rebuilt = _canonical(
                {
                    "claim_id": c["claim_id"],
                    "request_id": outer_req,
                    "service_id": svc,
                    "claim_type": claim_type,
                    "data_seen": ds,
                    "data_not_seen": dns,
                    "payload": cm.get("payload"),
                    "timestamp": cm.get("timestamp"),
                }
            ).encode()
        except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
            return _outcome("7g")
        if rebuilt != cp:
            return _outcome("7g")
        # 7h. Signed request id.
        if cm.get("request_id") != cert["request_id"]:
            return _outcome("7h")
        # 7i. Typed mirrors.
        payload = cm.get("payload") if isinstance(cm.get("payload"), dict) else {}
        if not _typed_bound(c, claim_type, payload):
            return _outcome("7i")
        canon.append(payload)
        values: dict[str, Any] = {}
        _flatten(cm, "", values)
        verified_claims[f"{i}:{svc}:{claim_type}"] = {"canonical": cp.decode("utf-8"), "values": values}

    # 8a. Signed digest lists.
    digest_claim, digests = -1, []
    for i, (c, p) in enumerate(zip(claims, canon)):
        if (
            c["service_id"] != "dsa-ai"
            or c.get("claim_type") != "CLAIM_TYPE_INFERENCE_COMPLETED"
            or "upstream_body_sha256" not in p
        ):
            continue
        d = p["upstream_body_sha256"]
        if (
            not isinstance(d, list)
            or not d
            or digest_claim >= 0
            or not all(isinstance(x, str) and _HEX64.fullmatch(x) for x in d)
        ):
            return _outcome("8a")
        digest_claim, digests = i, d

    def bodies_of(c: dict[str, Any]) -> list[Any] | None:
        inf = c.get("inference")
        if not isinstance(inf, dict) or inf.get("upstream_request_bodies") is None:
            return []
        b = inf["upstream_request_bodies"]
        return b if isinstance(b, list) else None

    # 8b. Stored bodies only on the digest-carrying claim.
    for i, c in enumerate(claims):
        b = bodies_of(c)
        if b is None or (b and i != digest_claim):
            return _outcome("8b")
    # 8c. Stored bodies hash to the signed digests.
    if digest_claim >= 0:
        bodies = bodies_of(claims[digest_claim]) or []
        if bodies:
            if len(bodies) != len(digests):
                return _outcome("8c")
            for j, body in enumerate(bodies):
                raw = _b64(body)
                if raw is None or hashlib.sha256(raw).hexdigest() != digests[j]:
                    return _outcome("8c")
    # 8d. cert_tier against the signed copies.
    tier, tier_ok, tier_cap = _cert_tier_check(claims, canon, unsigned_tier, sealed)
    if not tier_ok:
        return _outcome("8d")

    egress = "signed_digests" if digest_claim >= 0 else "unattested"
    user_unredacted = (
        "true"
        if any(
            isinstance(p.get("layers_active"), list) and _TOKEN in p["layers_active"]
            for c, p in zip(claims, canon)
            if c["service_id"] in ("dsa-sanitizer", "dsa-sanitizer-streaming")
        )
        else "false"
    )
    verified = {"certificate": _plain(signable), "claims": verified_claims}

    def done(step: str) -> CertificateChainResult:
        return _outcome(step, egress, sv, user_unredacted, tier, binding, verified)

    # 9. Ceilings (first match wins).
    if any("inference_outcome" in p for p in canon):  # key PRESENCE: a signed null counts
        return done("9a")
    if user_unredacted == "true":
        return done("9b")
    if sealed == "VERDICT_PARTIAL":
        return done("9c")
    if egress == "unattested" or tier_cap:
        return done("9d")
    return done("9e")
