"""Certificate chain verification (T-935 S3 / T-794) — every inner claim.

:func:`verify_certificate` checks the witness signatures only: a certificate
whose claim body was edited while its claim id stayed the same still passes it,
because the witness signs the claim-id LIST, not the claim content. This module
adds the layer on top: every claim's own Ed25519 signature against a PINNED
per-service key, the claim's canonical bytes rebuilt from its outer fields,
claim-id membership in the witness-signed list, the typed (unsigned) mirrors
against the signed payload, the signed egress digests, the unsigned
``cert_tier`` against its signed copies, and the ``user_unredacted_segment``
token read from the SIGNED sanitizer payload only.

The specification is the parity corpus README (Declade/dual-sandbox-architecture
``tools/parity-corpus/README.md``; its ordered check table is vendored at
``testdata/parity-corpus/recipe-table.md``)
§ Verification recipe. The steps below carry its step ids; the TS and Go SDKs
implement the same table and all three are held to the same 54-case corpus
under both policies (``python/tests/test_parity_corpus.py``).

Labelling MUST (README § Result): every entry of
``CertificateChainResult.unauthenticated_fields`` is UNVERIFIED — show it as
unverified wherever it is displayed and never base a decision on it. Only
``verdict == "VERIFIED"`` is green; ``EGRESS_UNATTESTED`` never is.
"""

from __future__ import annotations

import base64
import binascii
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

from lucairn.verify_certificate.keys import normalize_ed25519_public_key

__all__ = [
    "CertificateChainKeys",
    "CertificateChainResult",
    "verify_certificate_chain",
]


# ---------------------------------------------------------------------------
# Public types.
# ---------------------------------------------------------------------------


@dataclass
class CertificateChainKeys:
    """The pinned trust roots for :func:`verify_certificate_chain`.

    Attributes:
        witness_key_id: the witness ``key_id`` the certificate must name.
        witness_public_key: raw 32-byte Ed25519 key or its base64 string.
        service_public_keys: ``{service_id: key}`` — raw 32-byte Ed25519 keys
            or base64 strings, one per service that emits claims in the
            deployment (e.g. ``dsa-sanitizer``, ``dsa-ai``, ``dsa-gateway``,
            ``dsa-bridge``, ``dsa-audit``, ``dsa-reid-guard``). A claim from a
            service with no pinned key FAILS the certificate
            (``unknown_service``); it is never skipped.
    """

    witness_key_id: str
    witness_public_key: bytes | str
    service_public_keys: Mapping[str, bytes | str] = field(default_factory=dict)


@dataclass(frozen=True)
class CertificateChainResult:
    """README § Result — the field names and values are the corpus's.

    Attributes:
        verdict: ``FAILED`` < ``PARTIAL`` < ``EGRESS_UNATTESTED`` <
            ``VERIFIED``; only ``VERIFIED`` is green.
        reason: the reason of the recipe step that decided.
        egress_attestation: ``signed_digests`` | ``unattested`` |
            ``not_evaluated`` (every FAILED result).
        user_unredacted: the STRING ``"true"`` | ``"false"`` | ``"unknown"``
            (every FAILED result). Compare to ``"true"``, never by truthiness.
            Read from the verified, signed sanitizer payload only.
        signed_cert_tier: ``absent`` | ``input_shield`` | ``inconsistent`` |
            ``not_evaluated``. Show THIS tier, never the unsigned
            ``verification.cert_tier``.
        signable_version: ``v3`` | ``v2`` | ``none``.
        authenticated_fields: the witness-signable keys that authenticated the
            certificate metadata (sorted).
        unauthenticated_fields: fields NO signature covers (sorted). Every
            entry MUST be labelled unverified wherever it is displayed and
            MUST NEVER be the basis of a decision.
    """

    verdict: str
    reason: str
    egress_attestation: str
    user_unredacted: str
    signed_cert_tier: str
    signable_version: str
    authenticated_fields: list[str]
    unauthenticated_fields: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "egress_attestation": self.egress_attestation,
            "user_unredacted": self.user_unredacted,
            "signed_cert_tier": self.signed_cert_tier,
            "signable_version": self.signable_version,
            "authenticated_fields": list(self.authenticated_fields),
            "unauthenticated_fields": list(self.unauthenticated_fields),
        }


# ---------------------------------------------------------------------------
# The ordered check list (README § Verification recipe, recipe-table).
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

_V2_FIELDS = ("certificate_id", "claim_ids", "issued_at", "overall_verdict", "protocol_version", "request_id", "witness_key_id")
_V3_ONLY = ("api_key_id", "byok_exempt", "client_id", "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash")
_DISPLAYED_V3_ONLY = ("api_key_id", "byok_exempt", "client_id")
_TOKEN = "user_unredacted_segment"
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
# Step 7i "unauthenticated typed fields": bound only while the signed key
# carries this JSON type.
_CONDITIONAL_TYPED = (
    ("inference", "isolation_probe", "string"),
    ("inference", "model_used", "string"),
    ("sanitizer", "pii_entities_found", "number"),
    ("bridge", "token_hash", "string"),
    ("bridge", "encryption_enabled", "boolean"),
    ("audit", "chain_head_hash", "string"),
    ("audit", "chain_length", "number"),
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_INT_TOKEN = re.compile(r"0|[1-9][0-9]*")
_INT_MAX_DIGITS = 20  # len(str(2**64 - 1)); decided BEFORE int()
_TIMESTAMP = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|([+-])(\d\d):(\d\d))",
    re.ASCII,
)
# Nesting bound (containers inside strings do not count). The same bound is
# enforced in the TS and Go SDKs so all three decide deep documents alike;
# real certificates nest fewer than 10 levels.
MAX_DEPTH = 256
# Go's unicode.IsSpace set (the witness is Go): step 4's "non-blank".
_GO_SPACE = " \t\n\v\f\r\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
_SURROGATE = re.compile("[\ud800-\udfff]")
# A JSON string (skipped whole) or one bracket.
_DEPTH_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]', re.DOTALL)
_U32 = 2**32 - 1
_U64 = 2**64 - 1


# ---------------------------------------------------------------------------
# JSON with number lexemes kept (README § Canonical JSON).
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


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _depth_ok(text: str) -> bool:
    """At most MAX_DEPTH nested arrays/objects (brackets inside strings skipped)."""
    depth = 0
    for m in _DEPTH_TOKEN.finditer(text):
        t = m.group()
        if t in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif t in "]}":
            depth -= 1
    return True


def _fix_surrogates(v: Any) -> Any:
    """An escaped UTF-16 surrogate that is not part of a pair becomes U+FFFD,
    exactly as Go's encoding/json (the witness) decodes it. Python's json
    already joins valid pairs, so any surrogate left in a str is unpaired."""
    if isinstance(v, str):
        return _SURROGATE.sub("\ufffd", v) if _SURROGATE.search(v) else v
    if isinstance(v, list):
        return [_fix_surrogates(x) for x in v]
    if isinstance(v, dict):
        return {_fix_surrogates(k): _fix_surrogates(x) for k, x in v.items()}
    return v


def _loads(data: bytes | str) -> Any:
    """README § Input document: UTF-8 without BOM, exactly one JSON value,
    only JSON whitespace after it, no NaN / Infinity; at most MAX_DEPTH
    levels; unpaired surrogate escapes read as U+FFFD."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data).decode("utf-8")  # strict: invalid UTF-8 raises
    if not _depth_ok(data):
        raise ValueError("nesting too deep")
    return _fix_surrogates(json.loads(data, parse_int=_Num, parse_float=_Num, parse_constant=_no_constant))


def _canonical(v: Any) -> str:
    """Python ``json.dumps(sort_keys=True, separators=(",", ":"),
    ensure_ascii=True)`` with number lexemes kept."""
    if isinstance(v, _Num):
        return v.text
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=True)
    if isinstance(v, list):
        return "[" + ",".join(_canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=True) + ":" + _canonical(v[k]) for k in sorted(v)) + "}"
    raise TypeError(type(v))


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
        if math.isinf(d):
            return None
        return struct.unpack("<f", struct.pack("<f", d))[0]
    except (OverflowError, ValueError):
        return None


def _rfc3339nano_utc(s: str) -> str | None:
    """Step 5a: the ONE timestamp grammar, then the UTC RFC3339Nano form."""
    m = _TIMESTAMP.fullmatch(s)
    if not m:
        return None
    year, month, day, hour, minute, second, frac, _tz, sign, oh, om = m.groups()
    if sign and (int(oh) > 23 or int(om) > 59):
        return None
    try:
        dt = _dt.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        if sign:
            dt -= (1 if sign == "+" else -1) * _dt.timedelta(hours=int(oh), minutes=int(om))
    except (ValueError, OverflowError):
        return None
    frac = (frac or "").rstrip("0")
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        + ("." + frac if frac else "")
        + "Z"
    )


def _ed25519_ok(pub: Ed25519PublicKey, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
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
    typed_unauth: list[str] | None = None,
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
            authenticated_fields=[],
            unauthenticated_fields=list(_DISPLAYED_V3_ONLY),
        )
    auth = sorted(_V2_FIELDS + _V3_ONLY) if sv == "v3" else list(_V2_FIELDS)
    unauth = sorted(([] if sv == "v3" else list(_DISPLAYED_V3_ONLY)) + list(typed_unauth or []))
    return CertificateChainResult(
        verdict=verdict,
        reason=reason,
        egress_attestation=egress,
        user_unredacted=user_unredacted,
        signed_cert_tier=tier,
        signable_version=sv,
        authenticated_fields=auth,
        unauthenticated_fields=unauth,
    )


def _sanitizer_hash(claims: list[dict[str, Any]], key: str) -> Any:
    """The FIRST dsa-sanitizer claim's canonical ``payload.payload[key]`` as a
    non-empty string, else None (witness ``sanitizerPayloadString``)."""
    for c in claims:
        if c.get("service_id") != "dsa-sanitizer":
            continue
        cp = _b64(c.get("canonical_payload"))
        if not cp:
            return None
        try:
            outer = _loads(cp)  # the same strict parser as every other read
        except (ValueError, RecursionError):
            return None
        if not isinstance(outer, dict):
            return None
        inner = outer.get("payload") if isinstance(outer.get("payload"), dict) else outer
        val = inner.get(key)
        return val if isinstance(val, str) and val != "" else None
    return None


def _ascii_upper(s: str) -> str:
    return s.translate(_ASCII_UPPER)


_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _qi_verdict(s: str) -> str:
    v = _ascii_upper(s.strip(" \t\n\r\f\v"))
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


def _typed_unbound(i: int, c: dict[str, Any], p: dict[str, Any]) -> list[str]:
    """Step 7i: typed fields present while their signed key is absent, null
    or of another JSON type — bound by nothing, listed as unauthenticated."""
    out = []
    for kind, fld, want in _CONDITIONAL_TYPED:
        if not isinstance(c.get(kind), dict):
            continue
        v = p.get(fld)
        got = (
            "boolean" if isinstance(v, bool)
            else "string" if isinstance(v, str)
            else "number" if isinstance(v, _Num)
            else None
        )
        if got != want:
            out.append(f"claims[{i}].{kind}.{fld}")
    return out


def _cert_tier_check(
    claims: list[dict[str, Any]], canon: list[dict[str, Any]], unsigned: str, sealed: str
) -> tuple[str, bool, bool]:
    """Step 8d → (signed tier, the unsigned label passes, capped at
    EGRESS_UNATTESTED by fix A)."""
    carriers = [(c["service_id"], p["cert_tier"]) for c, p in zip(claims, canon) if "cert_tier" in p]
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
        self.witness_key_id = keys.witness_key_id
        self.witness = Ed25519PublicKey.from_public_bytes(normalize_ed25519_public_key(keys.witness_public_key))
        if not isinstance(keys.service_public_keys, Mapping):
            raise TypeError("CertificateChainKeys.service_public_keys must be a mapping {service_id: key}")
        self.services: dict[str, Ed25519PublicKey] = {}
        for svc, key in keys.service_public_keys.items():
            if not isinstance(svc, str) or svc == "":
                raise TypeError("service_public_keys keys must be non-empty service_id strings")
            self.services[svc] = Ed25519PublicKey.from_public_bytes(normalize_ed25519_public_key(key))


def verify_certificate_chain(
    certificate: bytes | str,
    keys: CertificateChainKeys,
    *,
    minimum_signable_version: str | None = None,
) -> CertificateChainResult:
    """Verify a Lucairn certificate AND every claim inside it.

    Runs README § Verification recipe (steps 1–9e) of the parity corpus and
    returns a :class:`CertificateChainResult`. Certificate problems never
    raise: they are a ``FAILED`` verdict with the deciding step's reason.

    Args:
        certificate: the certificate JSON exactly as received — the raw body
            of ``GET /api/v1/veil/certificate/{id}`` (or a witness export), as
            UTF-8 ``bytes`` or ``str``. Pass the raw text, not a parsed
            ``dict``: integer tokens, float lexemes and trailing data are
            part of the checks.
        keys: the pinned witness key and per-service claim keys.
        minimum_signable_version: ``None`` / ``"v2"`` (policy ``default``,
            accepts legacy v2-only certificates — their v3-only fields are
            then listed in ``unauthenticated_fields``) or ``"v3"`` (policy
            ``minimum_v3``: a certificate that authenticates only through the
            v2 signable FAILS ``signable_version_insufficient``).

    Raises:
        TypeError / ValueError: programmer errors only — a malformed key set
            or an unknown ``minimum_signable_version``.
    """

    if minimum_signable_version not in (None, "v2", "v3"):
        raise ValueError(f"minimum_signable_version must be None, 'v2' or 'v3', got {minimum_signable_version!r}")
    if not isinstance(certificate, (bytes, bytearray, memoryview, str)):
        raise TypeError(
            "certificate must be the raw certificate JSON as bytes or str, got "
            f"{type(certificate).__name__}"
        )
    pinned = _PinnedKeys(keys)
    return _verify(certificate, pinned, minimum_signable_version == "v3")


def _verify(cert_json: bytes | str, keys: _PinnedKeys, min_v3: bool) -> CertificateChainResult:
    # 1. Shape.
    try:
        cert = _loads(cert_json)
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
    # 4. Signable-version tri-state.
    v3present = v3sig.strip(_GO_SPACE) != ""
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
    # 5d. Policy.
    if min_v3 and sv != "v3":
        return _outcome("5d")
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
    typed_unauth: list[str] = []
    for i, c in enumerate(claims):
        svc = c["service_id"]
        pub = keys.services.get(svc)
        if pub is None:
            return _outcome("7a")
        cp, sig = _b64(c.get("canonical_payload")), _b64(c.get("signature"))
        if cp is None or sig is None:
            return _outcome("7b")
        own = _ed25519_ok(pub, cp, sig)
        if not own and any(_ed25519_ok(k, cp, sig) for s, k in keys.services.items() if s != svc):
            return _outcome("7c")
        if not own:
            return _outcome("7d")
        try:
            cm = _loads(cp)
        except (ValueError, RecursionError):
            return _outcome("7e")
        if not isinstance(cm, dict):
            return _outcome("7e")
        if not isinstance(cm.get("claim_id"), str) or cm["claim_id"] not in listed:
            return _outcome("7f")
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
        if cm.get("request_id") != cert["request_id"]:
            return _outcome("7h")
        payload = cm.get("payload") if isinstance(cm.get("payload"), dict) else {}
        if not _typed_bound(c, claim_type, payload):
            return _outcome("7i")
        typed_unauth += _typed_unbound(i, c, payload)
        canon.append(payload)

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

    def done(step: str) -> CertificateChainResult:
        return _outcome(step, egress, sv, user_unredacted, tier, typed_unauth)

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
