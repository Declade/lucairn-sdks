"""Canonical JSON serializer — Python port of the Veil witness signing algorithm.

Byte-identical to:
  dual-sandbox-architecture/pkg/veil/canonical.go
  theveil-sdks/ts/src/verify-certificate/canonical-json.ts

This is NOT RFC 8785 JCS. It is the witness's signing algorithm:
  - recursive sorted keys at every map depth (bytewise UTF-8 sort)
  - leaves through json.dumps(..., ensure_ascii=False, separators=(",", ":"))
    then HTML-safe post-processing to match Go's default json.Marshal
  - Python int emits as integer JSON (e.g. ``2``), preserving Go's
    json.Marshal(int) output. ``float`` is rejected at the boundary to
    prevent accidental float-formatting divergence between languages —
    the Veil signed subset carries no floats.
  - ``bool`` is checked before ``int`` (since ``bool`` subclasses ``int``
    in Python) so ``True``/``False`` emit as ``true``/``false``, not ``1``/``0``.

Output: zero whitespace, no trailing newline, UTF-8 bytes.

Array-of-maps behaviour: Go's marshalSorted does NOT recurse into arrays —
arrays delegate to json.Marshal, which itself alphabetizes map keys. The
Python port reaches sorted-keys through explicit recursion; the
canonical-JSON golden fixture locks in byte-agreement across all three
implementations.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_json"]


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON bytes.

    Raises:
        TypeError: on floats, circular references, unsupported value
            types, or invalid Unicode (lone surrogates, invalid UTF-16
            pairs). These are deliberate boundary rejections — the Veil
            signable subset contains only strings, bools, ints, None,
            lists, and dicts, all representable in well-formed UTF-8.
    """

    seen: set[int] = set()
    s = _marshal_sorted(value, seen)
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError as exc:
        # Lone / mismatched surrogates survive json.dumps(ensure_ascii=False)
        # as Python str codepoints but fail to encode to UTF-8. Convert to
        # TypeError so the verify_certificate pipeline wraps it as
        # TheVeilCertificateError(reason="malformed") rather than leaking
        # a raw UnicodeEncodeError.
        raise TypeError(
            f"canonical_json: input contains invalid UTF-16 surrogate bytes: {exc}"
        ) from exc


def _stringify_leaf(s: str) -> str:
    # json.dumps with ensure_ascii=False emits the string's Unicode verbatim
    # (matching JS JSON.stringify pre-HTML-escape). separators is irrelevant
    # for a leaf string but passed for uniformity. json.dumps will still
    # escape control chars, quotes, and backslashes per the JSON spec.
    encoded = json.dumps(s, ensure_ascii=False, separators=(",", ":"))
    # HTML-safe escape to match Go's default json.Marshal. Lowercase hex —
    # case and exact char set are load-bearing. Order does not matter since
    # none of these replacements introduce another target character.
    encoded = encoded.replace("<", "\\u003c")
    encoded = encoded.replace(">", "\\u003e")
    encoded = encoded.replace("&", "\\u0026")
    # U+2028 / U+2029 are valid UTF-8 but illegal inside a JS string literal.
    # Pre-ES2019 JSON.stringify escaped them by default; ES2019+ does not.
    # Go's json.Marshal does not escape them by default either. Both TS and
    # Python explicitly escape so the witness sees the same bytes regardless
    # of host JSON engine.
    encoded = encoded.replace("\u2028", "\\u2028")
    encoded = encoded.replace("\u2029", "\\u2029")
    return encoded


def _marshal_sorted(v: Any, seen: set[int]) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        # bool check BEFORE int because bool subclasses int in Python.
        # True/False must emit as true/false, not 1/0.
        return "true" if v else "false"
    if isinstance(v, int):
        # Integer leaf — emit without quotes, matching Go json.Marshal(int).
        # Python int has unbounded precision; the Veil signed subset
        # contains only protocol_version which is a small int. No bounds
        # check here — callers constructing signable dicts own correctness.
        return str(v)
    if isinstance(v, float):
        # Defensive: refuse floats at the canonical-JSON boundary. Go and
        # Python disagree on float formatting (Python: "1.0", Go depending
        # on value). The Veil signed subset carries no floats, so this is
        # a pure safety rail against accidental float-typing of an integer
        # field by a dict-literal caller.
        raise TypeError(
            f"canonical_json: float {v!r} not permitted — "
            "all integer leaves must be Python int, not float"
        )
    if isinstance(v, str):
        return _stringify_leaf(v)
    if isinstance(v, bytes):
        raise TypeError(
            "canonical_json: bytes not permitted — encode as str (base64) before passing"
        )
    if isinstance(v, list):
        obj_id = id(v)
        if obj_id in seen:
            raise TypeError("canonical_json: circular reference in list")
        seen.add(obj_id)
        try:
            parts = [_marshal_sorted(item, seen) for item in v]
        finally:
            seen.discard(obj_id)
        return "[" + ",".join(parts) + "]"
    if isinstance(v, dict):
        obj_id = id(v)
        if obj_id in seen:
            raise TypeError("canonical_json: circular reference in dict")
        seen.add(obj_id)
        try:
            # Reject non-string keys BEFORE sorting — `sorted` with the
            # UTF-8 encode key function would raise AttributeError on an
            # int/None/tuple key, which is not a typed SDK error.
            for k in v.keys():
                if not isinstance(k, str):
                    raise TypeError(
                        f"canonical_json: dict key must be str, got {type(k).__name__}"
                    )
            # Bytewise UTF-8 sort matches Go sort.Strings on UTF-8-encoded
            # keys. For pure-ASCII keys (which is the Veil 7-field signable
            # set), this is equivalent to Python's default lexical sort,
            # but the explicit UTF-8 encoding keeps us forward-compatible
            # with any future signed field whose keys contain non-ASCII.
            keys = sorted(v.keys(), key=lambda k: k.encode("utf-8"))
            parts = [
                f"{_stringify_leaf(k)}:{_marshal_sorted(v[k], seen)}" for k in keys
            ]
        finally:
            seen.discard(obj_id)
        return "{" + ",".join(parts) + "}"
    raise TypeError(
        f"canonical_json: unsupported value type {type(v).__name__}"
    )
