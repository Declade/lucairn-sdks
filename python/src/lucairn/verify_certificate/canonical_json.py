"""Canonical JSON serializer — Python port of the Veil witness signing algorithm.

Byte-identical to:
  dual-sandbox-architecture/pkg/veil/canonical.go
  theveil-sdks/ts/src/verify-certificate/canonical-json.ts

This is NOT RFC 8785 JCS. It is the witness's signing algorithm:
  - recursive sorted keys at every map depth (bytewise UTF-8 sort)
  - leaves through json.dumps(..., ensure_ascii=True, separators=(",", ":")),
    which is byte-identical to the witness signer
    (dual-sandbox-architecture/pkg/veil/canonical.go:encodePythonAsciiString):
    every codepoint >= U+0080 is escaped to a lowercase ``\\uXXXX`` (supplementary
    plane -> UTF-16 surrogate pair ``\\uHHHH\\uLLLL``), and ``<`` ``>`` ``&`` are
    emitted LITERALLY (the witness does NOT HTML-escape them). U+2028 / U+2029 are
    >= U+0080 and so are escaped to ``\\u2028`` / ``\\u2029`` by ensure_ascii=True —
    no special-casing needed.
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
    # The serialized string is pure ASCII (ensure_ascii=True escapes every
    # codepoint >= U+0080), so encoding never raises UnicodeEncodeError. Lone /
    # mismatched surrogates are rejected earlier, inside _stringify_leaf, before
    # they can survive into the escaped output — see the surrogate guard there.
    return s.encode("ascii")


def _stringify_leaf(s: str) -> str:
    # Reject lone / mismatched UTF-16 surrogate codepoints BEFORE serializing.
    # ensure_ascii=True would otherwise emit them as a lowercase \uXXXX escape
    # (and the ASCII encode would succeed), silently producing a string no
    # well-formed witness-signed payload could contain. A surrogate means
    # malformed Unicode -> reject as a typed TypeError so the verify_certificate
    # pipeline wraps it as reason="malformed".
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise TypeError(
                "canonical_json: input contains invalid UTF-16 surrogate "
                f"codepoint U+{ord(ch):04X}"
            )
    # json.dumps with ensure_ascii=True is byte-identical to the witness signer
    # (dual-sandbox-architecture/pkg/veil/canonical.go:encodePythonAsciiString):
    #   - escapes EVERY codepoint >= U+0080 to a lowercase \uXXXX escape
    #     (supplementary plane -> UTF-16 surrogate pair \uHHHH\uLLLL), including
    #     U+2028 / U+2029 -> \u2028 / \u2029 (no special-casing needed);
    #   - emits <, >, & LITERALLY (the witness does NOT HTML-escape them);
    #   - escapes control chars, quotes, and backslashes per the JSON spec.
    # separators is irrelevant for a leaf string but passed for uniformity.
    return json.dumps(s, ensure_ascii=True, separators=(",", ":"))


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
        # on value). The witness signed subset carries no floats, so this is
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
