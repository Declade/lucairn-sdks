"""Text rules of the witness-only verifier, written out so the TypeScript,
Python and Go SDKs judge the same signature TEXT the same way instead of
inheriting whatever each language's ``strip`` and base64 decoder happen to do.

Private module: nothing here is part of the package's public API.
"""

from __future__ import annotations

import base64
import binascii

__all__: list[str] = []

# The white-space set: Go's ``unicode.IsSpace`` (which ``strings.TrimSpace``
# uses) — U+0009–000D, U+0020, U+0085, U+00A0, U+1680, U+2000–200A, U+2028,
# U+2029, U+202F, U+205F, U+3000. Python's argument-less ``str.strip()``
# additionally strips U+001C–U+001F, so it is not used for these tests.
_WHITE_SPACE = "".join(
    chr(c)
    for c in (
        *range(0x0009, 0x000E),
        0x0020,
        0x0085,
        0x00A0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)


def is_blank_signature_text(text: str | None) -> bool:
    """True when a signature field is absent, empty, or holds only white
    space of the set above."""
    return not text or text.strip(_WHITE_SPACE) == ""


def decode_signature_text(text: str) -> bytes:
    """Decode a signature field. The text must be CANONICAL standard padded
    base64 (alphabet ``A-Z a-z 0-9 + /``, ``=`` padding, nothing else):
    decode, re-encode, compare.

    Raises:
        ValueError: for anything else — including non-zero padding bits,
            which ``base64.b64decode(validate=True)`` accepts.
    """
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(str(exc)) from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("not canonical standard padded base64")
    return raw
