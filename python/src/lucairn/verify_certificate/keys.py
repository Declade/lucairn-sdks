"""Ed25519 public-key input normalization.

Accepts raw 32-byte keys or base64 strings. Rejects PEM SPKI, hex, and
other formats — the SDK's contract is raw-bytes-or-base64 only.
"""

from __future__ import annotations

import base64

__all__ = ["normalize_ed25519_public_key"]


def normalize_ed25519_public_key(input_: bytes | str) -> bytes:
    """Normalize a witness public-key input to raw 32 bytes.

    Raises:
        TypeError: on unsupported input type, wrong length, or invalid
            base64. The caller (:func:`verify_certificate`) wraps these
            as ``TheVeilCertificateError(reason="invalid_signature")`` so
            a malformed key still surfaces as a typed SDK error.
    """

    if isinstance(input_, bytes):
        raw = input_
    elif isinstance(input_, bytearray):
        raw = bytes(input_)
    elif isinstance(input_, str):
        try:
            raw = base64.b64decode(input_, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise TypeError(f"Ed25519 public key base64 decode failed: {exc}") from exc
    else:
        raise TypeError(
            "Ed25519 public key must be bytes or base64 string, got "
            f"{type(input_).__name__}"
        )
    if len(raw) != 32:
        raise TypeError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return raw
