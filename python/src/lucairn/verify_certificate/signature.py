"""Ed25519 signature verification via ``cryptography``."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucairn.verify_certificate._ed25519_rule import (
    key_acceptable,
    signature_encoding_acceptable,
)
from lucairn.verify_certificate.keys import normalize_ed25519_public_key

__all__ = ["verify_ed25519"]


def verify_ed25519(
    message: bytes,
    signature: bytes,
    public_key: bytes | str,
) -> bool:
    """Verify an Ed25519 signature over ``message``.

    Returns True on valid signature, False on invalid. Raises
    :class:`TypeError` if ``public_key`` is malformed (wrong length,
    non-base64 string, unsupported type). The orchestrator layer
    (:func:`verify_certificate`) is responsible for translating ``False``
    into a :class:`LucairnCertificateError`.

    Before the library is called, this SDK's own rule
    (:mod:`lucairn.verify_certificate._ed25519_rule`) is applied to the 32
    raw key bytes and to the signature bytes, so the result does not depend
    on the OpenSSL build behind ``cryptography``. Each of these returns False
    (an invalid signature):

    - a public key that is a small-order encoding or is not the canonical
      encoding of a curve point;
    - a signature that is not 64 bytes ``R || S``, has ``S >= L``, or whose
      ``R`` is a non-canonical encoding (y >= p) or a small-order point.
    """

    raw = normalize_ed25519_public_key(public_key)
    # bytes, bytearray and memoryview signatures are all accepted, as before.
    signature = bytes(signature)
    if not key_acceptable(raw) or not signature_encoding_acceptable(signature):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
