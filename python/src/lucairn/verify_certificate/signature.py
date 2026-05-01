"""Ed25519 signature verification via ``cryptography``."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    """

    raw = normalize_ed25519_public_key(public_key)
    key = Ed25519PublicKey.from_public_bytes(raw)
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
