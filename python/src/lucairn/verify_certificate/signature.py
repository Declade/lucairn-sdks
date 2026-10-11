"""Ed25519 signature verification for the witness-only verifier.

The acceptance rule is the chain verifier's
(:mod:`lucairn.verify_certificate.chain`), called here rather than copied, so
the two paths cannot drift and the result does not depend on the OpenSSL
build behind ``cryptography``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lucairn.verify_certificate.chain import (
    _SMALL_ORDER_Y,
    _canonical_curve_point,
    _ed25519_ok,
    _masked,
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

    Also False (an invalid signature), by this function's own checks:

    - a public key whose 32 raw bytes are a small-order encoding or are not
      the canonical encoding of a curve point;
    - a signature that is not 64 bytes ``R || S``, has ``S >= L``, or whose
      ``R`` is a non-canonical encoding (y >= p) or a small-order point.

    The chain verifier's refusal of the published parity-corpus test keys is
    a pinned-key-set policy and is deliberately not applied here.
    """

    raw = normalize_ed25519_public_key(public_key)
    if _masked(raw) in _SMALL_ORDER_Y or not _canonical_curve_point(raw):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:  # pragma: no cover - the checks above are stricter
        return False
    return _ed25519_ok(key, message, signature)
