"""The Ed25519 acceptance rule of the witness-only verifier, applied by this
SDK's own code before the bytes reach ``cryptography``.

The library computes the cofactorless equation and compares the ENCODING of
R. What it does with a small-order R (for example the identity, a signature
made with nonce 0) or a small-order public key differs between library
builds, so those checks are explicit here and never left to the library.

Private module: nothing here is part of the package's public API. Plain
integer arithmetic only, so it runs on every Python version the package
supports.
"""

from __future__ import annotations

__all__: list[str] = []

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


def _masked(enc: bytes) -> bytes:
    """The encoding with the sign bit (top bit of byte 31) cleared. Always a
    new ``bytes`` object, whatever buffer type came in."""
    enc = bytes(enc)
    return enc[:31] + bytes([enc[31] & 0x7F])


def _is_small_order(enc: bytes) -> bool:
    """True for the 14 small-order encodings (32 bytes)."""
    return _masked(enc) in _SMALL_ORDER_Y


def _canonical_curve_point(enc: bytes) -> bool:
    """The canonical encoding of a curve point: y (the low 255 bits) < p,
    some x satisfies -x^2 + y^2 = 1 + d*x^2*y^2, and the sign bit is clear
    when x is 0."""
    y = int.from_bytes(_masked(enc), "little")
    if y >= _ED_P:
        return False
    y2 = y * y % _ED_P
    x2 = (y2 - 1) * pow(_ED_D * y2 + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return enc[31] & 0x80 == 0
    return pow(x2, (_ED_P - 1) // 2, _ED_P) == 1


def key_acceptable(raw: bytes) -> bool:
    """The public key (exactly 32 raw bytes, after normalisation) is
    acceptable: not a small-order encoding, and the canonical encoding of a
    curve point."""
    raw = bytes(raw)
    if len(raw) != 32:
        return False
    return not _is_small_order(raw) and _canonical_curve_point(raw)


def signature_encoding_acceptable(sig: bytes) -> bool:
    """The signature encoding is acceptable: 64 bytes R || S with S < L and R
    the canonical encoding (y < p) of a point that is not of small order.
    Whether the signature VERIFIES is still the library's cofactorless
    equation."""
    sig = bytes(sig)
    if len(sig) != 64 or int.from_bytes(sig[32:], "little") >= _ED_L:
        return False
    r = sig[:32]
    return int.from_bytes(_masked(r), "little") < _ED_P and not _is_small_order(r)
