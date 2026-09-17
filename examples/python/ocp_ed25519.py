"""Ed25519 (RFC 8032) in pure Python, standard library only.

**Why this file exists.** The rest of `examples/python` has no third-party
dependencies, and this machine has no `cryptography` module. Python's stdlib has
SHA-512 and big integers but no Ed25519, so verifying an OCP attribution chain
from Python means either taking a dependency or carrying the ~80 lines of field
arithmetic below. The dependency is the wrong trade for an *example*: the point
of `examples/python` is that a reader can run it against a real catalog node
with nothing installed.

The implementation is the reference one from RFC 8032 §7, in extended
(projective) coordinates. Two properties it shares with OpenSSL, which is what
`node:crypto` uses on the other side of the matrix, and which have to match or
cross-verification fails:

- **Cofactorless verification.** `[s]B = R + [h]A`, not the cofactored variant
  multiplied through by 8. The two disagree on a small set of malleable
  signatures; a matrix where one language used each would be green on honest
  inputs and disagree on exactly the inputs an attacker picks.
- **`s < L` is rejected, not reduced.** Accepting `s + L` as a second valid
  encoding of the same signature is signature malleability, and
  `AttributionChainNode.signature` is a dedupe key in places.

.. warning::

   **Not constant time.** `point_mul` branches on secret bits and Python
   integers are variable-time; a co-located attacker who can time `sign` can
   recover the key. That is acceptable here because this is a reference and
   test implementation -- but a node that signs real attribution tokens in
   Python should use `cryptography`'s `Ed25519PrivateKey`, which wraps a
   constant-time C implementation. Verification handles no secrets, so the
   verify path -- the one W4 actually needs -- carries no such caveat.
"""
from __future__ import annotations

import hashlib

__all__ = ["sign", "verify", "public_key_from_seed", "SIGNATURE_BYTES", "KEY_BYTES"]

KEY_BYTES = 32
SIGNATURE_BYTES = 64

# Curve25519 field and group orders, and the twisted Edwards parameter d.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# A point is (X, Y, Z, T) with x = X/Z, y = Y/Z and T = XY/Z.
_Point = tuple


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _L


def _recover_x(y: int, sign_bit: int) -> int | None:
    """Solve the curve equation for x given y and the compressed sign bit."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign_bit else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # y is not on the curve
    if (x & 1) != sign_bit:
        x = _P - x
    return x


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)
_NEUTRAL: _Point = (0, 1, 1, 0)


def _point_add(p1: _Point, p2: _Point) -> _Point:
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _P
    c = 2 * p1[3] * p2[3] * _D % _P
    e = 2 * p1[2] * p2[2] % _P
    f, g, h, i = b - a, e - c, e + c, b + a
    return (f * g % _P, h * i % _P, g * h % _P, f * i % _P)


def _point_mul(scalar: int, point: _Point) -> _Point:
    acc = _NEUTRAL
    while scalar > 0:
        if scalar & 1:
            acc = _point_add(acc, point)
        point = _point_add(point, point)
        scalar >>= 1
    return acc


def _point_equal(p1: _Point, p2: _Point) -> bool:
    # Projective, so compare cross-multiplied rather than normalising twice.
    return (p1[0] * p2[2] - p2[0] * p1[2]) % _P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0


def _point_compress(point: _Point) -> bytes:
    z_inv = pow(point[2], _P - 2, _P)
    x = point[0] * z_inv % _P
    y = point[1] * z_inv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(data: bytes) -> _Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign_bit)
    return None if x is None else (x, y, 1, x * y % _P)


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != KEY_BYTES:
        raise ValueError(f"Ed25519 seed must be {KEY_BYTES} bytes, got {len(seed)}")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8  # clear the low 3 bits (cofactor) and the top bit
    a |= 1 << 254  # and set bit 254, so the scalar has a fixed bit length
    return a, h[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed -- JWK `d` to JWK `x`."""
    a, _ = _expand_seed(seed)
    return _point_compress(_point_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign `message`, returning the 64-byte signature.

    Deterministic: the nonce comes from the seed and the message, never from a
    random source. Two implementations signing the same canonical bytes with
    the same key therefore produce identical signatures -- which is what lets
    the cross-language matrix assert byte equality rather than just mutual
    verifiability.
    """
    a, prefix = _expand_seed(seed)
    pub = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(prefix + message)
    r_bytes = _point_compress(_point_mul(r, _G))
    h = _sha512_modq(r_bytes + pub + message)
    s = (r + h * a) % _L
    return r_bytes + int.to_bytes(s, 32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Check a detached signature. Returns `False` for anything unusable.

    Never raises on bad input: a caller holding several candidate tokens has to
    record "this one did not verify" and carry on, and an exception would make
    a malformed signature look like a configuration failure instead.
    """
    if len(public_key) != KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    a_point = _point_decompress(public_key)
    if a_point is None:
        return False
    r_bytes = signature[:32]
    r_point = _point_decompress(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False  # non-canonical s -- see the module docstring
    h = _sha512_modq(r_bytes + public_key + message)
    return _point_equal(_point_mul(s, _G), _point_add(r_point, _point_mul(h, a_point)))
