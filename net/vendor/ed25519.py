"""Vendored pure-Python Ed25519 (RFC 8032) — PIENUVO v0.

Why vendored: the FalloutWorld server side verifies login signatures
(one verify per login handshake) and must run with ZERO pip dependencies —
stdlib only.  This module implements Ed25519 per RFC 8032 using nothing but
``hashlib.sha512`` and ``os.urandom``, in the style of the well-known RFC 8032
reference implementation (twisted Edwards point arithmetic + SHA-512), with
extended homogeneous coordinates for speed.

Performance: sign/verify each cost two-ish scalar multiplications in pure
Python big-int arithmetic — a few milliseconds on a modern CPU, comfortably
under the ~50 ms budget.  This is used once per login, never per frame.

Security notes:
- ``verify()`` NEVER raises: any malformed input (wrong lengths, wrong types,
  non-canonical point encodings, out-of-range scalar S >= L, small-order /
  identity points) returns ``False``.
- S >= L is rejected explicitly to block signature malleability.
- This is NOT constant-time.  It is fine for server-side *verification* of
  public signatures; key generation and signing use secrets that a
  determined local attacker with timing access could in principle probe.
  Acceptable for our threat model (server owns its own keys).

Public API:
    create_keypair() -> (private_seed_32, public_key_32)
    sign(private_seed_32, message) -> signature_64
    verify(public_key_32, message, signature_64) -> bool
"""
from __future__ import annotations

import hashlib
import os

__all__ = ["create_keypair", "sign", "verify"]

# ---------------------------------------------------------------------------
# Curve constants (edwards25519, RFC 8032 section 5.1)
# ---------------------------------------------------------------------------

_p = 2 ** 255 - 19                                          # field prime
_L = 2 ** 252 + 27742317777372353535851937790883648493      # group order
_d = (-121665 * pow(121666, _p - 2, _p)) % _p               # curve constant
_I = pow(2, (_p - 1) // 4, _p)                              # sqrt(-1) mod p


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# ---------------------------------------------------------------------------
# Point arithmetic — extended homogeneous coordinates (X, Y, Z, T)
# with x = X/Z, y = Y/Z, x*y = T/Z.  The addition formula below is the
# unified/complete "add-2008-hwcd-3" for a = -1 twisted Edwards curves,
# so it is safe to use for doubling as well.
# ---------------------------------------------------------------------------

_IDENTITY = (0, 1, 1, 0)


def _point_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    B = (Y1 + X1) * (Y2 + X2) % _p
    C = 2 * T1 * T2 * _d % _p
    D = 2 * Z1 * Z2 % _p
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _scalar_mult(s: int, P):
    """Compute [s]P by double-and-add (LSB first)."""
    Q = _IDENTITY
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    # Cross-multiply to compare projective coordinates without inversion.
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True


def _is_small_order(P) -> bool:
    """True if P is in the 8-torsion subgroup (includes the identity)."""
    Q = _point_add(P, P)      # 2P
    Q = _point_add(Q, Q)      # 4P
    Q = _point_add(Q, Q)      # 8P
    return _point_equal(Q, _IDENTITY)


# ---------------------------------------------------------------------------
# Point (de)compression (RFC 8032 section 5.1.2 / 5.1.3)
# ---------------------------------------------------------------------------

def _recover_x(y: int, sign: int) -> int:
    """Recover the x coordinate from y and the sign bit; raise on failure."""
    if y >= _p:
        raise ValueError("non-canonical y coordinate")
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
    if x2 == 0:
        if sign:
            raise ValueError("non-canonical encoding: x = 0 with sign bit set")
        return 0
    # Square root candidate: x = x2^((p+3)/8) mod p
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _I % _p
    if (x * x - x2) % _p != 0:
        raise ValueError("point not on curve (x^2 has no square root)")
    if x & 1 != sign:
        x = _p - x
    return x


def _point_compress(P) -> bytes:
    X, Y, Z, _T = P
    zinv = pow(Z, _p - 2, _p)
    x = X * zinv % _p
    y = Y * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    """Decode a 32-byte point encoding; raise ValueError on malformed input."""
    if len(s) != 32:
        raise ValueError("point encoding must be 32 bytes")
    n = int.from_bytes(s, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _p)


# Base point B: y = 4/5 (mod p), x chosen with sign bit 0.
_B_y = 4 * pow(5, _p - 2, _p) % _p
_B_x = _recover_x(_B_y, 0)
_B = (_B_x, _B_y, 1, _B_x * _B_y % _p)


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 section 5.1.5 / 5.1.6 / 5.1.7)
# ---------------------------------------------------------------------------

def _secret_expand(seed: bytes):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("private seed must be exactly 32 bytes")
    h = _sha512(bytes(seed))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8       # clear the low 3 bits and bit 255
    a |= 1 << 254             # set bit 254
    return a, h[32:]


def create_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh keypair: (private_seed_32, public_key_32)."""
    seed = os.urandom(32)
    a, _prefix = _secret_expand(seed)
    public_key = _point_compress(_scalar_mult(a, _B))
    return seed, public_key


def sign(private_seed_32: bytes, message: bytes) -> bytes:
    """Sign ``message`` with the 32-byte private seed; return 64-byte signature."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    message = bytes(message)
    a, prefix = _secret_expand(private_seed_32)
    A = _point_compress(_scalar_mult(a, _B))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    R = _point_compress(_scalar_mult(r, _B))
    h = int.from_bytes(_sha512(R + A + message), "little") % _L
    s = (r + h * a) % _L
    return R + int.to_bytes(s, 32, "little")


def verify(public_key_32: bytes, message: bytes, signature_64: bytes) -> bool:
    """Verify a signature.  Returns False (never raises) on ANY malformed input:
    wrong lengths/types, non-canonical point encodings, S >= L (malleability),
    small-order / identity points, or a simply-wrong signature.
    """
    try:
        if not isinstance(public_key_32, (bytes, bytearray)):
            return False
        if not isinstance(message, (bytes, bytearray)):
            return False
        if not isinstance(signature_64, (bytes, bytearray)):
            return False
        public_key_32 = bytes(public_key_32)
        message = bytes(message)
        signature_64 = bytes(signature_64)
        if len(public_key_32) != 32 or len(signature_64) != 64:
            return False

        A = _point_decompress(public_key_32)
        R = _point_decompress(signature_64[:32])
        S = int.from_bytes(signature_64[32:], "little")
        if S >= _L:
            return False  # reject malleable encodings
        if _is_small_order(A) or _is_small_order(R):
            return False  # identity / low-order edge cases

        h = int.from_bytes(
            _sha512(signature_64[:32] + public_key_32 + message), "little"
        ) % _L
        # Check [S]B == R + [h]A  (strict, non-cofactored group equation)
        return _point_equal(
            _scalar_mult(S, _B),
            _point_add(R, _scalar_mult(h, A)),
        )
    except Exception:
        return False
