"""Test-only pure-stdlib RFC 8032 Ed25519 signer for `tests/approval/`.

WARNING: Uses variable-time Python big-integer scalar multiplication and is
STRICTLY for hermetic test fixtures and RFC 8032 vector verification. NEVER use
this helper for production private keys; `bin/approval_enforce.py` exports
public-input verification only.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)

_Point = tuple[int, int, int, int]
_NEUTRAL: _Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    u = (y * y - 1) % ED25519_P
    v = (ED25519_D * y * y + 1) % ED25519_P
    v3 = pow(v, 3, ED25519_P)
    v7 = (v3 * v3 % ED25519_P) * v % ED25519_P
    x = (
        (u * v3 % ED25519_P)
        * pow((u * v7) % ED25519_P, (ED25519_P - 5) // 8, ED25519_P)
    ) % ED25519_P
    if (v * x * x) % ED25519_P == (-u) % ED25519_P:
        x = (x * _SQRT_M1) % ED25519_P
    if (x & 1) != sign:
        x = ED25519_P - x
    return x


def _point_add(p1: _Point, p2: _Point) -> _Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % ED25519_P
    c = (2 * t1 * t2 * ED25519_D) % ED25519_P
    d = (2 * z1 * z2) % ED25519_P
    e = (b - a) % ED25519_P
    f = (d - c) % ED25519_P
    g = (d + c) % ED25519_P
    h = (b + a) % ED25519_P
    return (
        (e * f) % ED25519_P,
        (g * h) % ED25519_P,
        (f * g) % ED25519_P,
        (e * h) % ED25519_P,
    )


def _point_mul(scalar: int, pt: _Point) -> _Point:
    acc = _NEUTRAL
    cur = pt
    k = scalar
    while k > 0:
        if k & 1:
            acc = _point_add(acc, cur)
        cur = _point_add(cur, cur)
        k >>= 1
    return acc


def compress_point(pt: _Point) -> bytes:
    z_inv = pow(pt[2], ED25519_P - 2, ED25519_P)
    x = (pt[0] * z_inv) % ED25519_P
    y = (pt[1] * z_inv) % ED25519_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE_Y = (4 * pow(5, ED25519_P - 2, ED25519_P)) % ED25519_P
_BASE_X = _recover_x(_BASE_Y, 0)
BASE_POINT: _Point = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % ED25519_P)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte test seed (RFC 8032 §5.1.5)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a_bytes = bytearray(digest[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    return compress_point(_point_mul(a, BASE_POINT))


def sign(seed: bytes, msg_bytes: bytes) -> bytes:
    """Produce 64-byte RFC 8032 pure Ed25519 signature (test-only, non-constant-time)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a_bytes = bytearray(digest[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    prefix = digest[32:]
    pub = compress_point(_point_mul(a, BASE_POINT))

    r = int.from_bytes(hashlib.sha512(prefix + msg_bytes).digest(), "little") % ED25519_L
    r_bytes = compress_point(_point_mul(r, BASE_POINT))
    k = (
        int.from_bytes(hashlib.sha512(r_bytes + pub + msg_bytes).digest(), "little")
        % ED25519_L
    )
    s = (r + k * a) % ED25519_L
    return r_bytes + s.to_bytes(32, "little")


def sign_approval_record(
    record_without_sig: dict[str, Any], seed: bytes, jcs_dumps_fn: Any
) -> dict[str, Any]:
    """Return a copy of `record_without_sig` signed under pure Ed25519 over JCS bytes."""
    unsigned = {k: copy.deepcopy(v) for k, v in record_without_sig.items() if k != "signature"}
    payload = jcs_dumps_fn(unsigned)
    sig = sign(seed, payload)
    signed = dict(unsigned)
    signed["signature"] = "ed25519-sig:" + sig.hex()
    return signed
