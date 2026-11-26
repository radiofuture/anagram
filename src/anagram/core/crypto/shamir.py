"""Shamir secret sharing of a 32-byte secret through pycryptodome.

We do not write field arithmetic. pycryptodome `Crypto.Protocol.SecretSharing.Shamir`
shares a 16-byte secret in GF(2^128). We cut the 32-byte secret into two
16-byte halves and share each half on its own with the same k and n. Share i
is `share_i(half 0) || share_i(half 1)` (32 bytes), with index i in 1..n.
Each half is a k-of-n sharing, so k - 1 shares tell nothing about either half.
See spec/vault.md section 6.
"""

from __future__ import annotations

from Crypto.Protocol.SecretSharing import Shamir

SECRET_LEN = 32
SHARE_LEN = 32
MAX_SHARES = 16


def _check_kn(k: int, n: int) -> None:
    if not 2 <= k <= n <= MAX_SHARES:
        raise ValueError(f"need 2 <= threshold <= shares <= {MAX_SHARES}")


def split(secret: bytes, k: int, n: int) -> list[tuple[int, bytes]]:
    """Return n shares (index, 32 bytes). Any k of them give the secret."""
    if len(secret) != SECRET_LEN:
        raise ValueError("secret must be 32 bytes")
    _check_kn(k, n)
    lo = Shamir.split(k, n, secret[:16])
    hi = Shamir.split(k, n, secret[16:])
    out = []
    for (i, a), (j, b) in zip(lo, hi, strict=True):
        if i != j:
            raise ValueError("share index mismatch")
        out.append((i, a + b))
    return out


def combine(shares: list[tuple[int, bytes]], k: int) -> bytes:
    """Combine exactly k shares with distinct indices. With wrong or too few
    shares, the result is a wrong value, not an error: the caller must check the
    result (for example against a key ID)."""
    if not 2 <= k <= MAX_SHARES:
        raise ValueError("bad threshold")
    if len(shares) != k or len({i for i, _ in shares}) != k:
        raise ValueError(f"need exactly {k} shares with distinct indices")
    for i, s in shares:
        if not 1 <= i <= MAX_SHARES or len(s) != SHARE_LEN:
            raise ValueError("bad share")
    lo = Shamir.combine([(i, s[:16]) for i, s in shares])
    hi = Shamir.combine([(i, s[16:]) for i, s in shares])
    return lo + hi
