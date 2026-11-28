"""RFC 6962 / RFC 9162 Merkle tree hashing and proofs.

Leaf hash: SHA-256(0x00 || data). Node hash: SHA-256(0x01 || left || right).
The empty tree hash is SHA-256("").

The proof builders take a `subtree(lo, hi)` callback that returns the Merkle
tree hash of leaves lo..hi-1. A list of leaf hashes and the SQLite log both
supply such a callback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence

Subtree = Callable[[int, int], bytes]

HASH_LEN = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_point(n: int) -> int:
    """Return the largest power of two that is smaller than n (n >= 2)."""
    if n < 2:
        raise ValueError("split_point needs n >= 2")
    return 1 << ((n - 1).bit_length() - 1)


def _is_pow2(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def list_subtree(leaf_hashes: Sequence[bytes]) -> Subtree:
    """Return a subtree callback over an in-memory list of leaf hashes."""

    def subtree(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return leaf_hashes[lo]
        k = split_point(n)
        return node_hash(subtree(lo, lo + k), subtree(lo + k, hi))

    return subtree


def root(leaf_hashes: Sequence[bytes]) -> bytes:
    return list_subtree(leaf_hashes)(0, len(leaf_hashes))


def inclusion_path(subtree: Subtree, index: int, size: int) -> list[bytes]:
    """RFC 6962 PATH(index, D[0:size]), leaf side first."""
    if not 0 <= index < size:
        raise ValueError("index out of range")
    path: list[bytes] = []

    def walk(m: int, lo: int, hi: int) -> None:
        n = hi - lo
        if n <= 1:
            return
        k = split_point(n)
        if m < k:
            walk(m, lo, lo + k)
            path.append(subtree(lo + k, hi))
        else:
            walk(m - k, lo + k, hi)
            path.append(subtree(lo, lo + k))

    walk(index, 0, size)
    return path


def consistency_path(subtree: Subtree, old_size: int, new_size: int) -> list[bytes]:
    """RFC 6962 PROOF(old_size, D[0:new_size])."""
    if not 0 <= old_size <= new_size:
        raise ValueError("bad sizes")
    if old_size == 0 or old_size == new_size:
        return []
    path: list[bytes] = []

    def sub(m: int, lo: int, hi: int, complete: bool) -> None:
        n = hi - lo
        if m == n:
            if not complete:
                path.append(subtree(lo, hi))
            return
        k = split_point(n)
        if m <= k:
            sub(m, lo, lo + k, complete)
            path.append(subtree(lo + k, hi))
        else:
            sub(m - k, lo + k, hi, False)
            path.append(subtree(lo, lo + k))

    sub(old_size, 0, new_size, True)
    return path


def root_from_inclusion(leaf: bytes, index: int, size: int, path: Sequence[bytes]) -> bytes | None:
    """Compute the root from a leaf hash and an inclusion path (RFC 9162 2.1.3.2).

    Return None if the path has the wrong shape or any hash is not 32 bytes.
    """
    if not 0 <= index < size:
        return None
    if len(leaf) != HASH_LEN or any(len(p) != HASH_LEN for p in path):
        return None
    fn, sn = index, size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return r


def verify_inclusion(
    leaf: bytes, index: int, size: int, path: Sequence[bytes], expected_root: bytes
) -> bool:
    if len(expected_root) != HASH_LEN:
        return False
    computed = root_from_inclusion(leaf, index, size, path)
    return computed is not None and computed == expected_root


def verify_consistency(
    old_size: int,
    new_size: int,
    path: Sequence[bytes],
    old_root: bytes,
    new_root: bytes,
) -> bool:
    """RFC 9162 2.1.4.2 consistency proof check."""
    if (
        old_size < 0
        or old_size > new_size
        or len(old_root) != HASH_LEN
        or len(new_root) != HASH_LEN
        or any(len(c) != HASH_LEN for c in path)
        or (old_size == 0 and old_root != EMPTY_ROOT)
    ):
        return False
    if old_size == new_size:
        return len(path) == 0 and old_root == new_root
    if old_size == 0:
        return len(path) == 0
    if not path:
        return False
    proof = list(path)
    if _is_pow2(old_size):
        proof = [old_root, *proof]
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


class StreamingRoot:
    """Compute an RFC 6962 root over leaves that arrive one at a time.

    Memory use is O(log n) hashes.
    """

    def __init__(self) -> None:
        self._stack: list[tuple[int, bytes]] = []
        self.count = 0

    def add_leaf_hash(self, h: bytes) -> None:
        self._stack.append((0, h))
        self.count += 1
        while len(self._stack) >= 2 and self._stack[-1][0] == self._stack[-2][0]:
            height, right = self._stack.pop()
            _, left = self._stack.pop()
            self._stack.append((height + 1, node_hash(left, right)))

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_ROOT
        r = self._stack[-1][1]
        for _, h in reversed(self._stack[:-1]):
            r = node_hash(h, r)
        return r


# ----------------------------------------------------------- compact range


def frontier_append(frontier: Sequence[bytes], size: int, leaf: bytes) -> list[bytes]:
    """Add one leaf hash to a compact range (the roots of the perfect subtrees of
    a tree of `size` leaves, largest first). Return the range for size + 1."""
    out = list(frontier)
    h = leaf
    while size & 1:
        h = node_hash(out.pop(), h)
        size >>= 1
    out.append(h)
    return out


def frontier_root(frontier: Sequence[bytes]) -> bytes:
    """RFC 6962 root of the tree that a compact range describes."""
    if not frontier:
        return EMPTY_ROOT
    acc = frontier[-1]
    for h in reversed(frontier[:-1]):
        acc = node_hash(h, acc)
    return acc
