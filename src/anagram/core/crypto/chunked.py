"""Chunked content digest for files of any size.

The content digest is:

    tagged_hash(TAG_CONTENT, u64(size) || u32(chunk_size) || MTH(chunks))

MTH is the RFC 6962 Merkle tree hash with each chunk as one leaf. The reader
holds one chunk in memory at a time, so a multi-GB file never loads in full.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from anagram.core.canonical import JsonObject
from anagram.core.crypto import merkle
from anagram.core.crypto.hashing import TAG_CONTENT, tagged_hash, u32, u64

CONTENT_ALG = "anagram-chunked-sha256-v1"
# Default chunk size: 1 MiB. The chunk size is recorded in each digest, so a
# change here does not break old proofs.
CHUNK_SIZE = 1 << 20
MAX_CHUNK_SIZE = 1 << 26


@dataclass(frozen=True)
class ContentDigest:
    size: int
    chunk_size: int
    digest: bytes
    alg: str = CONTENT_ALG

    def to_json(self) -> JsonObject:
        return {
            "alg": self.alg,
            "chunk_size": self.chunk_size,
            "digest": self.digest.hex(),
            "size": self.size,
        }

    @classmethod
    def from_json(cls, obj: JsonObject) -> ContentDigest:
        """Parse and check the JSON form. It can come from an untrusted bundle,
        so each value must be in range."""
        if not isinstance(obj, dict) or obj.get("alg") != CONTENT_ALG:
            raise ValueError("unknown content alg")
        size, chunk_size, digest = obj.get("size"), obj.get("chunk_size"), obj.get("digest")
        if type(size) is not int or size < 0 or size >= 1 << 64:
            raise ValueError("bad content size")
        if type(chunk_size) is not int or not 0 < chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError("bad chunk size")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("bad content digest")
        return cls(size=size, chunk_size=chunk_size, digest=bytes.fromhex(digest))


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read up to n bytes; return fewer only at end of stream."""
    first = stream.read(n)
    if not first or len(first) == n:
        return first
    parts = [first]
    have = len(first)
    while have < n:
        more = stream.read(n - have)
        if not more:
            break
        parts.append(more)
        have += len(more)
    return b"".join(parts)


def hash_stream(stream: BinaryIO, chunk_size: int | None = None) -> ContentDigest:
    if chunk_size is None:
        chunk_size = CHUNK_SIZE
    if not 0 < chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("bad chunk size")
    tree = merkle.StreamingRoot()
    size = 0
    while True:
        chunk = _read_exact(stream, chunk_size)
        if not chunk:
            break
        size += len(chunk)
        tree.add_leaf_hash(merkle.leaf_hash(chunk))
        if len(chunk) < chunk_size:
            break
    digest = tagged_hash(TAG_CONTENT, u64(size), u32(chunk_size), tree.root())
    return ContentDigest(size=size, chunk_size=chunk_size, digest=digest)


def hash_file(path: str | Path, chunk_size: int | None = None) -> ContentDigest:
    with open(path, "rb") as stream:
        return hash_stream(stream, chunk_size)


def hash_bytes(data: bytes, chunk_size: int | None = None) -> ContentDigest:
    import io

    return hash_stream(io.BytesIO(data), chunk_size)
