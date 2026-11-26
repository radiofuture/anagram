import os
import tracemalloc

import pytest

from anagram.core.crypto import chunked, merkle
from anagram.core.crypto.hashing import TAG_CONTENT, tagged_hash, u32, u64


def reference_digest(data: bytes, chunk_size: int) -> bytes:
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    mth = merkle.root([merkle.leaf_hash(c) for c in chunks])
    return tagged_hash(TAG_CONTENT, u64(len(data)), u32(chunk_size), mth)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 64, 1000])
def test_matches_reference(size):
    data = os.urandom(size)
    d = chunked.hash_bytes(data, chunk_size=16)
    assert d.size == size
    assert d.digest == reference_digest(data, 16)


def test_chunk_size_is_bound():
    data = b"x" * 100
    assert chunked.hash_bytes(data, 16).digest != chunked.hash_bytes(data, 32).digest


class CountingReader:
    def __init__(self, f):
        self.f = f
        self.max_read = 0

    def read(self, n=-1):
        if n is None or n < 0:
            raise AssertionError("reader asked for whole file")
        self.max_read = max(self.max_read, n)
        return self.f.read(n)


def test_large_file_streams(tmp_path, monkeypatch):
    # 8 MiB file, 4 KiB chunks: the reader must never ask for more than one chunk,
    # and peak Python memory must stay far below the file size.
    monkeypatch.setattr(chunked, "CHUNK_SIZE", 4096)
    path = tmp_path / "big.bin"
    block = os.urandom(1 << 16)
    with open(path, "wb") as f:
        for _ in range(128):
            f.write(block)
    size = path.stat().st_size
    assert size == 8 << 20

    with open(path, "rb") as f:
        reader = CountingReader(f)
        tracemalloc.start()
        d = chunked.hash_stream(reader)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    assert reader.max_read == 4096
    assert peak < 1 << 20
    assert d.size == size and d.chunk_size == 4096
    assert d == chunked.hash_file(path)
    assert d.digest == reference_digest(path.read_bytes(), 4096)


def test_json_round_trip():
    d = chunked.hash_bytes(b"hello")
    assert chunked.ContentDigest.from_json(d.to_json()) == d
