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


def test_core_validators_reject_trailing_newline_and_bad_dates(tmp_path, monkeypatch):
    import sys

    from anagram.core.errors import FormatError
    from anagram.core.files import fsync_dir
    from anagram.core.jsontable import JsonTable
    from anagram.core.shared_db import SharedDB
    from anagram.core.timefmt import parse_time
    from anagram.core.validate import HEX16, HEX32, HEX64

    assert not HEX16.match("a" * 32 + "\n")
    assert not HEX32.match("a" * 64 + "\n")
    assert not HEX64.match("a" * 128 + "\n")
    with pytest.raises(FormatError):
        parse_time("2026-10-15T12:00:00Z\n")
    with pytest.raises(FormatError):
        parse_time("2026-02-30T12:00:00Z")
    db = SharedDB(tmp_path / "t.sqlite")
    with pytest.raises(ValueError, match="bad table name"):
        JsonTable(db, "good_name\n")
    db.close()

    # L1: ContentDigest.from_json requires 64 lowercase hex chars.
    d = chunked.hash_bytes(b"hello").to_json()
    for bad in ("A" * 64, "z" * 64, d["digest"] + "\n"):
        with pytest.raises(ValueError, match="bad content digest"):
            chunked.ContentDigest.from_json({**d, "digest": bad})

    # L1: fsync_dir is a no-op on Windows.
    monkeypatch.setattr(sys, "platform", "win32")
    fsync_dir(tmp_path / "does-not-even-open-on-win32")
