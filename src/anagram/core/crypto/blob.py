"""Chunked authenticated encryption of evidence blobs (`chacha20-poly1305-chunked-v1`).

We do not write cipher code. pyca `cryptography` gives HKDF-SHA256 and
ChaCha20-Poly1305. This module only derives keys and nonces, and frames chunks.
See spec/vault.md section 2.

    blob_key = HKDF-SHA256(ikm = content key, salt = none,
                           info = tagged_message(TAG_BLOB_KEY, finding_root || u32(slot)),
                           L = 32)
    nonce(i) = 4 zero bytes || u64(i)
    aad(i)   = tagged_message(TAG_BLOB_CHUNK,
                 finding_root || evidence_root || u32(slot) || u64(i) || u8(final))
    ct(i)    = ChaCha20-Poly1305(blob_key, nonce(i), chunk(i), aad(i))
    blob     = ct(0) || ct(1) || ... || ct(n-1)

Each plaintext chunk has `chunk_size` bytes, except the last chunk, which can be
shorter. Each ciphertext chunk is 16 bytes longer than its plaintext chunk. An
empty file is one final chunk with no plaintext (16 bytes). `final` is 1 only
for the last chunk.

The key is different for each (content key, finding root, slot). So each nonce
is used once with each key. The AAD binds each chunk to its finding, its
evidence slot, its position, and the end of the blob. A changed, reordered,
removed, or moved chunk (also into another finding or slot) fails to decrypt.
A cut at a chunk boundary fails, because the new last chunk has `final` = 0.
"""

from __future__ import annotations

from typing import BinaryIO, NotRequired, TypedDict, Unpack

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from anagram.core.crypto.chunked import MAX_CHUNK_SIZE, _read_exact
from anagram.core.crypto.hashing import TAG_BLOB_CHUNK, TAG_BLOB_KEY, tagged_message, u32, u64

BLOB_ALG = "chacha20-poly1305-chunked-v1"
DEFAULT_CHUNK_SIZE = 1 << 20
AEAD_TAG_LEN = 16


class BlobError(ValueError):
    """The blob does not decrypt: a wrong key, or a changed, moved, or cut chunk."""


def _check(finding_root: bytes, evidence_root: bytes, slot: int, chunk_size: int) -> None:
    if len(finding_root) != 32 or len(evidence_root) != 32:
        raise ValueError("roots must be 32 bytes")
    if not 0 <= slot < 1 << 32:
        raise ValueError("bad slot")
    if not 0 < chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("bad chunk size")


def blob_key(content_key: bytes, finding_root: bytes, slot: int) -> bytes:
    if len(content_key) != 32:
        raise ValueError("content key must be 32 bytes")
    info = tagged_message(TAG_BLOB_KEY, finding_root + u32(slot))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(content_key)


def chunk_nonce(index: int) -> bytes:
    return bytes(4) + u64(index)


def chunk_aad(
    finding_root: bytes, evidence_root: bytes, slot: int, index: int, final: bool
) -> bytes:
    payload = finding_root + evidence_root + u32(slot) + u64(index) + bytes([1 if final else 0])
    return tagged_message(TAG_BLOB_CHUNK, payload)


def ciphertext_size(size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    chunks = max(1, -(-size // chunk_size))
    return size + chunks * AEAD_TAG_LEN


class BlobParams(TypedDict):
    """The keyword arguments of `encrypt_stream` and `decrypt_stream`."""

    content_key: bytes
    finding_root: bytes
    evidence_root: bytes
    slot: int
    chunk_size: NotRequired[int]


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    content_key: bytes,
    finding_root: bytes,
    evidence_root: bytes,
    slot: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[int, int]:
    """Encrypt `src` to `dst`. Return (plaintext size, ciphertext size).
    Only two chunks are in memory at a time."""
    _check(finding_root, evidence_root, slot, chunk_size)
    aead = ChaCha20Poly1305(blob_key(content_key, finding_root, slot))
    index, size, out = 0, 0, 0
    current = _read_exact(src, chunk_size)
    while True:
        nxt = _read_exact(src, chunk_size) if len(current) == chunk_size else b""
        final = not nxt
        aad = chunk_aad(finding_root, evidence_root, slot, index, final)
        ct = aead.encrypt(chunk_nonce(index), current, aad)
        dst.write(ct)
        size += len(current)
        out += len(ct)
        if final:
            return size, out
        index += 1
        current = nxt


def decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    content_key: bytes,
    finding_root: bytes,
    evidence_root: bytes,
    slot: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """Decrypt `src` to `dst`. Return the plaintext size. Raise BlobError on any
    change. The caller must discard `dst` after an error (it can hold the
    chunks that came before the bad chunk)."""
    _check(finding_root, evidence_root, slot, chunk_size)
    aead = ChaCha20Poly1305(blob_key(content_key, finding_root, slot))
    step = chunk_size + AEAD_TAG_LEN
    index, size = 0, 0
    current = _read_exact(src, step)
    if len(current) < AEAD_TAG_LEN:
        raise BlobError("blob is too short")
    while True:
        nxt = _read_exact(src, step) if len(current) == step else b""
        final = not nxt
        if not final and len(nxt) < AEAD_TAG_LEN:
            raise BlobError("blob has a damaged last chunk")
        aad = chunk_aad(finding_root, evidence_root, slot, index, final)
        try:
            plain = aead.decrypt(chunk_nonce(index), current, aad)
        except InvalidTag as exc:
            raise BlobError(f"chunk {index} does not decrypt") from exc
        dst.write(plain)
        size += len(plain)
        if final:
            return size
        index += 1
        current = nxt


def encrypt_bytes(data: bytes, **kw: Unpack[BlobParams]) -> bytes:
    import io

    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, **kw)
    return out.getvalue()


def decrypt_bytes(data: bytes, **kw: Unpack[BlobParams]) -> bytes:
    import io

    out = io.BytesIO()
    decrypt_stream(io.BytesIO(data), out, **kw)
    return out.getvalue()
