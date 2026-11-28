"""Chunked blob encryption and Shamir shares (unit tests, no node)."""

import io
import os

import pytest

from anagram.core.crypto import shamir
from anagram.core.crypto.blob import (
    AEAD_TAG_LEN,
    BlobError,
    ciphertext_size,
    decrypt_bytes,
    decrypt_stream,
    encrypt_bytes,
)

KEY = bytes(range(32))
ROOT_A = b"\xaa" * 32
ROOT_B = b"\xbb" * 32
EV = b"\xee" * 32
CHUNK = 64


def enc(data, root=ROOT_A, slot=0, key=KEY, ev=EV, chunk=CHUNK):
    return encrypt_bytes(
        data, content_key=key, finding_root=root, evidence_root=ev, slot=slot, chunk_size=chunk
    )


def dec(data, root=ROOT_A, slot=0, key=KEY, ev=EV, chunk=CHUNK):
    return decrypt_bytes(
        data, content_key=key, finding_root=root, evidence_root=ev, slot=slot, chunk_size=chunk
    )


def chunks(ct, chunk=CHUNK):
    step = chunk + AEAD_TAG_LEN
    return [ct[i : i + step] for i in range(0, len(ct), step)]


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 5 * CHUNK + 7])
def test_round_trip_and_size(size):
    data = os.urandom(size)
    ct = enc(data)
    assert len(ct) == ciphertext_size(size, CHUNK)
    assert dec(ct) == data
    # A short plaintext can occur in random ciphertext by chance; check long ones only.
    assert size < 16 or data not in ct


def test_deterministic_for_same_inputs_and_different_per_slot():
    data = b"x" * 200
    assert enc(data) == enc(data)
    assert enc(data, slot=1) != enc(data)
    assert enc(data, root=ROOT_B) != enc(data)


def test_chunk_reorder_fails():
    ct = chunks(enc(os.urandom(4 * CHUNK)))
    swapped = ct[1] + ct[0] + b"".join(ct[2:])
    with pytest.raises(BlobError):
        dec(swapped)


def test_truncation_at_chunk_boundary_fails():
    ct = chunks(enc(os.urandom(4 * CHUNK)))
    with pytest.raises(BlobError):
        dec(b"".join(ct[:2]))
    with pytest.raises(BlobError):
        dec(b"".join(ct[:-1]))
    with pytest.raises(BlobError):
        dec(enc(os.urandom(3 * CHUNK))[:-5])
    with pytest.raises(BlobError):
        dec(b"")


def test_appended_chunk_fails():
    ct = enc(os.urandom(2 * CHUNK))
    other = chunks(enc(os.urandom(2 * CHUNK)))
    with pytest.raises(BlobError):
        dec(ct + other[-1])


def test_chunk_swap_across_findings_and_slots_fails():
    data = os.urandom(3 * CHUNK)
    a = chunks(enc(data, root=ROOT_A))
    b = chunks(enc(data, root=ROOT_B))
    with pytest.raises(BlobError):
        dec(a[0] + b[1] + a[2], root=ROOT_A)
    s1 = chunks(enc(data, slot=1))
    with pytest.raises(BlobError):
        dec(a[0] + s1[1] + a[2])
    # A whole blob moved to another finding, slot, or evidence root fails too.
    whole = enc(data)
    for kw in ({"root": ROOT_B}, {"slot": 1}, {"ev": b"\x01" * 32}, {"key": b"\x02" * 32}):
        with pytest.raises(BlobError):
            dec(whole, **kw)


def test_bit_flip_fails():
    ct = bytearray(enc(os.urandom(2 * CHUNK)))
    ct[CHUNK + 3] ^= 1
    with pytest.raises(BlobError):
        dec(bytes(ct))


def test_streaming_large_input():
    data = os.urandom(5 * (1 << 20) + 3)
    out = io.BytesIO()
    ct = encrypt_bytes(
        data, content_key=KEY, finding_root=ROOT_A, evidence_root=EV, slot=2, chunk_size=1 << 20
    )
    n = decrypt_stream(
        io.BytesIO(ct),
        out,
        content_key=KEY,
        finding_root=ROOT_A,
        evidence_root=EV,
        slot=2,
        chunk_size=1 << 20,
    )
    assert n == len(data) and out.getvalue() == data


# ------------------------------------------------------------------ Shamir


def test_shamir_two_of_three():
    secret = os.urandom(32)
    shares = shamir.split(secret, 2, 3)
    assert [i for i, _ in shares] == [1, 2, 3]
    for a in range(3):
        for b in range(a + 1, 3):
            assert shamir.combine([shares[a], shares[b]], 2) == secret
    # One share does not give the secret; a wrong pair gives a wrong value.
    with pytest.raises(ValueError):
        shamir.combine([shares[0]], 2)
    assert shamir.combine([shares[0], (2, os.urandom(32))], 2) != secret


def test_shamir_three_of_five_and_limits():
    secret = os.urandom(32)
    shares = shamir.split(secret, 3, 5)
    assert shamir.combine([shares[4], shares[0], shares[2]], 3) == secret
    with pytest.raises(ValueError):
        shamir.combine([shares[0], shares[0], shares[1]], 3)
    with pytest.raises(ValueError):
        shamir.split(secret, 1, 3)
    with pytest.raises(ValueError):
        shamir.split(secret, 4, 3)
    with pytest.raises(ValueError):
        shamir.split(secret[:16], 2, 3)
