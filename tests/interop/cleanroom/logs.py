"""RFC 6962 trees, C2SP signed notes and cosignatures (log.md 1 to 4), and
the quorum and signed times of enclave-trust.md 2.4."""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import Refused, cjson, sha256


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def mth(leaves: list[bytes]) -> bytes:
    """Merkle tree hash of leaf hashes."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def root_of(entries: list[dict]) -> bytes:
    return mth([leaf_hash(cjson(e)) for e in entries])


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 audit path of leaf `index` (leaf side first)."""
    if len(leaves) <= 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if index < k:
        return [*inclusion_proof(leaves[:k], index), mth(leaves[k:])]
    return [*inclusion_proof(leaves[k:], index - k), mth(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---- notes --------------------------------------------------------------------


@dataclass(frozen=True)
class NoteKey:
    name: str
    alg: int
    public: bytes

    @classmethod
    def parse(cls, text: str) -> NoteKey:
        name, khash, b64 = text.split("+", 2)
        raw = base64.b64decode(b64)
        k = cls(name, raw[0], raw[1:])
        if k.key_hash().hex() != khash:
            raise ValueError("key hash")
        return k

    def key_hash(self) -> bytes:
        return sha256(self.name.encode() + b"\n" + bytes([self.alg]) + self.public)[:4]


@dataclass(frozen=True)
class Checkpoint:
    text: str
    origin: str
    size: int
    root: bytes
    cosigs: dict[str, int]  # witness name -> time

    @property
    def anchor(self) -> bytes:
        return sha256(self.text.encode())


def _split(note: str) -> tuple[str, list[tuple[str, bytes]]]:
    head, sep, rest = note.partition("\n\n")
    if not sep:
        raise ValueError("no signature block")
    lines = []
    for line in rest.split("\n"):
        if not line:
            continue
        if not line.startswith("— "):
            raise ValueError("bad signature line")
        name, b64 = line[2:].rsplit(" ", 1)
        lines.append((name, base64.b64decode(b64)))
    return head + "\n", lines


def parse_checkpoint(note: str, log_key: NoteKey, witnesses: list[dict]) -> Checkpoint:
    """Check the log signature and each pinned witness cosignature. Return
    the checkpoint with the valid cosignature times only."""
    text, sigs = _split(note)
    origin, size, root_b64 = text.rstrip("\n").split("\n")[:3]
    if origin != log_key.name:
        raise Refused("bad_checkpoint", "origin")
    ok = any(
        name == log_key.name
        and raw[:4] == log_key.key_hash()
        and verify_raw(log_key.public, text.encode(), raw[4:])
        for name, raw in sigs
    )
    if not ok:
        raise Refused("bad_checkpoint", "log signature")
    cosigs: dict[str, int] = {}
    for w in witnesses:
        wk: NoteKey = w["key"]
        for name, raw in sigs:
            if name != wk.name or raw[:4] != wk.key_hash() or len(raw) != 76:
                continue
            t = struct.unpack(">Q", raw[4:12])[0]
            msg = f"cosignature/v1\ntime {t}\n".encode() + text.encode()
            if verify_raw(wk.public, msg, raw[12:]):
                cosigs[wk.name] = t
    return Checkpoint(text, origin, int(size), base64.b64decode(root_b64), cosigs)


def verify_raw(public: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


def quorum_times(cp: Checkpoint, witnesses: list[dict]) -> list[int] | None:
    """Times of a quorum (2 distinct pinned witnesses, at least 1
    independent), or None.

    SPEC GAP (G2): enclave-trust.md 2.4 defines lower(cp) and upper(cp) over
    "the quorum's cosignature times", but a checkpoint can carry three valid
    cosignatures, which hold more than one quorum. This code uses all valid
    pinned cosignatures of a checkpoint that has a quorum.
    """
    indep = {w["key"].name for w in witnesses if w["independent"]}
    names = set(cp.cosigs)
    if len(names) < 2 or not names & indep:
        return None
    return sorted(cp.cosigs.values())


def lower(cp: Checkpoint, witnesses: list[dict]) -> int:
    q = quorum_times(cp, witnesses)
    if q is None:
        raise Refused("no_quorum")
    return q[0]


def upper(cp: Checkpoint, witnesses: list[dict]) -> int:
    q = quorum_times(cp, witnesses)
    if q is None:
        raise Refused("no_quorum")
    return q[-1]
