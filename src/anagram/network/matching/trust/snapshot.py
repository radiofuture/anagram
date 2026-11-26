"""Sealed snapshots and the load rule (spec/enclave-trust.md 6.1, 6.2).

A snapshot is one whole state, padded to a fixed size bucket and sealed
with the line's state key, so host disk I/O shows no record (review H2). It
loads only at the counter of the line's latest state epoch with the logged
digest, so a restore of an older snapshot undoes nothing (review B3).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json, loads_canonical
from anagram.core.crypto import aead
from anagram.core.crypto.hashing import lp, sha256
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.lines import line_forked
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

SCHEMA = "anagram.enclave.snapshot.v1"
NONCE = 12


def header(line_id: str, counter: int, size: int) -> JsonObject:
    return {"counter": counter, "line_id": line_id, "schema": SCHEMA, "size": size}


def seal(state_key: bytes, line_id: str, counter: int, size: int, body: bytes) -> bytes:
    """`size` is the bucket of the plaintext. The nonce is random."""
    return _seal_with_nonce(state_key, line_id, counter, size, body, None)


def _seal_with_nonce(
    state_key: bytes, line_id: str, counter: int, size: int, body: bytes, nonce: bytes | None
) -> bytes:
    """`seal` with a given nonce. Only the vectors give one: a nonce used
    twice under one state key breaks the AEAD."""
    if 4 + len(body) > size:
        raise ValueError(f"state of {len(body)} bytes does not fit the {size}-byte bucket")
    head = canonical_json(header(line_id, counter, size))
    plain = len(body).to_bytes(4, "big") + body + bytes(size - 4 - len(body))
    nonce, ct = aead.seal(state_key, plain, head, nonce=nonce)
    return lp(head) + nonce + ct


def digest(sealed: bytes) -> bytes:
    return sha256(sealed)


def open_snapshot(state_key: bytes, sealed: bytes) -> tuple[JsonObject, bytes]:
    """Return (header, body). A snapshot that does not open is
    `snapshot_unknown`: it is counted, not loaded."""
    try:
        n = int.from_bytes(sealed[:4], "big")
        head_raw = sealed[4 : 4 + n]
        head = loads_canonical(head_raw)
        nonce, ct = sealed[4 + n : 4 + n + NONCE], sealed[4 + n + NONCE :]
        plain = aead.open_sealed(state_key, nonce, ct, head_raw)
    except (InvalidTag, CanonicalError, ValueError) as exc:
        raise Refused("snapshot_unknown", "does not open") from exc
    if not (
        isinstance(head, dict)
        and isinstance(line_id := head.get("line_id"), str)
        and type(counter := head.get("counter")) is int
        and head == header(line_id, counter, len(plain))
    ):
        raise Refused("snapshot_unknown", "header")
    size = int.from_bytes(plain[:4], "big")
    if 4 + size > len(plain) or any(plain[4 + size :]):
        raise Refused("snapshot_unknown", "padding")
    return head, plain[4 : 4 + size]


def check_load(
    view: LogView,
    roots: Roots,
    line_id: str,
    counter: int,
    digest_hex: str,
    handoff: tuple[str, int, str] | None = None,
) -> None:
    """Section 6.2: the line is not forked; the counter is the counter of
    the line's latest state epoch (older: `snapshot_stale`); the digest is
    that epoch's digest (else `snapshot_unknown`). The view holds only
    entries of checkpoints with a quorum; the caller checks that the newest
    one is fresh (1 hour).

    `handoff` is (loader instance ID, counter, snapshot digest) of the
    handoff message that gave the loader the state key. The message named
    the epoch before the handoff; the epoch that loads is the next one,
    which names the loader as `next_writer` (5.3 step 5). So the latest
    epoch must name the loader, its counter must be one more than the
    message's, and the epoch at the message's counter must have the
    message's digest (else `snapshot_unknown`)."""
    if line_forked(view, line_id, roots):
        raise Refused("line_forked")
    epochs = [e for _, e in view.of_kind("enclave_state_epoch") if e["line_id"] == line_id]
    if not epochs:
        raise Refused("snapshot_unknown", "the line has no state epoch")
    latest = epochs[-1]
    if counter < latest["counter"]:
        raise Refused("snapshot_stale")
    if counter != latest["counter"] or digest_hex != latest["snapshot_digest"]:
        raise Refused("snapshot_unknown")
    if handoff is None:
        return
    loader, sent, sent_digest = handoff
    if sent < 0 or latest["next_writer"] != loader or latest["counter"] != sent + 1:
        raise Refused("snapshot_unknown", "the latest epoch does not hand the line to the loader")
    if epochs[sent]["snapshot_digest"] != sent_digest:
        raise Refused("snapshot_unknown", "the handoff names another snapshot")
