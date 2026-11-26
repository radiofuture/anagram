"""Commit a stream checkpoint through the client.

The client facade has `commit_finding` but no stream method. This module
adds one, with the same client primitives (the `Committer` port) and in the
same order:

1. Build the `anagram.stream_checkpoint.v1` fields and a salted opening.
2. Sign the root with the device key (`SignedSubject`, kind `stream_checkpoint`).
3. The caller stores the opening (sealed) before the node sees anything.
4. Submit the log entry. Check the checkpoint, the inclusion proof, and
   consistency with the last seen checkpoint (`Client.findings.check_submit`).
5. Make a proof bundle. `anagram.proofs.proof.verify_bundle` checks it offline.

The node receives only the public log entry: a kind and a hash.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from anagram.local.ports import Committer
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.proof import VerifyReport, build_bundle, verify_bundle
from anagram.proofs.records import (
    KIND_STREAM,
    Opening,
    SignedSubject,
    stream_checkpoint_fields,
    stream_items_root,
    stream_opening,
)


@dataclass(frozen=True)
class StreamCommit:
    root: bytes
    opening: Opening
    bundle: ProofBundle


def commit_stream_checkpoint(
    client: Committer,
    *,
    stream_id: bytes,
    seq: int,
    prev: bytes | None,
    start: int,
    item_roots: Sequence[bytes],
    store_opening: Callable[[bytes, Opening], None],
) -> StreamCommit:
    """Sign, store, and log one checkpoint over `item_roots`.

    `store_opening(root, opening)` must keep the opening safe (encrypted) before
    this function submits anything. Lost salts make a proof worthless."""
    key = client.device.device_key()
    fields = stream_checkpoint_fields(
        stream_id=stream_id,
        seq=seq,
        prev=prev,
        start=start,
        item_roots=list(item_roots),
        owner_key=key.public_bytes(),
        created_at=client.device.now(),
    )
    opening = stream_opening(fields)
    root = opening.root()
    subject = SignedSubject.sign(KIND_STREAM, root, key)
    store_opening(root, opening)
    result = client.node.submit(subject.log_entry())
    client.findings.check_submit(subject, result)
    return StreamCommit(root, opening, build_bundle(subject, result))


def verify_stream_commit(
    client: Committer,
    bundle: ProofBundle,
    opening: Opening | None = None,
    item_roots: Sequence[bytes] | None = None,
) -> tuple[VerifyReport, bool]:
    """Check the bundle offline against the client's pinned trust. With the
    opening and the item roots, also check that the committed `items_root`
    and `item_count` equal the items."""
    report = verify_bundle(bundle, client.device.trust())
    items_ok = True
    if opening is not None:
        items_ok = opening.root() == bundle.subject.root
        if item_roots is not None:
            items_ok = items_ok and (
                opening.fields["items_root"] == stream_items_root(list(item_roots)).hex()
                and opening.fields["item_count"] == len(item_roots)
            )
    return report, items_ok
