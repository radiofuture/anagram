"""The streams of the local index: checkpoints of the evidence of a source.

    index.streams.pending(sid)                  # evidence roots with no checkpoint
    index.streams.checkpoint_due(sid, 3600)
    index.streams.checkpoint(client, sid)       # Merkle root of new items -> log
    index.streams.verify_checkpoint(client, sid, seq)

`Streams` is the part `LocalIndex.streams`. Each source is one stream. A
checkpoint commits the Merkle root over the pending evidence roots
(`anagram.stream_checkpoint.v1`, spec/index.md section 2). A source whose
items are the work of other people, or one that is being removed, gets no
checkpoint.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from anagram.core.crypto.hashing import TAG_STREAM_ROOT
from anagram.core.timefmt import seconds
from anagram.local.index.commit import StreamCommit, commit_stream_checkpoint, verify_stream_commit
from anagram.local.index.store import dumps, loads
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.records import Opening

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex
    from anagram.local.ports import Committer


class Streams:
    """The stream part of one `LocalIndex`."""

    def __init__(self, index: LocalIndex) -> None:
        self.index = index
        self.store = index.store

    def pending(self, sid: str) -> list[bytes]:
        """Evidence roots that wait for a checkpoint. A source with
        `own = False`, or one that is being removed, has none."""
        if not self.index.is_own(sid) or self.index.removing(sid):
            return []
        return [
            bytes.fromhex(r[0])
            for r in self.store.q(
                "SELECT root FROM version WHERE source_id = ? AND checkpoint_seq IS NULL"
                " ORDER BY id",
                (sid,),
            )
        ]

    def checkpoint_due(self, sid: str, interval_s: int) -> bool:
        """True when the source has new items and the last checkpoint is older
        than `interval_s` (or there is none)."""
        if not self.pending(sid):
            return False
        last = self.index.source(sid)["last_checkpoint_at"]
        if last is None:
            return True
        then = seconds(last)
        return self.index.clock() - then >= interval_s

    def checkpoint(self, client: Committer, sid: str) -> StreamCommit | None:
        """Commit the pending items of one source as the next checkpoint.
        Return None when nothing is pending."""
        index = self.index
        if not index.is_own(sid) or index.removing(sid):
            return None
        src = index.source(sid)
        rows = self.store.q(
            "SELECT id, root FROM version WHERE source_id = ? AND checkpoint_seq IS NULL"
            " ORDER BY id",
            (sid,),
        )
        if not rows:
            return None
        vids = [r[0] for r in rows]
        roots_hex = [r[1] for r in rows]
        seq = src["seq"]

        def store_opening(root: bytes, opening: Opening) -> None:
            # Reserved inside BEGIN IMMEDIATE before the node sees anything:
            # never overwrite an existing checkpoint opening or its salts.
            with self.store.transaction():
                cur_src = self.store.one("SELECT seq FROM source WHERE id = ?", (sid,))
                if cur_src is None or cur_src["seq"] != seq:
                    raise RuntimeError(f"concurrent checkpoint for {sid} at seq {seq}")
                existing = self.store.one(
                    "SELECT root, bundle FROM checkpoint WHERE source_id = ? AND seq = ?",
                    (sid, seq),
                )
                if existing is not None:
                    raise RuntimeError(
                        f"checkpoint {seq} for {sid} already exists; refusing to overwrite salts"
                    )
                self.store.x(
                    "INSERT INTO checkpoint (source_id, seq, root, opening, item_roots,"
                    " bundle, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?)",
                    (
                        sid,
                        seq,
                        root.hex(),
                        dumps(opening.to_json()),
                        dumps(roots_hex),
                        index.now(),
                    ),
                )

        result = commit_stream_checkpoint(
            client,
            stream_id=bytes.fromhex(src["stream_id"]),
            seq=seq,
            prev=bytes.fromhex(src["prev"]) if src["prev"] else None,
            start=src["start"],
            item_roots=[bytes.fromhex(r) for r in roots_hex],
            store_opening=store_opening,
        )
        with self.store.transaction():
            updated = self.store.x(
                "UPDATE source SET last_checkpoint_at = ?, prev = ?, seq = ?, start = ?"
                " WHERE id = ? AND seq = ?",
                (index.now(), result.root.hex(), seq + 1, src["start"] + len(vids), sid, seq),
            )
            if updated.rowcount != 1:
                raise RuntimeError(f"concurrent checkpoint update for {sid} at seq {seq}")
            self.store.x(
                "UPDATE checkpoint SET bundle = ? WHERE source_id = ? AND seq = ?",
                (dumps(result.bundle.to_json()), sid, seq),
            )
            self.store.many(
                "UPDATE version SET checkpoint_seq = ? WHERE id = ?", [(seq, v) for v in vids]
            )
        return result

    def checkpoints(self, sid: str) -> list[dict]:
        return [
            {
                "bundle": loads(r["bundle"]),
                "item_roots": loads(r["item_roots"]),
                "opening": loads(r["opening"]),
                "root": r["root"],
                "seq": r["seq"],
            }
            for r in self.store.q(
                "SELECT * FROM checkpoint WHERE source_id = ? ORDER BY seq", (sid,)
            )
        ]

    def verify_checkpoint(self, client: Committer, sid: str, seq: int):
        """Offline check of one stored checkpoint: the proof bundle against the
        pinned trust, and the opening against the stored item roots."""

        row = self.store.one("SELECT * FROM checkpoint WHERE source_id = ? AND seq = ?", (sid, seq))
        if row is None or row["bundle"] is None:
            raise KeyError(f"no logged checkpoint {seq} for {sid}")
        bundle = ProofBundle.from_json(loads(row["bundle"]))
        opening = Opening.from_json(TAG_STREAM_ROOT, loads(row["opening"]))
        roots = [bytes.fromhex(r) for r in loads(row["item_roots"])]
        return verify_stream_commit(client, bundle, opening, roots)
