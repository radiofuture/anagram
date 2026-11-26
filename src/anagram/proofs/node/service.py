"""Node log service: accepts log entries, publishes cosigned and anchored checkpoints.

The node sees only log entries (kind and a hash). It never receives a root,
a salt, a signature, or any evidence.

The log publishes one checkpoint per entry. Batching is later.

A layer that writes public entries (L1: key bindings) gives a check for its
entry kind (`public_kinds`); the composition root (`NodeHome.service`) gives
the checks. The log service does not import the layers above it.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Mapping

from anagram.core.canonical import canonical_json
from anagram.core.errors import FormatError
from anagram.proofs.anchors.base import Anchor
from anagram.proofs.log.checkpoint import Checkpoint, sign_checkpoint
from anagram.proofs.log.note import NoteSigner, add_signature_lines
from anagram.proofs.log.store import SQLiteLog
from anagram.proofs.log.witness import Witness, WitnessConflict
from anagram.proofs.records import KINDS, LOG_ENTRY_SCHEMA, LOG_ONLY_KINDS

_HEX32 = re.compile(r"^[0-9a-f]{64}$")


class EntryRejected(ValueError):
    pass


MAX_RANGE = 1000

# A check of one public entry kind: it raises `FormatError` for a bad entry.
EntryCheck = Callable[[dict], object]


def validate_entry(entry: object, public_kinds: Mapping[str, EntryCheck] | None = None) -> bytes:
    """Return the leaf data of a valid entry: a hidden commitment, or a public
    entry of a kind in `public_kinds` (checked here only in form; for a key
    binding, the identity service checks the chain)."""
    check = (public_kinds or {}).get(entry.get("kind")) if isinstance(entry, dict) else None
    if check is not None:
        try:
            check(entry)
        except FormatError as exc:
            raise EntryRejected(f"bad {entry['kind'].replace('_', ' ')}: {exc}") from exc
        return canonical_json(entry)
    if not isinstance(entry, dict) or set(entry) != {"commitment", "kind", "schema"}:
        raise EntryRejected("entry must have exactly: commitment, kind, schema")
    if entry["schema"] != LOG_ENTRY_SCHEMA or entry["kind"] not in (*KINDS, *LOG_ONLY_KINDS):
        raise EntryRejected("unknown entry schema or kind")
    if not isinstance(entry["commitment"], str) or not _HEX32.match(entry["commitment"]):
        raise EntryRejected("commitment must be 64 lowercase hex chars")
    return canonical_json(entry)


class NodeService:
    def __init__(
        self,
        store: SQLiteLog,
        signer: NoteSigner,
        witnesses: list[Witness] | tuple = (),
        anchors: list[Anchor] | tuple = (),
        public_kinds: Mapping[str, EntryCheck] | None = None,
    ) -> None:
        self.store = store
        self.public_kinds = dict(public_kinds or {})
        self.signer = signer
        self.witnesses = list(witnesses)
        self.anchors = list(anchors)
        self._witness_size: dict[int, int] = {}
        self._lock = threading.Lock()

    @property
    def origin(self) -> str:
        return self.signer.name

    def submit(self, entry: dict) -> dict:
        data = validate_entry(entry, self.public_kinds)
        with self._lock:
            idx = self.store.append(data)
            size, note, anchors = self._publish()
        return {
            "anchors": anchors,
            "checkpoint": note,
            "inclusion": [h.hex() for h in self.store.inclusion_proof(idx, size)],
            "leaf_index": idx,
            "tree_size": size,
        }

    def _cosign(self, i: int, w: Witness, note: str, size: int) -> str:
        old = self._witness_size.get(i, 0)
        try:
            line = w.cosign(note, old, self.store.consistency_proof(old, size))
        except WitnessConflict as conflict:
            old = conflict.known_size
            line = w.cosign(note, old, self.store.consistency_proof(old, size))
        self._witness_size[i] = size
        return line

    def _publish(self) -> tuple[int, str, list[dict]]:
        size = self.store.size()
        cp = Checkpoint(self.origin, size, self.store.root(size))
        note = sign_checkpoint(cp, self.signer)
        lines = [self._cosign(i, w, note, size) for i, w in enumerate(self.witnesses)]
        note = add_signature_lines(note, lines)
        anchors = [a.stamp(cp.digest()) for a in self.anchors]
        self.store.save_checkpoint(size, note, json.dumps(anchors))
        return size, note, anchors

    def checkpoint(self) -> dict:
        latest = self.store.latest_checkpoint()
        if latest is None:
            return {"anchors": [], "checkpoint": None, "tree_size": 0}
        size, note, anchors = latest
        return {"anchors": json.loads(anchors), "checkpoint": note, "tree_size": size}

    def entries(self, start: int, end: int) -> list[str]:
        """Leaf data of entries start..end-1, as UTF-8 text (canonical JSON)."""
        size = self.store.size()
        if not 0 <= start <= end <= size or end - start > MAX_RANGE:
            raise ValueError(f"range must be inside 0..{size} and at most {MAX_RANGE} entries")
        return [self.store.entry(i).decode("utf-8") for i in range(start, end)]

    def inclusion(self, index: int, size: int) -> list[str]:
        return [h.hex() for h in self.store.inclusion_proof(index, size)]

    def consistency(self, old_size: int, new_size: int) -> list[str]:
        return [h.hex() for h in self.store.consistency_proof(old_size, new_size)]
