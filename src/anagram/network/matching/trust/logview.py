"""The entries of the enclave log that a reader checked against cosigned
checkpoints (spec/enclave-trust.md 2.4).

A rule that reads the log (the release rules, the line rules, the handoff
and the snapshot load) reads a `LogView`, never the log itself: every entry
in a view passed `check_entry`, and `logged_by` gives the signed time at
which each entry was first in a checkpoint with a quorum.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import merkle
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.entries import EntryError, check_entry, entry_digest
from anagram.network.matching.trust.roots import Roots, Witness, quorum_times


def _check_all(entries: list[JsonObject]) -> None:
    for e in entries:
        try:
            check_entry(e)
        except EntryError as exc:
            raise Refused("bad_attestation", str(exc)) from exc


@dataclass
class LogView:
    """The entries of the enclave log that the app checked against cosigned
    checkpoints, in log order. `logged_by[i]` is the earliest signed upper
    bound of the time at which entry i was in the log.

    `extend` puts new lists in place and never changes a list in place, so
    a `copy` stays the same while the view grows."""

    entries: list[JsonObject]
    logged_by: list[int]
    digests: list[bytes] = field(init=False)

    def __post_init__(self) -> None:
        self.digests = [entry_digest(e) for e in self.entries]

    @classmethod
    def from_checkpoints(cls, entries: list[JsonObject], notes: list[str], roots: Roots) -> LogView:
        _check_all(entries)
        leaves = [merkle.leaf_hash(canonical_json(e)) for e in entries]
        logged_by: list[int | None] = [None] * len(entries)
        for note in notes:
            _, size, _, upper, root = quorum_times(note, roots)
            if size > len(entries) or merkle.root(leaves[:size]) != root:
                raise Refused("bad_attestation", "checkpoint does not match the entries")
            for i in range(size):
                old = logged_by[i]
                if old is None or upper < old:
                    logged_by[i] = upper
        times = [t for t in logged_by if t is not None]
        if len(times) != len(logged_by):
            raise Refused("bad_attestation", "an entry is in no checkpoint")
        return cls(list(entries), times)

    def extend(self, more: list[JsonObject], note: str, roots: Roots) -> None:
        """Add the entries that a newer checkpoint with a quorum covers. The
        note must cover exactly the entries so far and `more`."""
        _check_all(more)
        _, size, _, upper, root = quorum_times(note, roots)
        entries = self.entries + more
        if size != len(entries):
            raise Refused("bad_attestation", "checkpoint does not match the entries")
        leaves = [merkle.leaf_hash(canonical_json(e)) for e in entries]
        if merkle.root(leaves) != root:
            raise Refused("bad_attestation", "checkpoint does not match the entries")
        self.entries = entries
        self.logged_by = self.logged_by + [upper] * len(more)
        self.digests = self.digests + [entry_digest(e) for e in more]

    def copy(self) -> LogView:
        """A view that does not grow: one operation reads one view, even
        when another thread extends this one meanwhile."""
        out = LogView.__new__(LogView)
        out.entries, out.logged_by, out.digests = self.entries, self.logged_by, self.digests
        return out

    def of_kind(self, kind: str) -> list[tuple[int, JsonObject]]:
        return [(i, e) for i, e in enumerate(self.entries) if e["kind"] == kind]

    def find(self, digest: bytes) -> int | None:
        return self.digests.index(digest) if digest in self.digests else None

    def cosign_quorum(
        self,
        digest: bytes,
        roots: Roots,
        before: int | None = None,
        independent_only: bool = False,
    ) -> bool:
        """True if 2 distinct pinned witnesses cosigned the entry with this
        digest (enclave_entry_cosign), at or before `before`. The plain quorum
        needs 1 independent witness; `independent_only` needs both cosigners
        to be independent (W4 ruling 7: the `security_fix` path, quorum
        revokes and new lines)."""
        by_key = {w.entry_key: w for w in roots.witnesses}
        seen: dict[str, Witness] = {}
        for _, e in self.of_kind("enclave_entry_cosign"):
            w = by_key.get(e["signer"])
            if w and e["entry"] == digest.hex() and (before is None or e["time"] <= before):
                seen[e["signer"]] = w
        good = [w for w in seen.values() if w.independent or not independent_only]
        return len(good) >= 2 and any(w.independent for w in good)

    def revoked(self, target: JsonObject, roots: Roots) -> bool:
        for i, e in self.of_kind("enclave_revoke"):
            if e["target"] == target and (
                e["signer"] == roots.release_key
                or self.cosign_quorum(self.digests[i], roots, independent_only=True)
            ):
                return True
        return False
