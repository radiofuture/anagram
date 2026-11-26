"""Follow the public enclave log from its read API (spec/enclave-trust.md
2.1, 2.4).

`LogFollower` keeps a `LogView` that only grows. A fresh reader also asks
`covering` for each run of timed entries: the release rules (2.5), the
total-loss rule (5.6) and rule 7 (a) need the time at which an entry was
first in a cosigned checkpoint, and the latest checkpoint alone would give
"now". The app, the enclave host and the witnesses read the log this way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from anagram.core.canonical import JsonObject
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

# Entries whose log time (`logged_by`) a rule uses: the notice and rebuild
# rules (2.5), the lease bound (rule 7 (a)) and the total-loss rule (5.6).
TIMED_KINDS = frozenset(
    {"enclave_release", "enclave_rebuild", "enclave_line", "enclave_instance_key"}
)


class LogReader(Protocol):
    """The public enclave log: entries, and the first cosigned checkpoint
    that holds an entry (enclave-trust.md 2.4)."""

    def read(self, start: int, end: int) -> list[JsonObject]: ...

    def covering(self, index: int) -> str: ...


def checkpoint_size(note: str) -> int:
    """The tree size: the second line of a C2SP checkpoint."""
    return int(note.split("\n")[1])


@dataclass
class LogFollower:
    reader: LogReader
    roots: Roots
    view: LogView | None = None  # what was checked so far; it only grows

    def follow(self, note: str) -> LogView:
        """Grow the checked view to the checkpoint `note` (2.4)."""
        size = checkpoint_size(note)
        if self.view is None:
            entries = self.reader.read(0, size) if size else []
            notes = [*self._covering(entries, size), note]
            self.view = LogView.from_checkpoints(entries, notes, self.roots)
        elif size > len(self.view.entries):
            more = self.reader.read(len(self.view.entries), size)
            self.view.extend(more, note, self.roots)
        return self.view

    def _covering(self, entries: list[JsonObject], size: int) -> list[str]:
        """One covering checkpoint serves every entry below its size, so
        the reader asks once for each run of timed entries."""
        notes: list[str] = []
        covered = 0
        for i, e in enumerate(entries):
            if i < covered or e["kind"] not in TIMED_KINDS:
                continue
            cp = self.reader.covering(i)
            covered = checkpoint_size(cp)
            if covered <= size:
                notes.append(cp)
        return notes
