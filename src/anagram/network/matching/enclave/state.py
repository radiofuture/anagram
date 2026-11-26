"""What one enclave instance is given, and its roles (spec/enclave-trust.md
1, 5, 6).

- `Role`: the role of an instance in its line (see `instance.py`);
- `Release`: the logged release entry and its descriptors;
- `Host`: what the operator gives a line: disk, log, control feed, clock;
- `LogPort`, `FeedPort`: the log and the control feed as an instance
  uses them.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.entries import entry_digest
from anagram.network.matching.trust.logview import LogView

EPOCH = 600  # 6.3: an epoch at each 10-minute boundary
RENEW = 43_200  # a new lease every 12 hours
SNAPSHOT_SIZES = (1 << 20, 1 << 22, 1 << 24, 1 << 26)  # size buckets (6.1)


class Role(StrEnum):
    """The role of an instance in its line. The sealed record keeps the
    value, so a restarted instance has the same role."""

    NEW = "new"
    WRITER = "writer"
    HOLDER = "holder"
    DRAINING = "draining"
    RETIRED = "retired"


class Forbidden(Refused):
    """A relay request with no valid node request signature (`403`)."""

    def __init__(self, detail: str) -> None:
        super().__init__("forbidden", detail)


class NotReady(Refused):
    """Nothing to serve yet: a receipt before release (`404`), a batch
    before its cosigned epoch (`503`)."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("not_ready", detail)


class LogPort(Protocol):
    """The transparency log as an instance uses it (section 2)."""

    origin: str

    def view(self) -> LogView: ...

    def checkpoint(self) -> str: ...

    def append(self, entry: JsonObject) -> int: ...

    def append_instance_key(self, entry: JsonObject, document: JsonObject) -> int: ...

    def root_at(self, size: int) -> bytes: ...


class FeedPort(Protocol):
    """Control events of the roster and of each node (spec/network.md 8.5)."""

    def events(self, chain: str, after: int) -> list[JsonObject]: ...


@dataclass(frozen=True)
class Release:
    """What an instance runs: the logged release entry and its descriptors."""

    entry: JsonObject
    descriptors: tuple[JsonObject, ...]

    def __post_init__(self) -> None:
        dsc.check_set(list(self.descriptors), self.entry["descriptor_hashes"])

    def kind(self, name: str) -> list[JsonObject]:
        return [d for d in self.descriptors if d["kind"] == name]

    @property
    def matching(self) -> JsonObject:
        body: JsonObject = self.kind("matching")[0]["body"]  # checked by `dsc.check_set`
        return body

    @property
    def digest(self) -> bytes:
        return entry_digest(self.entry)

    @property
    def descriptor_set(self) -> bytes:
        return dsc.set_hash(list(self.descriptors))


@dataclass
class Host:
    """What the operator gives a line: disk for sealed snapshots, the log,
    the control feed and the host clock. All untrusted."""

    log: LogPort
    feed: FeedPort
    clock: Callable[[], int]
    disk: MutableMapping[int, bytes] = field(default_factory=dict)
