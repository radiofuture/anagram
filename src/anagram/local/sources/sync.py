"""Source contract v2: a source that gives changes with a cursor.

Contract v1 (`base.py`) stays valid: `scan(known)` yields all current items
and the index finds what changed. That is correct for a local folder. It is
too slow for a mailbox with 100 000 messages.

A connector is a v2 source if it has a `sync` method. `sync(ctx)` yields
changes (`Upsert`, `Delete`), progress (`Note`), and cursors (`Cursor`). The
sync engine (`local/sources/sync_engine.py`) makes all changes before a `Cursor` and
the cursor itself durable in one transaction.

Rules for a v2 source:

1. Yield a `Cursor` after each page, or after a batch of at most 200 upserts.
   A crash loses at most one batch, and the batch is read again.
2. `sync` is idempotent. An `Upsert` with the digest of the current version
   changes nothing.
3. A `Delete` of an unknown key changes nothing.
4. Stop at the next `Cursor` when `ctx.stop()` is true or the time is after
   `ctx.deadline`. The state in that cursor must let the next call continue.
5. Do not hold the full item list in memory. Use `ctx.known(key)`.
6. Raise `SourceFault` (`http.py`) for a fault that the person must see. Each
   other exception becomes the fault `unknown`.
7. `scan()` of a v2 source raises `ConnectorError("use sync")`. The index
   never calls it.

A cursor state, a note, and a fault hold no token and no item text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol

from anagram.local.sources.base import EvidenceItem, KnownItem, SourceContext

if TYPE_CHECKING:  # the account type comes with the credential store
    from anagram.local.sources.credentials import Account

BATCH_MAX = 200  # the largest number of upserts between two cursors

PHASES = ("first_sync", "live", "reconcile")
AUTH_KINDS = ("none", "oauth", "api_key")


@dataclass(frozen=True)
class Upsert:
    item: EvidenceItem  # a new item or a new version of an item


@dataclass(frozen=True)
class Delete:
    key: str  # an exact key
    prefix: bool = False  # True: each key that starts with `key`


@dataclass(frozen=True)
class Cursor:
    state: dict  # JSON; replaces the stored state; durable with the changes before it


def copy_cursor_state(state: dict, nested: tuple[str, ...] = ("backfill",)) -> dict:
    """A copy of the cursor state for a `Cursor` (the connector changes its
    own state after the yield): the `nested` dicts and the `seen` list are
    copied too."""
    out = dict(state)
    for key in nested:
        out[key] = dict(state[key])
    if "seen" in state:
        out["seen"] = list(state["seen"])
    return out


@dataclass(frozen=True)
class Note:
    """Progress that the person can see. All fields are optional."""

    phase: str | None = None  # "first_sync" | "live" | "reconcile"
    total: int | None = None  # estimate of items in the first sync
    done: int | None = None
    at: str | None = None  # RFC 3339 time of the oldest item read so far
    skipped: int = 0  # items that a filter or a limit left out, so far; 0 keeps the stored count

    def __post_init__(self) -> None:
        if self.phase is not None and self.phase not in PHASES:
            raise ValueError(f"unknown sync phase: {self.phase}")


Change = Upsert | Delete | Cursor | Note


@dataclass(frozen=True)
class SyncContext:
    state: dict  # the stored cursor state ({} on first run)
    known: Callable[[str], KnownItem | None]  # one indexed lookup; no full list
    known_keys: Callable[[str], Iterator[str]]  # keys with a prefix (for threads, reconcile)
    deadline: float  # monotonic time; stop at a Cursor after it
    stop: Callable[[], bool]  # True: pause or removal was requested


class SyncSource(Protocol):
    """The contract of a v2 source. `fetch`, `choices`, and `preview` are
    optional: a source has `fetch` only if it is `refetchable`."""

    kind: ClassVar[str]
    auth: ClassVar[str]  # "none" | "oauth" | "api_key"
    refetchable: ClassVar[bool]  # True: `fetch` can get the same bytes again

    def sync(self, ctx: SyncContext) -> Iterator[Change]: ...

    def fetch(self, key: str, extra: dict) -> bytes: ...

    @classmethod
    def choices(cls, ctx: SourceContext, account: Account, parent: str | None) -> dict: ...

    @classmethod
    def preview(cls, ctx: SourceContext, cfg: dict) -> dict: ...


def is_sync_source(conn: object) -> bool:
    """True for a v2 source (an object or a class with a `sync` method)."""
    return callable(getattr(conn, "sync", None))


def is_own(conn: object) -> bool:
    """False for a source whose items are the work of other people (the
    kind `labspace`). A source with no `own` flag is the member's own, so an
    entry-point source with only `scan` needs no change."""
    return bool(getattr(conn, "own", True))
