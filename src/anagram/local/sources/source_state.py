"""State of a source: space, status, pause, cursor, progress, fault, and the
source event log.

Tables (in `store.py`, all inside SQLCipher): `source_state`, `account`,
`source_event`. This module has the read and write functions for
`source_state` and `source_event`. The credential store (`credentials.py`)
owns the rows of `account`.

Each source has one `source_state` row, contract v1 sources too (for `space`,
`paused`, `status`). `ensure` makes the row on first read, so an old store
needs no migration. A source with no row is in the private space.

Status. The stored status is one of `first_sync`, `live`, `waiting` (rate
limit or no connection; `next_at` says when to try again), `attention` (the
person must act), `removing`. `paused` is a separate flag, so that a resume
gives back the status from before the pause. The status that the person sees
(`SourceState.status`) is `paused` when the flag is set. `removing` is final.

Space. `source_state.space` is `private` or `lab:<lab id>`. It is the one
field for the space of a source and of its items. The lab code owns the meaning
of a lab space; this module stores the value and calls each space hook that the
caller gives (`set_space(..., hooks=...)`) after a change.

Events. Index code does not call the UI event bus. It calls
`publish(topic, data)`, and for sources that callable is `publisher(store)`:
it appends a row to `source_event`. The UI process reads the rows with
`events_after` and sends them on its one event stream. This works with one
process and with two. An event holds no token, no item name, and no item
text.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from anagram.core.timefmt import format_time
from anagram.local.index.store import IndexStore, dumps, loads

log = logging.getLogger("anagram.local.index")

PRIVATE = "private"
_LAB_SPACE = re.compile(r"^lab:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

FIRST_SYNC = "first_sync"
LIVE = "live"
WAITING = "waiting"
ATTENTION = "attention"
REMOVING = "removing"
PAUSED = "paused"  # shown only; the stored value is the flag `paused`
STORED_STATUSES = (FIRST_SYNC, LIVE, WAITING, ATTENTION, REMOVING)

# fault code -> (status, the one action for the person)
FAULTS: dict[str, tuple[str, str | None]] = {
    "rate_limited": (WAITING, None),
    "offline": (WAITING, None),
    "quota": (WAITING, None),
    "auth_expired": (ATTENTION, "signin"),
    "permission_lost": (ATTENTION, "choose"),
    "not_found": (ATTENTION, "choose"),
    "client_missing": (ATTENTION, None),
    "unknown": (WAITING, None),
}
UNKNOWN_MAX = 5  # after this number of failures, `unknown` needs the person
BACKOFF_MAX_S = 15 * 60.0
QUOTA_WAIT_S = 60 * 60.0  # when the connector gives no time for a quota fault
DETAIL_MAX = 200

TOPICS = frozenset(
    {
        "source.added",
        "source.progress",
        "source.state",
        "source.removed",
        "account.state",
        "oauth.flow",
    }
)
EVENT_KEEP = 2000

Publish = Callable[[str, dict], None]

# A space hook gets (source id, old space, new space) after a space change.
# The lab space (L3) gives one; the caller passes it to `set_space`.
SpaceHook = Callable[[str, str, str], None]


class SourceStateError(Exception):
    pass


class SpaceHookError(SourceStateError):
    """One or more space hooks failed. The new space is stored."""


@dataclass(frozen=True)
class SourceState:
    source_id: str
    account_id: str | None
    space: str
    stored_status: str
    paused: bool
    cursor: dict
    phase: str | None
    total: int | None
    done: int | None
    at: str | None
    skipped: int
    error_code: str | None
    error_detail: str | None
    error_at: str | None
    failures: int
    next_at: float
    updated_at: float

    @property
    def status(self) -> str:
        """The status that the person sees."""
        if self.paused and self.stored_status != REMOVING:
            return PAUSED
        return self.stored_status

    @property
    def fault(self) -> dict | None:
        """`{"code", "action", "retry_at"}`, or None with no fault. The
        sentence for the person is UI text and is not made here."""
        if self.error_code is None:
            return None
        action = FAULTS.get(self.error_code, (WAITING, None))[1]
        if self.error_code == "unknown" and self.stored_status == ATTENTION:
            action = "retry"
        waiting = self.stored_status == WAITING and self.next_at > 0
        return {
            "action": action,
            "code": self.error_code,
            "retry_at": self.next_at if waiting else None,
        }

    def due(self, now: float) -> bool:
        """True if a sync can run now."""
        if self.paused or self.stored_status in (REMOVING, ATTENTION):
            return False
        return self.next_at <= now


def backoff(n: int) -> float:
    """Seconds to wait after failure number `n` (1, 2, ...): 30, 60, 120,
    and so on, up to 15 minutes."""
    return min(BACKOFF_MAX_S, 30.0 * 2.0 ** max(0, n - 1))


def check_space(space: str) -> str:
    if space == PRIVATE or (isinstance(space, str) and _LAB_SPACE.match(space)):
        return space
    raise SourceStateError("a space is 'private' or 'lab:<lab id>'")


def state_event(state: SourceState) -> dict:
    """The data of a `source.state` event."""
    return {
        "fault": state.fault,
        "id": state.source_id,
        "paused": state.paused,
        "space": state.space,
        "status": state.status,
    }


# ------------------------------------------------------------------- rows

_COLUMNS = (
    "source_id, account_id, space, status, paused, cursor, phase, total, done, at, skipped, "
    "error_code, error_detail, error_at, failures, next_at, updated_at"
)


def _state(row) -> SourceState:
    return SourceState(
        source_id=row["source_id"],
        account_id=row["account_id"],
        space=row["space"],
        stored_status=row["status"],
        paused=bool(row["paused"]),
        cursor=loads(row["cursor"]) or {},
        phase=row["phase"],
        total=row["total"],
        done=row["done"],
        at=row["at"],
        skipped=row["skipped"],
        error_code=row["error_code"],
        error_detail=row["error_detail"],
        error_at=row["error_at"],
        failures=row["failures"],
        next_at=row["next_at"],
        updated_at=row["updated_at"],
    )


def read(store: IndexStore, sid: str) -> SourceState | None:
    """The state row, or None. It does not make a row."""
    row = store.one(f"SELECT {_COLUMNS} FROM source_state WHERE source_id = ?", (sid,))  # noqa: S608
    return None if row is None else _state(row)


def ensure(
    store: IndexStore,
    sid: str,
    now: float | None = None,
    *,
    account_id: str | None = None,
    space: str = PRIVATE,
) -> None:
    """Make the state row of a source if it is absent. A source that was
    scanned before (an old store) starts as `live`; a new source starts as
    `first_sync`. `account_id` and `space` apply only to a new row."""
    if store.one("SELECT 1 FROM source_state WHERE source_id = ?", (sid,)) is not None:
        return
    src = store.one("SELECT last_scan_at FROM source WHERE id = ?", (sid,))
    if src is None:
        raise SourceStateError("unknown source")
    status = LIVE if src["last_scan_at"] else FIRST_SYNC
    store.x(
        "INSERT OR IGNORE INTO source_state (source_id, account_id, space, status, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (sid, account_id, check_space(space), status, time.time() if now is None else now),
    )


def get(store: IndexStore, sid: str, now: float | None = None) -> SourceState:
    """The state of a source. It makes the row on first read."""
    ensure(store, sid, now)
    state = read(store, sid)
    if state is None:  # the row was deleted between the two statements
        raise SourceStateError("unknown source")
    return state


def sources_in_space(store: IndexStore, space: str) -> list[str]:
    """IDs of the sources in a space, in ID order. A source with no state row
    is in the private space."""
    check_space(space)
    rows = store.q(
        "SELECT s.id FROM source s LEFT JOIN source_state st ON st.source_id = s.id "
        "WHERE coalesce(st.space, ?) = ? ORDER BY s.id",
        (PRIVATE, space),
    )
    return [r[0] for r in rows]


def _update(
    store: IndexStore, sid: str, now: float, publish: Publish | None, sets: dict
) -> SourceState:
    """Write columns of one row. Publish `source.state` if the data of that
    event changed."""
    with store.transaction():
        before = get(store, sid, now)
        cols = {**sets, "updated_at": now}
        store.x(
            f"UPDATE source_state SET {', '.join(f'{c} = ?' for c in cols)} "  # noqa: S608
            "WHERE source_id = ?",
            (*cols.values(), sid),
        )
        after = get(store, sid, now)
    if publish is not None and state_event(before) != state_event(after):
        publish("source.state", state_event(after))
    return after


def _not_removing(store: IndexStore, sid: str, now: float) -> SourceState:
    state = get(store, sid, now)
    if state.stored_status == REMOVING:
        raise SourceStateError("the source is being removed")
    return state


_NO_ERROR = {
    "error_code": None,
    "error_detail": None,
    "error_at": None,
    "failures": 0,
    "next_at": 0.0,
}

# ----------------------------------------------------------- state machine


def set_status(
    store: IndexStore, sid: str, status: str, *, now: float, publish: Publish | None = None
) -> SourceState:
    """Set the stored status. `first_sync` and `live` clear the fault.
    `removing` is final: no other status can follow it. Use `set_fault` for
    `waiting` and `attention` with a fault."""
    if status not in STORED_STATUSES:
        raise SourceStateError(f"unknown status: {status}")
    with store.transaction():
        state = get(store, sid, now)
        if state.stored_status == REMOVING and status != REMOVING:
            raise SourceStateError("the source is being removed")
        sets: dict = {"status": status}
        if status in (FIRST_SYNC, LIVE):
            sets.update(_NO_ERROR)
        return _update(store, sid, now, publish, sets)


def pause(
    store: IndexStore, sid: str, *, now: float, publish: Publish | None = None
) -> SourceState:
    with store.transaction():
        _not_removing(store, sid, now)
        return _update(store, sid, now, publish, {"paused": 1})


def resume(
    store: IndexStore, sid: str, *, now: float, publish: Publish | None = None
) -> SourceState:
    """Clear the pause flag. The status from before the pause shows again."""
    with store.transaction():
        _not_removing(store, sid, now)
        return _update(store, sid, now, publish, {"paused": 0})


def set_fault(
    store: IndexStore,
    sid: str,
    code: str,
    detail: str = "",
    *,
    now: float,
    retry_at: float | None = None,
    publish: Publish | None = None,
) -> SourceState:
    """Record a fault of the source. The cursor stays. The code gives the
    status: `waiting` with a time for the next try, or
    `attention`. A code that is not a source fault is recorded as `unknown`.
    `unknown` becomes `attention` after `UNKNOWN_MAX` failures in sequence.
    `detail` must hold no secret; only its first 200 characters are kept."""
    if code not in FAULTS:
        code = "unknown"
    with store.transaction():
        state = _not_removing(store, sid, now)
        status = FAULTS[code][0]
        failures = state.failures + 1
        if code == "unknown" and failures >= UNKNOWN_MAX:
            status = ATTENTION
        if status == ATTENTION:
            next_at = 0.0
        elif retry_at is not None:
            next_at = float(retry_at)
        elif code == "quota":
            next_at = now + QUOTA_WAIT_S
        else:
            next_at = now + backoff(failures)
        return _update(
            store,
            sid,
            now,
            publish,
            {
                "status": status,
                "error_code": code,
                "error_detail": detail[:DETAIL_MAX] or None,
                "error_at": format_time(datetime.fromtimestamp(int(now), UTC)),
                "failures": failures,
                "next_at": next_at,
            },
        )


def clear_fault(
    store: IndexStore, sid: str, *, now: float, publish: Publish | None = None
) -> SourceState:
    """Remove the fault after a run with no fault, or when the person acted
    (sign in, choose again, try again). The status becomes `first_sync` if the
    first sync is not complete, else `live`. With no fault, nothing changes."""
    with store.transaction():
        state = _not_removing(store, sid, now)
        if state.error_code is None and state.stored_status in (FIRST_SYNC, LIVE):
            return state
        first = state.phase == FIRST_SYNC
        if state.phase is None:
            src = store.one("SELECT last_scan_at FROM source WHERE id = ?", (sid,))
            first = src is None or not src["last_scan_at"]
        return _update(
            store, sid, now, publish, {"status": FIRST_SYNC if first else LIVE, **_NO_ERROR}
        )


# ------------------------------------------------------- cursor, progress


def set_cursor(store: IndexStore, sid: str, state: dict, *, now: float) -> None:
    """Replace the cursor state. The sync engine calls this in the same
    transaction as the changes that came before the cursor."""
    if not isinstance(state, dict):
        raise SourceStateError("a cursor state is a JSON object")
    ensure(store, sid, now)
    store.x(
        "UPDATE source_state SET cursor = ?, updated_at = ? WHERE source_id = ?",
        (dumps(state), now, sid),
    )


def set_progress(
    store: IndexStore,
    sid: str,
    *,
    now: float,
    phase: str | None = None,
    total: int | None = None,
    done: int | None = None,
    at: str | None = None,
    skipped: int | None = None,
) -> None:
    """Record progress that the person can see. A value of None keeps the
    stored value."""
    ensure(store, sid, now)
    store.x(
        "UPDATE source_state SET phase = coalesce(?, phase), total = coalesce(?, total), "
        "done = coalesce(?, done), at = coalesce(?, at), skipped = coalesce(?, skipped), "
        "updated_at = ? WHERE source_id = ?",
        (phase, total, done, at, skipped, now, sid),
    )


def set_account(store: IndexStore, sid: str, account_id: str | None, *, now: float) -> None:
    ensure(store, sid, now)
    store.x(
        "UPDATE source_state SET account_id = ?, updated_at = ? WHERE source_id = ?",
        (account_id, now, sid),
    )


def account_view(store: IndexStore, account_id: str | None) -> dict | None:
    """`{"id", "label"}` of the account of a source, for a source row. None
    if the source has no account. The `account` table holds no token."""
    if account_id is None:
        return None
    row = store.one("SELECT id, label FROM account WHERE id = ?", (account_id,))
    return None if row is None else {"id": row["id"], "label": row["label"]}


# ------------------------------------------------------------------ space


def set_space(
    store: IndexStore,
    sid: str,
    space: str,
    *,
    now: float,
    publish: Publish | None = None,
    hooks: Iterable[SpaceHook] = (),
) -> SourceState:
    """Store the space of a source. After a change: publish `source.state`,
    then call each of `hooks` with (source id, old space, new space). Each hook runs, also after a hook that failed; then
    `SpaceHookError` tells the caller that a hook failed. The new space stays
    stored in that case.

    This function does not ask a lab policy and does not look at the source
    kind. The caller does these checks before the call."""
    check_space(space)
    with store.transaction():
        old = _not_removing(store, sid, now).space
        state = _update(store, sid, now, None, {"space": space})
    if old == space:
        return state
    if publish is not None:
        publish("source.state", state_event(state))
    failed = 0
    for hook in hooks:
        try:
            hook(sid, old, space)
        except Exception as exc:  # one hook must not stop the others
            failed += 1
            log.error("space hook failed: %s", type(exc).__name__)
    if failed:
        raise SpaceHookError(f"{failed} space hook(s) failed; the space is stored")
    return state


# ----------------------------------------------------------------- events


def append_event(store: IndexStore, topic: str, data: dict, now: float) -> int:
    """Append one event and return its ID. The table keeps the last
    `EVENT_KEEP` rows. IDs always increase, also after old rows are gone."""
    if topic not in TOPICS:
        raise SourceStateError(f"unknown source event topic: {topic}")
    if not isinstance(data, dict):
        raise SourceStateError("event data is a JSON object")
    with store.transaction():
        cur = store.x(
            "INSERT INTO source_event (at, topic, data) VALUES (?, ?, ?)",
            (now, topic, dumps(data)),
        )
        eid = int(cur.lastrowid)
        store.x("DELETE FROM source_event WHERE id <= ?", (eid - EVENT_KEEP,))
    return eid


def events_after(store: IndexStore, last_id: int, limit: int = 200) -> list[dict]:
    """Events with an ID above `last_id`, oldest first:
    `{"id", "at", "topic", "data"}`."""
    rows = store.q(
        "SELECT id, at, topic, data FROM source_event WHERE id > ? ORDER BY id LIMIT ?",
        (int(last_id), int(limit)),
    )
    return [
        {"id": r["id"], "at": r["at"], "topic": r["topic"], "data": loads(r["data"])} for r in rows
    ]


def last_event_id(store: IndexStore) -> int:
    """The ID of the newest event, or 0. A reader that wants only new events
    starts from this value."""
    row = store.one("SELECT max(id) FROM source_event")
    return int(row[0] or 0)


def publisher(store: IndexStore, clock: Callable[[], float] = time.time) -> Publish:
    """The `publish(topic, data)` callable for source code: it appends a row
    to `source_event`."""

    def publish(topic: str, data: dict) -> None:
        append_event(store, topic, data, clock())

    return publish
