"""The index job queue (spec/index.md section 7).

Each stage after the scan is one `job` row for one item version:

    scan (hash -> evidence -> pending; no job) -> convert -> enrich -> embed

States: `queued`, `running`, `done`, `skipped` (no converter, with a reason),
`failed` (too many attempts). A failed attempt goes back to `queued` with
exponential backoff. A `running` job of a stopped process goes back to
`queued` after `STALE_S`.

The evidence commit never waits for a job: the scan writes the evidence
opening and the pending root in its own transaction, before any conversion.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from anagram.local.index.store import IndexStore

log = logging.getLogger("anagram.local.index")

CONVERT = "convert"
ENRICH = "enrich"
EMBED = "embed"
STAGES = (CONVERT, ENRICH, EMBED)
# The model stage (understand.py). It is not in STAGES: `JobRunner.run` does not
# run it; `understand.run` claims it with a model.
UNDERSTAND = "understand"

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
SKIPPED = "skipped"
FAILED = "failed"

MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 30.0
BACKOFF_CAP_S = 6 * 3600.0
STALE_S = 600.0


@dataclass(frozen=True)
class Job:
    id: int
    stage: str
    version_id: int
    source_id: str
    attempts: int


def backoff(attempts: int) -> float:
    return min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** max(0, attempts - 1)))


def enqueue(
    store: IndexStore, stage: str, version_id: int, source_id: str, now: float, *, reset=False
) -> None:
    """Add a job. With `reset`, a job that exists goes back to `queued`."""
    if reset:
        store.x(
            "INSERT INTO job (stage, version_id, source_id, state, attempts, next_at,"
            " created_at, updated_at) VALUES (?, ?, ?, 'queued', 0, ?, ?, ?)"
            " ON CONFLICT (stage, version_id) DO UPDATE SET state = 'queued', attempts = 0,"
            " next_at = excluded.next_at, error = NULL, reason = NULL, fix = NULL,"
            " updated_at = excluded.updated_at",
            (stage, version_id, source_id, now, now, now),
        )
    else:
        store.x(
            "INSERT OR IGNORE INTO job (stage, version_id, source_id, state, attempts, next_at,"
            " created_at, updated_at) VALUES (?, ?, ?, 'queued', 0, ?, ?, ?)",
            (stage, version_id, source_id, now, now, now),
        )


def claim(
    store: IndexStore, stages: tuple[str, ...], now: float, *, newest_first: bool = False
) -> Job | None:
    """Take the oldest ready job of the stages (atomic across processes). With
    `newest_first`, take the newest: the person sees new work first."""
    marks = ",".join("?" for _ in stages)
    order = "id DESC" if newest_first else "id"
    with store.transaction():
        row = store.one(
            f"SELECT id, stage, version_id, source_id, attempts FROM job"  # noqa: S608
            f" WHERE state = 'queued' AND next_at <= ? AND stage IN ({marks})"
            f" ORDER BY {order} LIMIT 1",
            (now, *stages),
        )
        if row is None:
            return None
        store.x("UPDATE job SET state = 'running', updated_at = ? WHERE id = ?", (now, row[0]))
    return Job(row[0], row[1], row[2], row[3], row[4])


def finish(
    store: IndexStore,
    job: Job,
    now: float,
    state: str = DONE,
    reason: str | None = None,
    fix: str | None = None,
) -> None:
    store.x(
        "UPDATE job SET state = ?, reason = ?, fix = ?, error = NULL, updated_at = ? WHERE id = ?",
        (state, reason, fix, now, job.id),
    )


def fail(store: IndexStore, job: Job, error: str, now: float) -> str:
    """Record a failed attempt. Return the new state (`queued` or `failed`)."""
    attempts = job.attempts + 1
    state = FAILED if attempts >= MAX_ATTEMPTS else QUEUED
    store.x(
        "UPDATE job SET state = ?, attempts = ?, next_at = ?, error = ?, updated_at = ?"
        " WHERE id = ?",
        (state, attempts, now + backoff(attempts), error[:2000], now, job.id),
    )
    return state


def release(store: IndexStore, job: Job, now: float) -> None:
    """Put a claimed job back unchanged (for example: no embedder now)."""
    store.x("UPDATE job SET state = 'queued', updated_at = ? WHERE id = ?", (now, job.id))


def recover_stale(store: IndexStore, now: float, older_than: float = STALE_S) -> int:
    cur = store.x(
        "UPDATE job SET state = 'queued' WHERE state = 'running' AND updated_at < ?",
        (now - older_than,),
    )
    return cur.rowcount


def counts(store: IndexStore, source_id: str | None = None) -> dict[str, dict[str, int]]:
    """{stage: {state: n}}."""
    sql = "SELECT stage, state, count(*) FROM job"
    args: tuple = ()
    if source_id is not None:
        sql += " WHERE source_id = ?"
        args = (source_id,)
    out: dict[str, dict[str, int]] = {}
    for stage, state, n in store.q(sql + " GROUP BY stage, state", args):
        out.setdefault(stage, {})[state] = n
    return out
