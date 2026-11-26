"""The roster service process (`anagram roster serve`; spec/network.md 3, 8.7).

    GET /net/roster/events?after={n}   {"count", "events"}: at most 1,000, ascending
    GET /net/roster/checkpoint         the newest roster checkpoint
    GET /healthz                       {"status", "count", "seq"}

The roster operator holds the roster key. It signs a roster checkpoint at
each change of the roster head and at least every `checkpoint_every`
seconds (15 minutes), and writes each one to the enclave log as a
`roster_checkpoint` entry (3.5). The enclave uses a roster checkpoint only
from the log.

`anagram roster admit RECORD.json` adds a `node_admitted` event (endorser
`roster`) after the checks of 3.3 that a machine can make (the record
form, a new ID that matches the key), and logs its `node_admission` entry.
The domain check (DNS TXT) and the human check stay with the operator.
Events are in `roster.sqlite`; the CLI and the server share it.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from fastapi import FastAPI, HTTPException, Query, Response

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.core.shared_db import SharedDB
from anagram.network.formats.roster import (
    ROSTER,
    ZERO,
    check_node_record,
    event_hash,
    make_event,
    node_id,
    roster_checkpoint,
)
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.hosting.runtime import Ticker, event
from anagram.network.matching.trust.entries import sign_entry

CHECKPOINT_EVERY = 900  # 3.5: at least every 15 minutes
MAX_EVENTS = 1_000  # 8.7
TICK_SECONDS = 2.0
log = logging.getLogger("anagram.services.roster")


class AppendLog(Protocol):
    def append(self, entry: JsonObject) -> int: ...


class RosterStore:
    def __init__(self, path: str | Path) -> None:
        self._db = SharedDB(path)  # the CLI and the server share the file
        self._db.executescript(
            "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS checkpoint (id INTEGER PRIMARY KEY CHECK (id = 0),"
            " body TEXT NOT NULL);"
        )
        self.lock = threading.Lock()

    def events(self, after: int = 0, limit: int | None = None) -> list[JsonObject]:
        sql = "SELECT body FROM events WHERE seq >= ? ORDER BY seq"
        rows = self._db.execute(sql + (f" LIMIT {int(limit)}" if limit else ""), (after,))
        return [json.loads(r[0]) for r in rows]

    def count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def last(self) -> JsonObject | None:
        row = self._db.execute("SELECT body FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def add(self, make: Callable[[int, bytes], JsonObject]) -> JsonObject:
        """Add the event that `make(seq, prev)` gives, in one transaction."""
        with self.lock, self._db.lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                last = self.last()
                seq = 0 if last is None else last["seq"] + 1
                ev = make(seq, ZERO if last is None else event_hash(last))
                self._db.execute(
                    "INSERT INTO events (seq, body) VALUES (?, ?)",
                    (seq, canonical_json(ev).decode()),
                )
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return ev

    def checkpoint(self) -> JsonObject | None:
        row = self._db.execute("SELECT body FROM checkpoint WHERE id = 0").fetchone()
        return json.loads(row[0]) if row else None

    def set_checkpoint(self, doc: JsonObject) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO checkpoint (id, body) VALUES (0, ?)",
            (canonical_json(doc).decode(),),
        )


REMOVE_REASONS = ("abuse", "compromised", "left", "other")  # network.md 3.2


@dataclass
class RosterService:
    network: str
    key: SigningKey
    store: RosterStore
    log: AppendLog
    clock: Callable[[], int]
    checkpoint_every: int = CHECKPOINT_EVERY
    lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> None:
        """Make the chain on the first start: `roster_created` at seq 0."""
        if self.store.count() == 0:
            body = {"network": self.network, "roster_key": self.key.public_bytes().hex()}
            self.store.add(lambda seq, prev: self._event(seq, prev, "roster_created", body))

    def _event(self, seq: int, prev: bytes, kind: str, body: JsonObject) -> JsonObject:
        last = self.store.last()
        t = max(self.clock(), _time(last) if last else 0)  # 8.1: time never goes back
        return make_event(ROSTER, seq, prev, kind, body, t, self.key)

    def admit(self, record: JsonObject) -> JsonObject:
        """Add a node (3.3, endorser `roster`) and log its admission entry."""
        try:
            check_node_record(record)
        except Refused as exc:
            raise ValueError(f"node record: {exc}") from exc
        if record["id"] != node_id(bytes.fromhex(record["key"])):
            raise ValueError("the node ID is not the ID of its key")
        known = {
            e["body"]["node"]["id"] for e in self.store.events() if e["kind"] == "node_admitted"
        }
        if record["id"] in known:
            raise ValueError("this node is admitted already")
        body = {"endorsement": None, "endorser": ROSTER, "node": record}
        ev = self.store.add(lambda seq, prev: self._event(seq, prev, "node_admitted", body))
        fields = {"node_id": record["id"], "record_digest": event_hash(ev).hex()}
        self.log.append(sign_entry("node_admission", fields, self.key))
        event(log, "node_admitted", node=record["id"], seq=ev["seq"])
        return ev

    def remove(self, node: str, reason: str) -> JsonObject:
        """`node_removed` (spec/network.md 3.2): the enclave erases the
        node's members at once (enclave-trust.md 7.1). For a node that
        floods the network with fake members, the reason is `abuse`
        (network.md 6.7)."""
        if reason not in REMOVE_REASONS:
            raise ValueError(f"reason is one of {', '.join(REMOVE_REASONS)}")
        events = self.store.events()
        admitted = {e["body"]["node"]["id"] for e in events if e["kind"] == "node_admitted"}
        removed = {e["body"]["node"] for e in events if e["kind"] == "node_removed"}
        if node not in admitted or node in removed:
            raise ValueError("this node is not an admitted node")
        body = {"node": node, "reason": reason}
        ev = self.store.add(lambda seq, prev: self._event(seq, prev, "node_removed", body))
        event(log, "node_removed", node=node, reason=reason, seq=ev["seq"])
        return ev

    def tick(self) -> None:
        """A new roster checkpoint, logged, at a new head or when the last one
        is `checkpoint_every` seconds old."""
        with self.lock:
            last, cp = self.store.last(), self.store.checkpoint()
            if last is None:
                return
            now = self.clock()
            stale = (
                cp is None or cp["seq"] != last["seq"] or now - _time(cp) >= self.checkpoint_every
            )
            if not stale:
                return
            doc = roster_checkpoint(self.network, last["seq"], event_hash(last), now, self.key)
            try:
                self.log.append(doc)
            except Refused as exc:
                event(log, "checkpoint_not_logged", logging.WARNING, error=exc.code)
                return
            self.store.set_checkpoint(doc)
            event(log, "checkpoint_logged", seq=last["seq"])


def _time(doc: JsonObject) -> int:
    return parse_time(doc["time"], "time")


def roster_app(service: RosterService, tick_every: float = TICK_SECONDS) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        service.start()
        ticker = Ticker("roster", service.tick, tick_every).start()
        event(log, "started", count=service.store.count())
        yield
        ticker.stop()
        event(log, "stopped")

    app = FastAPI(title="Anagram network roster (simulated profile)", lifespan=lifespan)

    @app.get("/net/roster/events")
    def events(after: int = Query(0, ge=0)) -> JsonObject:  # noqa: B008
        return {"count": service.store.count(), "events": service.store.events(after, MAX_EVENTS)}

    @app.get("/net/roster/checkpoint")
    def checkpoint() -> JsonObject:
        cp = service.store.checkpoint()
        if cp is None:
            raise HTTPException(503, "no roster checkpoint yet")
        return cp

    @app.get("/healthz")
    def health(response: Response) -> JsonObject:
        cp = service.store.checkpoint()
        if cp is None:
            response.status_code = 503
        return {
            "count": service.store.count(),
            "seq": cp["seq"] if cp else None,
            "status": "ok" if cp else "starting",
        }

    return app
