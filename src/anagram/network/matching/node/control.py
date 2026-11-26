"""The node's control chain (spec/network.md 8).

    GET /net/control?after={n}   {"count", "events"}: events with seq >= n, at most 1,000
    GET /net/node                {"id", "key"}: the node ID and node key, so that an
                                 app can name the node in a credential request

The node signs its events (`member_removed`, `member_left`,
`credential_revoked`, 8.4) with its node key. The enclave polls this route
at the node's record URL and applies the events in order. The route is
public: events name a member only by the subject hash. Each member
credential carries the count of events so far (`control_head`), so a
credential issued after an event commits to it (8.6).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Query

from anagram.core.canonical import JsonObject
from anagram.core.crypto.signing import SigningKey
from anagram.core.jsontable import JsonTable
from anagram.core.shared_db import SharedDB
from anagram.network.formats.roster import ZERO, event_hash, make_event, subject_hash
from anagram.network.formats.strict import parse_time

MAX_EVENTS = 1_000


class ControlChain:
    def __init__(self, path: str | Path, node: str, key: SigningKey, clock: Callable[[], int]):
        self.node = node
        self.key = key
        self.clock = clock
        self.db = SharedDB(path)
        self._events = JsonTable(self.db, "control_events")  # "%012d" % seq -> event

    @property
    def count(self) -> int:
        return len(self._events)

    def events(self, after: int = 0) -> list[JsonObject]:
        keys = sorted(self._events)[after : after + MAX_EVENTS]
        return [self._events[k] for k in keys]

    def left(self, person_key: str) -> int:
        """The time of the person's last `member_removed` or `member_left`
        (not `moved`) in this chain, or 0. The credential issuer then makes
        the next credential a join entry (network.md 6.7: a re-join counts
        as a new member)."""
        subj = subject_hash(bytes.fromhex(person_key))
        times = [
            parse_time(e["time"], "time")
            for e in self._events.values()
            if e["kind"] in ("member_removed", "member_left")
            and e["body"].get("subject") == subj
            and e["body"].get("reason") != "moved"
        ]
        return max(times, default=0)

    def add(self, kind: str, body: JsonObject) -> JsonObject:
        """Sign and keep the next event of the chain."""
        with self.db.lock:
            seq = self.count
            prev = event_hash(self._events[f"{seq - 1:012d}"]) if seq else ZERO
            event = make_event(self.node, seq, prev, kind, body, self.clock(), self.key)
            self._events[f"{seq:012d}"] = event
            return event


def control_router(chain: ControlChain) -> APIRouter:
    router = APIRouter(prefix="/net")

    @router.get("/control")
    def control(after: int = Query(0, ge=0)) -> JsonObject:  # noqa: B008
        return {"count": chain.count, "events": chain.events(after)}

    @router.get("/node")
    def node() -> JsonObject:
        return {"id": chain.node, "key": chain.key.public_bytes().hex()}

    return router
