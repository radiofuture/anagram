"""The log service process (`anagram log serve`; spec/enclave-trust.md 2.1).

    GET  /log/checkpoint, /log/checkpoint/covering/{i}, /log/entries   the read API
    POST /log/write/entries        {"entry"}                -> {"index"}
    POST /log/write/instance-keys  {"entry", "document"}    -> {"index"}
    GET  /healthz                  {"status", "size", "cosigned"}

The log signs a checkpoint after each entry and at least every
`publish_every` seconds, and asks each witness (`HttpCosigner`) to cosign
it. A checkpoint without a quorum is not kept; the next tick tries again.
A refused entry gets `400` with `{"detail": {"code", "detail"}}`.

The write API takes any entry that passes its form and its signature
(2.2), as the in-process `SimulatedLog` does. The entries, the cosigned
notes and the attestation documents are in `log.sqlite`, so a restart
serves the same log.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import Body, FastAPI, HTTPException, Response

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.hosting.runtime import Ticker, event
from anagram.network.matching.trust.log_routes import log_read_router
from anagram.network.matching.trust.translog import (
    TransparencyLog,
    WitnessConflict,
    WitnessRefused,
)

PUBLISH_EVERY = 600  # 2.1: a new checkpoint at least every 10 minutes
TICK_SECONDS = 2.0
log = logging.getLogger("anagram.services.log")


@dataclass
class HttpCosigner:
    """A witness process as the log asks it (`POST /witness/cosign`)."""

    name: str
    http: httpx.Client

    def cosign(self, note: str, old: int, proof: list[bytes], new: list[JsonObject]) -> str:
        body = {"entries": new, "note": note, "old_size": old, "proof": [h.hex() for h in proof]}
        try:
            r = self.http.post("/witness/cosign", json=body)
        except httpx.HTTPError as exc:
            raise WitnessRefused(f"witness unreachable: {type(exc).__name__}") from exc
        if r.status_code == 409:
            raise WitnessConflict(int(r.json()["known_size"]))
        if r.status_code != 200:
            raise WitnessRefused(f"witness answered {r.status_code}")
        line: str = r.json()["cosignature"]
        return line


@dataclass
class LogService:
    log: TransparencyLog
    clock: Callable[[], int]
    publish_every: int = PUBLISH_EVERY
    published_at: int = -PUBLISH_EVERY
    lock: threading.RLock = field(default_factory=threading.RLock)

    def append(self, entry: JsonObject) -> int:
        with self.lock:
            index = self.log.append(entry)
            event(log, "entry_appended", index=index, kind=entry["kind"])
            self.publish()
            return index

    def append_instance_key(self, entry: JsonObject, document: JsonObject) -> int:
        with self.lock:
            index = self.log.append_instance_key(entry, document)
            event(log, "entry_appended", index=index, kind=entry["kind"])
            self.publish()
            return index

    def publish(self) -> bool:
        with self.lock:
            try:
                note = self.log.publish()
            except Refused:
                event(log, "checkpoint_without_quorum", logging.WARNING, size=len(self.log.entries))
                return False
            self.published_at = self.clock()
            witnesses = len(note.strip().split("\n\n", 1)[1].splitlines()) - 1
            event(log, "checkpoint_published", size=len(self.log.entries), witnesses=witnesses)
            return True

    def tick(self) -> None:
        """A new checkpoint when the log grew since the last one, or after
        `publish_every` seconds."""
        with self.lock:
            behind = not self.log.sizes or self.log.sizes[-1] < len(self.log.entries)
            if behind or self.clock() - self.published_at >= self.publish_every:
                self.publish()

    def health(self) -> JsonObject:
        cosigned = self.log.sizes[-1] if self.log.sizes else None
        status = "ok" if cosigned is not None else "starting"
        return {"cosigned": cosigned, "size": len(self.log.entries), "status": status}


def _refused(exc: Refused) -> HTTPException:
    return HTTPException(400, {"code": exc.code, "detail": str(exc)})


def log_app(service: LogService, tick_every: float = TICK_SECONDS) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        service.tick()
        ticker = Ticker("log", service.tick, tick_every).start()
        event(log, "started", size=len(service.log.entries))
        yield
        ticker.stop()
        event(log, "stopped", size=len(service.log.entries))

    app = FastAPI(title="Anagram enclave log (simulated profile)", lifespan=lifespan)

    class Reads:
        """The read API waits for the first cosigned checkpoint."""

        def checkpoint(self) -> str:
            if not service.log.notes:
                raise HTTPException(503, "no cosigned checkpoint yet")
            return service.log.checkpoint()

        def covering(self, index: int) -> str:
            return service.log.covering(index)

        def read(self, start: int, end: int) -> list[JsonObject]:
            return service.log.read(start, end)

    app.include_router(log_read_router(Reads()))

    @app.post("/log/write/entries")
    def append(body: JsonObject = Body(...)) -> JsonObject:
        entry: Any = body.get("entry")  # untrusted: `check_entry` refuses a bad one
        try:
            return {"index": service.append(entry)}
        except Refused as exc:
            raise _refused(exc) from exc

    @app.post("/log/write/instance-keys")
    def append_instance_key(body: JsonObject = Body(...)) -> JsonObject:
        entry: Any = body.get("entry")  # untrusted: checked by the log, as above
        document: Any = body.get("document")
        try:
            return {"index": service.append_instance_key(entry, document)}
        except Refused as exc:
            raise _refused(exc) from exc

    @app.get("/healthz")
    def health(response: Response) -> JsonObject:
        doc = service.health()
        if doc["status"] != "ok":
            response.status_code = 503
        return doc

    return app
