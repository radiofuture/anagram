"""One enclave instance as a process (`anagram enclave serve --profile simulated`).

    POST /v1/relay/{uploads,known,answers}, GET /v1/relay/receipts/{d},
    GET  /v1/relay/slots/{day}, GET /v1/attestation     the relay API (node -> enclave)
    POST /v1/handoff/standby  {"document"} -> {"message"}  a standby asks the writer (5.3)
    POST /v1/handoff/finish   {"ready"}                   the writer adds the holder
    GET  /healthz             {"status", "role", "instance_id", "line_id", "counter", "cosigned"}

`EnclaveHost` is the untrusted operator code around one `EnclaveInstance`:
the disk for sealed snapshots (`DiskSnapshots`), the log and the control
feed over HTTP, the timer, and the sealed record of the instance
(`sealed_record`, sealed with the host's platform key) so that a restart
of the process goes on from the latest cosigned epoch (spec/enclave-trust.md
6.2). The relay API is the front end of 3.7 for this instance: when this
instance is not the writer it answers `503` (or `404` for a receipt), and
the node tries its next enclave URL.

A standby (`--standby-of URL`) logs its instance key, then asks the writer
for the state key: the writer checks the standby's attestation document
(same release, logged, rules 1 to 9) and seals the key to its intake key.
After a failover entry names it, the standby loads the latest epoch and
writes.

Every call into the instance holds one lock: the instance is not thread
safe, and the tick and the requests share it. No route runs on the event
loop with that lock or with I/O: the relay routes and the handoff routes
run in worker threads, and `/healthz` reads a copy of the health that the
host makes under the lock, so a slow log does not stop `/healthz`. The
tick reads the new log entries before it takes the lock, and a standby
asks the writer over HTTP without the lock.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import AsyncIterator, Callable, Iterator, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, HTTPException, Response
from fastapi.concurrency import run_in_threadpool

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import aead
from anagram.core.crypto.signing import SigningKey
from anagram.core.files import atomic_write
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.http import FrontEnd, relay_router
from anagram.network.matching.enclave.instance import EnclaveInstance
from anagram.network.matching.enclave.simulated_engines import simulated_engines
from anagram.network.matching.enclave.state import Host, Release
from anagram.network.matching.hosting.clients import HttpFeed, HttpLog
from anagram.network.matching.hosting.runtime import Ticker, event
from anagram.network.matching.hosting.tools.operator import ReleaseFile
from anagram.network.matching.trust.profiles.simulated import PROFILE, SimulatedPlatform
from anagram.network.matching.trust.roots import Roots

TICK_SECONDS = 2.0
RECORD_AAD = b"anagram/v1/enclave/simulated-record"
log = logging.getLogger("anagram.services.enclave")


class DiskSnapshots(MutableMapping[int, bytes]):
    """Sealed snapshots on the host disk, one file for each counter.
    `atomic_write`: a crash leaves the old snapshot or the new one, never
    half of one."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, counter: int) -> Path:
        return self.dir / f"{int(counter):012d}.snapshot"

    def __getitem__(self, counter: int) -> bytes:
        try:
            return self._path(counter).read_bytes()
        except FileNotFoundError:
            raise KeyError(counter) from None

    def __setitem__(self, counter: int, data: bytes) -> None:
        atomic_write(self._path(counter), data)

    def __delitem__(self, counter: int) -> None:
        try:
            self._path(counter).unlink()
        except FileNotFoundError:
            raise KeyError(counter) from None

    def __iter__(self) -> Iterator[int]:
        return iter(sorted(int(p.stem) for p in self.dir.glob("*.snapshot")))

    def __len__(self) -> int:
        return sum(1 for _ in self.dir.glob("*.snapshot"))


class SealedFile:
    """The simulated platform's sealing: the record, encrypted with a key
    in the host's state directory. A TEE would seal it to its measurement;
    here anyone with the directory can open it (the profile protects
    nothing).

    `write` seals and writes only a record that differs from the last one:
    the host saves after each tick (every 2 s), and most ticks change
    nothing in the record."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "instance.sealed"
        key_path = directory / "platform.key"
        if not key_path.exists():
            atomic_write(key_path, aead.new_key())
        self.key = key_path.read_bytes()
        self._last: bytes | None = None  # the canonical form of the record on disk

    def read(self) -> JsonObject | None:
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        plain = aead.open_sealed(self.key, raw[:12], raw[12:], RECORD_AAD)
        record: JsonObject = json.loads(plain)  # written by `write`, sealed with the platform key
        self._last = canonical_json(record)
        return record

    def write(self, record: JsonObject) -> None:
        plain = canonical_json(record)
        if plain == self._last:
            return
        nonce, ct = aead.seal(self.key, plain, RECORD_AAD)
        atomic_write(self.path, nonce + ct)
        self._last = plain


class LockedFront(FrontEnd):
    """The front end of one instance, with the host lock on each call."""

    def __init__(
        self, release: Release, instances: list[EnclaveInstance], lock: threading.RLock
    ) -> None:
        super().__init__(release, instances)
        self.lock = lock

    def post(self, name: str, body: bytes, headers: dict[str, str]) -> None:
        with self.lock:
            super().post(name, body, headers)

    def receipt(self, digest: str, headers: dict[str, str]) -> bytes:
        with self.lock:
            return super().receipt(digest, headers)

    def slots(self, day: int, headers: dict[str, str]) -> bytes:
        with self.lock:
            return super().slots(day, headers)

    def attestation(self, headers: dict[str, str]) -> JsonObject:
        with self.lock:
            return super().attestation(headers)


@dataclass
class EnclaveHost:
    instance: EnclaveInstance
    sealed: SealedFile
    standby_of: httpx.Client | None = None  # the writer, for a standby
    lock: threading.RLock = field(default_factory=threading.RLock)
    # What `close` closes: the HTTP clients of the log and the control feed.
    closers: list[Callable[[], None]] = field(default_factory=list)
    front: LockedFront = field(init=False)
    _role: str = field(init=False, default="")
    _health: JsonObject = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.front = LockedFront(self.instance.release, [self.instance], self.lock)
        self._role = self.instance.role
        self._health = self._read_health()

    @classmethod
    def open(
        cls,
        state_dir: Path,
        release: ReleaseFile,
        roots: Roots,
        log_client: HttpLog,
        feed: HttpFeed,
        clock: Callable[[], int],
        dev_root: SigningKey,
        snapshots: Path,
    ) -> EnclaveHost:
        """The instance of `state_dir`: the sealed record of an earlier run,
        or a new instance with new keys. `snapshots` is the directory of the
        sealed snapshots, shared by all instances of the line: a standby
        that takes over loads the writer's latest epoch from it."""
        state_dir.mkdir(parents=True, exist_ok=True)
        rel = Release(release.release, tuple(release.descriptors))
        reference = release.release["profiles"][PROFILE]["reference"]
        platform = SimulatedPlatform(dev_root, reference)
        host = Host(log_client, feed, clock, disk=DiskSnapshots(snapshots))
        sealed = SealedFile(state_dir)
        record = sealed.read()
        if record is not None:
            if record["line_id"] != release.line_id:
                raise ValueError("the state directory holds another line")
            inst = EnclaveInstance.resume(record, rel, platform, roots, host, simulated_engines)
            event(log, "resumed", role=inst.role, instance_id=inst.instance_id)
        else:
            inst = EnclaveInstance(rel, platform, roots, host, release.line_id, simulated_engines)
            event(log, "created", instance_id=inst.instance_id)
        return cls(inst, sealed, closers=[log_client.http.close, feed.close])

    def save(self) -> None:
        with self.lock:
            self.sealed.write(self.instance.sealed_record())
            if self.instance.role != self._role:
                event(log, "role", role=self.instance.role, instance_id=self.instance.instance_id)
                self._role = self.instance.role
            self._health = self._read_health()

    def start(self, first_line: bool) -> None:
        """Log the instance key (a new instance), and start the line if this
        is its first instance."""
        with self.lock:
            inst = self.instance
            if inst.document is None:
                inst.register()
            if first_line and inst.role == "new":
                inst.start_line()
            self.save()

    def tick(self) -> None:
        # The new entries come in before the lock: under it, a log read
        # fetches only the checkpoint and what was added since.
        self.instance.host.log.view()
        with self.lock:
            if self.instance.document is None:
                self.instance.register()
            self.save()
            ask = self.standby_of is not None and self.instance.role == "new"
            document = self.instance.document
        if ask and self.standby_of is not None and document is not None:
            self._ask_for_standby(self.standby_of, document)
        with self.lock:
            self.instance.tick()
            self.save()

    # ---- standby handoff (5.3) ---------------------------------------------

    def _ask_for_standby(self, writer: httpx.Client, document: JsonObject) -> None:
        """A new instance asks the writer for the state key. The HTTP calls
        to the writer run without the lock."""
        r = writer.post("/v1/handoff/standby", json={"document": document})
        if r.status_code != 200:
            event(log, "standby_refused", logging.WARNING, status=r.status_code)
            return
        msg = r.json()["message"]
        with self.lock:
            self.instance.accept_hand_off(msg)
            self.save()
            note = self.instance.ready(msg)
        r = writer.post("/v1/handoff/finish", json={"ready": note})
        event(log, "standby_ready", status=r.status_code, role=self.instance.role)

    def give_standby(self, document: JsonObject) -> JsonObject:
        with self.lock:
            msg = self.instance.hand_off(document, self.instance.release.entry, standby=True)
            self.save()
            return msg

    def finish_standby(self, note: object) -> None:
        with self.lock:
            self.instance.check_ready(note)
            self.instance.finish_hand_off()
            self.save()

    def close(self) -> None:
        """Close the HTTP clients (at the end of the lifespan)."""
        for close in self.closers:
            close()
        if self.standby_of is not None:
            self.standby_of.close()

    def health(self) -> JsonObject:
        """The health at the last save. No lock: `/healthz` answers while
        a tick waits for a slow log."""
        return self._health

    def _read_health(self) -> JsonObject:
        inst = self.instance
        j = inst.journal
        return {
            "cosigned": j.cosigned if j is not None else None,
            "counter": j.counter if j is not None else None,
            "instance_id": inst.instance_id,
            "line_id": inst.line_id,
            "profile": inst.platform.profile,
            "role": inst.role,
            "status": "ok" if inst.document is not None else "starting",
        }


def enclave_app(
    host: EnclaveHost, first_line: bool = False, tick_every: float = TICK_SECONDS
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            await run_in_threadpool(host.start, first_line)
        except Refused as exc:  # the log or the release is not ready: the ticker tries again
            event(log, "start_waiting", logging.WARNING, error=exc.code)
        ticker = Ticker("enclave", host.tick, tick_every).start()
        event(log, "started", role=host.instance.role, instance_id=host.instance.instance_id)
        yield
        ticker.stop()
        await run_in_threadpool(host.save)
        host.close()
        event(log, "stopped", role=host.instance.role)

    app = FastAPI(title="Anagram matching enclave (simulated profile)", lifespan=lifespan)
    app.include_router(relay_router(host.front))

    @app.post("/v1/handoff/standby")
    def standby(body: JsonObject = Body(...)) -> JsonObject:
        document: Any = body.get("document")  # untrusted: the hand-off checks it
        try:
            return {"message": host.give_standby(document)}
        except Refused as exc:  # the checks are total on any document
            raise HTTPException(409, {"code": exc.code}) from exc

    @app.post("/v1/handoff/finish")
    def finish(body: JsonObject = Body(...)) -> JsonObject:
        try:
            host.finish_standby(body.get("ready"))  # untrusted: `check_ready` is total
        except Refused as exc:
            raise HTTPException(409, {"code": exc.code}) from exc
        return {"role": host.instance.role}

    @app.get("/healthz")
    def health(response: Response) -> JsonObject:
        doc = host.health()
        if doc["status"] != "ok":
            response.status_code = 503
        return doc

    return app
