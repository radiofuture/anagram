"""The node's relay to the matching enclave (spec/enclave-messages.md 4.4,
6.3, 6.7 and 9).

The node moves ciphertext only. It checks the length of each sealed
request, answers the app `202`, and forwards the bytes at once with a node
request signature. It fetches receipts and day batches from the enclave and
serves them unchanged. For a digest or an address with nothing stored it
serves a filler of the same length, so a fetch never shows whether a
request or an address belongs to a member.

    GET  /enclave/attestation          the attestation bundle, unchanged
    POST /enclave/{uploads,known,answers}   fixed-size bodies -> 202
    GET  /enclave/receipts/{digest}    1,024 bytes: receipt or filler
    GET  /enclave/slots/{address}      4,096 bytes: slot or filler

`EnclaveRelay.tick` is the node timer: it fetches the day batches and
drops receipts after 48 hours and slots after 28 days. `node serve` runs it
with `hosting.runtime.Ticker`.

The timer thread and the request threads share the relay, so one lock
covers all of its state; no network call runs under the lock. The node
keeps `slots`, `relayed` and `slot_secret` in `JsonTable`s
(`NodeEnclave.build`): a restart keeps up to 28 days of slots, and the
fillers stay the same bytes. Receipts are a cache: the node fetches a
relayed digest again.

A restart of the writer (a new process from its sealed state) takes some
seconds. In that time the writer refuses connections and the standby
answers `503`. The relay does not drop an app request for that: it tries
the line again, with a new node request signature each time, for up to
`RESTART_WAIT` seconds. A second try is safe: the writer gives the same
bytes the same receipt (8.5), and each try has a new nonce (9.3).
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool

from anagram.core.canonical import JsonObject
from anagram.core.crypto.signing import SigningKey
from anagram.core.jsontable import JsonTable
from anagram.core.shared_db import SharedDB
from anagram.network.formats import enclave as m
from anagram.network.formats.strict import DAY, HEX32, fmt_time

CLASSES = {"uploads": m.CLASS_UPLOAD, "known": m.CLASS_KNOWN, "answers": m.CLASS_ANSWER}
SLOT_DAYS = m.SLOT_DAYS  # 6.3: 28 days, longer than a proposal lives
RECEIPT_KEEP = 2 * DAY  # 4.4: the node keeps each receipt for 48 hours
TICK_SECONDS = 60.0
RESTART_WAIT = 10.0  # seconds; less than the app's request timeout (30 s)
RETRY_STEPS = (0.2, 0.5, 1.0, 2.0)  # seconds between two tries; the last one repeats


class EnclaveUnavailable(Exception):
    """The enclave did not answer (`502`/`503` to the app)."""


class FailoverLink:
    """The relay's link to a line with more than one instance (a writer and
    a standby). Only the writer serves (spec/enclave-trust.md 3.7); another
    instance answers `503`. The link sends each request to the instance
    that served last, and moves to the next one on `503` or when the
    instance does not answer, so after a failover (5.7) the node finds the
    new writer at once. A `404` (a receipt not released yet) is an answer.
    It has the `request` call of `httpx.Client` that `EnclaveRelay` uses."""

    def __init__(self, clients: list[httpx.Client]) -> None:
        if not clients:
            raise ValueError("an enclave link needs at least one URL")
        self.clients = clients
        self.current = 0
        self._lock = threading.Lock()

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        with self._lock:
            start = self.current
        last: httpx.Response | None = None
        error: httpx.HTTPError | None = None
        for step in range(len(self.clients)):
            at = (start + step) % len(self.clients)
            try:
                r = self.clients[at].request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                error = exc
                continue
            if r.status_code != 503:
                with self._lock:
                    self.current = at
                return r
            last = r
        if last is not None:
            return last
        raise error or httpx.ConnectError("no enclave answered")

    def close(self) -> None:
        for client in self.clients:
            client.close()


class EnclaveLink(Protocol):
    """The one call that the relay makes: `httpx.Client.request`, or
    `FailoverLink.request` over the instances of the line."""

    def request(
        self, method: str, path: str, /, *, content: bytes, headers: dict[str, str]
    ) -> httpx.Response: ...


@dataclass
class EnclaveRelay:
    node: str
    key: SigningKey
    audience: str  # the enclave log origin (9.3)
    link: EnclaveLink  # base URL of the enclave relay API
    clock: Callable[[], int]
    # The filler secret of the node (32 bytes). The caller gives the stored
    # value (`persistent`): a new random value would change every filler.
    slot_secret: bytes
    receipts: dict[str, tuple[bytes, int]] = field(default_factory=dict)  # digest -> (raw, at)
    # digests this node sent -> time
    relayed: MutableMapping[str, int] = field(default_factory=dict)
    # address -> [hex of the slot, day]: JSON values, so a `JsonTable` can hold them
    slots: MutableMapping[str, Any] = field(default_factory=dict)
    fetched: set[int] = field(default_factory=set)  # days whose batch the node stored
    wait: float = RESTART_WAIT  # how long an app request waits for a writer
    sleep: Callable[[float], None] = time.sleep
    timer: Callable[[], float] = time.monotonic  # for `wait`; `clock` is the protocol time
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    @classmethod
    def persistent(
        cls,
        db: SharedDB,
        node: str,
        key: SigningKey,
        audience: str,
        link: EnclaveLink,
        clock: Callable[[], int],
    ) -> EnclaveRelay:
        """A relay whose slots, relayed digests and filler secret are in
        `db`, so a restart keeps them (a filler must not change)."""
        secret = JsonTable(db, "relay").setdefault("slot_secret", secrets.token_hex(32))
        return cls(
            node,
            key,
            audience,
            link,
            clock,
            slot_secret=bytes.fromhex(secret),
            relayed=JsonTable(db, "relayed"),
            slots=JsonTable(db, "slots"),
        )

    def signed_headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        t = self.clock()
        nonce = secrets.token_bytes(m.NODE_NONCE)
        payload = m.node_request_payload(self.node, self.audience, method, path, t, body, nonce)
        return {
            "Anagram-Node": self.node,
            "Anagram-Nonce": nonce.hex(),
            "Anagram-Time": fmt_time(t),
            "Anagram-Signature": self.key.sign(m.TAG_SIGN_NODE_REQUEST, payload).hex(),
        }

    def _call(
        self, method: str, path: str, body: bytes = b"", *, wait: bool = False
    ) -> httpx.Response:
        """One signed request to the line. With `wait` (an app request), a
        line where no instance answers, or where each answers `503` (no
        writer: a restart), gets more tries until `self.wait` seconds have
        passed. Without `wait` (the timer), the next tick tries again."""
        deadline = self.timer() + (self.wait if wait else 0.0)
        step = 0
        while True:
            headers = self.signed_headers(method, path, body)  # a new nonce for each try
            try:
                r = self.link.request(method, path, content=body, headers=headers)
            except httpx.HTTPError as exc:
                if self.timer() >= deadline:
                    raise EnclaveUnavailable(str(exc)) from exc
            else:
                if r.status_code != 503 or self.timer() >= deadline:
                    return r
            self.sleep(RETRY_STEPS[min(step, len(RETRY_STEPS) - 1)])
            step += 1

    # ---- app -> node -------------------------------------------------------

    def forward(self, name: str, body: bytes) -> None:
        m.check_length(CLASSES[name], body)
        with self._lock:
            self.relayed[m.request_digest(body).hex()] = self.clock()
        r = self._call("POST", f"/v1/relay/{name}", body, wait=True)
        if r.status_code != 202:
            raise EnclaveUnavailable(f"relay answered {r.status_code}")

    def receipt(self, digest: str) -> bytes:
        """The receipt if the enclave released it, else the filler. The
        node asks the enclave only for digests that it relayed (9.2)."""
        filler = m.receipt_filler(self.slot_secret, bytes.fromhex(digest))
        with self._lock:
            ask = digest not in self.receipts and digest in self.relayed
        if ask:
            r = self._call("GET", f"/v1/relay/receipts/{digest}", wait=True)
            if r.status_code == 200 and len(r.content) == m.RECEIPT_SIZE:
                with self._lock:
                    self.receipts[digest] = (r.content, self.clock())
        with self._lock:
            found = self.receipts.get(digest)
        return found[0] if found is not None else filler

    def slot(self, address: str) -> bytes:
        with self._lock:
            found = self.slots.get(address)
        if found is None:
            return m.filler(self.slot_secret, bytes.fromhex(address))
        return bytes.fromhex(found[0])

    def attestation(self, wait: bool = True) -> JsonObject:
        """The bundle, unchanged. Each fetch is a new signed request with
        its own nonce (9.3). `wait=False`: the operator's status check
        reports at once."""
        r = self._call("GET", "/v1/attestation", wait=wait)
        if r.status_code != 200:
            raise EnclaveUnavailable(f"attestation answered {r.status_code}")
        bundle: JsonObject = r.json()  # the app checks it (enclave-trust.md)
        return bundle

    # ---- node -> enclave, by time ------------------------------------------

    def fetch_batch(self, day: int) -> bool:
        """Store the slots of day D for 28 days. False before the enclave
        serves the batch (`503`); the node tries again later."""
        r = self._call("GET", f"/v1/relay/slots/{day}")
        if r.status_code != 200:
            return False
        got_day, entries = m.read_batch(r.content)
        if got_day != day:
            return False
        with self._lock:
            for address, raw in entries.items():
                self.slots[address.hex()] = [raw.hex(), day]
            self.fetched.add(day)
        return True

    def tick(self) -> None:
        """The node timer. The batch of day D is made at the cut (23:00 UTC
        of day D - 1) and served after its cosigned epoch, so the node asks
        for today and tomorrow until it has each (6.7). Then it drops what
        it keeps no longer (4.4, 6.3)."""
        today = self.clock() // DAY
        for day in (today, today + 1):
            with self._lock:
                have = day in self.fetched
            if not have:
                self.fetch_batch(day)
        self.expire()

    def expire(self) -> None:
        """Delete in place: `slots` and `relayed` can be `JsonTable`s."""
        now = self.clock()
        today = now // DAY
        with self._lock:
            _drop(self.slots, lambda v: today - v[1] >= SLOT_DAYS)
            _drop(self.receipts, lambda v: now - v[1] >= RECEIPT_KEEP)
            _drop(self.relayed, lambda t: now - t >= RECEIPT_KEEP)
            self.fetched = {d for d in self.fetched if today - d < SLOT_DAYS}


def _drop(table: MutableMapping[str, Any], old: Callable[[Any], bool]) -> None:
    for k in [k for k, v in table.items() if old(v)]:
        del table[k]


def enclave_router(relay: EnclaveRelay) -> APIRouter:
    """The app-facing routes. The node shell mounts them behind member
    sign-in (9.1: `401` without a session, `403` for a non-member)."""
    router = APIRouter(prefix="/enclave")

    @router.get("/attestation")
    def attestation() -> JsonObject:
        try:
            return relay.attestation()
        except EnclaveUnavailable as exc:
            raise HTTPException(502, "enclave unavailable") from exc

    @router.post("/{name}", status_code=202)
    async def post(name: str, request: Request) -> Response:
        if name not in CLASSES:
            raise HTTPException(404)
        body = await request.body()
        try:
            # In a worker thread: a forward can wait for a writer that restarts
            # (`RESTART_WAIT`), and the event loop serves other requests meanwhile.
            await run_in_threadpool(relay.forward, name, body)
        except m.BadLength as exc:
            raise HTTPException(400, "body length") from exc
        except EnclaveUnavailable as exc:
            raise HTTPException(502, "enclave unavailable") from exc
        return Response(status_code=202)

    @router.get("/receipts/{digest}")
    def receipt(digest: str) -> Response:
        if not HEX32.match(digest):
            raise HTTPException(400)
        try:
            raw = relay.receipt(digest)
        except EnclaveUnavailable as exc:
            raise HTTPException(502, "enclave unavailable") from exc
        return Response(raw, media_type="application/octet-stream")

    @router.get("/slots/{address}")
    def slot(address: str) -> Response:
        if not HEX32.match(address):
            raise HTTPException(400)
        return Response(relay.slot(address), media_type="application/octet-stream")

    return router
