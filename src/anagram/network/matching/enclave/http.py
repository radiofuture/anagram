"""The enclave's relay API (spec/enclave-messages.md 9.2) and the operator's
front end (spec/enclave-trust.md 3.7).

`FrontEnd` is untrusted operator code. It sends every relay request to the
writer of the line (enclave-trust.md 3.7): only the writer opens requests
and signs receipts. A request sealed to another instance's intake key (a
standby, or an old writer after a handoff or a failover) gets
`unknown_instance_key` from the writer, and the app fetches the bundle
again (enclave-messages.md 8.5). With no writer, the node gets `503`.
Every route needs a valid node request signature (`403` without one).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool

from anagram.core.canonical import JsonObject
from anagram.network.formats import enclave as m
from anagram.network.formats.strict import HEX32
from anagram.network.matching.enclave.instance import EnclaveInstance, bundle
from anagram.network.matching.enclave.state import Forbidden, NotReady, Release

CLASSES = {"uploads": m.CLASS_UPLOAD, "known": m.CLASS_KNOWN, "answers": m.CLASS_ANSWER}
RETRY_AFTER = "600"  # one epoch


@dataclass
class FrontEnd:
    release: Release
    instances: list[EnclaveInstance]

    @property
    def writer(self) -> EnclaveInstance:
        found = [i for i in self.instances if i.role == "writer"]
        if not found:
            raise NotReady
        return found[0]

    def check(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> str:
        return self.writer.check_node(method, path, body, headers)

    def post(self, name: str, body: bytes, headers: dict[str, str]) -> None:
        """A sealed request: `202` after the check of length only."""
        node = self.check("POST", f"/v1/relay/{name}", body, headers)
        cls = CLASSES[name]
        m.check_length(cls, body)
        self.writer.take(cls, node, body)

    def receipt(self, digest: str, headers: dict[str, str]) -> bytes:
        node = self.check("GET", f"/v1/relay/receipts/{digest}", b"", headers)
        return self.writer.receipt(node, digest)

    def slots(self, day: int, headers: dict[str, str]) -> bytes:
        node = self.check("GET", f"/v1/relay/slots/{day}", b"", headers)
        return self.writer.slots(node, day)

    def attestation(self, headers: dict[str, str]) -> JsonObject:
        self.check("GET", "/v1/attestation", b"", headers)
        return bundle(self.writer.log, self.release, self.instances)


@contextmanager
def _statuses(not_ready: int) -> Iterator[None]:
    """Map the front end's refusals to plaintext status codes (9.2). Any
    other refusal (the log is not reachable) is a `500`, as before."""
    try:
        yield
    except Forbidden as exc:
        raise HTTPException(403, "node request signature") from exc
    except m.BadLength as exc:
        raise HTTPException(400, "body length") from exc
    except NotReady as exc:
        headers = {"Retry-After": RETRY_AFTER} if not_ready == 503 else None
        raise HTTPException(not_ready, headers=headers) from exc


def _headers(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


def relay_router(front: FrontEnd) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/relay/{name}", status_code=202)
    async def post(name: str, request: Request) -> Response:
        if name not in CLASSES:
            raise HTTPException(404)
        body = await request.body()
        with _statuses(503):
            # In a worker thread: the front end takes the host lock, and the
            # check can read the control feed over HTTP.
            await run_in_threadpool(front.post, name, body, _headers(request))
        return Response(status_code=202)

    @router.get("/v1/relay/receipts/{digest}")
    def receipt(digest: str, request: Request) -> Response:
        if not HEX32.match(digest):
            raise HTTPException(400)
        with _statuses(404):
            raw = front.receipt(digest, _headers(request))
        return Response(raw, media_type="application/octet-stream")

    @router.get("/v1/relay/slots/{day}")
    def slots(day: int, request: Request) -> Response:
        with _statuses(503):
            raw = front.slots(day, _headers(request))
        return Response(raw, media_type="application/octet-stream")

    @router.get("/v1/attestation")
    def attestation(request: Request) -> JsonObject:
        with _statuses(503):
            return front.attestation(_headers(request))

    return router
