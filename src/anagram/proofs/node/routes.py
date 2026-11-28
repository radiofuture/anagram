"""Node routes of the log (proofs; spec/log.md). Public, except the submit.

GET  /log/checkpoint                  latest cosigned checkpoint and anchors
GET  /log/anchored?size=N             first checkpoint >= N with background anchors
GET  /log/entries?start=&end=         leaf data (canonical JSON text)
POST /log/entries {entry}             a member submits an entry (rate limit)
GET  /log/proof/inclusion?index=&size=
GET  /log/proof/consistency?old=&new=
GET  /log/keys                        public keys (a hint only; clients pin keys)
GET  /tile/{level}/{path}             C2SP tlog-tiles hash tile
GET  /tile/entries/{path}             C2SP tlog-tiles entry bundle
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from fastapi import APIRouter, Header, HTTPException, Request, Response

from anagram.proofs.log.store import TILE_WIDTH, LogError
from anagram.proofs.node.service import EntryRejected, NodeService

_TILE_PATH = re.compile(r"\A((?:x\d{3}/)*\d{3})(?:\.p/(\d+))?\Z")
MAX_ENTRY_BODY = 64 << 10


async def _read_entry_body(request: Request) -> dict:
    size = request.headers.get("content-length")
    if size is not None and (not size.isdigit() or int(size) > MAX_ENTRY_BODY):
        raise HTTPException(413, "log entry is too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_ENTRY_BODY:
            raise HTTPException(413, "log entry is too large")
        chunks.append(chunk)
    try:
        body = json.loads(b"".join(chunks))
    except ValueError as exc:
        raise HTTPException(400, "send JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be an object")
    return body


def parse_tile_index(path: str) -> tuple[int, int]:
    m = _TILE_PATH.match(path)
    if not m:
        raise ValueError("bad tile path")
    index = int(m.group(1).replace("x", "").replace("/", ""))
    width = int(m.group(2)) if m.group(2) else TILE_WIDTH
    if not 1 <= width <= TILE_WIDTH:
        raise ValueError("bad tile width")
    return index, width


def log_router(
    service: NodeService,
    subject_of: Callable[[str | None], str],
    submit: Callable[[str, dict], dict] | None,
    public_keys: dict | None = None,
    anchoring=None,
) -> APIRouter:
    """`submit(subject, entry)` adds the entry of a member (the identity
    service); `subject_of` refuses each request when the node has no member
    sessions (a read-only log). `anchoring` gives the anchored checkpoints."""
    router = APIRouter()

    @router.post("/log/entries")
    async def add_entry(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict:
        subject = subject_of(authorization)
        if submit is None:
            raise HTTPException(403, "log is read-only")
        body = await _read_entry_body(request)
        try:
            return submit(subject, body.get("entry"))
        except EntryRejected as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/log/entries")
    def get_entries(start: int, end: int) -> dict:
        try:
            return {"entries": service.entries(start, end), "start": start}
        except (LogError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/log/checkpoint")
    def checkpoint() -> dict:
        return service.checkpoint()

    @router.get("/log/anchored")
    def anchored(size: int) -> dict:
        found = anchoring.anchored(size) if anchoring is not None else None
        if found is None:
            raise HTTPException(404, "no anchored checkpoint at or after this size yet")
        return found

    @router.get("/log/proof/inclusion")
    def inclusion(index: int, size: int) -> dict:
        try:
            return {"inclusion": service.inclusion(index, size)}
        except (LogError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/log/proof/consistency")
    def consistency(old: int, new: int) -> dict:
        try:
            return {"consistency": service.consistency(old, new)}
        except (LogError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/log/keys")
    def keys() -> dict:
        return public_keys or {"log_keys": [service.signer.vkey()]}

    @router.get("/tile/entries/{path:path}")
    def entry_bundle(path: str) -> Response:
        try:
            index, width = parse_tile_index(path)
            data = service.store.entry_bundle(index, width)
        except (LogError, ValueError) as exc:
            raise HTTPException(404, str(exc)) from exc
        return Response(data, media_type="application/octet-stream")

    @router.get("/tile/{level}/{path:path}")
    def hash_tile(level: int, path: str) -> Response:
        try:
            index, width = parse_tile_index(path)
            data = service.store.hash_tile(level, index, width)
        except (LogError, ValueError) as exc:
            raise HTTPException(404, str(exc)) from exc
        return Response(data, media_type="application/octet-stream")

    return router
