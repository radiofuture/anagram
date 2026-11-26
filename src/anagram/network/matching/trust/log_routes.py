"""The read API of the enclave log (spec/enclave-trust.md 2.1).

    GET /log/checkpoint                  the latest cosigned checkpoint note
    GET /log/checkpoint/covering/{index} the first cosigned checkpoint that holds entry `index`
    GET /log/entries?start=&end=         entries start <= i < end, as canonical JSON
    GET /log/issuance?month=YYYY-MM      new members (join entries) of each node in a month
                                         (spec/network.md 6.7)

Anyone may read: the log holds no person data (2.8). The C2SP tile paths
stay the bulk path; this JSON route gives a reader exact entries without a
tile decoder.
"""

from __future__ import annotations

import re
import threading
from typing import Protocol

from fastapi import APIRouter, HTTPException, Response

from anagram.core.canonical import canonical_json
from anagram.network.matching.trust import follow
from anagram.network.matching.trust.issuance import Issuance

MAX_ENTRIES = 256  # one C2SP tile width
NOTE_TYPE = "text/plain; charset=utf-8"
MONTH = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")


class LogReader(follow.LogReader, Protocol):
    def checkpoint(self) -> str: ...


def log_read_router(log: LogReader) -> APIRouter:
    router = APIRouter(prefix="/log")

    @router.get("/checkpoint")
    def checkpoint() -> Response:
        return Response(log.checkpoint(), media_type=NOTE_TYPE)

    @router.get("/checkpoint/covering/{index}")
    def covering(index: int) -> Response:
        if not 0 <= index < follow.checkpoint_size(log.checkpoint()):
            raise HTTPException(404, "no cosigned checkpoint holds the entry")
        return Response(log.covering(index), media_type=NOTE_TYPE)

    @router.get("/entries")
    def entries(start: int, end: int) -> Response:
        size = follow.checkpoint_size(log.checkpoint())
        if not (0 <= start < end <= size and end - start <= MAX_ENTRIES):
            raise HTTPException(400, f"0 <= start < end <= {size}, at most {MAX_ENTRIES}")
        body = canonical_json({"entries": log.read(start, end)})
        return Response(body, media_type="application/json")

    counts = Issuance()  # read once, then only the new cosigned entries
    lock = threading.Lock()  # the server runs sync routes in a thread pool

    @router.get("/issuance")
    def issuance(month: str) -> Response:
        if not MONTH.match(month):
            raise HTTPException(400, "month is YYYY-MM")
        size = follow.checkpoint_size(log.checkpoint())
        with lock:
            for start in range(counts.seen, size, MAX_ENTRIES):
                counts.update(log.read(start, min(start + MAX_ENTRIES, size)), start)
            nodes = counts.of_month(month)
        body = canonical_json({"month": month, "nodes": nodes})
        return Response(body, media_type="application/json")

    return router
