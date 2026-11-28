"""One witness process (`anagram witness serve`; spec/enclave-trust.md 2.4).

    POST /witness/cosign        {"note", "old_size", "proof", "entries"} -> {"cosignature"}
                                409 {"known_size"} when old_size is not the witness's size
    POST /witness/entry-cosign  {"entry"} -> {"entry": <enclave_entry_cosign>}
    GET  /healthz               {"status", "name", "size"}

The witness keeps the size and root that it cosigned last (`witness.sqlite`)
and, for an Anagram witness, its own copy of the entries (`entries.sqlite`),
so a restart goes on from the same state. For `entry-cosign` it reads the
public log (`HttpLog`) and checks the entry at its own time
(`check_entry_cosign`: a new line, or a failover that holds now). The
caller (the operator) appends the returned entry to the log.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import HEX32, Refused
from anagram.network.matching.hosting.clients import HttpLog
from anagram.network.matching.hosting.runtime import event
from anagram.network.matching.trust.follow import checkpoint_size
from anagram.network.matching.trust.translog import EntryWitness, WitnessConflict, WitnessRefused
from anagram.proofs.log.note import NoteError

log = logging.getLogger("anagram.services.witness")


def cosign_request(body: object) -> tuple[str, int, list[bytes], list[JsonObject]]:
    """(note, old size, consistency proof, new entries) of a cosign request.
    A body of another form is `bad_request`."""
    if not isinstance(body, dict) or not {"note", "old_size", "proof", "entries"} <= set(body):
        raise Refused("bad_request", "fields")
    note, old, proof, entries = body["note"], body["old_size"], body["proof"], body["entries"]
    if not (
        isinstance(note, str)
        and type(old) is int
        and old >= 0
        and isinstance(proof, list)
        and all(isinstance(h, str) and HEX32.match(h) for h in proof)
        and isinstance(entries, list)
    ):
        raise Refused("bad_request", "field form")
    return note, old, [bytes.fromhex(h) for h in proof], entries


def witness_app(witness: EntryWitness, reader: HttpLog) -> FastAPI:
    lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        event(log, "started", witness=witness.name, size=len(witness.entries))
        yield
        event(log, "stopped", witness=witness.name)

    app = FastAPI(title="Anagram enclave log witness (simulated profile)", lifespan=lifespan)

    @app.post("/witness/cosign", response_model=None)
    def cosign(body: JsonObject = Body(...)) -> JsonObject | JSONResponse:
        try:
            note, old, proof, entries = cosign_request(body)
            with lock:
                line = witness.cosign(note, old, proof, entries)
        except WitnessConflict as exc:
            return JSONResponse({"known_size": exc.known_size}, status_code=409)
        except (Refused, WitnessRefused, NoteError) as exc:  # the last two: the proofs layer
            event(log, "cosign_refused", logging.WARNING, witness=witness.name,
                  error=type(exc).__name__)  # fmt: skip
            raise HTTPException(400, "refused") from exc
        size = checkpoint_size(note)
        event(log, "cosigned", logging.DEBUG, witness=witness.name, size=size)
        return {"cosignature": line}

    @app.post("/witness/entry-cosign")
    def entry_cosign(body: JsonObject = Body(...)) -> JsonObject:
        entry: Any = body.get("entry")  # untrusted: `check_entry_cosign` refuses a bad one
        try:
            with lock:
                signed = witness.checked_entry_cosign(entry, reader.view())
        except Refused as exc:
            event(log, "entry_cosign_refused", logging.WARNING, witness=witness.name,
                  error=type(exc).__name__)  # fmt: skip
            raise HTTPException(400, {"code": exc.code}) from exc
        event(log, "entry_cosigned", witness=witness.name, kind=entry["kind"])
        return {"entry": signed}

    @app.get("/healthz")
    def health() -> JsonObject:
        return {"name": witness.name, "size": witness.cosigned_size, "status": "ok"}

    return app
