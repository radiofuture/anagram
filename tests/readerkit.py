"""A small web app that serves the reading view (`web/reader/`) with the
sharing API routes for fixed reading models, under the CSP of the
local UI. Used by `test_reader_assets.py` and to look at the view:

    uv run python tests/readerkit.py [port]     # then open /reader/#<grant>

No network: the models come from local fixture files.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from anagram.network.sharing.app import readcopy, received
from anagram.shell.ui.routers.sharing import READER
from anagram.shell.ui.server import CSP, STATIC

INLINE = ("application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp", "text/plain")


def reading_model(
    grant: str, files: dict[str, bytes], claim: str, *, label: str | None = "Dr. Chen"
):
    """The reading model (as `open_received` gives it) and the reading copy
    with figure data, for files in the given order."""
    names = list(files)
    doc = SimpleNamespace(
        evidence=[SimpleNamespace(fields={"name": n, "media_type": ""}) for n in names],
        finding=SimpleNamespace(fields={"claim": claim}),
    )
    copy = readcopy.build(doc, {i: files[n] for i, n in enumerate(names)})
    report = {
        "claim": claim,
        "granted_at": "2026-11-14T10:12:00Z",
        "not_after": "2026-11-12T08:00:00Z",
        "root": "ab" * 32,
        "verified": True,
    }
    model = received.reading_model(
        grant, {"owner": "pid:" + "0" * 32, "version": 2}, _Doc(), copy, report
    )
    model["owner"]["label"] = label
    return model, copy, {i: files[n] for i, n in enumerate(names)}


class _Doc:
    finding = SimpleNamespace(fields={"link_count": 0})


def reader_app(entries: dict[str, tuple[dict, dict, dict[int, bytes]]]) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def entry(grant: str):
        if grant not in entries:
            raise HTTPException(404)
        return entries[grant]

    @app.post("/api/shared/{grant}/open")
    def open_(grant: str) -> JSONResponse:
        return JSONResponse(entry(grant)[0])

    @app.get("/api/shared/{grant}/files/{slot}")
    def file(grant: str, slot: int) -> Response:
        model, _, data = entry(grant)
        item = next((it for it in model["items"] if it["slot"] == slot), None)
        if item is None:
            raise HTTPException(404)
        media = item["media_type"]
        disposition = "inline" if media in INLINE else "attachment"
        return Response(
            data[slot],
            media_type=media,
            headers={"Content-Disposition": f'{disposition}; filename="file"'},
        )

    @app.get("/api/shared/{grant}/figures/{slot}/{fid}")
    def figure(grant: str, slot: int, fid: str) -> Response:
        _, copy, _ = entry(grant)
        for it in copy["items"]:
            if it["slot"] == slot:
                for f in it["figures"]:
                    if f["id"] == fid:
                        return Response(base64.b64decode(f["data"]), media_type=f["media_type"])
        raise HTTPException(404)

    app.mount("/reader", StaticFiles(directory=READER, html=True), name="reader")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def demo_entries() -> dict:
    sys.path.insert(0, str(Path(__file__).parent))
    from readkit import ALL
    from readkit_rich import RICH

    rich = reading_model(
        "a" * 32,
        {n: make() for n, make in RICH.items()},
        "Growth of treated cells doubles at 37 degrees\n"
        "The rate stays two times higher with a new batch of medium, and it goes away when the "
        "treatment stops.",
    )
    small = reading_model(
        "b" * 32, {n: make() for n, make in ALL.items()}, "Growth doubled\nmore text"
    )
    one = reading_model("c" * 32, {"paper.pdf": RICH["paper.pdf"]()}, "One paper", label=None)
    return {"a" * 32: rich, "b" * 32: small, "c" * 32: one}


if __name__ == "__main__":  # pragma: no cover - a person runs it
    import uvicorn

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    uvicorn.run(reader_app(demo_entries()), host="127.0.0.1", port=port, log_level="warning")
