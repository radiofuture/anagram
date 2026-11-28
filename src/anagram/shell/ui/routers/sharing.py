"""Sharing routes of the local UI (layer L3). Logic: `shell/ui/sharing.py`
(the part `UIService.sharing`).

    GET    /api/share/targets?q=                  people, my labs, a typed address or ORCID iD
    POST   /api/findings/{root}/shares            share with people, my lab, or invite a reader
    GET    /api/findings/{root}/shares            who has this finding (history rows), versions
    POST   /api/findings/{root}/shares/stop       stop sharing with one target
    POST   /api/findings/{root}/rekey             "Make a new version now"
    GET    /api/findings/{root}/preview           "See what they see"
    GET    /api/history?finding=&person=          history rows
    GET    /api/history/{finding_id}/{subject}/record   "Export record" (JSON file)
    GET    /api/shared                            "Shared with me"
    POST   /api/shared/{grant_id}/open            the reading model
    GET    /api/shared/{grant_id}/files/{slot}    the original file
    GET    /api/shared/{grant_id}/figures/{slot}/{figure}   one figure of the reading copy
    GET    /api/shared/{grant_id}/proof           the proof bundle with all fields opened
    POST   /api/shared/{grant_id}/save            "Save a copy" into a folder
    GET    /api/reader-claims                     claims that wait for the owner
    POST   /api/reader-claims/{invite_id}         {"give": bool}: the answer of the owner
    GET    /reader/*                              the reading view (`src/anagram/web/reader/`)

The rings and the inbox of the first screens:

    GET    /api/rings                             POST /api/rings {name}
    POST   /api/rings/{ring}/members {member}     POST /api/rings/{ring}/members/remove {member}
    POST   /api/findings/{root}/share {ring, ack_third_party}
    POST   /api/findings/{root}/revoke {ring, ack_third_party}
    GET    /api/inbox                             POST /api/inbox/{grant_id}/open
    GET    /api/inbox/{grant_id}/files/{name}

All `/api/` routes need the cookie of the guard in `shell/ui/server.py`; the guard
also sets the CSP of the local UI on `/reader` (`worker-src 'self'` for the
pdf.js worker, `blob:` in `img-src`). `/reader/#<grant_id>` is the full page
of one received finding; it reads the `/api/shared/*` routes. The task
`shares.sync` (`ctx.tasks`) runs `SharingUI.sync`.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.routers import UIContext, body_dict, body_text
from anagram.shell.ui.sharing import disposition

READER = Path(str(resources.files("anagram").joinpath("web", "reader")))


def _download(name: str, text: str) -> Response:
    return Response(
        text,
        media_type="application/json",
        headers={"Content-Disposition": disposition("attachment", name)},
    )


def register(app: FastAPI, ctx: UIContext) -> None:
    sharing = ctx.service.sharing
    app.state.sharing = sharing
    ctx.tasks.add("shares.sync", sharing.sync, lambda: sharing.interval(ctx.bus))

    @app.get("/api/reader-claims")
    def reader_claims() -> list[dict]:
        return sharing.reader_claims()

    @app.post("/api/reader-claims/{invite_id}")
    def reader_claim_answer(invite_id: str, body: dict = Body(...)) -> dict:
        give = body_dict(body).get("give")
        if not isinstance(give, bool):
            raise UIError(400, "Give give as true or false.")
        return sharing.answer_claim(invite_id, give)

    @app.get("/api/share/targets")
    def share_targets(q: str = "") -> list[dict]:
        return sharing.targets(q)

    @app.post("/api/findings/{root}/shares")
    def share(root: str, body: dict = Body(...)) -> dict:
        return sharing.share(root, body_dict(body))

    @app.get("/api/findings/{root}/shares")
    def audience(root: str) -> dict:
        return sharing.audience(root)

    @app.post("/api/findings/{root}/shares/stop")
    def stop(root: str, body: dict = Body(...)) -> dict:
        return sharing.stop(root, body_dict(body))

    @app.post("/api/findings/{root}/rekey")
    def rekey(root: str, body: dict = Body(default={})) -> dict:
        return sharing.rekey(root, body_dict(body))

    @app.get("/api/findings/{root}/preview")
    def preview(root: str) -> dict:
        return sharing.preview(root)

    @app.get("/api/history")
    def history(finding: str | None = None, person: str | None = None) -> list[dict]:
        return sharing.history(finding, person)

    @app.get("/api/history/{finding_id}/{subject}/record")
    def record(finding_id: str, subject: str) -> Response:
        return _download(*sharing.record(finding_id, subject))

    @app.get("/api/shared")
    def shared() -> list[dict]:
        return sharing.shared()

    @app.post("/api/shared/{grant_id}/open")
    def open_shared(grant_id: str) -> dict:
        return sharing.open(grant_id)

    @app.get("/api/shared/{grant_id}/files/{slot}")
    def shared_file(grant_id: str, slot: int) -> Response:
        return sharing.file(grant_id, slot)

    @app.get("/api/shared/{grant_id}/figures/{slot}/{figure_id}")
    def shared_figure(grant_id: str, slot: int, figure_id: str) -> Response:
        return sharing.figure(grant_id, slot, figure_id)

    @app.get("/api/shared/{grant_id}/proof")
    def shared_proof(grant_id: str) -> Response:
        return _download(*sharing.proof(grant_id))

    @app.post("/api/shared/{grant_id}/save")
    def save_shared(grant_id: str, body: dict = Body(...)) -> dict:
        return sharing.save(grant_id, body_dict(body))

    # ------------------------------------------------------ rings and inbox

    @app.post("/api/findings/{root}/share")
    def share_ring(root: str, body: dict = Body(...)) -> dict:
        return sharing.share_ring(root, body_text(body, "ring"), bool(body.get("ack_third_party")))

    @app.post("/api/findings/{root}/revoke")
    def revoke_ring(root: str, body: dict = Body(...)) -> dict:
        return sharing.revoke_ring(root, body_text(body, "ring"), bool(body.get("ack_third_party")))

    @app.get("/api/rings")
    def rings() -> list[dict]:
        return sharing.rings()

    @app.post("/api/rings")
    def ring_create(body: dict = Body(...)) -> list[dict]:
        return sharing.ring_create(body_text(body, "name"))

    @app.post("/api/rings/{ring}/members")
    def ring_add(ring: str, body: dict = Body(...)) -> list[dict]:
        return sharing.ring_add(ring, body_text(body, "member"))

    @app.post("/api/rings/{ring}/members/remove")
    def ring_remove(ring: str, body: dict = Body(...)) -> list[dict]:
        return sharing.ring_remove(ring, body_text(body, "member"))

    @app.get("/api/inbox")
    def inbox() -> list[dict]:
        return sharing.inbox()

    @app.post("/api/inbox/{grant_id}/open")
    def open_grant(grant_id: str) -> dict:
        return sharing.open_inbox(grant_id)

    @app.get("/api/inbox/{grant_id}/files/{name}")
    def received(grant_id: str, name: str) -> FileResponse:
        p = sharing.received_file(grant_id, name)
        return FileResponse(p, filename=p.name)

    app.mount("/reader", StaticFiles(directory=READER, html=True), name="reader")
