"""Finding routes of the local UI (layer L2). Logic: `shell/ui/library.py`.

    GET  /api/drafts                            proposed findings
    POST /api/drafts/{draft_id}/model           a draft from the model of the task `draft`
    POST /api/findings                          {draft_id, claim?, keys}: the timestamp
    GET  /api/findings                          my findings
    GET  /api/findings/{root}                   one finding
    GET  /api/findings/{root}/proof             the proof file (download)
    GET  /api/findings/{root}/files/{slot}/proof  the proof of one file (download)

The certificate, the public proof, and the preprint are in `proof.py`; the
sharing of a finding is in `sharing.py`.
"""

from __future__ import annotations

from fastapi import Body, FastAPI
from fastapi.responses import Response

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.routers import UIContext, body_text, json_download


def register(app: FastAPI, ctx: UIContext) -> None:
    library = ctx.service.library

    @app.get("/api/drafts")
    def drafts() -> list[dict]:
        return library.drafts()

    @app.post("/api/drafts/{draft_id}/model")
    def model_draft(draft_id: str) -> dict:
        return library.model_draft(draft_id)

    @app.post("/api/findings")
    def timestamp(body: dict = Body(...)) -> dict:
        keys = body.get("keys") or []
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise UIError(400, "Bad file list.")
        return library.timestamp(
            body_text(body, "draft_id"), body_text(body, "claim", required=False), keys
        )

    @app.get("/api/findings")
    def findings() -> list[dict]:
        return library.findings()

    @app.get("/api/findings/{root}")
    def finding(root: str) -> dict:
        return library.finding(root)

    @app.get("/api/findings/{root}/proof")
    def proof(root: str) -> Response:
        return json_download(*library.proof_file(root))

    @app.get("/api/findings/{root}/files/{slot}/proof")
    def file_proof(root: str, slot: int) -> Response:
        return json_download(*library.file_proof(root, slot))
