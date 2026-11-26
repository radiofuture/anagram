"""Lab routes of the local UI (layer L3).

The logic is in `shell/ui/labs.py` (`LabUI`, the part `UIService.labs`). The
routes `/api/labs/mine`, `/api/labs/join`, and `/api/labs/invite` come
before `/api/labs/{lab_id}`. `GET /api/labs?q=` searches the labs of the
community (`shell/ui/people.py`).

The task `lab.watch` (`shell/ui/labwatch.py`) keeps the labs of this computer up
to date and publishes the changes of other members.
"""

from __future__ import annotations

import urllib.parse

from fastapi import Body, FastAPI
from fastapi.responses import Response

from anagram.shell.ui.labwatch import LabWatch
from anagram.shell.ui.routers import UIContext


def register(app: FastAPI, ctx: UIContext) -> None:
    labs = ctx.service.labs
    watch = LabWatch(ctx.service, ctx.service.publish)
    ctx.tasks.add("lab.watch", watch.run, every_s=watch.wait)

    @app.get("/api/labs/mine")
    def mine() -> list[dict]:
        return labs.mine()

    @app.get("/api/labs")
    def search(q: str = "") -> list[dict]:
        return ctx.service.people.search_labs(q)

    @app.post("/api/labs")
    def create(body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.create(body.get("name"))

    @app.post("/api/labs/join")
    def join(body: dict | None = Body(None)) -> dict:  # noqa: B008
        return labs.join((body or {}).get("url"))

    @app.get("/api/labs/invite")
    def invite_preview(url: str | None = None) -> dict:
        return labs.preview(url)

    @app.get("/api/labs/{lab_id}")
    def view(lab_id: str) -> dict:
        return labs.view(lab_id)

    @app.put("/api/labs/{lab_id}/name")
    def rename(lab_id: str, body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.rename(lab_id, body.get("name"))

    @app.post("/api/labs/{lab_id}/invites")
    def invite(lab_id: str, body: dict | None = Body(None)) -> dict:  # noqa: B008
        return labs.invite(lab_id, body or {})

    @app.delete("/api/labs/{lab_id}/invites/{invite_id}")
    def revoke(lab_id: str, invite_id: str) -> dict:
        return labs.revoke(lab_id, invite_id)

    @app.post("/api/labs/{lab_id}/members")
    def add(lab_id: str, body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.add(lab_id, body)

    @app.delete("/api/labs/{lab_id}/members/{pid}")
    def remove(lab_id: str, pid: str) -> dict:
        return labs.remove(lab_id, pid)

    @app.put("/api/labs/{lab_id}/members/{pid}")
    def change(lab_id: str, pid: str, body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.change(lab_id, pid, body)

    @app.post("/api/labs/{lab_id}/leave")
    def leave(lab_id: str) -> dict:
        return labs.leave(lab_id)

    @app.get("/api/labs/{lab_id}/settings")
    def settings(lab_id: str) -> dict:
        return labs.settings(lab_id)

    @app.put("/api/labs/{lab_id}/settings")
    def set_settings(lab_id: str, body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.set_settings(lab_id, body)

    @app.get("/api/labs/{lab_id}/space")
    def space(lab_id: str, after: int = 0, limit: int = 100) -> dict:
        return labs.space(lab_id, after, limit)

    @app.post("/api/labs/{lab_id}/space")
    def put(lab_id: str, body: dict = Body(...)) -> dict:  # noqa: B008
        return labs.put(lab_id, body)

    @app.get("/api/labs/{lab_id}/space/{item_id}")
    def item(lab_id: str, item_id: str) -> dict:
        return labs.item(lab_id, item_id)

    @app.delete("/api/labs/{lab_id}/space/{item_id}")
    def unpublish(lab_id: str, item_id: str) -> dict:
        return labs.unpublish(lab_id, item_id)

    @app.get("/api/labs/{lab_id}/space/{item_id}/files/{n}")
    def file(lab_id: str, item_id: str, n: int) -> Response:
        name, _, data = labs.file(lab_id, item_id, n)
        # Served as a download, never shown in the page (no sniffing).
        return Response(
            data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": _attachment(name), "X-Content-Type-Options": "nosniff"},
        )


def _attachment(name: str) -> str:
    """A download header with a safe file name."""
    safe = "".join(ch for ch in name if ch.isprintable() and ch not in '"\\/;').strip() or "file"
    plain = safe.encode("ascii", "replace").decode().replace("?", "_")
    return f"attachment; filename=\"{plain}\"; filename*=UTF-8''{urllib.parse.quote(safe)}"
