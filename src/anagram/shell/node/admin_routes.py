"""JSON routes of the organizer page for labs.

The routes use the cookie session and the CSRF check of the organizer page
(`shell/node/admin.py`: `current`, `checked`). A change needs the same origin, the
`Origin` header, and the `csrf` value of the session in the JSON body.

    GET  /admin/api/status        Admin.status() and "labs": LabService.node_stats()
    GET  /admin/api/labs          LabService.node_stats()
    POST /admin/api/labs/{id}     {"quota"?: bytes, "suspended"?: bool, "csrf"} -> the row
    POST /admin/api/invites       {"days", "csrf"} -> {"invite_url"} (a node invite)

The organizer sees counts and sizes. The organizer cannot read an item, a
setting, or a key, and cannot add or remove a lab member (clients refuse a
roster entry that no member device signed).
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse

from anagram.core.errors import NodeError, NotFound
from anagram.shell.node.admin import Admin, checked, current, json_headers


def _json(data, status: int = 200):
    return json_headers(JSONResponse(data, status_code=status))


def admin_api_router(admin: Admin, labs) -> APIRouter:
    router = APIRouter(prefix="/admin/api")

    def refused() -> JSONResponse:
        return _json({"detail": "Sign in again."}, 403)

    @router.get("/status")
    def status(request: Request) -> JSONResponse:
        if current(admin, request) is None:
            return refused()
        out = admin.status()
        out["labs"] = labs.node_stats() if labs is not None else []
        return _json(out)

    @router.get("/labs")
    def lab_rows(request: Request) -> JSONResponse:
        if current(admin, request) is None:
            return refused()
        return _json(labs.node_stats() if labs is not None else [])

    @router.post("/labs/{lab_id}")
    def set_lab(request: Request, lab_id: str, body: dict = Body(...)) -> JSONResponse:  # noqa: B008
        if checked(admin, request, str(body.get("csrf", "")), required=True) is None:
            return refused()
        if labs is None:
            return _json({"detail": "This node has no labs."}, 404)
        try:
            row = labs.set_node_limits(
                lab_id, quota=body.get("quota"), suspended=body.get("suspended")
            )
        except NotFound:
            return _json({"detail": "This lab is not on this node."}, 404)
        except NodeError as exc:
            return _json({"detail": str(exc)}, 400)
        return _json(row)

    @router.post("/invites")
    def invite(request: Request, body: dict = Body(...)) -> JSONResponse:  # noqa: B008
        sess = checked(admin, request, str(body.get("csrf", "")), required=True)
        if sess is None:
            return refused()
        try:
            days = min(max(float(body.get("days", 7)), 1), 30)
        except (TypeError, ValueError):
            days = 7
        return _json({"invite_url": admin.admission.create_invite(sess[0], days)["invite_url"]})

    return router
