"""Node routes of admission (layer L4; spec/admission.md). The paths did not
change when these routes moved to this layer.

    POST /auth/invite              {"invite", "device_key", "nonce", "pid"?, "email"?}
    POST /auth/invite/preview      {"invite"} -> {"contact", "email_hint"}
    POST /invites                  {"expires_days"?} -> {"invite", "invite_url"} (organizer)
    POST /invites/claim            {"token"} -> receipt
    POST /labs/{id}/invites        {"auth", "package", "entry"} -> {"invite_id"} (PI, admin)
    GET  /labs/invites/{invite_id} any session: {"auth", "package", "open"}
    POST /labs/{id}/join           any session: {"request"} -> {"seq", "head", "role"};
                                   202 {"status": "bind_device"} for a new device;
                                   409 used; 410 expired or revoked

The routes of the reader invites are in `anagram.admission.node.reader`.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Body, Header
from fastapi.responses import JSONResponse

from anagram.admission.node.service import AdmissionService
from anagram.core.http import field


def admission_router(
    admission: AdmissionService, subject_of: Callable[[str | None], str]
) -> APIRouter:
    router = APIRouter()

    @router.post("/auth/invite")
    def invite_signin(body: dict = Body(...)) -> dict:  # noqa: B008
        return admission.invite_signin(
            field(body, "invite"),
            field(body, "device_key"),
            field(body, "nonce"),
            body.get("pid"),
            body.get("email"),
        )

    @router.post("/auth/invite/preview")
    def invite_preview(body: dict = Body(...)) -> dict:  # noqa: B008
        return admission.invite_preview(field(body, "invite"))

    @router.post("/invites")
    def create_invite(
        body: dict = Body(default={}),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return admission.create_invite(subject_of(authorization), body.get("expires_days", 7))

    @router.post("/invites/claim")
    def claim(
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return admission.claim_invite(subject_of(authorization), str(field(body, "token")))

    if admission.labs is None:
        return router

    @router.get("/labs/invites/{invite_id}")
    def lab_invite_info(invite_id: str, authorization: str | None = Header(default=None)) -> dict:
        return admission.lab_invite_info(invite_id, subject_of(authorization))  # any session

    @router.post("/labs/{lab_id}/invites")
    def put_lab_invite(
        lab_id: str,
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return admission.put_lab_invite(
            subject_of(authorization),
            lab_id,
            field(body, "auth"),
            body.get("package"),
            field(body, "entry"),
        )

    @router.post("/labs/{lab_id}/join")
    def join_lab(
        lab_id: str,
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ):
        out = admission.join_lab(subject_of(authorization), lab_id, field(body, "request"))
        if out.get("status") == "bind_device":
            return JSONResponse(out, status_code=202)
        return out

    return router
