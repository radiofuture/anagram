"""The ORCID pages of the node (shell): the pages that a browser sees
during an ORCID sign-in or link (optional).

    GET /auth/orcid/callback              ORCID redirect target (exact registered URI);
                                          the organizer page owns some flows
    GET /fake-orcid/authorize             only when the ORCID mode is "fake"
"""

from __future__ import annotations

import urllib.parse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from anagram.shell import pages


def orcid_pages_router(identity, admin=None) -> APIRouter:
    """`identity` is the `IdentityService`; `admin` the organizer page
    (`shell/node/admin.py`), or None."""
    router = APIRouter()

    @router.get("/auth/orcid/callback")
    def orcid_callback(request: Request, state: str, code: str) -> Response:
        if admin is not None and admin.owns(state):
            from anagram.shell.node.admin import orcid_callback as admin_callback

            return admin_callback(admin, request, state, code)
        location, one_time = identity.orcid_signin.callback(state, code)
        if location:
            return RedirectResponse(location, status_code=303)
        return HTMLResponse(pages.orcid_code(one_time), headers=pages.HEADERS)

    if identity.orcid_signin.orcid.mode != "fake":
        return router

    @router.get("/fake-orcid/authorize", response_class=HTMLResponse)
    def fake_authorize(
        state: str, redirect_uri: str, orcid: str | None = None, name: str | None = None
    ) -> Response:
        if not orcid:
            return HTMLResponse(
                pages.fake_orcid(state, redirect_uri), headers=pages.FAKE_ORCID_HEADERS
            )
        if redirect_uri != identity.cfg.callback_url:
            raise HTTPException(400, "redirect_uri is not registered")
        try:
            code = identity.orcid_signin.orcid.approve(orcid, name or None, redirect_uri)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        q = urllib.parse.urlencode({"code": code, "state": state})
        return RedirectResponse(f"{redirect_uri}?{q}", status_code=303)

    return router
