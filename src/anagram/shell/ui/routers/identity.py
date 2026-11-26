"""Join and sign-in routes of the local UI (layers L4 and L1; a
person needs no ORCID iD).
Logic: `shell/ui/join.py`.

    GET  /api/join         the stored invite and the join task view
    POST /api/join         {"invite"?} -> the join task view (the invite only)
    POST /api/join/start   {"invite"?, "name", "email"?} -> the join task view
    POST /api/join/code    {"code"} -> the join task view (a reader invite to an email)
    POST /api/signin       sign in again with the key of this computer
    POST /api/logout       end the session on the node
    POST /api/orcid/link   {} -> the task view; the page goes to ORCID (optional)
    POST /api/organizer/open {} -> {"url"}: a one-time link to the organizer page

The join task state reaches the page as `join.state` events (`shell/ui/bridge.py`).
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.routers import UIContext, body_text


def _text(body: dict, name: str) -> str | None:
    value = body.get(name) if isinstance(body, dict) else None
    if value is not None and not isinstance(value, str):
        raise UIError(400, f"Give {name} as text.")
    return value


def register(app: FastAPI, ctx: UIContext) -> None:
    join = ctx.service.join

    @app.get("/api/join")
    def join_info() -> dict:
        return {**join.invite_info(), "status": join.status()}

    @app.post("/api/join")
    def join_invite(body: dict = Body(default={})) -> dict:  # noqa: B008
        return join.start_join(body_text(body, "invite", required=False))

    @app.post("/api/join/start")
    def join_start(body: dict = Body(default={})) -> dict:  # noqa: B008
        return join.start_join(_text(body, "invite"), _text(body, "name"), _text(body, "email"))

    @app.post("/api/join/code")
    def join_code(body: dict = Body(...)) -> dict:  # noqa: B008
        return join.give_code(_text(body, "code") or "")

    @app.post("/api/signin")
    def signin_start() -> dict:
        return join.start_signin()

    @app.post("/api/logout")
    def logout() -> dict:
        return join.logout()

    @app.post("/api/orcid/link")
    def orcid_link() -> dict:
        return join.start_link_orcid()

    @app.post("/api/organizer/open")
    def organizer_open() -> dict:
        return ctx.service.account.organizer_link()
