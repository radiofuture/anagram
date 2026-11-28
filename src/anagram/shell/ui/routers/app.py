"""App routes of the local UI. Logic: `shell/app/settings.py`
and `AccountUI.recover`.

    GET  /api/app                     helper, keys, start_at_login, update, version
    PUT  /api/app/start-at-login      {"on": bool} -> the start_at_login block
    POST /api/app/restart-helper      {} -> the helper block
    POST /api/recover                 {"kit": str} -> {"state": "restored", "subject"}

The other recovery kit routes are in `shell/ui/routers/account.py`.
The guard of `shell/ui/server.py` applies: each route needs the cookie, and a
change needs the Origin of this UI.
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.app.settings import AppSettings
from anagram.shell.ui.errors import UIError


def register(app: FastAPI, ctx) -> None:
    settings = AppSettings(ctx.service.home, runtime=ctx.runtime)

    @app.get("/api/app")
    def app_view() -> dict:
        return settings.view()

    @app.put("/api/app/start-at-login")
    def start_at_login(body: dict = Body(...)) -> dict:
        on = body.get("on") if isinstance(body, dict) else None
        if not isinstance(on, bool):
            raise UIError(400, "Give on as true or false.")
        return settings.set_start_at_login(on)

    @app.post("/api/app/restart-helper")
    def restart_helper() -> dict:
        return settings.restart_helper()  # the runtime publishes app.helper

    @app.post("/api/recover")
    def recover(body: dict = Body(...)) -> dict:
        kit = body.get("kit") if isinstance(body, dict) else None
        out = ctx.service.account.recover(kit)
        ctx.bus.publish("overview.changed")
        return out
