"""Account routes of the local UI (layer L1). Logic: `shell/ui/account.py`.

GET  /api/overview                 the start state of the page
PUT  /api/identity                 {name, ror, institution_name?, lab_id?, new_lab?}
GET  /api/account                  devices, guardians, alerts, guardian requests
POST /api/devices                  {request}: add a device
POST /api/guardians                {people, threshold}
POST /api/guardians/approve        {request_id}
PUT  /api/settings/findable        {on}
POST /api/store/sync               send the vault records to the personal store
GET  /api/recovery-kit             the pending kit (code), or saved
GET  /api/recovery-kit/file        the kit as a download
POST /api/recovery-kit/saved       the person saved the kit
POST /api/recovery-kit/new         make a new kit
GET  /api/flows                    the guided flows of the page
"""

from __future__ import annotations

from fastapi import Body, FastAPI
from fastapi.responses import Response

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.flows import live_flows
from anagram.shell.ui.routers import UIContext, body_text


def register(app: FastAPI, ctx: UIContext) -> None:
    account = ctx.service.account

    @app.get("/api/overview")
    def overview() -> dict:
        return account.overview()

    @app.put("/api/identity")
    def identity(body: dict = Body(...)) -> dict:
        return account.set_identity(
            body_text(body, "name"),
            body_text(body, "ror", required=False),
            body_text(body, "institution_name", required=False),
            lab_id=body_text(body, "lab_id", required=False),
            new_lab=body_text(body, "new_lab", required=False),
        )

    @app.get("/api/account")
    def view() -> dict:
        return account.view()

    @app.post("/api/devices")
    def add_device(body: dict = Body(...)) -> dict:
        return account.add_device(body_text(body, "request"))

    @app.post("/api/guardians")
    def guardians(body: dict = Body(...)) -> dict:
        people = body.get("people")
        if not isinstance(people, list) or not all(isinstance(p, str) for p in people):
            raise UIError(400, "Choose people from the search results.")
        return account.set_guardians(people, int(body.get("threshold") or 2))

    @app.post("/api/guardians/approve")
    def guardian_approve(body: dict = Body(...)) -> dict:
        return account.approve_guardian(body_text(body, "request_id"))

    @app.put("/api/settings/findable")
    def set_findable(body: dict = Body(...)) -> dict:
        return account.set_findable(bool(body.get("on")))

    @app.post("/api/store/sync")
    def sync_store() -> dict:
        return account.sync_store()

    @app.get("/api/recovery-kit")
    def kit() -> dict:
        return account.recovery_kit()

    @app.get("/api/recovery-kit/file")
    def kit_file() -> Response:
        return Response(
            account.recovery_kit_text(),
            media_type="text/markdown",
            headers={"Content-Disposition": 'attachment; filename="anagram-recovery-kit.md"'},
        )

    @app.post("/api/recovery-kit/saved")
    def kit_saved() -> dict:
        return account.kit_saved()

    @app.post("/api/recovery-kit/new")
    def kit_new() -> dict:
        return account.new_recovery_kit()

    @app.get("/api/flows")
    def flows() -> list[dict]:
        return live_flows(ctx.service)
