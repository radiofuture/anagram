"""Source routes of the local UI (layer L2). The logic
is in three parts of `UIService`: `sources` (`shell/ui/sources.py`),
`connections` (`shell/ui/connections.py`: accounts and sign-in), and
`lab_sources` (`shell/ui/lab_sources.py`: the source settings of a lab).

Live events of sources do not go to `ctx.bus` here. The service writes them to
the table `source_event`, and the event bridge sends them on the one stream.
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.routers import UIContext, body_text


def register(app: FastAPI, ctx: UIContext) -> None:
    sources = ctx.service.sources
    connections = ctx.service.connections
    lab_sources = ctx.service.lab_sources

    @app.get("/api/sources")
    def listing() -> dict:
        return sources.list()

    @app.post("/api/sources")
    def add(body: dict = Body(...)) -> dict:
        # The whole body goes to the sources service (kind, path, space,
        # label, and the fields of later kinds); it checks each field.
        body_text(body, "kind")
        return sources.add(body)

    @app.post("/api/sources/refresh")
    def refresh() -> dict:
        return sources.refresh()

    @app.get("/api/browse")
    def browse(path: str | None = None) -> dict:
        return sources.browse(path)

    @app.get("/api/source-kinds")
    def source_kinds() -> dict:
        return sources.kinds()

    @app.get("/api/sources/{sid}")
    def source(sid: str) -> dict:
        return sources.get(sid)

    @app.patch("/api/sources/{sid}")
    def change(sid: str, body: dict = Body(...)) -> dict:
        return sources.patch(sid, body)

    @app.post("/api/sources/{sid}/pause")
    def pause(sid: str) -> dict:
        return sources.pause(sid)

    @app.post("/api/sources/{sid}/resume")
    def resume(sid: str) -> dict:
        return sources.resume(sid)

    @app.post("/api/sources/{sid}/sync")
    def sync(sid: str) -> dict:
        return sources.sync(sid)

    @app.delete("/api/sources/{sid}")
    def remove(sid: str, body: dict | None = Body(None)) -> dict:
        delete_data = (body or {}).get("delete_data", True)
        return sources.remove(sid, delete_data=delete_data)

    # Accounts of connected sources. The sign-in redirect goes to
    # a separate one-use listener on 127.0.0.1 (`local/sources/oauth.py`), not to a
    # route of this server.

    @app.get("/api/accounts")
    def accounts() -> dict:
        return connections.accounts()

    @app.get("/api/accounts/{account_id}/choices")
    def choices(account_id: str, kind: str, parent: str | None = None) -> dict:
        return sources.choices(account_id, kind, parent)

    @app.post("/api/sources/preview")
    def preview(body: dict = Body(...)) -> dict:
        return sources.preview(body)

    @app.post("/api/accounts/connect")
    def connect(body: dict = Body(...)) -> dict:
        return connections.connect(body)

    @app.post("/api/accounts/key")
    def connect_key(body: dict = Body(...)) -> dict:
        return connections.connect_key(body)

    @app.get("/api/accounts/connect/{flow}")
    def connect_state(flow: str) -> dict:
        return connections.flow(flow)

    @app.post("/api/accounts/connect/{flow}/cancel")
    def connect_cancel(flow: str) -> dict:
        return connections.cancel(flow)

    # The sections `oauth_clients` and `sources` of the lab settings. The
    # slot view `lab.settings` and the add-source setup use them.

    @app.get("/api/source-settings")
    def source_settings() -> dict:
        return lab_sources.lab_source_settings()

    @app.put("/api/source-settings/{lab_id}/clients/{provider}")
    def set_client(lab_id: str, provider: str, body: dict = Body(...)) -> dict:
        return lab_sources.set_lab_client(lab_id, provider, body)

    @app.delete("/api/source-settings/{lab_id}/clients/{provider}")
    def remove_client(lab_id: str, provider: str) -> dict:
        return lab_sources.remove_lab_client(lab_id, provider)

    @app.put("/api/source-settings/{lab_id}/sources")
    def set_lab_sources(lab_id: str, body: dict = Body(...)) -> dict:
        return lab_sources.set_lab_sources(lab_id, body)

    @app.delete("/api/accounts/{account_id}")
    def remove_account(account_id: str, body: dict | None = Body(None)) -> dict:
        remove_sources = (body or {}).get("remove_sources", False)
        return connections.remove_account(account_id, remove_sources=remove_sources)
