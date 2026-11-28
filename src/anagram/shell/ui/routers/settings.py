"""Drafting settings routes of the local UI. Logic: `shell/ui/settings.py`.

    GET /api/settings              the drafting mode and the external model opt-in
    GET /api/settings/ollama       a local Ollama server and its models
    PUT /api/settings/drafting     {mode, model?}
    PUT /api/settings/model        {enabled, provider?, acknowledged}

`PUT /api/settings/findable` is an account route (`account.py`).
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.routers import UIContext, body_text


def register(app: FastAPI, ctx: UIContext) -> None:
    settings = ctx.service.settings

    @app.get("/api/settings")
    def view() -> dict:
        return settings.view()

    @app.get("/api/settings/ollama")
    def ollama() -> dict:
        return settings.detect_ollama()

    @app.put("/api/settings/drafting")
    def set_drafting(body: dict = Body(...)) -> dict:
        return settings.set_drafting(
            body_text(body, "mode"), body_text(body, "model", required=False)
        )

    @app.put("/api/settings/model")
    def set_model(body: dict = Body(...)) -> dict:
        return settings.set_model(
            bool(body.get("enabled")),
            body_text(body, "provider", required=False),
            bool(body.get("acknowledged")),
        )
