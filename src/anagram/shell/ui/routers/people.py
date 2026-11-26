"""Directory routes of the local UI (layer L1). Logic: `shell/ui/people.py`.

    GET /api/people?q=          members (and a typed ORCID iD)
    GET /api/institutions?q=    the institution list, and the ones in use here

The lab search (`GET /api/labs?q=`) is in `shell/ui/routers/labs.py`.
"""

from __future__ import annotations

from fastapi import FastAPI

from anagram.shell.ui.routers import UIContext


def register(app: FastAPI, ctx: UIContext) -> None:
    people = ctx.service.people

    @app.get("/api/people")
    def search(q: str = "") -> list[dict]:
        return people.search(q)

    @app.get("/api/institutions")
    def institutions(q: str = "") -> list[dict]:
        return people.search_institutions(q)
