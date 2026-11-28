"""Assistant access routes (agent grant v2 and the act queue).

    GET    /api/assistant                       grants, past grants, proposals, places
    POST   /api/assistant                       {"name", "spaces", "recipient_class",
                                                 "acts", "expires"}: a new grant
    PUT    /api/assistant/{id}                  any of {"spaces", "recipient_class",
                                                 "acts", "expires"}
    DELETE /api/assistant/{id}                  stop access (revoke; the row stays)
    POST   /api/assistant/{id}/http             a new loopback HTTP key (shows one time)
    POST   /api/assistant/proposals/{id}        {"action": "approve" | "decline"}

All routes need the cookie (the guard of `shell/ui/server.py`). The only
way to approve a proposal of an agent is the last route; no agent tool
reaches it. Event: `assistant.changed`. The logic is `UIService.agents`
(`shell/ui/agents.py`).
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.routers import UIContext, body_dict


def register(app: FastAPI, ctx: UIContext) -> None:
    agents = ctx.service.agents

    @app.get("/api/assistant")
    def assistant() -> dict:
        return agents.assistant()

    @app.post("/api/assistant")
    def add_assistant(body: dict = Body(...)) -> dict:
        return agents.add_assistant(body_dict(body))

    @app.post("/api/assistant/proposals/{act_id}")
    def decide(act_id: str, body: dict = Body(...)) -> dict:
        return agents.decide(act_id, body_dict(body))

    @app.put("/api/assistant/{assistant_id}")
    def change_assistant(assistant_id: str, body: dict = Body(...)) -> dict:
        return agents.change_assistant(assistant_id, body_dict(body))

    @app.delete("/api/assistant/{assistant_id}")
    def remove_assistant(assistant_id: str) -> dict:
        return agents.remove_assistant(assistant_id)

    @app.post("/api/assistant/{assistant_id}/http")
    def http_key(assistant_id: str) -> dict:
        return agents.http_key(assistant_id)
