"""Understanding routes: models, items and
suggestions.

    GET    /api/models                          state, profiles, use, budget
    PUT    /api/models/profiles/{id}            make ("new") or change a profile
    DELETE /api/models/profiles/{id}            also deletes the key and the opt-ins
    PUT    /api/models/profiles/{id}/key        store the key; the answer has no key
    DELETE /api/models/profiles/{id}/key
    POST   /api/models/profiles/{id}/test       probe; no paid call
    PUT    /api/models/use                      the model for one task
    PUT    /api/models/budget                   the spend limit
    PUT    /api/labs/{lab_id}/models            the lab model: {"profile", "lab_text"} (PI or admin)
    GET    /api/sources/{sid}/recipients        the models that may read a source
    PUT    /api/sources/{sid}/recipients
    GET    /api/kinds?space=                    each kind with its count
    GET    /api/items?space=&kind=&q=&cursor=&limit=
    GET    /api/items/{ref}                     claims, names, links, versions
    PUT    /api/items/{ref}/kind                the correction of the person
    GET    /api/suggestions                     proposed findings
    POST   /api/suggestions/{id}                {"action": "later" | "dismiss"}
    GET    /api/search?q=&space=&kind=&since=&k=  scoped search
    GET    /api/ask/setup                       the model, the spaces, example titles
    POST   /api/ask                             {"question", "space"} -> {"thread"}
    GET    /api/ask/history, DELETE /api/ask/history
    GET    /api/ask/{thread}                    one answer of this session (a reload)
    GET    /api/timeline?space=&since=&until=   the weeks of a scope

Assistant access: `routers/agents.py`.

`space` is `private`, `lab:<lab id>`, or `all` (the default: each readable
space). All routes need the cookie (the guard of `shell/ui/server.py`). Events go
to the one stream: `models.state` when the state changes, `item.kind` for a
correction, `suggestion.new` and `suggestion.changed` for proposals, and
`ask.sources`, `ask.delta`, `ask.done`, `ask.error` (key: the thread id) for
an answer, and `timeline.changed` when a weekly summary is
ready. The logic is in three parts of `UIService`: `models`
(`shell/ui/models.py`), `understanding` (`shell/ui/understanding.py`: kinds,
items, suggestions), and `ask` (`shell/ui/ask.py`: search, ask,
timeline).
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.routers import UIContext, body_dict


def register(app: FastAPI, ctx: UIContext) -> None:
    models_ui = ctx.service.models
    understanding = ctx.service.understanding
    ask_ui = ctx.service.ask

    @app.get("/api/models")
    def models() -> dict:
        return models_ui.models()

    @app.put("/api/models/profiles/{pid}")
    def put_profile(pid: str, body: dict = Body(...)) -> dict:
        return models_ui.put_profile(pid, body_dict(body))

    @app.delete("/api/models/profiles/{pid}")
    def delete_profile(pid: str) -> dict:
        return models_ui.delete_profile(pid)

    @app.put("/api/models/profiles/{pid}/key")
    def put_key(pid: str, body: dict = Body(...)) -> dict:
        return models_ui.put_key(pid, body_dict(body).get("key"))

    @app.delete("/api/models/profiles/{pid}/key")
    def delete_key(pid: str) -> dict:
        return models_ui.delete_key(pid)

    @app.post("/api/models/profiles/{pid}/test")
    def test_profile(pid: str) -> dict:
        return models_ui.test_profile(pid)

    @app.put("/api/models/use")
    def set_use(body: dict = Body(...)) -> dict:
        body = body_dict(body)
        return models_ui.set_use(
            body.get("task"), body.get("profile"), body.get("acknowledged") is True
        )

    @app.put("/api/models/budget")
    def set_budget(body: dict = Body(...)) -> dict:
        body = body_dict(body)
        return models_ui.set_budget(body.get("budget_usd"), body.get("expires"))

    @app.put("/api/labs/{lab_id}/models")
    def set_lab_models(lab_id: str, body: dict = Body(...)) -> dict:
        return models_ui.set_lab_models(lab_id, body_dict(body))

    @app.get("/api/sources/{sid}/recipients")
    def get_recipients(sid: str) -> dict:
        return models_ui.get_recipients(sid)

    @app.put("/api/sources/{sid}/recipients")
    def set_recipients(sid: str, body: dict = Body(...)) -> dict:
        return models_ui.set_recipients(sid, body_dict(body).get("allow"))

    @app.get("/api/kinds")
    def kinds(space: str | None = None) -> list[dict]:
        return understanding.kind_counts(space)

    @app.get("/api/items")
    def items(
        space: str | None = None,
        kind: str | None = None,
        q: str | None = None,
        cursor: str | None = None,
        limit: str | None = None,  # the service parses it, for one error shape
    ) -> dict:
        return understanding.items(space, kind, q, cursor, limit)

    @app.get("/api/items/{ref}")
    def item(ref: str) -> dict:
        return understanding.item(ref)

    @app.put("/api/items/{ref}/kind")
    def set_kind(ref: str, body: dict = Body(...)) -> dict:
        return understanding.set_kind(ref, body_dict(body).get("kind"))

    @app.get("/api/suggestions")
    def suggestions() -> list[dict]:
        return understanding.suggestions()

    @app.post("/api/suggestions/{draft_id}")
    def act_on_suggestion(draft_id: str, body: dict = Body(...)) -> list[dict]:
        return understanding.act_on_suggestion(draft_id, body_dict(body).get("action"))

    @app.get("/api/search")
    def search(
        q: str | None = None,
        space: str | None = None,
        kind: str | None = None,
        since: str | None = None,
        k: str | None = None,
    ) -> dict:
        return ask_ui.search(q, space, kind, since, k)

    @app.get("/api/ask/setup")
    def ask_setup() -> dict:
        return ask_ui.ask_setup()

    @app.post("/api/ask")
    def ask(body: dict = Body(...)) -> dict:
        body = body_dict(body)
        return ask_ui.start_ask(body.get("question"), body.get("space"))

    @app.get("/api/ask/history")
    def ask_history() -> list[dict]:
        return ask_ui.ask_history()

    @app.delete("/api/ask/history")
    def clear_ask_history() -> dict:
        return ask_ui.clear_ask_history()

    @app.get("/api/ask/{thread}")
    def ask_thread(thread: str) -> dict:
        return ask_ui.ask_thread(thread)

    @app.get("/api/timeline")
    def timeline(
        space: str | None = None, since: str | None = None, until: str | None = None
    ) -> list:
        return ask_ui.timeline(space, since, until)
