"""Network matching routes of the local UI (layer L3): matching through the
network enclave (`simulated` profile in this build).

    GET  /api/enclave                  state: set up, draft, approved, on, cards, receipts
    PUT  /api/enclave/setup            {"log_url", "pins"}: the enclave log and the network pins
    POST /api/enclave/draft            a new beacon draft from the profile lens
    PUT  /api/enclave/draft            {"offers", "wants"}: keep the edited lines (not sent)
    GET  /api/enclave/consent          the consent statement of the checked release
    POST /api/enclave/approve          {"statement_hash"}
    POST /api/enclave/on               {"on": bool}: matching on (upload) or off (withdrawal)
    PUT  /api/enclave/weekly-cap       {"weekly_cap": n}: 1 to the network's maximum
    POST /api/enclave/run              the day's work now: upload, slot, answers, receipts
    POST /api/enclave/answer           {"proposal", "choice", "card"}

Logic: `shell/ui/enclave.py`. The task `enclave.daily` runs the day's work
each 10 minutes and publishes `enclave.changed`.
"""

from __future__ import annotations

from fastapi import Body, FastAPI

from anagram.shell.ui.routers import UIContext, body_dict, body_text

DAILY_S = 600


def register(app: FastAPI, ctx: UIContext) -> None:
    part = ctx.service.enclave
    ctx.tasks.add("enclave.daily", part.tick, DAILY_S)

    @app.get("/api/enclave")
    def state() -> dict:
        return part.state()

    @app.put("/api/enclave/setup")
    def setup(body: dict = Body(...)) -> dict:
        body = body_dict(body)
        return part.setup(body_text(body, "log_url"), body_dict(body.get("pins")))

    @app.post("/api/enclave/draft")
    def draft() -> dict:
        return part.draft()

    @app.put("/api/enclave/draft")
    def save_draft(body: dict = Body(...)) -> dict:
        return part.save_draft(body_dict(body))

    @app.post("/api/enclave/suggestions/apply")
    def apply_suggestions() -> dict:
        return part.apply_suggestions()

    @app.post("/api/enclave/suggestions/dismiss")
    def dismiss_suggestions() -> dict:
        return part.dismiss_suggestions()

    @app.post("/api/enclave/draft/archive-line")
    def archive_line(body: dict = Body(...)) -> dict:  # noqa: B008
        return part.archive_line(body_text(body_dict(body), "text"))

    @app.get("/api/enclave/consent")
    def consent() -> dict:
        return part.consent()

    @app.post("/api/enclave/approve")
    def approve(body: dict = Body(...)) -> dict:
        return part.approve(body_text(body_dict(body), "statement_hash"))

    @app.post("/api/enclave/on")
    def set_on(body: dict = Body(...)) -> dict:
        return part.set_on(bool(body_dict(body).get("on")))

    @app.put("/api/enclave/weekly-cap")
    def weekly_cap(body: dict = Body(...)) -> dict:
        return part.set_weekly_cap(body_dict(body).get("weekly_cap"))

    @app.post("/api/enclave/run")
    def run() -> dict:
        return part.run()

    @app.post("/api/enclave/answer")
    def answer(body: dict = Body(...)) -> dict:
        body = body_dict(body)
        card = body.get("card")
        return part.answer(
            body_text(body, "proposal"),
            body_text(body, "choice"),
            body_dict(card) if card is not None else None,
        )
