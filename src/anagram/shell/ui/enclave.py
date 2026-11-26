"""Matching through the network enclave in the local UI (layer L3).

The screen "Network matching": set up (log URL and network pins), the
beacon draft from the `profile` lens or typed lines, the consent statement
of the checked release, approval, on and off, the day's work, the cards,
and the answers. The logic is in `EnclaveMatching`
(`network/matching/app/enclave_matching.py`); this part maps it to the
screen and gives each error plain words.

The lens runs only on a local model (the `draft` model of the model
profiles, for example Ollama) and the index embedder. Without them the
person types the lines.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from anagram.local.api import ProfileLens, lens_items
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

NO_LENS = (
    "Anagram can draft your lines only with a local model and the search index."
    " Set a local model in Settings, or type your lines."
)


class EnclaveUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def state(self) -> dict:
        with self.ui.session() as c:
            return c.enclave.status()

    def setup(self, log_url: str, pins: dict) -> dict:
        with self.ui.session() as c:
            c.enclave.set_settings(log_url, pins)
            return c.enclave.status()

    def draft(self) -> dict:
        """A new beacon draft from the `profile` lens. Nothing leaves."""
        ui = self.ui
        if ui.embedder is None:
            raise UIError(409, NO_LENS)
        with ui.session(index=True) as (c, idx):
            model, _ = ui.settings.draft_model(c, idx)
            if model is None or getattr(model, "external", True):
                raise UIError(409, NO_LENS)
            items = lens_items(idx)  # own items; the default tier of own work
            view = ProfileLens(model, ui.embedder).view(
                items, today=datetime.fromtimestamp(ui.clock(), UTC).date()
            )
            c.enclave.set_draft(view.draft_json())
            return c.enclave.status()

    def save_draft(self, body: dict) -> dict:
        with self.ui.session() as c:
            c.enclave.set_draft(body)
            return c.enclave.status()

    def consent(self) -> dict:
        with self.ui.session() as c:
            return c.enclave.consent()

    def approve(self, statement_hash: str) -> dict:
        with self.ui.session() as c:
            c.enclave.approve(statement_hash)
            return c.enclave.status()

    def set_on(self, on: bool) -> dict:
        with self.ui.session() as c:
            return c.enclave.turn_on() if on else c.enclave.turn_off()

    def set_weekly_cap(self, value: object) -> dict:
        with self.ui.session() as c:
            return c.enclave.set_weekly_cap(value)

    def run(self) -> dict:
        with self.ui.session() as c:
            return c.enclave.run()

    def answer(self, proposal: str, choice: str, card: dict | None) -> dict:
        with self.ui.session() as c:
            return c.enclave.answer(proposal, choice, card)

    def tick(self) -> None:
        """The daily work in the background, when matching is set up and the
        person enrolled. An error waits for the next tick."""
        try:
            with self.ui.session() as c:
                if c.enclave.settings() and c.enclave.status()["enrolled"]:
                    c.enclave.run()
                    self.ui.publish("enclave.changed", {})
        except UIError:
            return
