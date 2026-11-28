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

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from anagram.local.api import (
    ProfileLens,
    SqliteLensCache,
    TrustPolicy,
    TrustStore,
    lens_items,
)
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

NO_LENS = (
    "Anagram can draft your lines only with a local model and the search index."
    " Set a local model in Account under Model, or type your lines."
)


def _is_simulated(enclave) -> bool:
    s = enclave.settings()
    pins = s.get("pins") if isinstance(s, dict) else None
    if not isinstance(pins, dict):
        return False
    return bool(pins.get("dev_root")) or pins.get("profile") == "simulated"


def _trust_policy(c, idx) -> TrustPolicy:
    device = c.device
    return TrustStore(idx.store, device.subject, [device.device_key().public_bytes()]).current()


def _items_fingerprint(items) -> str:
    parts = sorted(
        f"{i.id}\x1f{i.role}\x1f{i.date}\x1f{i.tier}\x1f"
        f"{hashlib.sha256(i.text.encode()).hexdigest()}"
        for i in items
    )
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


class EnclaveUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def state(self) -> dict:
        with self.ui.session() as c:
            return {**c.enclave.status(), "simulated": _is_simulated(c.enclave)}

    def setup(self, log_url: str, pins: dict) -> dict:
        with self.ui.session() as c:
            c.enclave.set_settings(log_url, pins)
            return {**c.enclave.status(), "simulated": _is_simulated(c.enclave)}

    def draft(self) -> dict:
        """A new beacon draft from the `profile` lens. Nothing leaves."""
        ui = self.ui
        if ui.embedder is None:
            raise UIError(409, NO_LENS)
        with ui.session(index=True) as (c, idx):
            model, _ = ui.settings.draft_model(c, idx)
            if model is None or getattr(model, "external", True):
                raise UIError(409, NO_LENS)
            policy = _trust_policy(c, idx)
            c.enclave.sync_trust_policy(policy.subjects("deny"))
            items = lens_items(idx, policy=policy)
            cache = SqliteLensCache(idx.store, clock=ui.clock)
            view = ProfileLens(model, ui.embedder, answers=cache).view(
                items, today=datetime.fromtimestamp(ui.clock(), UTC).date()
            )
            c.enclave.set_draft(view.draft_json())
            return c.enclave.status()

    def refresh_suggestions(self) -> dict | None:
        """Ambient background refresh: compute candidate lines into
        `suggested_draft` without modifying `draft` or contacting the enclave."""
        ui = self.ui
        if ui.embedder is None or not ui.joined():
            return None
        with ui.open_client(index=True) as (c, idx):
            model, _ = ui.settings.draft_model(c, idx)
            if model is None or getattr(model, "external", True):
                return None
            policy = _trust_policy(c, idx)
            items = lens_items(idx, policy=policy)
            if not items:
                return None
            fp = _items_fingerprint(items)
            last_fp, dismissed_fp = c.enclave.suggestion_fingerprints()
            if fp in (last_fp, dismissed_fp):
                return None
            cache = SqliteLensCache(idx.store, clock=ui.clock)
            view = ProfileLens(model, ui.embedder, answers=cache).view(
                items, today=datetime.fromtimestamp(ui.clock(), UTC).date()
            )
            suggested = view.draft_json()
        with ui.session() as c:
            kept = c.enclave.set_suggested_draft(suggested, fingerprint=fp)
            if kept is not None:
                ui.publish("enclave.changed", {})
            return kept

    def apply_suggestions(self) -> dict:
        with self.ui.session() as c:
            return {**c.enclave.apply_suggested_draft(), "simulated": _is_simulated(c.enclave)}

    def dismiss_suggestions(self) -> dict:
        with self.ui.session() as c:
            return {**c.enclave.dismiss_suggested_draft(), "simulated": _is_simulated(c.enclave)}

    def archive_line(self, text: str) -> dict:
        with self.ui.session() as c:
            return {**c.enclave.remove_draft_line(text), "simulated": _is_simulated(c.enclave)}

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
        with self.ui.session(index=True) as (c, idx):
            if on:
                c.enclave.sync_trust_policy(_trust_policy(c, idx).subjects("deny"))
            return c.enclave.turn_on() if on else c.enclave.turn_off()

    def set_weekly_cap(self, value: object) -> dict:
        with self.ui.session() as c:
            return c.enclave.set_weekly_cap(value)

    def run(self) -> dict:
        with self.ui.session(index=True) as (c, idx):
            c.enclave.sync_trust_policy(_trust_policy(c, idx).subjects("deny"))
            return c.enclave.run()

    def answer(self, proposal: str, choice: str, card: dict | None) -> dict:
        with self.ui.session() as c:
            return c.enclave.answer(proposal, choice, card)

    def tick(self) -> None:
        """The daily work in the background, when matching is set up and the
        person enrolled, plus ambient suggestion refresh. An error waits for
        the next tick."""
        try:
            self.refresh_suggestions()
        except UIError:
            pass
        try:
            with self.ui.session(index=True) as (c, idx):
                if c.enclave.settings() and c.enclave.status()["enrolled"]:
                    c.enclave.sync_trust_policy(_trust_policy(c, idx).subjects("deny"))
                    c.enclave.run()
                    self.ui.publish("enclave.changed", {})
        except UIError:
            return
