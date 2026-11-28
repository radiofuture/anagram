"""Matching through the network enclave in the local UI (layer L3).

The screen "Network matching": set up (log URL and network pins), the
beacon draft from the `profile` lens or typed lines, the consent statement
of the checked release, approval (manual or ambient), on and off, the day's
work, the cards, and the answers. The logic is in `EnclaveMatching`
(`network/matching/app/enclave_matching.py`); this part maps it to the
screen and gives each error plain words.

The lens runs only on a local model (the `draft` model of the model
profiles, for example Ollama) and the index embedder. Without them the
person types the lines.
"""

from __future__ import annotations

import hashlib
import logging
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

log = logging.getLogger(__name__)

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


def _local_draft_model(ui: UIService, c, idx):
    if ui.embedder is None:
        return None
    model, _ = ui.settings.draft_model(c, idx)
    if model is None or getattr(model, "external", True):
        return None
    return model


class EnclaveUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def _view(self, c, *, can_ambient: bool) -> dict:
        return {
            **c.enclave.status(),
            "can_ambient": can_ambient,
            "simulated": _is_simulated(c.enclave),
        }

    def state(self) -> dict:
        if self.ui.embedder is None:
            with self.ui.session() as c:
                return self._view(c, can_ambient=False)
        with self.ui.session(index=True) as (c, idx):
            return self._view(c, can_ambient=_local_draft_model(self.ui, c, idx) is not None)

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
            model = _local_draft_model(ui, c, idx)
            if model is None:
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

    def refresh_ambient(self) -> dict | None:
        """Ambient background refresh: once the person has consented to ambient
        mode and matching is on, keep the active matching lines updated from
        indexed work (respecting `TrustPolicy` and user-removed lines)."""
        ui = self.ui
        if ui.embedder is None or not ui.joined():
            return None
        with ui.open_client(index=True) as (c, idx):
            if not c.enclave.ambient_active():
                return None
            model = _local_draft_model(ui, c, idx)
            if model is None:
                return None
            policy = _trust_policy(c, idx)
            items = lens_items(idx, policy=policy)
            if not items:
                return None
            fp = _items_fingerprint(items)
            if fp == c.enclave.ambient_fingerprint():
                return None
            cache = SqliteLensCache(idx.store, clock=ui.clock)
            view = ProfileLens(model, ui.embedder, answers=cache).view(
                items, today=datetime.fromtimestamp(ui.clock(), UTC).date()
            )
            candidate = view.draft_json()
        with ui.session() as c:
            updated = c.enclave.update_ambient_lines(candidate, fingerprint=fp)
            if updated is not None:
                ui.publish("enclave.changed", {})
            return updated

    def switch_manual(self) -> dict:
        with self.ui.session() as c:
            return {**c.enclave.switch_to_manual(), "simulated": _is_simulated(c.enclave)}

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

    def approve(self, statement_hash: str, *, ambient: bool = False) -> dict:
        if ambient:
            if self.ui.embedder is None:
                raise UIError(409, NO_LENS)
            with self.ui.session(index=True) as (c, idx):
                if _local_draft_model(self.ui, c, idx) is None:
                    raise UIError(409, NO_LENS)
                c.enclave.approve(statement_hash, ambient=True)
                return c.enclave.status()
        with self.ui.session() as c:
            c.enclave.approve(statement_hash, ambient=False)
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
        """Run the day's enclave matching first so local indexing/LLM work
        never delays or skips matching; then run ambient line refresh in
        isolation."""
        try:
            with self.ui.session(index=True) as (c, idx):
                if c.enclave.settings() and c.enclave.status()["enrolled"]:
                    c.enclave.sync_trust_policy(_trust_policy(c, idx).subjects("deny"))
                    c.enclave.run()
                    self.ui.publish("enclave.changed", {})
        except UIError:
            pass
        try:
            self.refresh_ambient()
        except Exception as exc:
            log.warning("enclave ambient refresh failed: %s", type(exc).__name__)
