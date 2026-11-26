"""The drafting settings of the local UI (models, layer XM): how Anagram
drafts (built-in, a local Ollama model, or off), the opt-in for an
external drafting provider, and the model of the task `draft` in the model
profiles.

The model profiles themselves (`/api/models`) are in `shell/ui/understanding.py`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from anagram.local.api import LocalIndex
from anagram.models import ModelError
from anagram.models import profile as mprofile
from anagram.models.ollama_client import DEFAULT_MODEL as OLLAMA_DEFAULT_MODEL
from anagram.models.ollama_client import OllamaClient, OllamaError
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.client import Client
    from anagram.shell.ui.service import UIService

DRAFTING_LABELS = {
    "builtin": "Built-in (no AI)",
    "ollama": "Local model (Ollama)",
    "off": "Off",
}


def _no_ollama(method, url, body, timeout):
    raise OllamaError("Ollama detection is off in this UI")


class SettingsUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def drafting(self) -> dict:
        s = self.ui.state.get("settings") or {}
        d = s.get("drafting") or {}
        mode = d.get("mode") if d.get("mode") in DRAFTING_LABELS else "builtin"
        return {"mode": mode, "model": d.get("model") or OLLAMA_DEFAULT_MODEL}

    def view(self) -> dict:
        s = self.ui.state.get("settings") or {}
        model = s.get("model") or {"enabled": False, "provider": None}
        providers = [
            {"id": k, "label": d.recipient or d.name} for k, d in sorted(self.ui.drafters.items())
        ]
        d = self.drafting()
        return {
            "drafting": {
                "mode": d["mode"],
                "model": d["model"],
                "modes": [{"id": k, "label": v} for k, v in DRAFTING_LABELS.items()],
            },
            "model": model,
            "providers": providers,
        }

    def detect_ollama(self) -> dict:
        """Is a local Ollama server on this computer, and which models does it
        have? Only a loopback address is asked."""
        if self.ui.ollama is None:
            return {"available": False, "models": [], "url": None}
        return self.ui.ollama.detect()

    def set_drafting(self, mode: str, model: str | None) -> dict:
        if mode not in DRAFTING_LABELS:
            raise UIError(400, "Choose Built-in, Local model, or Off.")
        if model is not None and (not re.fullmatch(r"[\w.:/-]{1,100}", model)):
            raise UIError(400, "Type a model name as Ollama shows it, for example llama3.2.")
        s = self.ui.state.get("settings") or {}
        s["drafting"] = {"mode": mode, "model": model or self.drafting()["model"]}
        self.ui.state.update(settings=s)
        self._sync_draft_profile(mode, s["drafting"]["model"])
        return self.view()

    def set_model(self, enabled: bool, provider: str | None, acknowledged: bool) -> dict:
        if enabled:
            if provider not in self.ui.drafters:
                raise UIError(400, "Choose a provider.")
            if not acknowledged:
                raise UIError(400, "Confirm that the provider may read the files you select.")
        s = self.ui.state.get("settings") or {}
        s["model"] = {"enabled": bool(enabled), "provider": provider if enabled else None}
        self.ui.state.update(settings=s)
        return self.view()

    # ------------------------------------------------------- draft model

    def draft_model(self, c: Client, idx: LocalIndex) -> tuple[object | None, object]:
        """The model of the task `draft` (the model profiles, with the lab
        defaults of the first lab), and its profile; (None, None) if no model
        is set or the model cannot be used now (for example, no budget)."""

        first = next((x["lab_id"] for x in c.labs.lab_list()), None)
        lab = c.lab_space.lab_policy(first) if first else None
        cfg = mprofile.load(idx, lab)
        pid = cfg.use.get("draft")
        if pid is None:
            return None, None
        clients = {"ollama": self.ui.ollama or OllamaClient(transport=_no_ollama)}
        try:
            model = mprofile.resolve(cfg, "draft", c.keystore, self.ui.home, clients=clients)
        except ModelError:
            return None, None
        return model, cfg.profiles.get(pid)

    def _sync_draft_profile(self, mode: str, model: str) -> None:
        """Keep the `draft` task of the model profiles equal to the drafting
        setting of this screen: `ollama` selects a local Ollama profile;
        `builtin` and `off` select no model. Before the join there is no
        index, and no model is selected."""

        try:
            with self.ui.session(index=True) as (_, idx):
                cfg = mprofile.load(idx, None)
                pid = None
                if mode == "ollama":
                    p = mprofile.make_profile(
                        {"label": "Local model (Ollama)", "model": model, "provider": "ollama"}
                    )
                    cfg = mprofile.put_profile(cfg, p)
                    pid = p.id
                mprofile.save(idx, mprofile.set_use(cfg, "draft", pid))
        except (UIError, ModelError):
            return
