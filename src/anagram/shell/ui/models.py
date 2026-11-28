"""Models in the local UI (layer L2; the part `UIService.models`).
The routes are in `shell/ui/routers/understanding.py`.

The part keeps the profiles, the keys, the test of a profile, the model for
each task, the spend limit, the lab model, and the sources that a model may
read. It also resolves the model of the task `ask` for the other parts.

Rules:

- The config is in the encrypted index store. A key goes to the keystore
  only. No method returns a key, and no error or event holds one.
- Each method uses `UIService.session`, so the person must be joined.
- A change publishes `models.state` when the state changes. The data is
  `{"state", "message", "next"}`.
- The test of a profile makes no paid call (`TextModel.probe`).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, replace
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from anagram.local.api import (
    shown,
    space_of,
)
from anagram.models import ModelError, profile, recipients
from anagram.models.budget import ledger_path, ledger_state
from anagram.models.ledger import BudgetLedger, EngineError, usd_text
from anagram.models.ollama_client import OllamaClient, OllamaError
from anagram.shell.client import lab_context
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

APPROVED_BY = "member"  # on this computer, the member approves the spend
MAX_BUDGET_USD = Decimal(1000)
NEW = "new"  # the id in the path for a profile that does not exist yet

# One plain sentence for each fault code. No code shows on a screen.
MESSAGES = {
    "invalid_key": "Type the key as the provider gives it, with no spaces.",
    "invalid_prices": "Type the two prices as numbers, in USD for one million tokens.",
    "invalid_profile": "Choose a provider and type a model name.",
    "invalid_profile_id": "This model is not in your list.",
    "invalid_url": "Type the address of the endpoint, for example https://llm.example.edu/v1.",
    "invalid_use": "Choose a model from your list.",
    "key_refused": "The provider refused the key.",
    "model_not_found": "The provider does not have a model with this name.",
    "model_not_installed": "Ollama does not have this model. Install it with Ollama first.",
    "no_key": "This model has no key.",
    "no_route": "Name the provider that OpenRouter must use.",
    "not_loopback": "Ollama must run on this computer.",
    "sdk_not_installed": "The Anthropic library is not installed on this computer.",
    "unreachable": "Anagram cannot reach the model.",
    "url_not_https": "The address must start with https://.",
}
FALLBACK = "The model did not give an answer that Anagram can use."


def sentence(code: str | None) -> str | None:
    return None if code is None else MESSAGES.get(code, FALLBACK)


def _refused(method: str, url: str, body: dict | None, timeout: float) -> Any:
    raise OllamaError("no Ollama client in this UI")


class ModelsUI:
    """`transport` and `clients` are for tests (a fake HTTP transport and fake
    provider clients). With no Ollama client in `ui` and none in
    `clients`, an Ollama profile is not reachable and no network call is made."""

    def __init__(
        self,
        ui: UIService,
        *,
        transport: object | None = None,
        clients: Mapping[str, object] | None = None,
        today: Callable[[], date] = lambda: datetime.now(UTC).date(),
    ) -> None:
        self.ui = ui
        self.transport = transport
        self.clients = dict(clients or {})
        # The UTC day: item times and weeks are UTC, so a local day lags
        # them in the evening west of Greenwich (the range ends tomorrow).
        self.today = today
        self.local_default = (
            True  # False: no zero-choice Ollama default (tests of the explicit flow)
        )

    # ----------------------------------------------------------- plumbing

    def provider_clients(self) -> dict:
        ollama = self.ui.ollama or OllamaClient(transport=_refused)
        return {"ollama": ollama, **self.clients}

    def lab_policy(self, client: Any) -> Any:
        """The policy of the first lab of the member, when the lab unit
        is in the client. None before that, and for a member with no lab."""
        labs = lab_context(client)
        if labs is None:
            return None
        for lab in labs.lab_list():
            lab_id = lab.get("lab_id") if isinstance(lab, dict) else None
            if lab_id:
                return labs.lab_policy(lab_id)
        return None

    def load(self, client: Any, idx: Any) -> tuple[profile.ModelConfig, Any]:
        lab = self.lab_policy(client)
        return profile.load(idx, lab), lab

    def state(self, client: Any, idx: Any, cfg: profile.ModelConfig) -> dict:
        return profile.state(
            idx, keystore=client.keystore, home=self.ui.home, today=self.today(), cfg=cfg
        )

    def _budget(self, cfg: profile.ModelConfig) -> dict | None:
        if cfg.budget is None:
            return None
        out = {
            "budget_usd": str(cfg.budget.get("budget_usd")),
            "expires": str(cfg.budget.get("expires")),
            "open": False,
            "spent_usd": None,
        }
        try:
            got = ledger_state(self.ui.home, cfg.budget, self.today())
        except ModelError:
            # Expired or invalid approval: still show the real spent total if a
            # ledger file exists, instead of falling back to $0.
            try:
                path = ledger_path(self.ui.home, cfg.budget)
                if path.exists():
                    snap = BudgetLedger(path, cfg.budget["budget_usd"]).snapshot()
                    out["spent_usd"] = usd_text(Decimal(snap["reserved_nanousd"]) / 10**9)
            except (EngineError, KeyError, OSError, ValueError):
                pass
            return out
        out["open"] = not got["breached"] and got["spent_usd"] < got["budget_usd"]
        out["spent_usd"] = usd_text(got["spent_usd"])
        return out

    def _profile_json(self, p: profile.Profile, keystore: Any, lab: Any) -> dict:
        model = profile.build(p)
        about = recipients.describe(p, lab)
        return {
            "base_url": p.base_url,
            "capabilities": asdict(model.capabilities()),
            "external": model.external,
            "has_key": profile.has_key(keystore, p.id),
            "id": p.id,
            "label": p.label,
            "lab_allows": about["lab_allows"],
            "model": p.model,
            "needs_key": p.provider in profile.KEY_MANDATORY,
            "origin": p.origin,
            "paid": model.paid,
            "prices": None if model.prices is None else [str(x) for x in model.prices],
            "provider": p.provider,
            "recipient": model.recipient,
            "route": list(p.route),
            "sentence": about["sentence"],
        }

    def adopt_local(
        self, client: Any, idx: Any, cfg: profile.ModelConfig
    ) -> tuple[profile.ModelConfig, dict | None]:
        """The zero-choice default: when no model reads the items, the member
        did not choose, and Ollama runs on this computer with a model, use it.
        One loopback call (`/api/tags`), and only while the default can apply.
        Give the config and what the call found (None: no call)."""
        if not self.local_default or not profile.wants_local(cfg):
            return cfg, None
        found = self.ui.settings.detect_ollama()
        new = (
            profile.local_default(cfg, list(found.get("models") or []))
            if found.get("available")
            else None
        )
        if new is None:
            return cfg, found
        before = self.state(client, idx, cfg)
        profile.save(idx, new)
        cfg, _ = self.load(client, idx)
        self.changed(before, self.state(client, idx, cfg))
        return cfg, found

    def _sources(self, idx: Any) -> list[dict]:
        """Each source with its name for people and the models that it permits."""
        out = []
        for sid, s in idx.sources().items():
            allow = (s.get("prefs") or {}).get("allow_external", [])
            out.append(
                {
                    "allow": [a.removeprefix("model:") for a in allow if a.startswith("model:")],
                    "id": sid,
                    "label": shown(idx.store, s.get("label"), s.get("config") or {}),
                    "space": space_of(idx, sid),
                }
            )
        return out

    def _view(
        self, client: Any, idx: Any, cfg: profile.ModelConfig, lab: Any, found: dict | None = None
    ) -> dict:
        lab_json = None
        if lab is not None:
            disclosure = lab.disclosure if isinstance(lab.disclosure, dict) else {}
            lab_json = {
                "allow_assistant": bool(disclosure.get("allow_assistant", False)),
                "allow_external": list(disclosure.get("allow_external", [])),
            }
        return {
            "budget": self._budget(cfg),
            "lab": lab_json,
            "ollama": {
                k: v for k, v in (found or self.ui.settings.detect_ollama()).items() if k != "url"
            },
            "profiles": [
                self._profile_json(p, client.keystore, lab) for _, p in sorted(cfg.profiles.items())
            ],
            "sources": self._sources(idx),
            "state": self.state(client, idx, cfg),
            "use": dict(cfg.use),
        }

    def changed(self, before: dict, after: dict) -> None:
        if after != before:
            self.ui.publish("models.state", after)

    def _edit(self, change: Callable[[Any, Any, profile.ModelConfig], profile.ModelConfig]) -> dict:
        """Load the config, apply `change`, store it, and give the view."""
        with self.ui.session(index=True) as (client, idx):
            cfg, lab = self.load(client, idx)
            before = self.state(client, idx, cfg)
            try:
                new = change(client, idx, cfg)
            except ModelError as exc:
                raise UIError(400, sentence(exc.code) or FALLBACK) from None
            if new is not cfg:
                profile.save(idx, new)
                cfg, lab = self.load(client, idx)
            view = self._view(client, idx, cfg, lab)
        self.changed(before, view["state"])
        return view

    def _member_profile(self, cfg: profile.ModelConfig, pid: str) -> profile.Profile:
        p = cfg.profiles.get(pid)
        if p is None:
            raise UIError(404, MESSAGES["invalid_profile_id"])
        if p.origin != "member":
            raise UIError(400, "Your lab set up this model. You cannot change it here.")
        return p

    def ask_model(self, client: Any, cfg: profile.ModelConfig) -> tuple[Any, str | None]:
        """The model of the task `ask` (else of `understand`), or None and the
        code of the reason. No network call."""
        task = "ask" if cfg.use.get("ask") else "understand"
        try:
            model = profile.resolve(
                cfg,
                task,
                client.keystore,
                self.ui.home,
                transport=self.transport,
                clients=self.provider_clients(),
                clock=self.ui.clock,
                today=self.today(),
            )
        except ModelError as exc:
            return None, exc.code
        return model, None if model is not None else "no_model"

    # ------------------------------------------------------------- routes

    def models(self) -> dict:
        with self.ui.session(index=True) as (client, idx):
            cfg, lab = self.load(client, idx)
            cfg, found = self.adopt_local(client, idx, cfg)
            return self._view(client, idx, cfg, lab, found)

    def set_lab_models(self, lab_id: str, body: object) -> dict:
        """The model of a lab, set by a PI or an admin: `{"profile": Profile
        JSON | null, "lab_text": bool}`. A profile becomes the lab default
        for reading, answers, and drafts. `lab_text`: an external model may
        read the text of the lab space. No key goes into the record; each
        member types a key. The answer is the lab settings view."""
        if not isinstance(body, dict) or not set(body) <= {"profile", "lab_text"}:
            raise UIError(400, "Bad request.")
        labs = self.ui.labs
        old = labs.settings(lab_id)["settings"]
        models = dict(old.get("models") or {})
        disclosure = dict(old.get("disclosure") or {})
        raw = body.get("profile")
        if raw is None:
            models.update(profiles=[], use={})
            disclosure["allow_external"] = []
        else:
            try:
                p = profile.make_profile(raw, origin=f"lab:{lab_id}")
            except ModelError as exc:
                raise UIError(400, sentence(exc.code) or FALLBACK) from None
            models.update(profiles=[p.to_json()], use=dict.fromkeys(profile.LOCAL_TASKS, p.id))
            external = profile.build(p).external
            allow = external and body.get("lab_text") is True
            disclosure["allow_external"] = [recipients.recipient_id(p)] if allow else []
        return labs.set_settings(lab_id, {"disclosure": disclosure, "models": models})

    def put_profile(self, pid: str, body: object) -> dict:
        """Make a profile (`pid` is "new") or change one. If the provider or
        the host changes, the profile gets a new id, and the old key and the
        old opt-ins are removed: they do not move to a different party."""
        saved: list[str] = []

        def change(client: Any, idx: Any, cfg: profile.ModelConfig) -> profile.ModelConfig:
            old = None if pid == NEW else self._member_profile(cfg, pid)
            p = profile.make_profile(body, keep_id=None if old is None else old.id)
            if old is None and p.id in cfg.profiles:
                raise UIError(409, "You have a model with this name. Give this one a new name.")
            if old is not None and p.id != old.id:
                if p.id in cfg.profiles:
                    raise UIError(409, "You have a model with this name and this address.")
                tasks = [t for t, used in cfg.use.items() if used == old.id]
                cfg = profile.remove_profile(idx, client.keystore, cfg, old.id)
                cfg = profile.put_profile(cfg, p)
                for task in tasks:
                    cfg = profile.set_use(cfg, task, None)
            else:
                cfg = profile.put_profile(cfg, p)
                profile.forget_health(idx, p.id)
            saved.append(p.id)
            return cfg

        return {**self._edit(change), "saved": saved[0]}

    def delete_profile(self, pid: str) -> dict:
        def change(client: Any, idx: Any, cfg: profile.ModelConfig) -> profile.ModelConfig:
            self._member_profile(cfg, pid)
            return profile.remove_profile(idx, client.keystore, cfg, pid)

        return self._edit(change)

    def put_key(self, pid: str, key: object) -> dict:
        with self.ui.session(index=True) as (client, idx):
            cfg, _ = self.load(client, idx)
            if pid not in cfg.profiles:
                raise UIError(404, MESSAGES["invalid_profile_id"])
            before = self.state(client, idx, cfg)
            try:
                profile.set_key(client.keystore, pid, key)  # type: ignore[arg-type]
            except ModelError as exc:
                raise UIError(400, sentence(exc.code) or FALLBACK) from None
            profile.forget_health(idx, pid)  # an old fault says nothing about a new key
            after = self.state(client, idx, cfg)
        self.changed(before, after)
        return {"has_key": True}

    def delete_key(self, pid: str) -> dict:
        with self.ui.session(index=True) as (client, idx):
            cfg, _ = self.load(client, idx)
            if pid not in cfg.profiles:
                raise UIError(404, MESSAGES["invalid_profile_id"])
            before = self.state(client, idx, cfg)
            profile.delete_key(client.keystore, pid)
            after = self.state(client, idx, cfg)
        self.changed(before, after)
        return {"has_key": False}

    def test_profile(self, pid: str) -> dict:
        """Check the address, the key, and the model name. No paid call. The
        network call is made with no lock held."""
        with self.ui.session(index=True) as (client, idx):
            cfg, _ = self.load(client, idx)
            p = cfg.profiles.get(pid)
            if p is None:
                raise UIError(404, MESSAGES["invalid_profile_id"])
            try:
                model = profile.build(
                    p,
                    key=profile.get_key(client.keystore, pid),
                    transport=self.transport,
                    structured=profile.cached_mode(cfg, pid, self.ui.clock()),
                    clients=self.provider_clients(),
                )
            except ModelError as exc:
                raise UIError(400, sentence(exc.code) or FALLBACK) from None
        try:
            got = model.probe()
        except ModelError as exc:
            got = {"ok": False, "reason": exc.code}
        ok = bool(got.get("ok"))
        reason = None if ok else str(got.get("reason") or "unreachable")
        with self.ui.session(index=True) as (client, idx):
            cfg, _ = self.load(client, idx)
            if pid not in cfg.profiles:
                raise UIError(404, MESSAGES["invalid_profile_id"])
            before = self.state(client, idx, cfg)
            profile.note_probe(idx, pid, {"ok": ok, "reason": reason})
            if ok:
                profile.remember_mode(idx, model, self.ui.clock)
            cfg, _ = self.load(client, idx)
            after = self.state(client, idx, cfg)
        self.changed(before, after)
        return {
            "capabilities": asdict(model.capabilities()),
            "message": sentence(reason),
            "ok": ok,
            "reason": reason,
        }

    def set_use(self, task: object, pid: object, acknowledged: bool) -> dict:
        def change(client: Any, idx: Any, cfg: profile.ModelConfig) -> profile.ModelConfig:
            if task not in profile.TASKS or not (pid is None or isinstance(pid, str)):
                raise UIError(400, MESSAGES["invalid_use"])
            if pid is not None:
                p = cfg.profiles.get(pid)
                if p is None:
                    raise UIError(404, MESSAGES["invalid_profile_id"])
                about = recipients.describe(p)
                if about["external"] and not acknowledged:
                    raise UIError(
                        400,
                        f"Confirm that {about['name']} may read the text of the sources"
                        " that you permit.",
                        {"recipient": about["name"]},
                    )
            return profile.set_use(cfg, task, pid)  # type: ignore[arg-type]

        return self._edit(change)

    def set_budget(self, budget_usd: object, expires: object) -> dict:
        """Set the spend limit. `budget_usd: null` removes it. A new limit or
        a new end date is a new approval with a new ledger."""

        def change(client: Any, idx: Any, cfg: profile.ModelConfig) -> profile.ModelConfig:
            if budget_usd is None:
                return replace(cfg, budget=None)
            try:
                amount = Decimal(str(budget_usd))
                end = date.fromisoformat(str(expires))
            except (InvalidOperation, ValueError):
                raise UIError(400, "Type a spend limit in USD and an end date.") from None
            if isinstance(budget_usd, bool) or not amount.is_finite() or amount <= 0:
                raise UIError(400, "The spend limit must be more than 0.")
            if amount > MAX_BUDGET_USD:
                raise UIError(400, f"The spend limit can be at most {MAX_BUDGET_USD} USD.")
            if end < self.today():
                raise UIError(400, "The end date must be today or later.")
            budget = {
                "approved_by": APPROVED_BY,
                "budget_usd": usd_text(amount),
                "expires": end.isoformat(),
            }
            return replace(cfg, budget=budget)

        return self._edit(change)

    def set_recipients(self, sid: str, allow: object) -> dict:
        """The models that may read the text of one source. Other entries of
        the opt-in list of the source (converters) do not change."""
        if not isinstance(allow, list) or not all(isinstance(a, str) for a in allow):
            raise UIError(400, "Bad list of models.")
        with self.ui.session(index=True) as (client, idx):
            cfg, _ = self.load(client, idx)
            known = {recipients.recipient_id(p) for p in cfg.profiles.values()}
            if not set(allow) <= known:
                raise UIError(400, MESSAGES["invalid_profile_id"])
            try:
                prefs = idx.source(sid)["prefs"]
            except KeyError:
                raise UIError(404, "This source is not in your list.") from None
            before = self.state(client, idx, cfg)
            rest = [a for a in prefs.get("allow_external", []) if not a.startswith("model:")]
            idx.set_source_prefs(sid, allow_external=[*rest, *allow])
            after = self.state(client, idx, cfg)
        self.changed(before, after)
        return {"allow": sorted(set(allow))}

    def get_recipients(self, sid: str) -> dict:
        with self.ui.session(index=True) as (_, idx):
            try:
                prefs = idx.source(sid)["prefs"]
            except KeyError:
                raise UIError(404, "This source is not in your list.") from None
        return {"allow": [a for a in prefs.get("allow_external", []) if a.startswith("model:")]}
