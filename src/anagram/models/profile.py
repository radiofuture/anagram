"""Provider profiles: the unit of configuration, of consent, and of the key.

A `Profile` names one provider, one model, and (for some providers) one
address. Its id is the opt-in key of each source (`model:<profile id>` in
`source.prefs.allow_external`) and the name of its API key in the keystore
(`model-key-<profile id>`).

Where things are:

- The member config is the `meta` key `models` of the encrypted index store:
  `{"profiles", "use", "budget", "modes", "health"}`. It holds no key.
- An API key is in the keystore only. It is written with
  `put(..., overwrite=True)` and removed with `delete`.
- A lab gives default profiles in the sections `models` and `disclosure` of
  its settings record (`LabPolicy`). A member can select a different profile.

This module does not import the index, the UI, or a provider module at import
time, so the node can use `from_config` (`anagram.models`) with no index.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

from anagram.models.base import (
    STRUCTURED_MODES,
    BudgetRefused,
    ModelError,
    TextModel,
    parse_prices,
)
from anagram.models.budget import (
    DEFAULT_USAGE_LIMIT,
    Gate,
    UsageGate,
    UsageLedger,
    ledger_state,
    open_ledger,
    usage_path,
)
from anagram.models.http import check_url, host_of, is_loopback
from anagram.models.ledger import ANTHROPIC_PRICES, OPENROUTER_PRICES
from anagram.models.providers import openai_compat
from anagram.models.providers.anthropic import AnthropicModel
from anagram.models.providers.ollama import OllamaModel

if TYPE_CHECKING:
    from pathlib import Path

    from anagram.models.ports import SecretStore

PROVIDERS = ("ollama", "openai_compatible", "anthropic", "openai", "openrouter")
TASKS = ("understand", "ask", "draft", "embed")
META_KEY = "models"
KEY_PREFIX = "model-key-"
MODE_TTL = 24 * 3600  # seconds that a found structured mode stays valid
FAILURE_LIMIT = 3
OLLAMA_HOST = "127.0.0.1"
FIXED_HOSTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "openrouter": "openrouter.ai",
}
# Providers that always need a key.
KEY_MANDATORY = frozenset({"anthropic", "openai", "openrouter"})
# The environment variable of the key on a node (`from_config`).
KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openai_compatible": "ANAGRAM_MODEL_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_MODEL = re.compile(r"^[\w.:/@+-]{1,200}$")
_FIELDS = frozenset({"provider", "model", "label", "base_url", "route", "prices", "limit"})
MAX_LIMIT = 10**9


@dataclass(frozen=True)
class Profile:
    id: str
    provider: str
    model: str
    label: str
    base_url: str | None = None
    route: tuple[str, ...] = ()  # openrouter: pinned providers, no fallback
    prices: tuple[str, str] | None = None  # USD per million tokens (input, output)
    origin: str = "member"  # "member" | "lab:<lab_id>" | "node"
    # Explicit limit for each UTC day (calls, characters) of a model with no
    # price (`UsageGate`). None: the default limit, or a refusal for a cloud
    # provider (`usage_limit`).
    limit: tuple[int, int] | None = None

    def to_json(self) -> dict:
        """Profile JSON: the form in the member config, the lab settings
        record, and the node config. It has no id and no key."""
        out: dict = {"label": self.label, "model": self.model, "provider": self.provider}
        if self.base_url:
            out["base_url"] = self.base_url
        if self.route:
            out["route"] = list(self.route)
        if self.prices is not None:
            out["prices"] = list(self.prices)
        if self.limit is not None:
            out["limit"] = {"calls": self.limit[0], "chars": self.limit[1]}
        return out


@dataclass(frozen=True)
class ModelConfig:
    profiles: dict[str, Profile]
    use: dict[str, str | None]  # task -> profile id
    budget: dict | None = None  # {"approved_by", "budget_usd", "expires"}
    # profile id -> {"mode", "at"}: the structured mode that a call found.
    modes: dict[str, dict] = field(default_factory=dict)
    # The tasks that the member selected. None: all keys of `use`. A task that
    # is not here has the default of the lab.
    chosen: frozenset[str] | None = None


# ------------------------------------------------------------------ ids


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:31].strip("-")
    return slug or "model"


def _host(provider: str, base_url: str | None) -> str:
    if provider in FIXED_HOSTS:
        return FIXED_HOSTS[provider]
    return host_of(base_url) if base_url else OLLAMA_HOST


def _suffix(provider: str, base_url: str | None, route: Sequence[str] = ()) -> str:
    host = _host(provider, base_url)
    if provider == "openrouter":
        canon = ",".join(sorted({r.strip() for r in route if isinstance(r, str) and r.strip()}))
        text = f"{provider}|{host}|{canon}"
    else:
        text = f"{provider}|{host}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def profile_id(
    provider: str, label: str, base_url: str | None = None, route: Sequence[str] = ()
) -> str:
    """`<slug of the label>-<8 hex of sha256(provider | host [| route])>`:
    lower case, at most 40 characters. A new host or OpenRouter route gives a
    new id, so a key and an opt-in never move to a different party."""
    return f"{_slug(label)}-{_suffix(provider, base_url, route)}"


def same_party(pid: str, provider: str, base_url: str | None, route: Sequence[str] = ()) -> bool:
    """True if the id `pid` was made for this provider, host, and route."""
    return pid.endswith("-" + _suffix(provider, base_url, route))


def check_id(pid: object) -> str:
    if not isinstance(pid, str) or not _ID.match(pid):
        raise ModelError("invalid_profile_id")
    return pid


def key_name(pid: str) -> str:
    """The keystore name of the API key of a profile."""
    return KEY_PREFIX + check_id(pid)


def _limit(value: object) -> tuple[int, int] | None:
    """`{"calls": n, "chars": n}` (each 1 to 10^9) or None."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"calls", "chars"}:
        raise ModelError("invalid_limit")
    out = []
    for name in ("calls", "chars"):
        n = value[name]
        if isinstance(n, bool) or not isinstance(n, int) or not 0 < n <= MAX_LIMIT:
            raise ModelError("invalid_limit")
        out.append(n)
    return out[0], out[1]


def make_profile(data: object, *, origin: str = "member", keep_id: str | None = None) -> Profile:
    """A checked `Profile` from Profile JSON. Raise `ModelError("invalid_profile")`
    (or the code of the fault) for input that is not correct.

    `keep_id`: the id of the profile that this data replaces. It stays if the
    provider and the host did not change."""
    if not isinstance(data, dict) or not set(data) <= _FIELDS:
        raise ModelError("invalid_profile")
    provider, model = data.get("provider"), data.get("model")
    if provider not in PROVIDERS or not isinstance(model, str) or not _MODEL.match(model):
        raise ModelError("invalid_profile")
    label = data.get("label") or model
    if not isinstance(label, str) or len(label) > 80 or not label.isprintable():
        raise ModelError("invalid_profile")
    label = label.strip() or model
    base_url = data.get("base_url") or None
    if provider in FIXED_HOSTS:
        base_url = None  # a profile must not move a key to a different host
    elif base_url is not None:
        if not isinstance(base_url, str):
            raise ModelError("invalid_url")
        base_url = check_url(base_url)
        if provider == "ollama" and not is_loopback(base_url):
            raise ModelError("not_loopback")
    elif provider == "openai_compatible":
        raise ModelError("invalid_url")
    route = data.get("route") or ()
    if not isinstance(route, list | tuple) or not all(
        isinstance(r, str) and r.strip() and len(r) <= 60 for r in route
    ):
        raise ModelError("invalid_profile")
    route = tuple(r.strip() for r in route) if provider == "openrouter" else ()
    if provider == "openrouter" and not route:
        raise ModelError("no_route")
    prices = parse_prices(data.get("prices"))
    if origin.startswith("lab:") and prices is not None:
        table = (
            ANTHROPIC_PRICES
            if provider == "anthropic"
            else OPENROUTER_PRICES
            if provider == "openrouter"
            else {}
        )
        floor = table.get(model)
        if floor is not None and (prices[0] < floor[0] or prices[1] < floor[1]):
            raise ModelError("invalid_prices")
    limit = _limit(data.get("limit"))
    pid = profile_id(provider, label, base_url, route)
    if (
        keep_id is not None
        and _ID.match(keep_id)
        and same_party(keep_id, provider, base_url, route)
    ):
        pid = keep_id
    profile = Profile(
        id=pid,
        provider=provider,
        model=model,
        label=label,
        base_url=base_url,
        route=route,
        prices=None if prices is None else (str(prices[0]), str(prices[1])),
        origin=origin,
        limit=limit,
    )
    build(profile)  # the provider rules (HTTPS, loopback, route) must hold
    return profile


# ---------------------------------------------------------------- build


def build(
    profile: Profile,
    *,
    key: str | None = None,
    transport: object | None = None,
    structured: str | None = None,
    clients: Mapping[str, object] | None = None,
) -> TextModel:
    """The provider adapter of a profile. No network call, and no spend gate.

    `transport` is the HTTP transport (`anagram.models.http`). `clients` gives
    the client object of a provider that has one: `{"ollama": OllamaClient,
    "anthropic": <SDK client>}` (tests give fakes)."""
    clients = clients or {}
    p = profile.provider
    if p == "ollama":
        kw: dict[str, Any] = {"http": transport, "profile_id": profile.id}
        if clients.get("ollama") is not None:
            kw["client"] = clients["ollama"]
        elif profile.base_url:
            kw["url"] = profile.base_url
        return OllamaModel(profile.model, **kw)
    if p == "anthropic":
        return AnthropicModel(
            profile.model,
            api_key=key,
            profile_id=profile.id,
            prices=profile.prices,
            client=clients.get("anthropic"),
        )
    kw = {
        "api_key": key,
        "label": profile.label,
        "prices": profile.prices,
        "profile_id": profile.id,
        "transport": transport,
    }
    if p == "openai_compatible":
        return openai_compat.OpenAICompatModel(
            profile.model, profile.base_url or "", structured=structured, **kw
        )
    if p == "openai":
        return openai_compat.OpenAIModel(profile.model, **kw)
    if p == "openrouter":
        return openai_compat.OpenRouterModel(profile.model, route=profile.route, **kw)
    raise ModelError("invalid_profile")


# ----------------------------------------------------------- config store


def _empty() -> dict:
    return {"budget": None, "health": {}, "modes": {}, "profiles": {}, "use": {}}


def _doc(index: Any) -> dict | None:
    doc = index.store.get_meta(META_KEY)
    if not isinstance(doc, dict):
        return None
    return {**_empty(), **doc}


def _lab_profiles(lab: Any) -> list[Profile]:
    out = []
    models = getattr(lab, "models", None)
    for raw in (models.get("profiles") if isinstance(models, dict) else None) or []:
        try:
            out.append(make_profile(raw, origin=f"lab:{lab.lab_id}"))
        except ModelError:
            continue  # one bad profile of a lab does not stop the others
    return out


def load(index: Any, lab: Any = None) -> ModelConfig:
    """The config of this member, with the defaults of the lab.

    `lab` is a `LabPolicy` (or None). Its profiles show with the origin
    `lab:<lab_id>`. For a task that the member did not select, the profile of
    the lab applies."""
    doc = _doc(index)
    if doc is None:
        doc = _empty()
        index.store.set_meta(META_KEY, doc)
    profiles: dict[str, Profile] = {}
    for pid, raw in sorted(doc["profiles"].items()):
        try:
            p = make_profile(raw, keep_id=pid)
            profiles[p.id] = p
        except ModelError:
            continue
    chosen = frozenset(t for t in doc["use"] if t in TASKS)
    use: dict[str, str | None] = {t: doc["use"].get(t) for t in TASKS}
    if lab is not None:
        for p in _lab_profiles(lab):
            profiles.setdefault(p.id, p)
        lab_use = lab.models.get("use") if isinstance(lab.models, dict) else None
        for task, pid in (lab_use or {}).items() if isinstance(lab_use, dict) else ():
            if task in TASKS and task not in chosen:
                use[task] = pid
    use = {t: (pid if pid in profiles else None) for t, pid in use.items()}
    budget = doc["budget"] if isinstance(doc["budget"], dict) else None
    modes = {p: m for p, m in doc["modes"].items() if isinstance(m, dict)}
    return ModelConfig(profiles, use, budget, modes, chosen)


def save(index: Any, cfg: ModelConfig) -> None:
    """Store the member part of `cfg`. Profiles of a lab and the tasks that
    the member did not select are not stored."""
    doc = _doc(index) or _empty()
    tasks = set(cfg.use) if cfg.chosen is None else set(cfg.chosen)
    doc["profiles"] = {
        pid: p.to_json() for pid, p in sorted(cfg.profiles.items()) if p.origin == "member"
    }
    doc["use"] = {t: cfg.use.get(t) for t in TASKS if t in tasks}
    doc["budget"] = cfg.budget
    doc["modes"] = {p: m for p, m in cfg.modes.items() if p in cfg.profiles}
    doc["health"] = {p: h for p, h in doc["health"].items() if p in cfg.profiles}
    index.store.set_meta(META_KEY, doc)


def set_use(cfg: ModelConfig, task: str, pid: str | None) -> ModelConfig:
    """A copy of `cfg` where the member selected `pid` (or no model) for `task`."""
    if task not in TASKS or (pid is not None and pid not in cfg.profiles):
        raise ModelError("invalid_use")
    chosen = (frozenset(cfg.use) if cfg.chosen is None else cfg.chosen) | {task}
    return replace(cfg, use={**cfg.use, task: pid}, chosen=chosen)


# The Ollama models that the default takes, in this order (measured on the
# labelled set of `anagram.sim.kinds`, 2026-11-16).
# A name with a tag must agree with the tag; a name with no tag takes any tag.
RECOMMENDED_LOCAL = ("qwen2.5:7b", "llama3.2")
LOCAL_TASKS = ("understand", "ask", "draft")  # the tasks that the local default fills


def _same_model(name: str, want: str) -> bool:
    """True if the Ollama name `name` is the model `want` (see RECOMMENDED_LOCAL)."""
    if ":" in want:
        return name == want
    return name.split(":")[0] == want


def wants_local(cfg: ModelConfig) -> bool:
    """True if the zero-choice default can apply: no model reads the items,
    and the member did not choose for the task `understand` (a lab default
    or a choice of "no model" stays)."""
    return cfg.use.get("understand") is None and "understand" not in (cfg.chosen or frozenset())


def local_default(cfg: ModelConfig, installed: list[str]) -> ModelConfig | None:
    """The default for a computer where Ollama runs: one local profile for
    task in `LOCAL_TASKS` that has no model and that the member did not
    choose. The model is
    the first of `RECOMMENDED_LOCAL` that Ollama has, else the first model
    that is not an embedding model. None: the default does not apply, or
    Ollama has no model. The caller saves the config that comes back."""
    if not wants_local(cfg):
        return None
    names = [n for n in installed if isinstance(n, str) and "embed" not in n.lower()]
    if not names:
        return None
    pick = next((n for want in RECOMMENDED_LOCAL for n in names if _same_model(n, want)), names[0])
    name = pick.removesuffix(":latest")
    p = next(
        (q for q in cfg.profiles.values() if q.provider == "ollama" and q.model in (pick, name)),
        None,
    )
    if p is None:
        try:
            p = make_profile({"label": name, "model": name, "provider": "ollama"})
        except ModelError:
            return None
        cfg = put_profile(cfg, p)
    chosen = cfg.chosen or frozenset()
    for task in LOCAL_TASKS:
        if task not in chosen and cfg.use.get(task) is None:
            cfg = set_use(cfg, task, p.id)
    return cfg


def put_profile(cfg: ModelConfig, profile: Profile) -> ModelConfig:
    return replace(cfg, profiles={**cfg.profiles, profile.id: profile})


def remove_profile(index: Any, keystore: SecretStore, cfg: ModelConfig, pid: str) -> ModelConfig:
    """Remove a member profile, its key, and its opt-in in each source. The
    caller saves the config that comes back."""
    profile = cfg.profiles.get(pid)
    if profile is None or profile.origin != "member":
        raise ModelError("invalid_profile_id")
    delete_key(keystore, pid)
    remove_opt_ins(index, pid)
    profiles = {k: v for k, v in cfg.profiles.items() if k != pid}
    use = {t: (None if p == pid else p) for t, p in cfg.use.items()}
    modes = {k: v for k, v in cfg.modes.items() if k != pid}
    return replace(cfg, profiles=profiles, use=use, modes=modes)


def opted_in(index: Any, pid: str) -> list[str]:
    """The ids of the sources that permit this profile."""
    rid = f"model:{pid}"
    return [
        sid
        for sid, s in index.sources().items()
        if rid in (s.get("prefs") or {}).get("allow_external", [])
    ]


def remove_opt_ins(index: Any, pid: str) -> None:
    rid = f"model:{pid}"
    for sid in opted_in(index, pid):
        allow = index.source(sid)["prefs"].get("allow_external", [])
        index.set_source_prefs(sid, allow_external=[a for a in allow if a != rid])


# ------------------------------------------------------------------ keys


def set_key(keystore: SecretStore, pid: str, key: str) -> None:
    """Store the API key of a profile. The old value does not stay."""
    name = key_name(pid)
    if not isinstance(key, str):
        raise ModelError("invalid_key")
    key = key.strip()
    if not key or len(key) > 500 or not key.isascii() or not key.isprintable() or " " in key:
        raise ModelError("invalid_key")
    keystore.put(name, key.encode("utf-8"), overwrite=True)


def get_key(keystore: SecretStore, pid: str) -> str | None:
    value = keystore.get(key_name(pid))
    return value.decode("utf-8") if value else None


def has_key(keystore: SecretStore, pid: str) -> bool:
    return keystore.get(key_name(pid)) is not None


def delete_key(keystore: SecretStore, pid: str) -> bool:
    return keystore.delete(key_name(pid))


# --------------------------------------------------------------- resolve


def cached_mode(cfg: ModelConfig, pid: str, now: float) -> str | None:
    entry = cfg.modes.get(pid) or {}
    at = entry.get("at")
    if entry.get("mode") not in STRUCTURED_MODES or not isinstance(at, int | float):
        return None
    return entry["mode"] if 0 <= now - at < MODE_TTL else None


def resolve(
    cfg: ModelConfig,
    task: str,
    keystore: SecretStore,
    home: str | Path,
    *,
    transport: object | None = None,
    clients: Mapping[str, object] | None = None,
    clock: Callable[[], float] = time.time,
    today: date | None = None,
) -> TextModel | None:
    """The model for a task, ready for calls. None: no profile is set, and the
    caller uses its deterministic path.

    A paid model comes back inside `Gate`, with the ledger of the approved
    budget. With no budget, no prices, or a budget that is not valid, this
    raises `BudgetRefused`. A model with no price that is not on this
    computer comes back inside `UsageGate` (`usage_limit`)."""
    pid = cfg.use.get(task)
    profile = cfg.profiles.get(pid) if pid else None
    if profile is None:
        return None
    model = build(
        profile,
        key=get_key(keystore, profile.id),
        transport=transport,
        structured=cached_mode(cfg, profile.id, clock()),
        clients=clients,
    )
    limit = usage_limit(profile, model)
    if limit is not None:
        return UsageGate(model, UsageLedger(usage_path(home, profile.id), limit), today=today)
    if not model.paid:
        return model
    if cfg.budget is None:
        raise BudgetRefused("no_budget")
    if model.prices is None:
        raise BudgetRefused("no_prices")
    return Gate(model, open_ledger(home, cfg.budget, today), cfg.budget, today=today)


def usage_limit(profile: Profile, model: TextModel) -> dict | None:
    """The limit of calls and characters for each day of a model with no
    price (security review). None: the model has prices (it runs in
    `Gate`), or it runs on this computer. A model that is not on this
    computer (a university endpoint) has the limit of its profile, else
    `DEFAULT_USAGE_LIMIT`. A cloud provider with no known price needs an
    explicit limit: else `BudgetRefused("no_prices")`."""
    if model.prices is not None or not (model.external or model.paid):
        return None
    if profile.limit is not None:
        return {"calls": profile.limit[0], "chars": profile.limit[1]}
    if model.paid:
        raise BudgetRefused("no_prices")
    return dict(DEFAULT_USAGE_LIMIT)


def may_read_lab(model: TextModel, lab: Any) -> bool:
    """True if this model may read text of the lab space: a local model, or a
    recipient that the lab permits."""
    return not model.external or bool(lab.allows_recipient(model.recipient_id))


# ---------------------------------------------------------------- health


def _update(index: Any, section: str, pid: str, change: Callable[[dict], dict]) -> None:
    doc = _doc(index) or _empty()
    doc[section][pid] = change(dict(doc[section].get(pid) or {}))
    index.store.set_meta(META_KEY, doc)


def remember_mode(index: Any, model: TextModel, clock: Callable[[], float] = time.time) -> None:
    """Store the structured mode that the model found, for 24 hours."""
    mode = getattr(getattr(model, "model", model), "structured", None)
    if mode in STRUCTURED_MODES and model.profile_id:
        _update(index, "modes", model.profile_id, lambda _: {"at": clock(), "mode": mode})


def note_probe(index: Any, pid: str, result: dict) -> None:
    """Record the result of `TextModel.probe()`."""

    def change(h: dict) -> dict:
        ok = bool(result.get("ok"))
        h["probe"] = {"ok": ok, "reason": result.get("reason")}
        if ok:
            h["failures"] = 0
        return h

    _update(index, "health", pid, change)


def forget_health(index: Any, pid: str) -> None:
    """Remove the recorded faults of a profile. Call it when the key or the
    profile changes: an old fault says nothing about the new values."""
    _update(index, "health", pid, lambda _: {})


def note_call(index: Any, pid: str, error: ModelError | None = None) -> None:
    """Record the result of one call. Three faults one after the other change
    the state (`state`). A call with no fault sets the counts to zero."""

    def change(h: dict) -> dict:
        if error is None:
            h.update(failures=0, parse_failures=0)
            h.pop("probe", None)
        elif error.code in ("bad_output", "output_cut"):
            h["parse_failures"] = int(h.get("parse_failures", 0)) + 1
        elif not isinstance(error, BudgetRefused):
            h["failures"] = int(h.get("failures", 0)) + 1
        return h

    _update(index, "health", pid, change)


# ----------------------------------------------------------------- state

STATES = ("ready", "no_model", "unreachable", "no_opt_in", "budget_reached", "weak_model")


def _state(state: str, message: str | None = None, next_step: str | None = None) -> dict:
    return {"message": message, "next": next_step, "state": state}


def budget_open(cfg: ModelConfig, home: str | Path | None, today: date | None = None) -> bool:
    """True if the approved budget is valid and its ledger has money left."""
    try:
        got = ledger_state(home, cfg.budget, today)
    except BudgetRefused:
        return False
    return not got["breached"] and got["spent_usd"] < got["budget_usd"]


def _usage_open(home: str | Path, pid: str, limit: dict, today: date | None) -> bool:
    path = usage_path(home, pid)
    if not path.exists():
        return True
    return UsageLedger(path, limit).is_open(today or datetime.now(UTC).date())


def state(
    index: Any,
    *,
    lab: Any = None,
    keystore: SecretStore | None = None,
    home: str | Path | None = None,
    today: date | None = None,
    cfg: ModelConfig | None = None,
) -> dict:
    """`{"state", "message", "next"}` for the task `understand`. One sentence
    and one next step for people. In each state that is not `ready`, the app
    works with rules and no model."""
    cfg = cfg or load(index, lab)
    pid = cfg.use.get("understand")
    profile = cfg.profiles.get(pid) if pid else None
    if profile is None:
        return _state(
            "no_model",
            "No model is selected. Anagram sorts your items with rules.",
            "Choose a model",
        )
    model = build(profile)
    address = "Start Ollama" if profile.provider == "ollama" else "Check the address"
    if keystore is not None and profile.provider in KEY_MANDATORY:
        if not has_key(keystore, profile.id):
            return _state("unreachable", "This model has no key.", "Type the key")
    if model.external and not opted_in(index, profile.id):
        return _state(
            "no_opt_in",
            "No source permits this model to read its text.",
            "Choose the sources this model may read",
        )
    return (
        _budget_state(cfg, profile, model, home, today)
        or _health_state(index, cfg, profile.id, address)
        or _state("ready")
    )


def _budget_state(
    cfg: ModelConfig,
    profile: Profile,
    model: TextModel,
    home: str | Path | None,
    today: date | None,
) -> dict | None:
    """The state `budget_reached`, or None if the model may spend."""
    try:
        limit = usage_limit(profile, model)
    except BudgetRefused:
        return _state("budget_reached", "This model has no price.", "Type the prices")
    if limit is not None:
        if home is not None and not _usage_open(home, profile.id, limit, today):
            return _state("budget_reached", "The limit of this model for today is reached.", None)
    elif model.paid and not budget_open(cfg, home, today):
        return _state("budget_reached", "The spend limit is reached.", "Set a new spend limit")
    return None


def _health_state(index: Any, cfg: ModelConfig, pid: str, address: str) -> dict | None:
    """The state `unreachable` or `weak_model` from the health record of a
    profile, or None if the model is healthy."""
    health = (_doc(index) or _empty())["health"].get(pid) or {}
    probe = health.get("probe") or {}
    if probe.get("ok") is False or int(health.get("failures", 0)) >= FAILURE_LIMIT:
        return _state("unreachable", "Anagram cannot reach the model.", address)
    text_mode = (cfg.modes.get(pid) or {}).get("mode") == "text"
    if text_mode and int(health.get("parse_failures", 0)) >= FAILURE_LIMIT:
        return _state(
            "weak_model",
            "This model does not give answers that Anagram can read.",
            "Choose a different model",
        )
    return None
