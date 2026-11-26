"""Model profiles: ids, the config in the index `meta`, keys in the keystore,
lab defaults, `resolve`, `state`, recipients, and `from_config`. No network:
each provider gets a fake transport or makes no call."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal

import pytest
from indexkit import KEY
from modelkit import NOT_A_KEY, REQ, UNI, FakeHTTP, chat

from anagram import models
from anagram.identity.app.keychain import keys_dir, open_keystore
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.models import BudgetRefused, ModelError, from_config, profile, recipients
from anagram.models.budget import Gate, UsageGate, ledger_path, usage_path
from anagram.models.providers.anthropic import AnthropicModel
from anagram.models.providers.ollama import OllamaModel
from anagram.models.providers.openai_compat import (
    OpenAICompatModel,
    OpenAIModel,
    OpenRouterModel,
)

pytestmark = pytest.mark.usefixtures("no_network")

TODAY = date(2026, 11, 16)
BUDGET = {"approved_by": "member", "budget_usd": "0.50", "expires": "2026-12-31"}
OLLAMA = {"label": "Local model", "model": "llama3.2", "provider": "ollama"}
UNIVERSITY = {
    "base_url": UNI,
    "label": "University endpoint",
    "model": "served-model",
    "provider": "openai_compatible",
}
HAIKU = {"label": "Claude Haiku", "model": "claude-haiku-5-5", "provider": "anthropic"}
FABLE = {"label": "Claude Fable", "model": "claude-fable-5-2", "provider": "anthropic"}
ROUTER = {
    "label": "Haiku by OpenRouter",
    "model": "anthropic/claude-haiku-5.5",
    "provider": "openrouter",
    "route": ["anthropic"],
}


@dataclass
class FakeLabPolicy:
    lab_id: str = "lab1"
    models: dict = field(default_factory=dict)
    disclosure: dict = field(default_factory=dict)

    def allows_recipient(self, recipient_id: str) -> bool:
        return recipient_id in self.disclosure.get("allow_external", [])


@pytest.fixture
def index(tmp_path):
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    yield idx
    idx.close()


@pytest.fixture
def keystore(tmp_path):
    return open_keystore(tmp_path / "home")


def add(index, *raw) -> tuple[profile.ModelConfig, list[profile.Profile]]:
    cfg = profile.load(index)
    made = [profile.make_profile(r) for r in raw]
    for p in made:
        cfg = profile.put_profile(cfg, p)
    profile.save(index, cfg)
    return cfg, made


def source(index, tmp_path) -> str:
    folder = tmp_path / "notes"
    folder.mkdir(exist_ok=True)
    return index.add_source(FolderConnector(folder))


# ---------------------------------------------------------------------- ids


def test_profile_id_is_a_valid_keystore_name_and_changes_with_the_host():
    a = profile.make_profile(UNIVERSITY)
    b = profile.make_profile({**UNIVERSITY, "base_url": "https://other.example.edu/v1"})
    assert a.id.startswith("university-endpoint-") and len(a.id) <= 40
    assert a.id != b.id  # a new host gives a new id
    long = profile.make_profile({**OLLAMA, "label": "A Very Long Label " * 4})
    assert len(long.id) <= 40
    for p in (a, b, long):
        assert profile.key_name(p.id) == f"model-key-{p.id}"
        assert p.id == p.id.lower() and "_" not in p.id
    # The same provider and host keep the id when the label changes.
    again = profile.make_profile({**UNIVERSITY, "label": "New name"}, keep_id=a.id)
    assert again.id == a.id and again.label == "New name"
    moved = profile.make_profile(
        {**UNIVERSITY, "base_url": "https://other.example.edu/v1"}, keep_id=a.id
    )
    assert moved.id == b.id


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ({**OLLAMA, "provider": "other"}, "invalid_profile"),
        ({**OLLAMA, "model": "two words"}, "invalid_profile"),
        ({**OLLAMA, "key": NOT_A_KEY}, "invalid_profile"),  # no key in a profile
        ({**OLLAMA, "base_url": "https://llm.example.edu"}, "not_loopback"),
        ({**UNIVERSITY, "base_url": "http://llm.example.edu/v1"}, "url_not_https"),
        ({"model": "m", "provider": "openai_compatible"}, "invalid_url"),
        ({**ROUTER, "route": []}, "no_route"),
        ({**HAIKU, "prices": ["1", "x"]}, "invalid_prices"),
    ],
)
def test_bad_profiles_are_refused(raw, code):
    with pytest.raises(ModelError) as err:
        profile.make_profile(raw)
    assert err.value.code == code


def test_a_fixed_provider_ignores_a_base_url():
    p = profile.make_profile({**HAIKU, "base_url": "https://evil.example/v1"})
    assert p.base_url is None and "base_url" not in p.to_json()


# ------------------------------------------------------------- config store


def test_config_round_trip_in_meta_holds_no_key(index, keystore):
    cfg, (uni,) = add(index, {**UNIVERSITY, "prices": ["0.2", "0.4"]})
    profile.set_key(keystore, uni.id, NOT_A_KEY)
    profile.save(index, profile.set_use(cfg, "understand", uni.id))
    got = profile.load(index)
    assert got.profiles[uni.id] == uni and got.profiles[uni.id].prices == ("0.2", "0.4")
    assert got.use == {"ask": None, "draft": None, "embed": None, "understand": uni.id}
    assert NOT_A_KEY not in str(index.store.get_meta("models"))
    with pytest.raises(ModelError):
        profile.set_use(got, "understand", "no-such-profile")
    with pytest.raises(ModelError):
        profile.set_use(got, "judge", uni.id)


# --------------------------------------------------------------------- keys


def test_a_key_overwrite_leaves_no_old_value(tmp_path, keystore):
    pid = profile.make_profile(HAIKU).id
    old, new = "old-" + NOT_A_KEY, "new-" + NOT_A_KEY
    profile.set_key(keystore, pid, old)
    profile.set_key(keystore, pid, f"  {new}\n")
    assert profile.get_key(keystore, pid) == new and profile.has_key(keystore, pid)

    def holds(secret: str) -> bool:  # the key file holds the value as hex text
        forms = (secret.encode(), secret.encode().hex().encode())
        files = [p for p in keys_dir(tmp_path / "home").rglob("*") if p.is_file()]
        assert not any(".replaced" in p.name for p in files)
        return any(f in p.read_bytes() for p in files for f in forms)

    assert holds(new) and not holds(old)
    assert keystore.list("model-key-") == [f"model-key-{pid}"]
    assert profile.delete_key(keystore, pid) and not profile.has_key(keystore, pid)
    assert not holds(new)


@pytest.mark.parametrize("key", ["", "   ", "two words", "x" * 501, "café", 7])
def test_bad_keys_are_refused(keystore, key):
    with pytest.raises(ModelError):
        profile.set_key(keystore, "claude-haiku-0a1b2c3d", key)
    with pytest.raises(ModelError):
        profile.set_key(keystore, "Bad_Id", NOT_A_KEY)


def test_remove_profile_deletes_the_key_and_the_opt_ins(index, keystore, tmp_path):
    cfg, (uni, local) = add(index, UNIVERSITY, OLLAMA)
    sid = source(index, tmp_path)
    index.set_source_prefs(sid, allow_external=["datalab", f"model:{uni.id}"])
    profile.set_key(keystore, uni.id, NOT_A_KEY)
    cfg = profile.set_use(cfg, "ask", uni.id)
    cfg = profile.remove_profile(index, keystore, cfg, uni.id)
    profile.save(index, cfg)
    got = profile.load(index)
    assert list(got.profiles) == [local.id] and got.use["ask"] is None
    assert not profile.has_key(keystore, uni.id)
    assert index.source(sid)["prefs"]["allow_external"] == ["datalab"]


# ------------------------------------------------------------------ resolve


def test_resolve_gives_none_with_no_profile(index, keystore, tmp_path):
    assert profile.resolve(profile.load(index), "understand", keystore, tmp_path) is None


def test_resolve_builds_each_provider_with_its_key(index, keystore, tmp_path):
    cfg, (local, uni) = add(index, OLLAMA, UNIVERSITY)
    profile.set_key(keystore, uni.id, NOT_A_KEY)
    cfg = profile.set_use(profile.set_use(cfg, "draft", local.id), "ask", uni.id)
    m = profile.resolve(cfg, "draft", keystore, tmp_path)
    assert isinstance(m, OllamaModel) and not m.external and m.profile_id == local.id
    http = FakeHTTP([(200, chat('{"kind": "note"}'))])
    m = profile.resolve(cfg, "ask", keystore, tmp_path, transport=http)
    # No price and not on this computer: inside the usage limit (review P2).
    assert isinstance(m, UsageGate) and m.external and not m.paid
    assert isinstance(m.model, OpenAICompatModel)
    assert m.recipient_id == f"model:{uni.id}"
    assert m.generate(REQ).data == {"kind": "note"}
    assert http.calls[0]["headers"]["Authorization"] == f"Bearer {NOT_A_KEY}"


def test_a_paid_profile_runs_only_inside_the_gate(index, keystore, tmp_path):
    cfg, (haiku, fable) = add(index, HAIKU, FABLE)
    cfg = profile.set_use(profile.set_use(cfg, "understand", haiku.id), "ask", fable.id)
    with pytest.raises(BudgetRefused):  # no budget
        profile.resolve(cfg, "understand", keystore, tmp_path, today=TODAY)
    cfg = profile.ModelConfig(cfg.profiles, cfg.use, BUDGET, cfg.modes, cfg.chosen)
    gate = profile.resolve(cfg, "understand", keystore, tmp_path, today=TODAY)
    assert isinstance(gate, Gate) and isinstance(gate.model, AnthropicModel)
    assert gate.ledger.path == ledger_path(tmp_path, BUDGET)
    with pytest.raises(ModelError) as err:  # no key: no call and no reservation
        gate.generate(REQ)
    assert err.value.code == "no_key" and gate.ledger.snapshot()["calls"] == 0
    # claude-fable-5-2 has no table price: the profile must give it.
    with pytest.raises(BudgetRefused):
        profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY)
    priced = profile.make_profile({**FABLE, "prices": ["5", "25"]}, keep_id=fable.id)
    cfg = profile.put_profile(cfg, priced)
    gate = profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY)
    assert gate.prices == (Decimal("5"), Decimal("25"))
    expired = {**BUDGET, "expires": "2026-11-01"}
    cfg = profile.ModelConfig(cfg.profiles, cfg.use, expired)
    with pytest.raises(BudgetRefused):
        profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY)


def test_an_endpoint_with_no_price_never_skips_the_gate(index, keystore, tmp_path):
    """Security review P2: a model with no price that is not on this computer
    counts calls and characters against a limit for each day. A cloud
    provider with no known price is refused until a price or a limit is set."""
    limited = {**UNIVERSITY, "label": "Small limit", "limit": {"calls": 3, "chars": 10_000}}
    cfg, (uni, small) = add(index, UNIVERSITY, limited)
    assert small.limit == (3, 10_000) and small.to_json()["limit"] == {"calls": 3, "chars": 10_000}
    cfg = profile.set_use(profile.set_use(cfg, "ask", uni.id), "draft", small.id)
    m = profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY)
    assert isinstance(m, UsageGate) and m.ledger.limit == {"calls": 200, "chars": 2_000_000}
    http = FakeHTTP([(200, chat('{"kind": "note"}'))] * 3)
    m = profile.resolve(cfg, "draft", keystore, tmp_path, transport=http, today=TODAY)
    assert m.ledger.path == usage_path(tmp_path, small.id)
    m.generate(REQ)
    m.generate(REQ)
    with pytest.raises(BudgetRefused) as err:  # 2 attempts (mode not known), then 1
        m.generate(REQ)
    assert err.value.code == "usage_limit" and len(http.calls) == 2
    assert m.ledger.used(TODAY)["calls"] == 3 and m.ledger.used(TODAY)["chars"] > 0
    assert not profile._usage_open(tmp_path, small.id, m.ledger.limit, TODAY)
    assert profile._usage_open(tmp_path, small.id, m.ledger.limit, date(2026, 11, 17))
    # The characters count too.
    tiny = profile.make_profile({**UNIVERSITY, "limit": {"calls": 9, "chars": 10}})
    cfg = profile.set_use(profile.put_profile(cfg, tiny), "ask", tiny.id)
    http = FakeHTTP([(200, chat('{"kind": "note"}'))])
    gated = profile.resolve(cfg, "ask", keystore, tmp_path, transport=http, today=TODAY)
    with pytest.raises(BudgetRefused):
        gated.generate(REQ)
    assert http.calls == []
    # A cloud host with no price: refused; with a limit or prices: gated.
    cloud = {
        "base_url": "https://api.groq.com/openai/v1",
        "label": "Groq",
        "model": "m",
        "provider": "openai_compatible",
    }
    c = profile.make_profile(cloud)
    cfg = profile.set_use(profile.put_profile(cfg, c), "ask", c.id)
    assert build_paid(c)
    with pytest.raises(BudgetRefused) as err:
        profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY)
    assert err.value.code == "no_prices"
    c2 = profile.make_profile({**cloud, "limit": {"calls": 5, "chars": 5000}}, keep_id=c.id)
    cfg = profile.put_profile(cfg, c2)
    assert isinstance(profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY), UsageGate)
    c3 = profile.make_profile({**cloud, "prices": ["1", "2"]}, keep_id=c.id)
    cfg = profile.ModelConfig({**cfg.profiles, c.id: c3}, cfg.use, BUDGET, cfg.modes, cfg.chosen)
    assert isinstance(profile.resolve(cfg, "ask", keystore, tmp_path, today=TODAY), Gate)
    # Claude Fable has no table price: a limit lets it run with no price.
    f = profile.make_profile({**FABLE, "limit": {"calls": 1, "chars": 50_000}})
    assert profile.usage_limit(f, profile.build(f)) == {"calls": 1, "chars": 50_000}
    # A model on this computer has no limit.
    local = profile.make_profile({**UNIVERSITY, "base_url": "http://127.0.0.1:8000/v1"})
    assert profile.usage_limit(local, profile.build(local)) is None
    for bad in ({"calls": 0, "chars": 1}, {"calls": 1}, {"calls": True, "chars": 1}, [1, 2]):
        with pytest.raises(ModelError):
            profile.make_profile({**UNIVERSITY, "limit": bad})


def build_paid(p) -> bool:
    return profile.build(p).paid


def test_the_structured_mode_cache_lasts_24_hours(index, keystore, tmp_path):
    cfg, (uni,) = add(index, UNIVERSITY)
    profile.save(index, profile.set_use(cfg, "understand", uni.id))
    http = FakeHTTP([(400, {}), (200, chat('{"kind": "note"}'))])
    m = profile.resolve(profile.load(index), "understand", keystore, tmp_path, transport=http)
    m.generate(REQ)
    assert m.model.structured == "json"
    profile.remember_mode(index, m, clock=lambda: 1000.0)
    cfg = profile.load(index)
    again = profile.resolve(cfg, "understand", keystore, tmp_path, clock=lambda: 1000.0 + 3600)
    assert again.model.structured == "json"
    late = profile.resolve(cfg, "understand", keystore, tmp_path, clock=lambda: 1000.0 + 90000)
    assert late.model.structured is None


# --------------------------------------------------------------- lab default


def test_lab_default_and_member_override(index, keystore, tmp_path):
    lab_profile = profile.make_profile(UNIVERSITY, origin="lab:lab1")
    lab = FakeLabPolicy(
        models={
            "profiles": [UNIVERSITY, {"provider": "broken"}],
            "use": {"ask": lab_profile.id, "understand": lab_profile.id},
        },
        disclosure={"allow_external": [f"model:{lab_profile.id}"]},
    )
    cfg = profile.load(index, lab)
    assert cfg.profiles[lab_profile.id].origin == "lab:lab1"
    assert cfg.use["understand"] == lab_profile.id and cfg.use["draft"] is None
    # The member selects a different profile for one task.
    local = profile.make_profile(OLLAMA)
    cfg = profile.set_use(profile.put_profile(cfg, local), "understand", local.id)
    profile.save(index, cfg)
    cfg = profile.load(index, lab)
    assert cfg.use["understand"] == local.id and cfg.use["ask"] == lab_profile.id
    # The lab profile is not copied into the member config.
    assert list(index.store.get_meta("models")["profiles"]) == [local.id]
    assert profile.load(index).use["ask"] is None  # the member left the lab
    with pytest.raises(ModelError):  # a member cannot remove a lab profile
        profile.remove_profile(index, keystore, cfg, lab_profile.id)
    # Lab-space text: a local model, or a recipient that the lab permits.
    assert profile.may_read_lab(profile.build(local), lab)
    assert profile.may_read_lab(profile.build(lab_profile), lab)
    other = profile.build(profile.make_profile(HAIKU))
    assert not profile.may_read_lab(other, lab)
    rows = {r["profile"]: r for r in recipients.recipients(cfg, lab)}
    assert rows[lab_profile.id]["lab_allows"] and rows[local.id]["lab_allows"]


# -------------------------------------------------------------------- state


def test_state_table(index, keystore, tmp_path):
    def state(**kw):
        return models.state(index, keystore=keystore, home=tmp_path, today=TODAY, **kw)

    assert state()["state"] == "no_model" and state()["next"] == "Choose a model"
    cfg, (local, uni, haiku) = add(index, OLLAMA, UNIVERSITY, HAIKU)
    profile.save(index, profile.set_use(cfg, "understand", local.id))
    assert state() == {"message": None, "next": None, "state": "ready"}
    profile.note_probe(index, local.id, {"ok": False, "reason": "unreachable"})
    assert (state()["state"], state()["next"]) == ("unreachable", "Start Ollama")
    profile.note_call(index, local.id)  # a good call clears the fault
    assert state()["state"] == "ready"
    for _ in range(3):
        profile.note_call(index, local.id, ModelError("unreachable", retryable=True))
    assert state()["state"] == "unreachable"

    # An external profile needs the opt-in of one source or more.
    profile.save(index, profile.set_use(profile.load(index), "understand", uni.id))
    assert state()["state"] == "no_opt_in"
    sid = source(index, tmp_path)
    index.set_source_prefs(sid, allow_external=[f"model:{uni.id}"])
    assert state()["state"] == "ready"
    index.store.set_meta(
        "models", {**index.store.get_meta("models"), "modes": {uni.id: {"at": 1, "mode": "text"}}}
    )
    for _ in range(3):
        profile.note_call(index, uni.id, ModelError("bad_output"))
    assert state()["state"] == "weak_model"

    # A paid profile needs a key, then a budget with money left.
    profile.save(index, profile.set_use(profile.load(index), "understand", haiku.id))
    assert (state()["state"], state()["next"]) == ("unreachable", "Type the key")
    profile.set_key(keystore, haiku.id, NOT_A_KEY)
    index.set_source_prefs(sid, allow_external=[f"model:{haiku.id}"])
    assert state()["state"] == "budget_reached"
    cfg = profile.load(index)
    profile.save(index, profile.ModelConfig(cfg.profiles, cfg.use, BUDGET, cfg.modes, cfg.chosen))
    assert state()["state"] == "ready"
    assert not ledger_path(tmp_path, BUDGET).exists()  # the state makes no ledger file
    gate = profile.resolve(profile.load(index), "understand", keystore, tmp_path, today=TODAY)
    gate.ledger.halt()
    assert state()["state"] == "budget_reached"
    for row in (state(), models.state(index)):
        assert set(row) == {"message", "next", "state"} and row["state"] in profile.STATES


# --------------------------------------------------------------- recipients


def test_recipients_and_flow_rows(index):
    cfg, (local, uni, router) = add(index, OLLAMA, UNIVERSITY, ROUTER)
    rows = {r["profile"]: r for r in recipients.recipients(cfg)}
    assert rows[local.id]["sentence"] == "A local model keeps all text on this computer."
    assert not rows[local.id]["external"] and rows[local.id]["lab_allows"] is None
    assert rows[uni.id]["external"] and rows[uni.id]["id"] == f"model:{uni.id}"
    assert "OpenRouter" in rows[router.id]["name"] and "anthropic" in rows[router.id]["name"]
    (off,) = recipients.flow_rows(cfg)  # no task uses an external profile
    assert off["id"] == "model-provider" and "model provider" in off["to"]
    cfg = profile.set_use(profile.set_use(cfg, "ask", uni.id), "draft", local.id)
    (row,) = recipients.flow_rows(cfg)
    assert "University endpoint" in row["to"] and "model provider" in row["to"]
    assert set(row) == {"can_see", "id", "to", "what", "when"}


# -------------------------------------------------------------- from_config


def test_from_config_builds_each_provider_with_the_key_from_key_env():
    env = {
        "ANAGRAM_MODEL_API_KEY": "uni-" + NOT_A_KEY,
        "ANTHROPIC_API_KEY": "ant-" + NOT_A_KEY,
        "OPENAI_API_KEY": "oai-" + NOT_A_KEY,
        "OPENROUTER_API_KEY": "or-" + NOT_A_KEY,
    }
    cases = [
        (UNIVERSITY, OpenAICompatModel, "uni-", UNI),
        ({"model": "gpt-x", "provider": "openai", "prices": [1, 2]}, OpenAIModel, "oai-", None),
        (ROUTER, OpenRouterModel, "or-", None),
    ]
    for cfg, cls, prefix, base in cases:
        http = FakeHTTP([(200, chat('{"kind": "note"}'))])
        m = from_config(cfg, key_env=env, transport=http)
        assert type(m) is cls and m.profile_id and not isinstance(m, Gate)
        assert m.generate(REQ).data == {"kind": "note"}
        call = http.calls[0]
        assert call["headers"]["Authorization"] == f"Bearer {prefix}{NOT_A_KEY}"
        assert base is None or call["url"].startswith(base)
    m = from_config(HAIKU, key_env=env)
    assert isinstance(m, AnthropicModel) and m.paid and m.prices is not None
    m.ready()  # the key is there; no client is made and no call is sent
    assert from_config(FABLE, key_env=env).prices is None
    assert from_config({**FABLE, "prices": ["5", "25"]}, key_env=env).prices is not None
    local = from_config(OLLAMA, key_env={})
    assert isinstance(local, OllamaModel) and not local.external and not local.paid


def test_from_config_without_a_key_refuses_before_a_call():
    for cfg in (HAIKU, ROUTER, {"model": "gpt-x", "provider": "openai"}):
        http = FakeHTTP()
        with pytest.raises(ModelError) as err:
            from_config(cfg, key_env={}, transport=http).generate(REQ)
        assert err.value.code == "no_key" and http.calls == []
    with pytest.raises(ModelError):
        from_config({"provider": {"model": "nested"}}, key_env={})
    with pytest.raises(ModelError):
        from_config({**HAIKU, "id": "x"}, key_env={})


def test_from_config_does_not_load_the_index_for_a_cloud_provider():
    code = (
        "import sys\n"
        "from anagram.models import from_config\n"
        "from_config({'provider': 'openai_compatible', 'model': 'm',"
        " 'base_url': 'https://llm.example.edu/v1'}, key_env={})\n"
        "from_config({'provider': 'anthropic', 'model': 'claude-haiku-5-5'}, key_env={})\n"
        "bad = [m for m in sys.modules if m.startswith(('anagram.local.index', 'anagram.shell.ui'))]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)  # noqa: S603
    assert done.returncode == 0, done.stderr
