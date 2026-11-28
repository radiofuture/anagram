"""The model routes of the local UI (`shell/ui/routers/understanding.py`): the
boundary, profiles, keys, the test of a profile, the task choice, the spend
limit, the sources that a model may read, and the event `models.state`.

Each provider gets a fake transport or a fake client. No network."""

from __future__ import annotations

import json
from datetime import date

import pytest
from conftest import make_net
from fastapi.testclient import TestClient
from modelkit import NOT_A_KEY, UNI, FakeHTTP, FakeOllama, chat

from anagram.identity.app.keychain import open_keystore
from anagram.local.sources import FolderConnector
from anagram.models import profile
from anagram.models.budget import ledger_path
from anagram.models.ollama_client import OllamaClient
from anagram.shell.ui.events import EventBus
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService

pytestmark = pytest.mark.usefixtures("no_network")

PORT = 41997
TOKEN = "launch-token-for-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = {"Origin": BASE}
ORCID = "0000-0002-1825-0097"
TODAY = date(2026, 11, 16)
OLLAMA = {"label": "Local model", "model": "llama3.2", "provider": "ollama"}
UNIVERSITY = {
    "base_url": UNI,
    "label": "University endpoint",
    "model": "served-model",
    "provider": "openai_compatible",
}
HAIKU = {"label": "Claude Haiku", "model": "claude-haiku-5-5", "provider": "anthropic"}
ROUTES = (
    ("GET", "/api/models"),
    ("PUT", "/api/models/profiles/some-id"),
    ("DELETE", "/api/models/profiles/some-id"),
    ("PUT", "/api/models/profiles/some-id/key"),
    ("DELETE", "/api/models/profiles/some-id/key"),
    ("POST", "/api/models/profiles/some-id/test"),
    ("PUT", "/api/models/use"),
    ("PUT", "/api/models/budget"),
    ("PUT", "/api/labs/{lab_id}/models"),
    ("GET", "/api/sources/some-source/recipients"),
    ("PUT", "/api/sources/some-source/recipients"),
)


class RecordingBus(EventBus):
    def __init__(self) -> None:
        super().__init__()
        self.seen: list[tuple[str, dict]] = []

    def publish(self, type, data=None, *, key=None):
        self.seen.append((type, data or {}))
        return super().publish(type, data, key=key)

    def states(self) -> list[str]:
        return [d["state"] for t, d in self.seen if t == "models.state"]


class UI:
    def __init__(self, tmp_path, joined: bool = True) -> None:
        self.net = make_net(tmp_path)
        self.home = tmp_path / "me"
        if joined:
            self.net.join(self.home, ORCID)
        self.ollama = FakeOllama()
        self.svc = UIService(
            self.home,
            transport=self.net.transport,
            clock=self.net.clock,
            ollama=OllamaClient(transport=self.ollama),
        )
        self.bus = RecordingBus()
        self.app = create_ui_app(self.svc, port=PORT, token=TOKEN, bus=self.bus)
        self.tc = TestClient(self.app, base_url=BASE)
        self.models = self.svc.models
        self.models.today = lambda: TODAY
        self.models.local_default = False  # these tests make each choice
        self.texts: list[str] = []  # each response body, to check for a key

    def launch(self) -> UI:
        assert self.tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303
        return self

    def call(self, method: str, path: str, body: dict | None = None, status: int = 200) -> dict:
        r = self.tc.request(method, path, json=body, headers=ORIGIN)
        self.texts.append(r.text)
        assert r.status_code == status, (method, path, r.status_code, r.text)
        return r.json()

    def add(self, raw: dict) -> str:
        return self.call("PUT", "/api/models/profiles/new", raw)["saved"]

    def source(self, tmp_path) -> str:
        folder = tmp_path / "notes"
        folder.mkdir(exist_ok=True)
        with self.svc.session(index=True) as (_, idx):
            return idx.add_source(FolderConnector(folder))

    def meta(self) -> dict:
        with self.svc.session(index=True) as (_, idx):
            return idx.store.get_meta("models")


@pytest.fixture
def ui(tmp_path):
    return UI(tmp_path).launch()


# ----------------------------------------------------------------- boundary


def test_model_routes_obey_the_local_ui_boundary(tmp_path):
    ui = UI(tmp_path)
    paths = {
        (m, r.path.replace("{pid}", "some-id").replace("{sid}", "some-source"))
        for r in ui.app.routes
        for m in getattr(r, "methods", None) or ()
        if "/models" in r.path or r.path.endswith("/recipients")
    }
    assert paths == set(ROUTES)  # the list below covers each route of the module
    for method, path in ROUTES:
        r = ui.tc.request(method, path, json={}, headers=ORIGIN)
        assert r.status_code == 401, path  # no cookie
    ui.launch()
    for method, path in ROUTES:
        evil = ui.tc.request(method, path, json={}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403, path
        cross = ui.tc.request(
            method, path, json={}, headers={**ORIGIN, "Sec-Fetch-Site": "cross-site"}
        )
        assert cross.status_code == 403, path
        rebind = ui.tc.request(method, path, json={}, headers={**ORIGIN, "Host": "evil.example"})
        assert rebind.status_code == 421, path
        if method != "GET":  # a change with no Origin header is refused
            assert ui.tc.request(method, path, json={}).status_code == 403, path
    assert ui.bus.seen == []


def test_model_routes_need_a_joined_home(tmp_path):
    ui = UI(tmp_path, joined=False).launch()
    assert "Join" in ui.call("GET", "/api/models", status=409)["error"]


# ------------------------------------------------------- profiles and state


def test_a_local_model_from_choice_to_ready(ui):
    first = ui.call("GET", "/api/models")
    assert first["state"]["state"] == "no_model" and first["state"]["next"] == "Choose a model"
    assert first["profiles"] == [] and first["budget"] is None and first["lab"] is None
    assert first["ollama"] == {"available": True, "models": ["llama3.2:latest"]}
    assert set(first["use"]) == {"ask", "draft", "embed", "understand"}

    pid = ui.add(OLLAMA)
    got = ui.call("GET", "/api/models")
    (row,) = got["profiles"]
    assert row["id"] == pid and row["origin"] == "member" and row["provider"] == "ollama"
    assert not row["external"] and not row["paid"] and not row["has_key"]
    assert row["sentence"] == "A local model keeps all text on this computer."
    assert row["capabilities"]["structured"] == "schema"
    assert ui.bus.states() == []  # a profile that no task uses does not change the state

    # A local model needs no acknowledgement.
    got = ui.call("PUT", "/api/models/use", {"profile": pid, "task": "understand"})
    assert got["use"]["understand"] == pid and got["state"]["state"] == "ready"
    assert ui.bus.states() == ["ready"]
    test = ui.call("POST", f"/api/models/profiles/{pid}/test")
    assert test == {
        "capabilities": row["capabilities"],
        "message": None,
        "ok": True,
        "reason": None,
    }
    assert ui.bus.states() == ["ready"]  # no change, no event

    # Ollama stops: the test fails, and the state says what to do.
    ui.ollama.down = True
    test = ui.call("POST", f"/api/models/profiles/{pid}/test")
    assert not test["ok"] and test["message"] == "Anagram cannot reach the model."
    state = ui.call("GET", "/api/models")["state"]
    assert (state["state"], state["next"]) == ("unreachable", "Start Ollama")
    ui.ollama.down = False
    assert ui.call("POST", f"/api/models/profiles/{pid}/test")["ok"]
    assert ui.bus.states() == ["ready", "unreachable", "ready"]
    for _, data in ui.bus.seen:
        assert set(data) == {"message", "next", "state"}

    got = ui.call("PUT", "/api/models/use", {"profile": None, "task": "understand"})
    assert got["state"]["state"] == "no_model" and ui.bus.states()[-1] == "no_model"


def test_bad_profiles_get_one_plain_sentence(ui):
    for raw, word in (
        ({"model": "m", "provider": "other"}, "provider"),
        ({**UNIVERSITY, "base_url": "http://llm.example.edu/v1"}, "https://"),
        ({**OLLAMA, "base_url": "https://llm.example.edu"}, "this computer"),
        ({"model": "x/y", "provider": "openrouter"}, "OpenRouter"),
        ({**HAIKU, "prices": ["a", "b"]}, "prices"),
        ({**HAIKU, "key": NOT_A_KEY}, "provider"),
    ):
        err = ui.call("PUT", "/api/models/profiles/new", raw, status=400)["error"]
        assert word in err and "invalid" not in err and NOT_A_KEY not in err
    ui.call("PUT", "/api/models/profiles/no-such-profile", OLLAMA, status=404)
    ui.call("DELETE", "/api/models/profiles/no-such-profile", status=404)
    ui.call("POST", "/api/models/profiles/no-such-profile/test", status=404)
    ui.call("PUT", "/api/models/profiles/no-such-profile/key", {"key": NOT_A_KEY}, status=404)
    ui.call("PUT", "/api/models/use", {"profile": "no-such-profile", "task": "ask"}, status=404)
    ui.call("PUT", "/api/models/use", {"profile": None, "task": "judge"}, status=400)
    ui.add(OLLAMA)
    ui.call("PUT", "/api/models/profiles/new", OLLAMA, status=409)  # the same name again
    assert ui.call("GET", "/api/models")["profiles"][0]["label"] == "Local model"


# ------------------------------------------------- external profile and keys


def test_an_external_profile_needs_acknowledgement_key_and_source_opt_in(ui, tmp_path):
    pid = ui.add(UNIVERSITY)
    row = ui.call("GET", "/api/models")["profiles"][0]
    assert row["external"] and not row["paid"] and row["recipient"] == "University endpoint"
    assert "University endpoint reads the text of the sources that you permit" in row["sentence"]

    use = {"profile": pid, "task": "understand"}
    err = ui.call("PUT", "/api/models/use", use, status=400)
    assert "University endpoint" in err["error"] and err["recipient"] == "University endpoint"
    err = ui.call("PUT", "/api/models/use", {**use, "acknowledged": "yes"}, status=400)
    got = ui.call("PUT", "/api/models/use", {**use, "acknowledged": True})
    assert got["state"]["state"] == "no_opt_in"
    assert got["state"]["next"] == "Choose the sources this model may read"

    # The opt-in of one source. Other entries of the list stay.
    sid = ui.source(tmp_path)
    with ui.svc.session(index=True) as (_, idx):
        idx.set_source_prefs(sid, allow_external=["datalab"])
    rid = f"model:{pid}"
    assert ui.call("GET", f"/api/sources/{sid}/recipients") == {"allow": []}
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": ["model:other"]}, status=400)
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": "all"}, status=400)
    ui.call("PUT", "/api/sources/no-such-source/recipients", {"allow": [rid]}, status=404)
    assert ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": [rid]}) == {"allow": [rid]}
    with ui.svc.session(index=True) as (_, idx):
        assert idx.source(sid)["prefs"]["allow_external"] == ["datalab", rid]
    assert ui.call("GET", "/api/models")["state"]["state"] == "ready"
    assert ui.bus.states() == ["no_opt_in", "ready"]

    # The key: stored in the keystore, sent to the endpoint, never returned.
    assert ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": NOT_A_KEY}) == {
        "has_key": True
    }
    assert ui.call("GET", "/api/models")["profiles"][0]["has_key"]
    assert open_keystore(ui.home).get(f"model-key-{pid}") == NOT_A_KEY.encode()
    http = FakeHTTP([(200, {"data": [{"id": "served-model"}]}), (200, chat('{"ok": true}'))])
    ui.models.transport = http
    test = ui.call("POST", f"/api/models/profiles/{pid}/test")
    assert test["ok"] and test["capabilities"]["structured"] == "schema"
    assert [c["url"] for c in http.calls] == [f"{UNI}/models", f"{UNI}/chat/completions"]
    assert all(c["headers"]["Authorization"] == f"Bearer {NOT_A_KEY}" for c in http.calls)
    assert ui.meta()["modes"][pid]["mode"] == "schema"  # the mode cache
    ui.models.transport = FakeHTTP([(401, {})])
    test = ui.call("POST", f"/api/models/profiles/{pid}/test")
    assert (test["ok"], test["message"]) == (False, "The provider refused the key.")

    # A new label keeps the id, the key, and the opt-in.
    same = ui.call("PUT", f"/api/models/profiles/{pid}", {**UNIVERSITY, "label": "Campus"})
    assert same["saved"] == pid and same["profiles"][0]["has_key"]
    # A new host is a new party: new id, no key, no opt-in, no task.
    moved = ui.call(
        "PUT", f"/api/models/profiles/{pid}", {**UNIVERSITY, "base_url": "https://b.example/v1"}
    )
    assert moved["saved"] != pid and [p["id"] for p in moved["profiles"]] == [moved["saved"]]
    assert not moved["profiles"][0]["has_key"] and moved["use"]["understand"] is None
    assert open_keystore(ui.home).get(f"model-key-{pid}") is None
    assert ui.call("GET", f"/api/sources/{sid}/recipients") == {"allow": []}

    # Delete: the key and the opt-ins go with the profile.
    new = moved["saved"]
    ui.call("PUT", f"/api/models/profiles/{new}/key", {"key": NOT_A_KEY})
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": [f"model:{new}"]})
    assert ui.call("DELETE", f"/api/models/profiles/{new}")["profiles"] == []
    assert open_keystore(ui.home).list("model-key-") == []
    with ui.svc.session(index=True) as (_, idx):
        assert idx.source(sid)["prefs"]["allow_external"] == ["datalab"]


def test_no_route_event_or_stored_config_holds_a_key(ui, tmp_path):
    secret = "sk-" + NOT_A_KEY
    pid = ui.add(HAIKU)
    for bad in ("", "two words", None, 7):
        err = ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": bad}, status=400)
        assert "key" in err["error"]
    ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": secret})
    ui.call("PUT", "/api/models/use", {"acknowledged": True, "profile": pid, "task": "ask"})
    sid = ui.source(tmp_path)
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": [f"model:{pid}"]})
    ui.call("PUT", "/api/models/budget", {"budget_usd": "2", "expires": "2026-12-31"})
    ui.call("GET", "/api/models")
    ui.call("PUT", f"/api/models/profiles/{pid}", {**HAIKU, "label": "Haiku"})
    ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": secret + " x"}, status=400)
    assert ui.call("DELETE", f"/api/models/profiles/{pid}/key") == {"has_key": False}
    ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": secret})
    ui.call("DELETE", f"/api/models/profiles/{pid}")
    assert len(ui.texts) > 10
    for text in (*ui.texts, json.dumps(ui.bus.seen), json.dumps(ui.meta())):
        assert secret not in text and NOT_A_KEY not in text
    assert (ui.home / "ui.json").exists() is False or secret not in (
        ui.home / "ui.json"
    ).read_text()


# ------------------------------------------------------- paid profile, budget


def test_a_paid_profile_needs_a_key_and_a_spend_limit(ui, tmp_path):
    pid = ui.add(HAIKU)
    row = ui.call("GET", "/api/models")["profiles"][0]
    assert row["paid"] and row["needs_key"] and row["prices"] == ["0.10", "0.50"]
    use = {"acknowledged": True, "profile": pid, "task": "understand"}
    state = ui.call("PUT", "/api/models/use", use)["state"]
    assert (state["state"], state["next"]) == ("unreachable", "Type the key")
    # The test of a paid profile with no key makes no call.
    test = ui.call("POST", f"/api/models/profiles/{pid}/test")
    assert (test["ok"], test["message"]) == (False, "This model has no key.")
    ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": NOT_A_KEY})
    sid = ui.source(tmp_path)
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": [f"model:{pid}"]})
    state = ui.call("GET", "/api/models")["state"]
    assert (state["state"], state["next"]) == ("budget_reached", "Set a new spend limit")

    for body in (
        {"budget_usd": "0", "expires": "2026-12-31"},
        {"budget_usd": "-1", "expires": "2026-12-31"},
        {"budget_usd": "many", "expires": "2026-12-31"},
        {"budget_usd": "5", "expires": "2026-11-15"},  # the day before today
        {"budget_usd": "5", "expires": "soon"},
        {"budget_usd": "5000", "expires": "2026-12-31"},
        {"budget_usd": True, "expires": "2026-12-31"},
    ):
        assert "error" in ui.call("PUT", "/api/models/budget", body, status=400)
    got = ui.call("PUT", "/api/models/budget", {"budget_usd": 2.5, "expires": "2026-12-31"})
    assert got["budget"] == {
        "budget_usd": "2.5",
        "expires": "2026-12-31",
        "open": True,
        "spent_usd": "0",
    }
    assert got["state"]["state"] == "ready"
    budget = ui.meta()["budget"]
    assert budget == {"approved_by": "member", "budget_usd": "2.5", "expires": "2026-12-31"}
    assert not ledger_path(ui.home, budget).exists()  # a view makes no ledger file

    # The model for the task is inside the spend gate; a halted ledger shows.
    with ui.svc.session(index=True) as (client, idx):
        gate = profile.resolve(
            profile.load(idx), "understand", client.keystore, ui.home, today=TODAY
        )
    gate.ledger.reserve("test", 500_000_000)
    assert ui.call("GET", "/api/models")["budget"]["spent_usd"] == "0.5"
    gate.ledger.halt()
    got = ui.call("GET", "/api/models")
    assert not got["budget"]["open"] and got["state"]["state"] == "budget_reached"
    # A new limit is a new approval with a new ledger.
    got = ui.call("PUT", "/api/models/budget", {"budget_usd": "3", "expires": "2026-12-31"})
    assert got["budget"]["spent_usd"] == "0" and got["state"]["state"] == "ready"
    got = ui.call("PUT", "/api/models/budget", {"budget_usd": None})
    assert got["budget"] is None and got["state"]["state"] == "budget_reached"
    # The second "ready": the ledger halt was not a route call, so the new
    # limit is the first change that the bus sees after it.
    assert ui.bus.states() == [
        "unreachable",
        "no_opt_in",
        "budget_reached",
        "ready",
        "ready",
        "budget_reached",
    ]


# --------------------------------------------------------------- migration


def test_the_old_drafting_setting_becomes_a_profile(ui):
    ui.svc.settings.set_drafting("ollama", "qwen2.5:7b")
    got = ui.call("GET", "/api/models")
    (row,) = got["profiles"]
    assert (row["provider"], row["model"]) == ("ollama", "qwen2.5:7b")
    assert got["use"]["draft"] == row["id"] and got["use"]["understand"] is None
    # The old routes stay.
    assert ui.call("GET", "/api/settings")["drafting"]["mode"] == "ollama"


# ------------------------------------------------- the zero-choice default


def test_with_ollama_the_default_needs_no_choice(ui):
    """Ollama runs with a model: the first read selects it for reading,
    answers, and drafts. An embedding model is never the choice."""
    ui.models.local_default = True
    ui.ollama.tags = ("nomic-embed-text:latest", "llama3.2:latest")
    got = ui.call("GET", "/api/models")
    (row,) = got["profiles"]
    assert row["provider"] == "ollama" and row["model"] == "llama3.2"
    assert got["use"]["understand"] == got["use"]["ask"] == got["use"]["draft"] == row["id"]
    assert got["use"]["embed"] is None
    assert got["state"]["state"] == "ready" and ui.bus.states() == ["ready"]
    # A choice of "no model" stays: the default does not come back.
    ui.call("PUT", "/api/models/use", {"profile": None, "task": "understand"})
    again = ui.call("GET", "/api/models")
    assert again["use"]["understand"] is None and len(again["profiles"]) == 1


def test_with_no_ollama_model_nothing_is_chosen(ui):
    ui.models.local_default = True
    ui.ollama.tags = ("nomic-embed-text:latest",)
    assert ui.call("GET", "/api/models")["profiles"] == []
    ui.ollama.down = True
    got = ui.call("GET", "/api/models")
    assert got["profiles"] == [] and got["ollama"]["available"] is False
    assert got["state"]["state"] == "no_model"


def test_local_default_keeps_a_choice():
    empty = dict.fromkeys(profile.TASKS)
    cfg = profile.ModelConfig(profiles={}, use=empty, chosen=frozenset())
    got = profile.local_default(cfg, ["mistral:7b"])
    assert got.use["understand"] == got.use["ask"] == got.use["draft"]
    assert got.profiles[got.use["understand"]].model == "mistral:7b"
    chose = profile.ModelConfig(profiles={}, use=empty, chosen=frozenset({"understand"}))
    assert profile.local_default(chose, ["llama3.2"]) is None
    assert profile.local_default(cfg, []) is None


def test_local_default_takes_the_measured_model_first():
    """R4 step 18: qwen2.5:7b had the best kind accuracy of the local models,
    then llama3.2. Another size of qwen2.5 is not the measured model."""
    empty = dict.fromkeys(profile.TASKS)
    cfg = profile.ModelConfig(profiles={}, use=empty, chosen=frozenset())

    def pick(installed):
        got = profile.local_default(cfg, installed)
        return got.profiles[got.use["understand"]].model

    assert pick(["mistral:7b", "llama3.2:latest", "qwen2.5:7b"]) == "qwen2.5:7b"
    assert pick(["mistral:7b", "qwen2.5:0.5b", "llama3.2:latest"]) == "llama3.2"
    assert pick(["mistral:7b", "llama3.2:3b"]) == "llama3.2:3b"
    assert pick(["qwen2.5:0.5b", "mistral:7b"]) == "qwen2.5:0.5b"  # no measured model


def test_the_empty_ollama_text_names_the_recommended_model():
    """The text that tells a person which model to add names the first
    recommended local model, and no other model name."""
    from pathlib import Path

    import anagram.shell.ui

    copy = Path(anagram.shell.ui.__file__).parent / "static" / "copy" / "models.json"
    text = json.loads(copy.read_text())["ollama_empty"]
    assert f"for example {profile.RECOMMENDED_LOCAL[0]}," in text
    assert not any(name in text for name in profile.RECOMMENDED_LOCAL[1:])


def test_the_models_view_lists_sources_with_their_opt_ins(ui, tmp_path):
    sid = ui.source(tmp_path)
    pid = ui.add(HAIKU)
    ui.call("PUT", f"/api/sources/{sid}/recipients", {"allow": [f"model:{pid}"]})
    (src,) = ui.call("GET", "/api/models")["sources"]
    assert src["id"] == sid and src["allow"] == [pid] and src["space"] == "private"
    assert src["label"] and "/" not in src["label"]


# ------------------------------------------------------------- lab model


def test_a_pi_sets_the_lab_model_and_members_get_it(ui):
    with ui.svc.session() as c:
        lab_id = c.labs.lab_create("Model Lab")["lab_id"]
    body = {"profile": UNIVERSITY, "lab_text": True}
    got = ui.call("PUT", f"/api/labs/{lab_id}/models", body)
    models = got["settings"]["models"]
    assert models["profiles"] == [UNIVERSITY]
    pid = models["use"]["understand"]
    assert models["use"] == {"ask": pid, "draft": pid, "understand": pid}
    assert got["settings"]["disclosure"]["allow_external"] == [f"model:{pid}"]
    view = ui.call("GET", "/api/models")
    row = next(p for p in view["profiles"] if p["id"] == pid)
    assert row["origin"] == f"lab:{lab_id}" and row["lab_allows"] is True
    assert view["use"]["understand"] == pid
    # Back to the model on each computer: no profile, no outside reader.
    got = ui.call("PUT", f"/api/labs/{lab_id}/models", {"profile": None})
    assert got["settings"]["models"]["profiles"] == []
    assert got["settings"]["disclosure"]["allow_external"] == []
    bad = {"profile": {"model": "m", "provider": "x"}}
    err = ui.call("PUT", f"/api/labs/{lab_id}/models", bad, status=400)
    assert err["error"] == "Choose a provider and type a model name."


def test_expired_budget_reports_real_spent_amount(ui, tmp_path):
    pid = ui.add(HAIKU)
    ui.call("PUT", f"/api/models/profiles/{pid}/key", {"key": NOT_A_KEY})
    ui.call("PUT", "/api/models/use", {"acknowledged": True, "profile": pid, "task": "understand"})
    ui.call("PUT", "/api/models/budget", {"budget_usd": "5", "expires": "2026-11-20"})
    with ui.svc.session(index=True) as (client, idx):
        gate = profile.resolve(
            profile.load(idx), "understand", client.keystore, ui.home, today=TODAY
        )
    gate.ledger.reserve("test", 1_250_000_000)
    # Advance past expiry: open becomes False, but spent_usd still shows 1.25 (not 0 or None).
    ui.models.today = lambda: date(2026, 11, 25)
    got = ui.call("GET", "/api/models")["budget"]
    assert got == {
        "budget_usd": "5",
        "expires": "2026-11-20",
        "open": False,
        "spent_usd": "1.25",
    }
