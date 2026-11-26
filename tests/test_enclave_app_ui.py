"""The network matching routes of the local UI (`shell/ui/routers/enclave.py`)
against the in-process development network (tests/enclavestack.py): set
up, lines, consent, approval, on, a proposal card, an answer, and off."""

from __future__ import annotations

import functools

import pytest
from enclavestack import HOUR, LOG_URL, Stack
from fastapi.testclient import TestClient
from test_ui_models_api import RecordingBus

from anagram.network.api import EnclaveMatching
from anagram.network.formats.strict import DAY
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService

PORT = 41996
TOKEN = "launch-token-for-enclave-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = {"Origin": BASE}


def lines(offer: str, want: str) -> dict:
    return {
        "offers": [{"class": "method", "match_types": ["T2"], "scope": "both", "text": offer}],
        "wants": [{"class": "skill", "match_types": ["T2"], "scope": "both", "text": want}],
    }


class UI:
    def __init__(self, stack: Stack, name: str) -> None:
        home = stack.root / "people" / name
        stack.net.join(home, f"fake-{name}", name.title())
        self.svc = UIService(home, transport=stack.net.transport, clock=stack.clock)
        self.app = create_ui_app(self.svc, port=PORT, token=TOKEN, bus=RecordingBus())
        self.tc = TestClient(self.app, base_url=BASE)
        assert self.tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303

    def json(self, method: str, path: str, body: dict | None = None, status: int = 200):
        r = self.tc.request(method, path, json=body, headers=ORIGIN)
        assert r.status_code == status, (method, path, r.status_code, r.text)
        return r.json()

    def join_matching(self, stack: Stack, draft: dict) -> dict:
        self.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": stack.pins.to_json()})
        self.json("PUT", "/api/enclave/draft", draft)
        consent = self.json("GET", "/api/enclave/consent")
        self.json("POST", "/api/enclave/approve", {"statement_hash": consent["statement_hash"]})
        return self.json("POST", "/api/enclave/on", {"on": True})


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    stack = Stack(tmp_path_factory.mktemp("ui"))
    # The app of each person reaches the stack's services in this process.
    mp.setattr(
        "anagram.shell.client.EnclaveMatching",
        functools.partial(EnclaveMatching, connect=stack.connect),
    )
    yield stack
    mp.undo()


def test_before_set_up_the_screen_asks_for_the_network(world) -> None:
    ui = UI(world, "erin")
    st = ui.json("GET", "/api/enclave")
    assert st["set_up"] is False and st["on"] is False and st["cards"] == []
    err = ui.json("GET", "/api/enclave/consent", status=400)
    assert "not set up" in err["error"]
    bad = ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": {}}, status=400)
    assert "pins" in bad["error"]


def test_the_lens_draft_needs_a_local_model(world) -> None:
    ui = UI(world, "frank")
    assert "local model" in ui.json("POST", "/api/enclave/draft", status=409)["error"]


def test_a_line_over_the_limit_is_refused(world) -> None:
    ui = UI(world, "gina")
    long = lines("x" * 141, "Electron tomography")
    assert "140" in ui.json("PUT", "/api/enclave/draft", long, status=400)["error"]


def test_on_proposal_answer_and_off(world) -> None:
    a, b = UI(world, "hana"), UI(world, "ivan")
    pair = (
        "Cryo-EM grid preparation for fragile complexes",
        "Native mass spectrometry of membrane complexes",
    )
    on = a.join_matching(world, lines(*pair))
    b.join_matching(world, lines(*reversed(pair)))
    assert on["on"] is True and on["approved"] is True and on["uploaded_day"] is not None
    # Two more people, so the pool is large enough (min_people = 2).
    UI(world, "jon").join_matching(world, lines("Ice core dating", "Isotope ratio analysis"))
    UI(world, "kim").join_matching(world, lines("Isotope ratio analysis", "Ice core dating"))
    day = world.now() // DAY + 1
    world.at(day * DAY - HOUR)
    world.at(day * DAY + 8 * HOUR)
    st = a.json("POST", "/api/enclave/run")
    proposal = next(c for c in st["cards"] if c["kind"] == "proposal")
    assert proposal["type"] == "method_help"
    assert set(proposal["reasons"]) <= set(pair)  # my own lines only
    assert proposal["choice"] == "unset"
    assert proposal["answer_by"] < proposal["expires"]  # the last checkpoint
    assert proposal["next_checkpoint"] is not None
    card = {
        "email": "hana@lab.example.org",
        "institution": "Test Lab",
        "lab": None,
        "name": "Hana",
        "orcid": None,
    }
    st = a.json(
        "POST", "/api/enclave/answer", {"proposal": proposal["id"], "choice": "yes", "card": card}
    )
    assert next(c for c in st["cards"] if c["kind"] == "proposal")["choice"] == "yes"
    bad = a.json(
        "POST",
        "/api/enclave/answer",
        {"proposal": proposal["id"], "choice": "yes", "card": {**card, "email": "x"}},
        status=400,
    )
    assert "card" in bad["error"]
    off = a.json("POST", "/api/enclave/on", {"on": False})
    assert off["on"] is False and off["approved"] is False


def test_the_person_chooses_a_weekly_cap(world) -> None:
    """C43: 1 to 10 proposals a week, default 3; the consent screen shows
    the network maximum and the three answer days."""
    ui = UI(world, "lena")
    assert ui.json("GET", "/api/enclave")["weekly_cap"] == 3
    ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": world.pins.to_json()})
    consent = ui.json("GET", "/api/enclave/consent")
    a = consent["answer_day"]
    assert consent["answer_days"] == [a, 2 * a, 3 * a]
    assert 1 <= consent["weekly_cap_max"] <= 10
    assert ui.json("PUT", "/api/enclave/weekly-cap", {"weekly_cap": 1})["weekly_cap"] == 1
    for bad in (0, 11, "3", True):
        ui.json("PUT", "/api/enclave/weekly-cap", {"weekly_cap": bad}, status=400)
