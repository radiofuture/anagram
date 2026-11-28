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
    assert on["draft_approved"] is True
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


def test_an_edit_after_the_approval_needs_a_new_approval(world) -> None:
    ui = UI(world, "lena")
    st = ui.join_matching(
        world, lines("Light-sheet imaging of organoids", "Spatial transcriptomics")
    )
    assert st["draft_approved"] is True
    st = ui.json(
        "PUT", "/api/enclave/draft", lines("Light-sheet imaging", "Spatial transcriptomics")
    )
    st = ui.json("GET", "/api/enclave")
    assert st["approved"] is True and st["draft_approved"] is False  # the network has the old lines
    consent = ui.json("GET", "/api/enclave/consent")
    ui.json("POST", "/api/enclave/approve", {"statement_hash": consent["statement_hash"]})
    assert ui.json("GET", "/api/enclave")["draft_approved"] is True


def test_private_tier_files_never_leak_into_beacon_draft(world, tmp_path) -> None:
    """Regression: `EnclaveUI.draft()` must load `TrustPolicy` and exclude
    `private`-tier items from `lens_items(idx, policy=policy)`."""
    from datetime import UTC, datetime

    from anagram.local.api import FolderConnector, TrustStore
    from anagram.local.trust.policy import PRIVATE, make_policy
    from anagram.models.embed import FakeEmbedder
    from anagram.models.providers.fake import FakeTextModel

    ui = UI(world, "mira")
    ui.svc.embedder = FakeEmbedder()

    folder = tmp_path / "mira-notes"
    folder.mkdir()
    private_canary = "UNPUBLISHED-PRIVATE-COMPOUND-991"
    (folder / "secret.md").write_text(
        f"# Private\n\nWe can share {private_canary} assays with external groups.\n"
    )
    (folder / "public.md").write_text(
        "# Public\n\nWe can share cryo-EM grid screening protocols with collaborators.\n"
    )

    with ui.svc.session(index=True) as (c, idx):
        sid = idx.add_source(FolderConnector(folder))
        idx.scan([sid], process=True)
        policy_doc = make_policy(
            owner=c.device.subject,
            rev=1,
            key=c.device.device_key(),
            updated_at=datetime.fromtimestamp(world.now(), UTC),
            items={sid: {"secret.md": PRIVATE}},
        )
        TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()]).save(
            policy_doc
        )

    def local_model(req):
        if "research topics" in req.system:
            return {"topics": []}
        return {
            "items": [
                {"index": 1, "kind": "offer", "class": "method"},
            ]
        }

    fake = FakeTextModel(local_model)
    ui.svc.settings.draft_model = lambda _c, _idx: (fake, None)  # type: ignore[method-assign]

    st = ui.json("POST", "/api/enclave/draft")
    blob = repr(st["draft"])
    assert "cryo-EM grid screening protocols" in blob
    assert private_canary not in blob
    assert all(private_canary not in seen for seen in fake.read)


def test_ambient_consent_background_updates_remove_and_switch_manual(world, tmp_path) -> None:
    """One-time ambient consent flow:
    - Matching stays off and `refresh_ambient()` does nothing until explicit
      ambient approval (`approve(..., ambient=True)`) and turning on;
    - Once consented, `refresh_ambient()` updates active matching lines in the
      background without requiring a new approval click;
    - Removing a line deletes it immediately and records `excluded_lines` so
      background indexing never silently re-adds it;
    - Switching to manual stops background updates cleanly.
    """
    from anagram.local.api import FolderConnector
    from anagram.models.embed import FakeEmbedder
    from anagram.models.providers.fake import FakeTextModel

    ui = UI(world, "nina")
    ui.svc.embedder = FakeEmbedder()

    folder = tmp_path / "nina-notes"
    folder.mkdir()
    (folder / "new.md").write_text(
        "# Recent\n\nWe can offer high-throughput cryo-EM single-particle reconstruction pipelines.\n"
    )
    with ui.svc.session(index=True) as (_c, idx):
        sid = idx.add_source(FolderConnector(folder))
        idx.scan([sid], process=True)

    def local_model(req):
        if "research topics" in req.system:
            return {"topics": []}
        return {"items": [{"index": 1, "kind": "offer", "class": "method"}]}

    ui.svc.settings.draft_model = lambda _c, _idx: (FakeTextModel(local_model), None)  # type: ignore[method-assign]

    initial = lines("Old spectroscopy service", "Access to 300 kV microscope")
    ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": world.pins.to_json()})
    ui.json("PUT", "/api/enclave/draft", initial)
    # Before ambient consent, refresh_ambient does nothing and matching stays off.
    assert ui.svc.enclave.refresh_ambient() is None
    st0 = ui.json("GET", "/api/enclave")
    assert st0["on"] is False and st0["mode"] == "manual" and st0["can_ambient"] is True
    assert st0["draft"] == initial

    # Opt in once to ambient matching via consent approval and turn matching on.
    consent = ui.json("GET", "/api/enclave/consent")
    ui.json(
        "POST",
        "/api/enclave/approve",
        {"statement_hash": consent["statement_hash"], "ambient": True},
    )
    st_on = ui.json("POST", "/api/enclave/on", {"on": True})
    assert st_on["on"] is True and st_on["mode"] == "ambient" and st_on["draft_approved"] is True

    # Background refresh updates active lines directly without needing re-approval!
    updated = ui.svc.enclave.refresh_ambient()
    assert updated is not None
    st1 = ui.json("GET", "/api/enclave")
    assert st1["draft_approved"] is True
    assert any("reconstruction pipelines" in ln["text"] for ln in st1["draft"]["offers"])

    # Removing a line updates active lines and adds to excluded_lines so refresh won't re-add it.
    removed_text = st1["draft"]["offers"][0]["text"]
    st2 = ui.json("POST", "/api/enclave/draft/archive-line", {"text": removed_text})
    assert removed_text in st2["excluded_lines"]
    assert all(ln["text"] != removed_text for ln in st2["draft"]["offers"])

    # Index a new file: the new line appears, while the removed line stays excluded!
    (folder / "newer.md").write_text(
        "# Update\n\nWe can offer native mass spectrometry calibration standards.\n"
    )
    with ui.svc.session(index=True) as (_c, idx):
        idx.scan(process=True)
    # Re-approve one line first if removing the sole line cleared approval, or verify via fresh file.
    if not st2["approved"]:
        ui.json("PUT", "/api/enclave/draft", initial)
        consent = ui.json("GET", "/api/enclave/consent")
        ui.json(
            "POST",
            "/api/enclave/approve",
            {"statement_hash": consent["statement_hash"], "ambient": True},
        )
        ui.json("POST", "/api/enclave/on", {"on": True})

    ui.svc.enclave.refresh_ambient()
    st3 = ui.json("GET", "/api/enclave")
    assert any("calibration standards" in ln["text"] for ln in st3["draft"]["offers"])
    assert all(ln["text"] != removed_text for ln in st3["draft"]["offers"])

    # Switching back to manual stops automatic background updates.
    st4 = ui.json("POST", "/api/enclave/mode/manual")
    assert st4["mode"] == "manual" and st4["on"] is True
    (folder / "third.md").write_text(
        "# Later\n\nWe can offer automated X-ray crystallography beamtime scheduling.\n"
    )
    with ui.svc.session(index=True) as (_c, idx):
        idx.scan(process=True)
    assert ui.svc.enclave.refresh_ambient() is None
    st5 = ui.json("GET", "/api/enclave")
    assert all("beamtime scheduling" not in ln["text"] for ln in st5["draft"]["offers"])


def test_tick_runs_matching_even_when_ambient_model_crashes(world, tmp_path) -> None:
    """Regression: a RuntimeError/OSError from the local model during ambient
    refresh in `tick()` must NEVER skip or block `c.enclave.run()`."""
    from anagram.local.api import FolderConnector
    from anagram.models.embed import FakeEmbedder

    ui = UI(world, "priya")
    ui.svc.embedder = FakeEmbedder()
    folder = tmp_path / "priya-notes"
    folder.mkdir()
    (folder / "doc.md").write_text("# Doc\n\nWe can offer cryo-EM grid screening.\n")
    with ui.svc.session(index=True) as (_c, idx):
        sid = idx.add_source(FolderConnector(folder))
        idx.scan([sid], process=True)

    class CrashingModel:
        external = False

        def generate(self, *_args, **_kwargs):
            raise RuntimeError("local model crashed")

    ui.svc.settings.draft_model = lambda _c, _idx: (CrashingModel(), None)  # type: ignore[method-assign]

    ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": world.pins.to_json()})
    ui.json("PUT", "/api/enclave/draft", lines("Cryo-EM screening", "Native mass spectrometry"))
    consent = ui.json("GET", "/api/enclave/consent")
    ui.json(
        "POST",
        "/api/enclave/approve",
        {"statement_hash": consent["statement_hash"], "ambient": True},
    )
    ui.json("POST", "/api/enclave/on", {"on": True})

    # Advance to the next UTC day so tick() MUST perform a fresh daily upload.
    next_day = world.now() // DAY + 1
    world.at(next_day * DAY + HOUR)
    assert ui.json("GET", "/api/enclave")["uploaded_day"] < next_day

    # tick() must complete without raising AND complete the daily upload!
    ui.svc.enclave.tick()
    st = ui.json("GET", "/api/enclave")
    assert st["uploaded_day"] == next_day


def test_over_limit_combined_block_and_deny_lists_refuse_instead_of_truncating(world) -> None:
    """Regression: combining explicit block/deny lists with TrustPolicy entries
    above network limits (128 block / 32 deny) MUST raise ClientError and NEVER
    upload a silently truncated pack."""
    from datetime import UTC, datetime

    from anagram.core.errors import ClientError
    from anagram.local.api import TrustStore
    from anagram.local.trust.policy import make_policy

    ui = UI(world, "quinn")
    ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": world.pins.to_json()})
    ui.json("PUT", "/api/enclave/draft", lines("Cryo-EM screening", "Native mass spectrometry"))
    consent = ui.json("GET", "/api/enclave/consent")
    ui.json("POST", "/api/enclave/approve", {"statement_hash": consent["statement_hash"]})

    # 80 explicit blocked people + 60 TrustPolicy blocked people = 140 > 128 -> must refuse!
    explicit_people = [f"pid:{i:032x}" for i in range(80)]
    policy_people = [f"pid:{i + 1000:032x}" for i in range(60)]
    with ui.svc.session(index=True) as (c, idx):
        c.enclave.set_block(people=explicit_people)
        policy_doc = make_policy(
            owner=c.device.subject,
            rev=1,
            key=c.device.device_key(),
            updated_at=datetime.fromtimestamp(world.now(), UTC),
            deny={"people": policy_people},
        )
        TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()]).save(
            policy_doc
        )
        with pytest.raises(ClientError, match="128"):
            c.enclave.sync_trust_policy(
                TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()])
                .current()
                .subjects("deny")
            )

    # Turning matching on via API refuses with 400 and does NOT upload a truncated pack!
    err = ui.json("POST", "/api/enclave/on", {"on": True}, status=400)
    assert "128" in err["error"]
    with ui.svc.session() as c:
        subject = c.enclave.person_key().public_bytes().hex()
    assert subject not in world.hosts[0].instance.ledger.subjects

    # Same fail-closed check for combined deny list exceeding 32 entries.
    explicit_domains = [f"d{i}.example.org" for i in range(20)]
    policy_domains = [f"domain:p{i}.example.org" for i in range(20)]
    with ui.svc.session(index=True) as (c, idx):
        c.enclave.set_block(people=[])
        c.enclave.set_deny(domains=explicit_domains)
        policy_doc2 = make_policy(
            owner=c.device.subject,
            rev=2,
            key=c.device.device_key(),
            updated_at=datetime.fromtimestamp(world.now(), UTC),
            deny={"orgs": policy_domains},
        )
        TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()]).save(
            policy_doc2
        )
        with pytest.raises(ClientError, match="32"):
            c.enclave.sync_trust_policy(
                TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()])
                .current()
                .subjects("deny")
            )
    err_deny = ui.json("POST", "/api/enclave/on", {"on": True}, status=400)
    assert "32" in err_deny["error"]
    assert subject not in world.hosts[0].instance.ledger.subjects


def test_pack_controls_max_lines_deny_block_rules_and_trust_policy(world) -> None:
    """Part 2: MAX_LINES=10, deny, block, charter.rules, and TrustPolicy deny
    entries reach uploaded packs."""
    from datetime import UTC, datetime

    from anagram.local.api import TrustStore
    from anagram.local.trust.policy import make_policy
    from anagram.network.matching.app.enclave_matching import MAX_LINES, charter, pack_lines

    assert MAX_LINES == 10
    ten = {
        "offers": [
            {"class": "method", "match_types": ["T1"], "scope": "both", "text": f"Offer {i}"}
            for i in range(10)
        ],
        "wants": [
            {"class": "skill", "match_types": ["T2"], "scope": "both", "text": f"Want {i}"}
            for i in range(10)
        ],
    }
    packed = pack_lines(ten)
    assert len(packed["offers"]) == 10 and len(packed["wants"]) == 10
    ch = charter(packed, 3, {"research_fit": "inside", "method_help": "outside"})
    assert ch["rules"] == {"method_help": "outside", "research_fit": "inside"}

    ui = UI(world, "omar")
    ui.json("PUT", "/api/enclave/setup", {"log_url": LOG_URL, "pins": world.pins.to_json()})
    ui.json("PUT", "/api/enclave/draft", ten)
    blocked_pid = "pid:" + "ab" * 16
    denied_node = "node-" + "cd" * 16
    with ui.svc.session(index=True) as (c, idx):
        policy_doc = make_policy(
            owner=c.device.subject,
            rev=1,
            key=c.device.device_key(),
            updated_at=datetime.fromtimestamp(world.now(), UTC),
            deny={"orgs": ["domain:rival.example.org", "ror:012345678"], "people": [blocked_pid]},
        )
        TrustStore(idx.store, c.device.subject, [c.device.device_key().public_bytes()]).save(
            policy_doc
        )
        c.enclave.set_deny(nodes=[denied_node])
        c.enclave.set_block(hide=[{"from": blocked_pid, "line": "o01"}])
        c.enclave.set_rules({"research_fit": "inside", "method_help": "outside"})

    consent = ui.json("GET", "/api/enclave/consent")
    ui.json("POST", "/api/enclave/approve", {"statement_hash": consent["statement_hash"]})
    st = ui.json("POST", "/api/enclave/on", {"on": True})
    assert st["on"] is True
    world.at(world.now() + HOUR)
    with ui.svc.session() as c:
        subject = c.enclave.person_key().public_bytes().hex()
    pack = world.hosts[0].instance.ledger.subjects[subject].pack
    assert pack is not None
    assert len(pack["lines"]["offers"]) == 10 and len(pack["lines"]["wants"]) == 10
    assert pack["charter"]["rules"] == {"method_help": "outside", "research_fit": "inside"}
    assert pack["deny"] == {
        "domains": ["rival.example.org"],
        "nodes": [denied_node],
        "rors": ["012345678"],
    }
    assert pack["block"] == {
        "hide": [{"from": blocked_pid, "line": "o01"}],
        "people": [blocked_pid],
    }
