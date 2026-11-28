"""Assistant access (R4 step 16): the MCP server on stdio and the consent
routes. The client of the protocol is in this process; no network.

Checks: off by default; one consent for each assistant; no write tool; only
the open spaces (a lab needs the lab to allow assistants); no text of other
people; no source that the person closed; the daily limit; one disclosure row
for each source that a result read."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import contextmanager

import pytest
from indexkit import KEY
from test_ui_models_api import ORIGIN, UI

from anagram.gateway import access
from anagram.gateway.server import HEADER, LIMIT, NO_PLACE, OFF, Server
from anagram.gateway.tools import TOOLS
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.local.sources import source_state as ss
from anagram.local.trust.policy import TrustPolicy
from anagram.network.groups.app.labrecords import LabPolicy
from anagram.shell.cli import mcp as cli
from anagram.sim.writers import eml_bytes

pytestmark = pytest.mark.usefixtures("no_network")

LAB_ID = "lab-0123456789abcdef"
LAB = f"lab:{LAB_ID}"
WORD = "zymoquartz"
THEIRS = "quillionate"  # only another person wrote this word
ME = "mira@example.org"
NOW = "2026-11-16T10:00:00Z"
OWNER = "pid:" + "aa" * 16


def default_policy(client, index) -> TrustPolicy:
    """The trust policy port: the default policy (own items discoverable)."""
    return TrustPolicy.default(OWNER)


def serve(session, grant_id: str, **kw) -> Server:
    return Server(session, grant_id, policy=kw.pop("policy", default_policy), **kw)


class FakeLabs:
    """The lab context of `Client` that the server reads
    (`Client.lab_context`, port `LabContext`)."""

    def __init__(self) -> None:
        self.readable = [LAB_ID]
        self.allow_assistant = False
        self.allow_cloud = False

    def readable_labs(self) -> list[str]:
        return list(self.readable)

    def lab_list(self) -> list[dict]:
        return [{"lab_id": LAB_ID, "name": "Chen Lab"}]

    def lab_policy(self, lab_id: str) -> LabPolicy:
        return LabPolicy(
            lab_id=lab_id,
            models={},
            disclosure={
                "allow_assistant": self.allow_assistant,
                "allow_cloud_assistant": self.allow_cloud,
            },
            oauth_clients={},
            sources={},
            matching={},
        )


class FakeClient:
    def __init__(self) -> None:
        self.lab_context = FakeLabs()


def _write(folder, name: str, text: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


@pytest.fixture
def lib(tmp_path):
    mine, shared, closed = tmp_path / "mine", tmp_path / "shared", tmp_path / "closed"
    _write(mine, "gel.md", f"# Gel run\n\nThe {WORD} buffer moved the band by 12 kDa.\n")
    _write(shared, "lab.md", f"# Lab note\n\nThe lab {WORD} stock is in freezer B.\n")
    _write(closed, "diary.md", f"# Diary\n\nA private {WORD} thought.\n")
    (mine / "mail.eml").write_bytes(
        eml_bytes(
            sender=("Tomas", "tomas@example.org"),
            to=("Mira", ME),
            subject="Stock",
            date="Mon, 02 Nov 2026 10:00:00 +0000",
            message_id="<m1@example.org>",
            body=f"I used all the {WORD} and the {THEIRS} from the shelf.\n",
        )
    )
    idx = LocalIndex(tmp_path / "index.sqlite", KEY, owner_emails=[ME])
    a = idx.add_source(FolderConnector(mine))
    b = idx.add_source(FolderConnector(shared))
    c = idx.add_source(FolderConnector(closed))
    idx.scan()
    ss.set_space(idx.store, b, LAB, now=1.0)
    idx.set_source_prefs(c, assistant=False)
    client = FakeClient()

    @contextmanager
    def session():
        yield client, idx

    yield idx, client, session, (a, b, c)
    idx.close()


class Peer:
    """The assistant side of the protocol, in this process."""

    def __init__(self, server: Server) -> None:
        self.server = server
        self.n = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self.n += 1
        msg = {"id": self.n, "jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        answer = self.server.handle(msg)
        assert answer["id"] == self.n
        return answer

    def call(self, tool: str, **args) -> tuple[str, bool]:
        got = self.request("tools/call", {"arguments": args, "name": tool})["result"]
        assert [c["type"] for c in got["content"]] == ["text"]
        return got["content"][0]["text"], got["isError"]

    def data(self, tool: str, **args) -> dict:
        text, error = self.call(tool, **args)
        assert not error, text
        head, _, body = text.partition("\n")
        assert head == HEADER
        return json.loads(body)


def consent(idx, spaces=("private",), **kw) -> access.Grant:
    return access.add(idx, "Claude Desktop", list(spaces), NOW, **kw)


# ---------------------------------------------------------------- protocol


def test_the_handshake_and_the_tool_list(lib):
    _, _, session, _ = lib
    peer = Peer(serve(session, "0" * 16))
    init = peer.request("initialize", {"protocolVersion": "2025-03-26", "clientInfo": {}})
    assert init["result"]["protocolVersion"] == "2025-03-26"
    assert init["result"]["capabilities"] == {"tools": {"listChanged": False}}
    other = peer.request("initialize", {"protocolVersion": "1999-01-01"})
    assert other["result"]["protocolVersion"] == "2025-06-18"
    assert peer.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert peer.request("ping")["result"] == {}
    tools = peer.request("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["search", "ask", "read_item", "timeline"]
    # No tool sends, shares, stamps, or changes anything.
    assert all(t["annotations"]["readOnlyHint"] for t in tools)
    assert all(not t["annotations"]["destructiveHint"] for t in tools)
    assert peer.request("resources/list")["error"]["code"] == -32601


def test_serve_reads_and_writes_lines(lib):
    _, _, session, _ = lib
    reader = io.StringIO(
        "not json\n\n"
        + json.dumps({"id": 1, "jsonrpc": "2.0", "method": "ping"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        + "\n"
    )
    writer = io.StringIO()
    serve(session, "0" * 16).serve(reader, writer)
    lines = [json.loads(x) for x in writer.getvalue().splitlines()]
    assert [x.get("error", {}).get("code") for x in lines] == [-32700, None]
    assert lines[1] == {"id": 1, "jsonrpc": "2.0", "result": {}}


# ----------------------------------------------------------------- consent


def test_off_by_default_and_after_removal(lib):
    idx, _, session, _ = lib
    peer = Peer(serve(session, "0" * 16))
    for tool in TOOLS:
        text, error = peer.call(tool, query=WORD, question=WORD, ref="item:1")
        assert error and text == OFF
    who = consent(idx)
    peer = Peer(serve(session, who.id))
    assert peer.data("search", query=WORD)["hits"]
    access.revoke(idx, who.id, NOW)
    assert peer.call("search", query=WORD) == (OFF, True)
    assert idx.disclosures()[-1]["adapter"] == f"agent:{who.id}"


def test_each_assistant_has_its_own_consent(lib):
    idx, _, session, _ = lib
    first = consent(idx)
    second = access.add(idx, "Another assistant", ["private"], NOW)
    assert first.id != second.id
    with pytest.raises(access.AccessError):
        access.add(idx, "claude desktop", ["private"], NOW)
    access.revoke(idx, first.id, NOW)
    assert Peer(serve(session, first.id)).call("search", query=WORD)[0] == OFF
    assert Peer(serve(session, second.id)).data("search", query=WORD)["hits"]


# ------------------------------------------------------------------- scope


def test_search_gives_own_text_of_open_places_only(lib):
    idx, _, session, (a, b, c) = lib
    who = consent(idx, ("private", LAB))
    peer = Peer(serve(session, who.id))
    hits = peer.data("search", query=WORD)["hits"]
    assert hits and {h["space"] for h in hits} == {"private"}  # the lab does not allow it
    assert all(WORD in h["text"] for h in hits)
    assert all(THEIRS not in h["text"] for h in hits)  # no text of other people
    assert all("Diary" not in (h["title"] or "") for h in hits)  # a closed source
    assert peer.data("search", query=THEIRS)["hits"] == []
    rows = idx.disclosures()
    assert {r["source_id"] for r in rows} == {a}
    assert rows[0]["recipient"] == "Claude Desktop and the company that runs it"
    assert rows[0]["what"] == "search results"


def test_a_lab_space_needs_the_lab_and_the_device(lib):
    idx, client, session, _ = lib
    who = consent(idx, ("private", LAB))
    peer = Peer(serve(session, who.id))
    client.lab_context.allow_assistant = True
    # A cloud agent (the default class) also needs the lab to allow cloud agents.
    assert {h["space"] for h in peer.data("search", query=WORD)["hits"]} == {"private"}
    client.lab_context.allow_cloud = True
    spaces = {h["space"] for h in peer.data("search", query=WORD)["hits"]}
    assert spaces == {"private", "Chen Lab"}
    assert {h["space"] for h in peer.data("search", query=WORD, space="Chen Lab")["hits"]} == {
        "Chen Lab"
    }
    client.lab_context.readable = []  # this device cannot read the lab now
    assert {h["space"] for h in peer.data("search", query=WORD)["hits"]} == {"private"}
    text, error = peer.call("search", query=WORD, space="Chen Lab")
    assert error and "not open" in text
    lab_only = access.add(idx, "Lab bot", [LAB], NOW)
    assert Peer(serve(session, lab_only.id)).call("search", query=WORD) == (NO_PLACE, True)


def test_ask_gives_numbered_passages_and_no_answer(lib):
    idx, _, session, _ = lib
    who = consent(idx)
    got = Peer(serve(session, who.id)).data("ask", question=f"Where is the {WORD}?")
    assert [s["n"] for s in got["sources"]] == list(range(1, len(got["sources"]) + 1))
    assert got["sources"] and "how" in got and "answer" not in got
    assert all(THEIRS not in s["text"] for s in got["sources"])
    assert idx.disclosures()[-1]["what"] == "passages for an answer"


def test_read_item_reads_one_open_item(lib):
    idx, _, session, _ = lib
    who = consent(idx)
    peer = Peer(serve(session, who.id))
    ref = peer.data("search", query="buffer")["hits"][0]["ref"]
    item = peer.data("read_item", ref=ref)
    assert item["ref"] == ref and WORD in item["text"] and len(item["text"]) <= 4000
    assert item["anchors"] and "source_id" not in item
    anchor = item["anchors"][0]
    assert peer.data("read_item", ref=ref, anchor=anchor)["anchors"] == [anchor]
    assert peer.call("read_item", ref=ref, anchor="nope")[1]
    ids = {r["name"]: r["id"] for r in idx.store.q("SELECT id, name FROM item")}
    for name in ("lab.md", "diary.md"):  # the lab is not open; the source is closed
        text, error = peer.call("read_item", ref=f"item:{ids[name]}")
        assert error and "not open" in text
    # A received mail is the text of another person: refused (security review P0-1).
    text, error = peer.call("read_item", ref=f"item:{ids['mail.eml']}")
    assert error and "not open" in text and THEIRS not in text
    assert peer.call("read_item", ref="/etc/passwd")[1]


def test_timeline_has_no_closed_source_and_no_summary(lib):
    idx, _, session, _ = lib
    who = consent(idx)
    got = Peer(serve(session, who.id)).data("timeline", since="2000-01-01", until="2100-01-01")
    assert got["weeks"]
    for week in got["weeks"]:
        assert "summary" not in week and week["space"] == "private"
    titles = json.dumps(got)
    assert "Diary" not in titles and "Lab note" not in titles


def test_bad_inputs_give_one_sentence(lib):
    idx, _, session, _ = lib
    peer = Peer(serve(session, consent(idx).id))
    for tool, args in (
        ("search", {}),
        ("search", {"query": WORD, "k": 500}),
        ("search", {"query": WORD, "kinds": ["poem"]}),
        ("search", {"query": WORD, "since": "yesterday"}),
        ("timeline", {"since": "2026-12-01", "until": "2026-11-01"}),
        ("nothing", {}),
    ):
        text, error = peer.call(tool, **args)
        assert error and "\n" not in text, (tool, args)
    assert idx.disclosures() == []


def test_the_daily_limit_stops_bulk_reads(lib):
    idx, _, session, _ = lib
    who = consent(idx)
    access.change(idx, who.id, daily_chars=1500)
    peer = Peer(serve(session, who.id, clock=lambda: 1_794_000_000.0))
    first, error = peer.call("search", query=WORD, k=1)
    assert not error
    used = access.used_today(idx, who.id, "2026-11-06")
    assert used == len(first)
    while True:
        text, error = peer.call("search", query=WORD, k=1)
        if error:
            break
    assert text == LIMIT
    assert access.used_today(idx, who.id, "2026-11-06") <= 1500
    assert access.find(idx, who.id).last_used == "2026-11-06T21:20:00Z"
    tomorrow = Peer(serve(session, who.id, clock=lambda: 1_794_000_000.0 + 86_400))
    assert not tomorrow.call("search", query=WORD, k=1)[1]


# --------------------------------------------------------------------- cli


def test_the_command_and_the_setup_text(tmp_path):
    got = cli.setup_json(tmp_path, "0123456789abcdef")
    entry = got["mcpServers"]["anagram"]
    assert entry["args"][:2] == ["-m", "anagram"]
    assert entry["args"][-3:] == ["mcp", "--assistant", "0123456789abcdef"]
    from anagram.shell.cli.main import main

    assert main(["--home", str(tmp_path), "mcp", "--assistant", "../x"]) == 2


def test_the_setup_text_of_the_packaged_app_runs_the_app_program(tmp_path, monkeypatch):
    """In the frozen app, `sys.executable` is the app program and takes the
    `anagram` arguments with no `-m` (packaging/entry.py)."""
    import importlib.util
    from pathlib import Path

    from anagram.shell.cli.main import build_parser

    program = str(tmp_path / "Anagram.app" / "Contents" / "MacOS" / "Anagram")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", program)
    entry = cli.setup_json(tmp_path / "x" / "..", "0123456789abcdef")["mcpServers"]["anagram"]
    assert entry["command"] == program
    assert "-m" not in entry["args"] and "uv" not in entry["args"]
    assert entry["args"][:2] == ["--home", str(tmp_path.resolve())]

    path = Path(__file__).resolve().parents[1] / "packaging" / "entry.py"
    spec = importlib.util.spec_from_file_location("anagram_packaging_entry", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args = build_parser().parse_args(module.arguments(entry["args"]))
    assert args.func is cli.cmd_mcp and args.assistant == "0123456789abcdef"


# ------------------------------------------------------------------ routes


ROUTES = (
    ("GET", "/api/assistant"),
    ("POST", "/api/assistant"),
    ("PUT", "/api/assistant/0123456789abcdef"),
    ("DELETE", "/api/assistant/0123456789abcdef"),
)


def test_assistant_routes_obey_the_local_ui_boundary(tmp_path):
    ui = UI(tmp_path)
    for method, path in ROUTES:
        assert ui.tc.request(method, path, json={}, headers=ORIGIN).status_code == 401, path
    ui.launch()
    for method, path in ROUTES:
        evil = ui.tc.request(method, path, json={}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403, path


def test_the_person_adds_changes_and_removes_an_assistant(tmp_path):
    ui = UI(tmp_path).launch()
    view = ui.call("GET", "/api/assistant")
    assert view["assistants"] == [] and view["daily_chars"] == access.DAILY_CHARS
    assert view["spaces"] == [
        {"allowed": True, "allowed_cloud": True, "id": "private", "label": None}
    ]
    got = ui.call("POST", "/api/assistant", {"name": " Claude  Desktop ", "spaces": ["private"]})
    row = got["assistants"][0]
    assert row["name"] == "Claude Desktop" and row["id"] == got["added"]
    setup = json.loads(row["setup"])["mcpServers"]["anagram"]
    assert setup["args"][-1] == row["id"] and str(ui.home) in setup["args"]
    assert ("assistant.changed", {}) in ui.bus.seen
    assert ui.call("POST", "/api/assistant", {"name": "X", "spaces": [LAB]}, status=400)["error"]
    assert ui.call("POST", "/api/assistant", {"name": "", "spaces": ["private"]}, status=400)
    assert ui.call("POST", "/api/assistant", {"name": "Y", "spaces": []}, status=400)
    assert ui.call("PUT", f"/api/assistant/{row['id']}", {"spaces": ["private"]})["added"] is None
    assert ui.call("PUT", "/api/assistant/ffffffffffffffff", {"spaces": ["private"]}, status=404)
    stopped = ui.call("DELETE", f"/api/assistant/{row['id']}")
    assert stopped["assistants"] == [] and stopped["past"][0]["state"] == "revoked"
    assert ui.call("DELETE", f"/api/assistant/{row['id']}", status=404)["error"]


def test_the_command_serves_a_real_home_in_a_second_process(tmp_path):
    """`anagram mcp` opens the client and the index of the home while the UI
    has them open too, and answers on stdio."""
    from test_ui_items_api import FILES, fill

    ui = UI(tmp_path).launch()
    fill(ui, tmp_path, FILES)
    got = ui.call("POST", "/api/assistant", {"name": "Claude Desktop", "spaces": ["private"]})
    entry = json.loads(got["assistants"][0]["setup"])["mcpServers"]["anagram"]
    assert entry["command"] == sys.executable
    search = {"arguments": {"query": "NbT7"}, "name": "search"}
    lines = [
        {"id": 1, "jsonrpc": "2.0", "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"id": 2, "jsonrpc": "2.0", "method": "tools/call", "params": search},
    ]
    env = {**os.environ, "ANAGRAM_KEYSTORE": "file", "HF_HUB_OFFLINE": "1"}
    out = subprocess.run(  # noqa: S603 - the command of the setup text
        [entry["command"], *entry["args"]],
        input="".join(json.dumps(x) + "\n" for x in lines),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    answers = [json.loads(x) for x in out.stdout.splitlines()]
    assert [a["id"] for a in answers] == [1, 2]
    result = answers[1]["result"]
    assert not result["isError"], result
    assert "Band shift of NbT7" in result["content"][0]["text"]


def test_read_item_refuses_removing_source(lib):
    from anagram.local.sources import source_state as ss

    idx, _, session, (a, _, _) = lib
    who = consent(idx)
    peer = Peer(serve(session, who.id))
    ref = peer.data("search", query="buffer")["hits"][0]["ref"]
    assert not peer.call("read_item", ref=ref)[1]
    ss.set_status(idx.store, a, ss.REMOVING, now=2.0)
    text, error = peer.call("read_item", ref=ref)
    assert error and "not open" in text
