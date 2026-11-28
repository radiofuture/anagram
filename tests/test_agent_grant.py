# ruff: noqa: F811 - the fixture `lib` from test_mcp
"""Agent grant v2 (primitive `agent-grant`): migration of the v1 record `mcp`,
tool scopes, end date, revoke, recipient class, the lab rule for cloud agents,
the trust policy at the gateway, no negotiation tool in v1, and no secret in
any output (secret fuzz)."""

from __future__ import annotations

import base64
import json
import random
import time

import pytest
from indexkit import KEY
from test_mcp import (
    LAB,
    NOW,
    OWNER,
    THEIRS,
    WORD,
    Peer,
    consent,
    lib,  # noqa: F401 - fixture
    serve,
)

from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.gateway import access
from anagram.gateway.server import EXPIRED, NOT_GRANTED, OFF, POLICY_FAULT
from anagram.gateway.tools import TOOLS
from anagram.local.trust.policy import PRIVATE, TrustPolicy, make_policy
from anagram.network.formats import labsettings
from anagram.network.groups.app.labrecords import LabPolicy
from anagram.shell.ui.agents import AgentsUI

pytestmark = pytest.mark.usefixtures("no_network")

ALL = list(access.TOOLS)
DAY = 86_400
T_NOW = 1_794_830_400.0  # 2026-11-16T12:00:00Z
DEVICE = SigningKey.from_seed(b"\x07" * 32)


# ----------------------------------------------------------------- record


def test_a_v1_record_becomes_grant_v2(lib):
    idx, _, session, _ = lib
    old = {
        "assistants": [
            {"added_at": NOW, "id": "0123456789abcdef", "name": "Claude Desktop",
             "spaces": ["private"], "last_used": None},
        ],
        "daily_chars": 1234,
    }  # fmt: skip
    idx.store.set_meta(access.V1_META, old)
    idx.store.set_meta(access.V1_USAGE, {"0123456789abcdef": {"chars": 5, "day": "2026-11-16"}})
    (g,) = access.grants(idx)
    assert g.id == "0123456789abcdef" and g.name == "Claude Desktop"
    assert g.tools == access.READ_TOOLS and g.recipient_class == access.CLOUD
    assert g.expires is None and g.revoked_at is None and g.daily_chars == 1234
    assert idx.store.get_meta(access.V1_META) is None  # the old key is gone
    assert idx.store.get_meta(access.V1_USAGE) is None
    assert access.used_today(idx, g.id, "2026-11-16") == 5
    # The command of the old setup text still works: the id stays.
    peer = Peer(serve(session, g.id))
    assert peer.data("search", query=WORD)["hits"]


def test_the_grant_rules_of_the_person(lib):
    idx, _, _, _ = lib
    with pytest.raises(access.AccessError):
        access.add(idx, "A", ["private"], NOW, recipient_class="server")
    with pytest.raises(access.AccessError):
        access.add(idx, "A", ["private"], NOW, tools=["read.everything"])
    with pytest.raises(access.AccessError):
        access.add(idx, "A", ["private"], NOW, expires="2026-11-16")  # not after today
    with pytest.raises(access.AccessError):
        access.add(idx, "A", ["private"], NOW, daily_chars=0)
    g = access.add(idx, "A", ["private"], NOW, tools=["act.lines_propose", "read.search"])
    assert g.tools == ("read.search", "act.lines_propose")  # the order of TOOLS
    assert g.recipient == "A and the company that runs it"
    local = access.add(idx, "B", ["private"], NOW, recipient_class="local")
    assert local.recipient == "B on this computer"


# --------------------------------------------------------- state at a call


def test_an_expired_grant_gives_no_text(lib):
    idx, _, session, _ = lib
    who = consent(idx, expires="2026-11-18")
    before = Peer(serve(session, who.id, clock=lambda: T_NOW + DAY))  # 11-17
    assert before.data("search", query=WORD)["hits"]
    after = Peer(serve(session, who.id, clock=lambda: T_NOW + 2 * DAY))  # 11-18
    assert after.call("search", query=WORD) == (EXPIRED, True)
    access.change(idx, who.id, expires="2027-01-01", today=after.server._now().date())
    assert after.data("search", query=WORD)["hits"]


def test_a_revoked_grant_keeps_its_row(lib):
    idx, _, session, _ = lib
    who = consent(idx)
    peer = Peer(serve(session, who.id))
    assert peer.data("search", query=WORD)["hits"]
    access.revoke(idx, who.id, NOW)
    assert peer.call("search", query=WORD) == (OFF, True)
    row = access.find(idx, who.id)
    assert row.revoked_at == NOW and row.name == "Claude Desktop"
    with pytest.raises(KeyError):
        access.revoke(idx, who.id, NOW)
    with pytest.raises(KeyError):
        access.change(idx, who.id, spaces=["private"])
    again = consent(idx)  # the name is free again; a new id
    assert again.id != who.id and len(access.grants(idx)) == 2
    for n in range(access.MAX_ACTIVE - 1):
        access.add(idx, f"Agent {n}", ["private"], NOW)
    with pytest.raises(access.AccessError):
        access.add(idx, "One more", ["private"], NOW)


def test_a_tool_that_is_not_in_the_grant_is_refused(lib):
    idx, _, session, _ = lib
    who = consent(idx, tools=["read.search"])
    peer = Peer(serve(session, who.id))
    names = [t["name"] for t in peer.request("tools/list")["result"]["tools"]]
    assert names == ["search"]
    assert peer.data("search", query=WORD)["hits"]
    for tool, args in (
        ("ask", {"question": WORD}),
        ("timeline", {}),
        ("read_item", {"ref": "item:1"}),
    ):
        assert peer.call(tool, **args) == (NOT_GRANTED, True)
    assert peer.call("propose_lines", offers=["x"], wants=["y"]) == (NOT_GRANTED, True)
    assert idx.store.get_meta("agent_pending") is None


def test_an_unknown_argument_is_refused(lib):
    idx, _, session, _ = lib
    peer = Peer(serve(session, consent(idx).id))
    text, error = peer.call("search", query=WORD, approve=True)
    assert error and "approve" in text and "\n" not in text
    assert idx.disclosures() == []


# ------------------------------------------------------------- lab and class


def test_a_lab_needs_to_permit_cloud_agents(lib):
    idx, client, session, _ = lib
    client.lab_context.allow_assistant = True
    cloud = consent(idx, ("private", LAB))
    local = access.add(idx, "Lab bot", ["private", LAB], NOW, recipient_class="local")

    def spaces(who):
        hits = Peer(serve(session, who.id)).data("search", query=WORD)["hits"]
        return {h["space"] for h in hits}

    assert spaces(cloud) == {"private"}
    assert spaces(local) == {"private", "Chen Lab"}
    client.lab_context.allow_cloud = True
    assert spaces(cloud) == {"private", "Chen Lab"}
    rows = idx.disclosures()
    assert {r["recipient"] for r in rows} == {
        "Claude Desktop and the company that runs it",
        "Lab bot on this computer",
    }
    # The lab settings format: an optional bool; cloud needs `allow_assistant` too.
    labsettings.validate_section("disclosure", {"allow_cloud_assistant": True})
    with pytest.raises(FormatError):
        labsettings.validate_section("disclosure", {"allow_cloud_assistant": "yes"})
    base = labsettings.section_defaults()
    pol = LabPolicy("lab-" + "0" * 16, **{**base, "disclosure": {"allow_cloud_assistant": True}})
    assert not pol.allows_cloud_assistant()  # no `allow_assistant`
    assert "allow_cloud_assistant" not in base["disclosure"]  # the vectors stay


# -------------------------------------------------------------- trust policy


def _signed(idx, **marks) -> TrustPolicy:
    doc = make_policy(owner=OWNER, rev=1, key=DEVICE, updated_at=_dt(), **marks)
    return TrustPolicy.from_doc(doc)


def _dt():
    from datetime import UTC, datetime

    return datetime(2026, 11, 16, tzinfo=UTC)


def _every_read(peer: Peer, refs: list[str]) -> str:
    out = [peer.call("search", query=WORD, k=20)[0], peer.call("ask", question=WORD)[0]]
    out += [peer.call("read_item", ref=r)[0] for r in refs]
    out.append(peer.call("timeline", since="2000-01-01", until="2100-01-01")[0])
    return "\n".join(out)


def test_grant_cannot_read_past_tier(lib, tmp_path):
    """A `private` item of the trust policy never goes to an agent, through
    any read tool. 200 random policies."""
    idx, client, session, (a, b, c) = lib
    client.lab_context.allow_assistant = client.lab_context.allow_cloud = True
    extra = tmp_path / "mine" / "more.md"
    extra.write_text(f"# More\n\nA second {WORD} note on the bench.\n")
    idx.scan()
    who = consent(idx, ("private", LAB))
    items = idx.store.q("SELECT id, source_id, key, name FROM item WHERE name LIKE '%.md'")
    refs = [f"item:{r['id']}" for r in items]
    titles = {"gel.md": "Gel run", "more.md": "More", "lab.md": "Lab note"}
    rng = random.Random(6)  # noqa: S311 - test data
    leaks = checked = 0
    for _ in range(200):
        marks: dict[str, dict[str, str]] = {}
        sources: dict[str, str] = {}
        if rng.random() < 0.2:
            sources[rng.choice([a, b])] = PRIVATE
        for r in items:
            if r["source_id"] != c and rng.random() < 0.4:
                marks.setdefault(r["source_id"], {})[r["key"]] = rng.choice(
                    ["private", "discoverable", "shared"]
                )
        policy = _signed(idx, sources=sources, items=marks)
        peer = Peer(serve(session, who.id, policy=lambda cl, ix, p=policy: p))
        text = _every_read(peer, refs)
        for r in items:
            if r["name"] not in titles:
                continue
            tier = policy.item_tier(r["source_id"], r["key"], third_party=False)
            if tier == PRIVATE:
                checked += 1
                leaks += titles[r["name"]] in text or f'"item:{r["id"]}"' in text
    assert checked > 50 and leaks == 0, (checked, leaks)


def test_a_policy_that_does_not_load_gives_no_text(lib):
    idx, _, session, _ = lib
    who = consent(idx, tools=ALL)

    def broken(client, index):
        raise FormatError("trust policy: bad signature")

    peer = Peer(serve(session, who.id, policy=broken))
    for tool, args in (
        ("search", {"query": WORD}),
        ("ask", {"question": WORD}),
        ("read_item", {"ref": "item:1"}),
        ("timeline", {}),
        ("propose_lines", {"offers": ["x"], "wants": ["y"]}),
    ):
        assert peer.call(tool, **args) == (POLICY_FAULT, True)
    assert idx.disclosures() == []


# ------------------------------------------- no negotiation in v1


NEGOTIATE_NAMES = (
    "act.ask", "act.table_reply", "act.intro_propose", "act.room_card",
    "ask", "table_reply", "ask_peer", "intro_propose", "propose_intro", "room_card",
    "show_line", "answer", "pass",
)  # fmt: skip


def test_an_outside_agent_cannot_negotiate_in_v1(lib):
    """1,000 sim attempts of an outside agent with every
    grant tool; each negotiation call is refused."""
    idx, _, session, _ = lib
    for scope in access.NEGOTIATION:
        with pytest.raises(access.AccessError):
            access.add(idx, "N", ["private"], NOW, tools=[*ALL, scope])
    who = consent(idx, tools=ALL)
    with pytest.raises(access.AccessError):
        access.change(idx, who.id, tools=[*ALL, "act.table_reply"])
    assert not {t.scope for t in TOOLS.values()} & set(access.NEGOTIATION)
    assert all(t.scope in access.TOOLS for t in TOOLS.values())
    peer = Peer(serve(session, who.id))
    rng = random.Random(15)  # noqa: S311 - test data
    refused = 0
    for _ in range(1000):
        name = rng.choice([n for n in NEGOTIATE_NAMES if n not in TOOLS])
        args = {"peer": rng.randbytes(8).hex(), "line": rng.randrange(99), "answer": "yes"}
        text, error = peer.call(name, **args)
        refused += error and text.startswith("Anagram has no tool named")
    assert refused == 1000
    # `ask` is the read tool of the library (passages), not a peer question.
    assert TOOLS["ask"].scope == "read.ask"


# ------------------------------------------------------------ secret fuzz


def _junk(rng: random.Random, depth: int = 0):
    pick = rng.randrange(8 if depth < 2 else 5)
    if pick == 0:
        return rng.choice(["", WORD, THEIRS, "item:1", "item:999", "../x", "all", "Chen Lab"])
    if pick == 1:
        return rng.randrange(-5, 200)
    if pick == 2:
        return None
    if pick == 3:
        return rng.choice([True, False, 1.5])
    if pick == 4:
        return "".join(chr(rng.randrange(32, 0x2FF)) for _ in range(rng.randrange(1, 40)))
    if pick == 5:
        return [_junk(rng, depth + 1) for _ in range(rng.randrange(0, 6))]
    if pick == 6:
        return {str(_junk(rng, 2)): _junk(rng, depth + 1) for _ in range(rng.randrange(0, 3))}
    return rng.choice(["2026-11-01", "2000-01-01", "yesterday", "kinds"])


def test_no_secret_byte_leaves_through_any_tool(lib):
    """Each tool, 1,000 random argument sets; no output holds
    a secret of the node (the index key in hex and base64, the loopback key
    of the grant, its hash, a planted keystore value)."""
    idx, _, session, _ = lib
    who = consent(idx, tools=ALL)
    http_key = access.new_http_key(idx, who.id)
    planted = "seed-" + "5a" * 16
    idx.store.set_meta("agent_root_test", planted)  # a secret in the same store
    secrets_ = [
        KEY.hex(),
        base64.b64encode(KEY).decode(),
        base64.urlsafe_b64encode(KEY).decode().rstrip("="),
        http_key,
        access.find(idx, who.id).http,
        planted,
    ]
    peer = Peer(serve(session, who.id))
    rng = random.Random(1806)  # noqa: S311 - test data
    calls = 0
    started = time.perf_counter()
    for name, tool in TOOLS.items():
        props = list(tool.schema["properties"])
        for _ in range(1000):
            args = {p: _junk(rng) for p in props if rng.random() < 0.7}
            if rng.random() < 0.1:
                args[str(_junk(rng, 2))] = _junk(rng)
            text, _ = peer.call(name, **args)
            calls += 1
            for s in secrets_:
                assert s not in text, (name, args)
    for msg in ("tools/list", "initialize"):
        assert not any(s in json.dumps(peer.request(msg)) for s in secrets_)
    assert calls == 1000 * len(TOOLS)
    print(f"secret fuzz: {calls} calls, {time.perf_counter() - started:.1f} s, 0 secret bytes")


# ----------------------------------------------------- what each agent read


def test_what_each_agent_read(lib):
    idx, _, session, (a, _, _) = lib
    first = consent(idx)
    second = access.add(idx, "Local helper", ["private"], NOW, recipient_class="local")
    Peer(serve(session, first.id)).data("search", query=WORD)
    Peer(serve(session, second.id)).data("ask", question=WORD)
    Peer(serve(session, second.id)).data("search", query="buffer")
    reads = AgentsUI._reads(idx)
    assert set(reads) == {first.id, second.id}
    assert [r["what"] for r in reads[first.id]] == ["search results"]
    assert [r["what"] for r in reads[second.id]] == ["search results", "passages for an answer"]
    assert all("source_id" not in r for rows in reads.values() for r in rows)
    access.revoke(idx, first.id, NOW)
    assert first.id in AgentsUI._reads(idx)  # the log keeps a revoked grant
