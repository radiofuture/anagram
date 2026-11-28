"""The local demo community (`anagram demo up`): matching only through the
demo enclave (simulated profile), reveals for the planted pairs, and a
clear stop on a demo folder that older code made."""

from __future__ import annotations

import json
import os

import pytest

from anagram.core.devclock import ENV
from anagram.shell.cli.main import build_parser
from anagram.sim import demo as demomod
from anagram.sim.demo import Demo


def test_demo_has_no_node_matching_options():
    """No match rounds on the node, so no round length and no pool size."""
    for flag in ("--round-seconds", "--min-pool", "--protocol"):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["demo", "up", flag, "3"])
    assert build_parser().parse_args(["demo", "up", "--day-seconds", "30"]).day_seconds == 30


@pytest.fixture(scope="module")
def ready_demo(tmp_path_factory):
    d = Demo(tmp_path_factory.mktemp("demo") / "demo", large_bytes=4096).start()
    try:
        assert d.ready_all() == []
        d.autopilot(d.people[0])  # the tester's steps too
        d.people[0].auto = True
        # The first checkpoint is 2 days after the first slot day (day 3).
        # A slot holds one item for each person and day, so a person with
        # more reveals gets them on later days, and the two reveals of a pair
        # can come on different days. A pair that a full queue or the weekly
        # cap holds waits for a later sweep. Run the days until no pair
        # waits or is open and every queue of the enclave is empty: then
        # each reveal is out to both people.
        days = [d.next_day() for _ in range(4)]
        ledger = d.network.host.instance.ledger

        def busy() -> bool:
            return bool(
                ledger.waiting
                or any(p.state == "open" for p in ledger.pairs.values())
                or any(s.queue for s in ledger.subjects.values())
            )

        while busy():
            assert len(days) < 24, "the enclave queues do not get empty"
            days.append(d.next_day())
        yield d, days
    finally:
        d.stop()
    assert ENV not in os.environ  # the demo puts the old value back


def test_demo_node_relays_to_the_enclave(ready_demo):
    from anagram.shell.node.home import NodeHome

    d, _ = ready_demo
    cfg = NodeHome(d.root / "node").config()
    assert "matching" not in cfg
    assert cfg["enclave"]["enabled"] and cfg["enclave"]["urls"] == [d.network.url["enclave"]]
    assert d.network.host.health()["role"] == "writer"


def test_people_set_up_and_on(ready_demo):
    d, _ = ready_demo
    for p in d.people:
        st = p.service.enclave.state()
        assert st["set_up"] and st["approved"] and st["on"], p.name
        assert st["draft"]["offers"] and st["draft"]["wants"], p.name


def test_lines_come_from_the_persons_files(ready_demo):
    """Each PI's draft is the offer and need bullets of the PI's own notes
    and slides, not the chips of the lab profile."""
    d, _ = ready_demo
    chen = d.person("chen")
    st = chen.service.enclave.state()
    offers, wants = demomod.draft_from_files(chen.own)
    assert [x["text"] for x in st["draft"]["offers"]] == offers
    assert [x["text"] for x in st["draft"]["wants"]] == wants
    assert "Binding-affinity prediction for pocket ligands" in wants  # the deck
    assert any("Krios time" in t for t in offers)  # the project plan
    labels = {x["label"] for x in chen.lab["profile"]["offers"]}
    assert not labels & set(offers)
    for p in d.people:
        assert not any(
            "Internal ref" in x["text"] for x in p.service.enclave.state()["draft"]["offers"]
        )


def test_planted_pairs_get_both_reveals(ready_demo):
    """The people's files state complementary offers and needs, so the
    planted pairs get a proposal, both say yes, and both get the reveal."""
    d, _ = ready_demo
    met = {}
    for p in d.people:
        cards = p.service.enclave.state()["cards"]
        assert any(c["kind"] == "proposal" for c in cards), p.name
        met[p.name] = {c["card_of_peer"]["name"] for c in cards if c["kind"] == "reveal"}
    assert "Chidi Okafor" in met["Mei-Lin Chen"] and "Mei-Lin Chen" in met["Chidi Okafor"]
    # Which other pairs meet depends on the weekly cap and the ranking; each
    # pair is both-or-neither once the queues are empty.
    assert sum(len(v) for v in met.values()) >= 4
    for name, peers in met.items():
        for peer in peers:
            assert name in met[peer], (name, peer)  # both or neither


def _old_folder(root):
    node = root / "node"
    node.mkdir(parents=True)
    # The node config of a demo that code before C48 made: matching on the node.
    (node / "node.json").write_text(json.dumps({"matching": {"allow_fake": True, "judge": "fake"}}))


def test_up_stops_with_one_sentence_on_an_old_folder(tmp_path, capsys, monkeypatch):
    root = tmp_path / "old"
    _old_folder(root)
    monkeypatch.setattr(demomod.subprocess, "Popen", lambda *a, **k: pytest.fail("started"))
    rc = demomod.up(root, everyone=False, ready=False, day_seconds=60)
    out = capsys.readouterr().out.strip()
    assert rc == 1
    assert out.count(".") >= 1 and "\n" not in out
    assert "older version" in out and "new folder" in out


def test_demo_start_refuses_an_old_folder(tmp_path):
    root = tmp_path / "old"
    _old_folder(root)
    with pytest.raises(RuntimeError, match="older version"):
        Demo(root, large_bytes=4096).start()


def test_a_folder_of_this_code_is_not_old(tmp_path):
    root = tmp_path / "new"
    node = root / "node"
    node.mkdir(parents=True)
    (node / "node.json").write_text(json.dumps({"enclave": {"enabled": True}}))
    assert not demomod.made_by_old_code(root)
    assert not demomod.made_by_old_code(tmp_path / "empty")


def test_ready_everyone_gives_each_member_a_lab_and_matching(tmp_path):
    """`demo up --everyone --ready`: the leaders go first and add their
    members, so each member has a lab and network matching on. The members
    of the tester's lab only join."""
    d = Demo(tmp_path / "demo", everyone=True, large_bytes=4096).start()
    try:
        assert d.ready_all() == []
        tester = d.people[0]
        members_on = 0
        for p in d.people[1:]:
            on = p.service.enclave.state()["on"]
            if p.lab["id"] == tester.lab["id"]:
                assert p.service.joined() and not on, p.name
                continue
            assert p.service.labs.mine() and on, p.name
            members_on += p.role != "pi"
        assert members_on >= 2
    finally:
        d.stop()
