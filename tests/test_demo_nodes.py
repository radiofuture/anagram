"""The local demo with several nodes (`anagram demo up --nodes 2|3`): each
lab on one node, the roster admits every node, all nodes relay to the one
demo enclave, and people of different nodes get a match and a reveal."""

from __future__ import annotations

import json
import os

import pytest

from anagram.core.devclock import ENV
from anagram.shell.cli.main import build_parser
from anagram.sim import demo as demomod
from anagram.sim.demo import Demo
from anagram.sim.demonet import node_record, record_url


@pytest.fixture(scope="module")
def two_nodes(tmp_path_factory):
    """`demo up --nodes 2 --ready`, and the tester's steps too: Chen is on
    node 1 and Okafor on node 2."""
    d = Demo(tmp_path_factory.mktemp("demo2") / "demo", large_bytes=4096, node_count=2).start()
    try:
        assert d.ready_all() == []
        d.autopilot(d.people[0])
        d.people[0].auto = True
        chen, okafor = d.person("chen"), d.person("okafor")
        for _ in range(8):
            d.next_day()
            if _peer_names(chen) and _peer_names(okafor):
                break
        yield d
    finally:
        d.stop()
    assert ENV not in os.environ


def _reveals(person) -> list[dict]:
    return [c for c in person.service.enclave.state()["cards"] if c["kind"] == "reveal"]


def _peer_names(person) -> set[str]:
    return {c["card_of_peer"]["name"] for c in _reveals(person)}


def _admitted(d: Demo) -> set[str]:
    return {
        e["body"]["node"]["id"]
        for e in d.network.roster.store.events()
        if e["kind"] == "node_admitted"
    }


def _ids(d: Demo) -> set[str]:
    return {
        node_record(x.home.enclave_config(), x.home.network_key(), record_url(x.n))["id"]
        for x in d.nodes
    }


def test_two_nodes_each_admitted_and_relaying(two_nodes):
    d = two_nodes
    assert [x.n for x in d.nodes] == [1, 2] and len({x.url for x in d.nodes}) == 2
    assert (d.root / "node").is_dir() and (d.root / "node-2").is_dir()
    assert _admitted(d) == _ids(d) and len(_ids(d)) == 2
    assert len(d.network.relays) == 2
    nodes = {p.lab["slug"]: p.node for p in d.people}
    assert nodes == {"chen": 1, "okafor": 2, "varga": 1, "helix": 2}
    # Each person joined the node of the lab.
    for p in d.people:
        with p.service.session() as c:
            assert c.config["node"]["url"] == d.nodes[p.node - 1].url, p.name


def test_a_cross_node_pair_gets_both_reveals(two_nodes):
    """Chen (node 1) and Okafor (node 2): one enclave matches the lines from
    their files, both say yes, and each reveal names the other's node."""
    d = two_nodes
    chen, okafor = d.person("chen"), d.person("okafor")
    for p in (chen, okafor):
        offers, wants = demomod.draft_from_files(p.own)
        draft = p.service.enclave.state()["draft"]
        assert [x["text"] for x in draft["offers"]] == offers, p.name
        assert [x["text"] for x in draft["wants"]] == wants, p.name
    assert "Chidi Okafor" in _peer_names(chen) and "Mei-Lin Chen" in _peer_names(okafor)
    to_okafor = next(c for c in _reveals(chen) if c["card_of_peer"]["name"] == "Chidi Okafor")
    to_chen = next(c for c in _reveals(okafor) if c["card_of_peer"]["name"] == "Mei-Lin Chen")
    assert to_okafor["node"]["affiliation"] == "Anagram demo node 2"
    assert to_chen["node"]["affiliation"] == "Anagram demo node"


def test_the_summary_names_each_node_and_the_day_command(two_nodes):
    d = two_nodes
    doc = json.loads((d.root / demomod.DEMO_FILE).read_text())
    text = "\n".join(demomod.summary(doc, d.root))
    for x in d.nodes:
        assert f"Node {x.n}: {x.url}" in text
    assert f"Chidi Okafor (Okafor Lab, node 2): {d.person('okafor').url}" in text
    assert f"anagram demo day --dir {d.root}" in text


def test_three_nodes_start_and_are_admitted(tmp_path):
    d = Demo(tmp_path / "demo", large_bytes=4096, node_count=3).start()
    try:
        assert [x.n for x in d.nodes] == [1, 2, 3]
        assert _admitted(d) == _ids(d) and len(_ids(d)) == 3
        nodes = {p.lab["slug"]: p.node for p in d.people}
        assert nodes == {"chen": 1, "okafor": 2, "varga": 3, "helix": 1}
        assert json.loads((d.root / demomod.NODES_FILE).read_text()) == {"nodes": 3}
    finally:
        d.stop()


def test_a_folder_keeps_its_number_of_nodes(tmp_path, capsys, monkeypatch):
    root = tmp_path / "demo"
    root.mkdir()
    (root / demomod.NODES_FILE).write_text('{"nodes": 2}\n')
    with pytest.raises(RuntimeError, match="--nodes 2"):
        Demo(root, large_bytes=4096).start()
    monkeypatch.setattr(demomod.subprocess, "Popen", lambda *a, **k: pytest.fail("started"))
    assert demomod.up(root, everyone=False, ready=False, day_seconds=60, nodes=3) == 1
    assert "--nodes 2" in capsys.readouterr().out
    assert demomod.folder_nodes(tmp_path / "new") is None
    (tmp_path / "one" / "node").mkdir(parents=True)
    assert demomod.folder_nodes(tmp_path / "one") == 1  # a one-node folder of older code


def test_demo_up_parses_nodes_and_day():
    assert build_parser().parse_args(["demo", "up", "--nodes", "3"]).nodes == 3
    assert build_parser().parse_args(["demo", "up"]).nodes == 1
    with pytest.raises(SystemExit):
        build_parser().parse_args(["demo", "up", "--nodes", "4"])
    assert build_parser().parse_args(["demo", "day", "--dir", "x"]).demo_command == "day"


def test_drafts_skip_canaries_and_keep_lines_short(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "plan.md").write_text(
        "# Plan\n\n## Offer\n\n"
        "- Spare confocal microscope time: Tuesdays and Thursdays, booked by email.\n"
        "- " + "long " * 40 + "\n"
        "- Internal ref: fake-canary-1\n\n"
        "## Gaps\n\n- No mass spectrometry\n  for lipid samples\n\n"
        "## Notes\n\n- Not a line\n"
    )
    offers, wants = demomod.draft_from_files(tmp_path)
    assert offers[0] == "Spare confocal microscope time"
    assert len(offers) == 2 and len(offers[1]) <= 140
    assert wants == ["No mass spectrometry for lipid samples"]
