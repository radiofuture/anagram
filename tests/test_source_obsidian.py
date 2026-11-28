"""The Obsidian vault source: items, private notes, facts, and links.
The fixture vault is `tests/fixtures/vault/`. No network."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from indexkit import KEY

from anagram.local.index.convert import Blob, ConversionError
from anagram.local.index.enrich import FACT_KINDS
from anagram.local.index.indexer import WATCH_IGNORED, watch_paths
from anagram.local.index.local import LocalIndex
from anagram.local.sources import (
    SOURCES,
    FolderConnector,
    ObsidianConnector,
    connector_from_config,
    discover,
)
from anagram.local.sources import source_state as ss
from anagram.local.sources.obsidian import (
    CANVAS,
    ObsidianConverter,
    ObsidianEnricher,
    is_private,
    note_links,
    note_tags,
    resolve_links,
    split_frontmatter,
)

pytestmark = pytest.mark.usefixtures("no_network")

FIXTURE = Path(__file__).parent / "fixtures" / "vault"
KEYS = [
    "Archive/2024/Methods.md",
    "Archive/2024/Notes.md",
    "Board.canvas",
    "Home.md",
    "Methods.md",
    "Projects/Grid robot.md",
    "Projects/Notes.md",
    "Reading/Paper notes.md",
    "Templates/Daily.md",
    "figures/gel.png",
]


@pytest.fixture
def vault(tmp_path) -> Path:
    root = tmp_path / "home" / "My vault"
    shutil.copytree(FIXTURE, root)
    return root


@pytest.fixture
def index(tmp_path):
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    yield idx
    idx.close()


@pytest.fixture
def sid(index, vault) -> str:
    sid = index.add_source(ObsidianConnector(vault))
    index.scan([sid])
    return sid


def keys(index, sid: str) -> list[str]:
    return [i.key for i in index.items(sid)]


def facts(index, sid: str, key: str, kind: str) -> list:
    return index.facts(sid, key, kind)


def relations(index, sid: str) -> set[tuple[str, str, str]]:
    """(kind, source key, target key) of the link relations."""
    key_of = {
        f"item:{r['id']}": r["key"]
        for r in index.store.q("SELECT id, key FROM item WHERE source_id = ?", (sid,))
    }
    return {
        (kind, key_of[src], key_of[dst])
        for kind, src, dst in index.relations()
        if kind in ("links_to", "embeds")
    }


# ------------------------------------------------------------------ parsing


def test_frontmatter_split():
    assert split_frontmatter("---\na: 1\n---\nBody\n") == ("a: 1", "Body\n")
    assert split_frontmatter("No frontmatter\n---\n") == (None, "No frontmatter\n---\n")
    assert split_frontmatter("---\na: 1\n") == (None, "---\na: 1\n")  # not closed


def test_tags_are_not_read_in_code_links_or_numbers():
    body = (
        "A #tag and #nested/tag-2 and #Tag again. Issue #42. A heading link [[Note#Part]]\n"
        "and [text](file.md#part) and https://example.org/#frag.\n"
        "```\n#in_code\n```\nInline `#also_code`.\n# Heading\n"
    )
    assert note_tags({"tags": "front, #hash"}, body) == ["front", "hash", "tag", "nested/tag-2"]
    assert note_tags({"tags": ["a", "b"], "tag": "c"}, "") == ["a", "b", "c"]


def test_links_of_each_form():
    body = (
        "[[Note]] [[Folder/Note#Heading|shown]] ![[image.png]] [[#Here]]\n"
        "[a file](sub/My%20file.md#part) ![pic](pic.png) [web](https://example.org/x.md)\n"
        "[mail](mailto:a@example.org) [anchor](#top) `[[code]]`\n"
    )
    assert note_links(body) == [
        ("Note", {"alias": None, "embed": False, "heading": None}),
        ("Folder/Note", {"alias": "shown", "embed": False, "heading": "Heading"}),
        ("image.png", {"alias": None, "embed": True, "heading": None}),
        ("", {"alias": None, "embed": False, "heading": "Here"}),
        ("sub/My file.md", {"alias": "a file", "embed": False, "heading": "part"}),
        ("pic.png", {"alias": "pic", "embed": True, "heading": None}),
    ]


def test_private_rules():
    assert is_private("---\nanagram: false\n---\nText\n")
    assert is_private("Text with #private in it\n")
    assert is_private("---\ntags: [work, Private]\n---\nText\n")
    assert not is_private("---\nanagram: true\n---\nText about #privateer ships\n")
    assert not is_private("```\n#private\n```\n")
    assert is_private("---\nanagram: [bad\n---\nText\n")  # bad YAML mentioning anagram fails closed


def test_fact_kinds_are_registered():
    assert {"frontmatter", "frontmatter_error", "tag", "alias", "link"} <= set(FACT_KINDS)


# ------------------------------------------------------------------- source


def test_kind_is_registered_and_opens_from_its_config(vault):
    assert SOURCES.get("obsidian") is ObsidianConnector
    conn = ObsidianConnector(vault, exclude=["Templates/"])
    cfg = conn.config()
    assert cfg == {"exclude": ["Templates"], "kind": "obsidian", "root": str(vault.resolve())}
    again = connector_from_config(cfg)
    assert isinstance(again, ObsidianConnector) and again.config() == cfg
    assert conn.describe() == "Obsidian vault My vault"
    assert ObsidianConnector.own is True


def test_discover_finds_a_vault_and_does_not_look_inside_it(vault, tmp_path):
    inner = vault / "Projects" / "nested"
    (inner / ".obsidian").mkdir(parents=True)
    at_root = ObsidianConnector.discover(vault)
    assert [s.config["root"] for s in at_root] == [str(vault.resolve())]
    from_parent = discover(tmp_path / "home", ["obsidian"])
    assert [(s.kind, s.config["root"]) for s in from_parent] == [("obsidian", str(vault.resolve()))]
    assert ObsidianConnector.discover(tmp_path / "nothing") == []
    assert ObsidianConnector.discover(vault / "Reading") == []


def test_items_of_the_vault(index, sid):
    assert keys(index, sid) == KEYS  # no `.obsidian`, no `.trash`, no private note
    by_key = {i.key: i for i in index.items(sid)}
    assert by_key["Home.md"].media_type == "text/markdown"
    assert by_key["Board.canvas"].media_type == CANVAS
    assert by_key["figures/gel.png"].media_type == "image/png"
    assert index.source(sid)["prefs"] == {"prefer": ["obsidian"]}


def test_private_and_ignored_text_is_not_in_the_index(index, sid):
    for word in ("quasicrystal", "heliotrope", "amethyst"):
        assert index.search(word) == []
    assert index.search("nanodiscs")[0].key == "Reading/Paper notes.md"
    stored = index.store.one(
        "SELECT count(*) FROM item WHERE key LIKE 'Private/%' OR key LIKE '.%'"
    )[0]
    assert stored == 0


def test_a_note_that_becomes_private_leaves_the_index(index, sid, vault):
    note = vault / "Projects" / "Notes.md"
    note.write_text(note.read_text() + "\nKeep this out. #private\n")
    report = index.scan([sid])
    assert report.removed == [(sid, "Projects/Notes.md")]
    assert "Projects/Notes.md" not in keys(index, sid)
    assert index.search("Nanobody") == []
    # The mark is removed: the note comes back.
    note.write_text("# Project notes\n\nNanobody libraries again.\n")
    assert index.scan([sid]).changed == [(sid, "Projects/Notes.md")]


def test_exclude_leaves_a_folder_out(index, vault):
    sid = index.add_source(ObsidianConnector(vault, exclude=["Templates", "Archive/2024"]))
    index.scan([sid])
    got = keys(index, sid)
    assert "Templates/Daily.md" not in got and "Archive/2024/Notes.md" not in got
    assert "Home.md" in got and index.search("boilerplate") == []


def test_an_unchanged_vault_is_not_hashed_again(index, sid, monkeypatch):
    import anagram.local.sources.obsidian as mod

    def no_hash(*args, **kwargs):
        raise AssertionError("an unchanged file was hashed")

    monkeypatch.setattr(mod, "hash_file", no_hash)
    report = index.scan([sid])
    assert report.new == report.changed == report.removed == []
    assert len(report.unchanged) == len(KEYS)


def test_a_vault_that_is_gone_is_a_fault_and_removes_nothing(index, sid, vault):
    shutil.rmtree(vault)
    report = index.scan([sid])
    assert report.removed == [] and keys(index, sid) == KEYS
    state = ss.read(index.store, sid)
    assert (state.status, state.error_code) == ("attention", "not_found")
    assert state.fault["action"] == "choose"
    events = ss.events_after(index.store, 0)
    assert str(vault) not in str(events)  # no path in an event


# ----------------------------------------------------------- facts, meaning


def test_note_document_has_no_frontmatter_text(index, sid):
    m = index.meaning(sid, "Home.md")
    assert m.converter == "obsidian"
    assert m.extracted.title == "Lab home"
    assert m.extracted.text.startswith("# Home")
    assert "aliases" not in m.extracted.text
    assert index.meaning(sid, "Projects/Grid robot.md").extracted.title == "Grid robot"
    assert index.meaning(sid, "figures/gel.png").converter != "obsidian"  # normal converters


def test_frontmatter_tag_and_alias_facts(index, sid):
    front = {f.value: f.data["value"] for f in facts(index, sid, "Home.md", "frontmatter")}
    assert front == {
        "aliases": ["Start page", "Index"],
        "started": "2026-01-12",
        "status": "active",
        "tags": ["lab", "planning"],
        "title": "Lab home",
    }
    assert [f.value for f in facts(index, sid, "Home.md", "tag")] == [
        "lab",
        "planning",
        "lab/protocols",
    ]
    assert [f.value for f in facts(index, sid, "Home.md", "alias")] == ["Start page", "Index"]
    assert [f.value for f in facts(index, sid, "Projects/Grid robot.md", "tag")] == ["Lab", "robot"]
    assert [f.value for f in facts(index, sid, "Reading/Paper notes.md", "alias")] == ["Papers"]
    assert [f.value for f in facts(index, sid, "Reading/Paper notes.md", "tag")] == ["reading"]


def test_link_facts(index, sid):
    links = [(f.value, f.data) for f in facts(index, sid, "Home.md", "link")]
    assert links == [
        ("Projects/Grid robot", {"alias": None, "embed": False, "heading": None}),
        ("Methods", {"alias": "the buffer", "embed": False, "heading": "Buffer"}),
        ("Notes", {"alias": None, "embed": False, "heading": None}),
        ("figures/gel.png", {"alias": None, "embed": True, "heading": None}),
        ("Reading/Paper notes.md", {"alias": "paper notes", "embed": False, "heading": None}),
        ("Board.canvas", {"alias": None, "embed": False, "heading": None}),
    ]


def test_bad_yaml_gives_one_error_fact_and_no_failure(index, sid):
    assert len(facts(index, sid, "Methods.md", "frontmatter_error")) == 1
    assert facts(index, sid, "Methods.md", "frontmatter") == []
    assert [f.value for f in facts(index, sid, "Methods.md", "link")] == ["Home"]
    assert index.meaning(sid, "Methods.md").extracted.title == "Methods"
    assert all(s.key != "Methods.md" for s in index.skipped(sid))
    assert index.search("HEPES")[0].key == "Methods.md"


def test_canvas_text_nodes_are_converted(index, sid):
    m = index.meaning(sid, "Board.canvas")
    assert m.converter == "obsidian" and m.extracted.kind == "canvas"
    assert "Order the grid robot before March" in m.extracted.text
    assert "## Purchases" in m.extracted.text
    assert [f.value for f in facts(index, sid, "Board.canvas", "link")] == [
        "Projects/Grid robot.md"
    ]
    with pytest.raises(ConversionError):
        ObsidianConverter().convert(Blob(b"not json", "x.canvas", CANVAS))


def test_the_enricher_runs_only_for_an_obsidian_source(index, vault):
    """The same notes in a folder source get no Obsidian facts."""
    sid = index.add_source(FolderConnector(vault))
    index.scan([sid])
    assert index.meaning(sid, "Home.md").converter == "basic"
    for kind in ("frontmatter", "tag", "alias", "link"):
        assert facts(index, sid, "Home.md", kind) == []
    assert ObsidianEnricher.external is False


# -------------------------------------------------------------------- links


def test_links_resolve_as_obsidian_does(index, sid):
    got = relations(index, sid)  # after_scan runs after the first scan's jobs make the link facts
    assert got == {
        ("links_to", "Home.md", "Projects/Grid robot.md"),  # exact path
        ("links_to", "Home.md", "Methods.md"),  # exact path wins over Archive/2024/Methods.md
        ("links_to", "Home.md", "Projects/Notes.md"),  # two notes "Notes": the shortest path
        ("embeds", "Home.md", "figures/gel.png"),
        ("links_to", "Home.md", "Reading/Paper notes.md"),  # a Markdown link
        ("links_to", "Home.md", "Board.canvas"),
        ("links_to", "Projects/Grid robot.md", "Home.md"),  # a unique file name
        ("links_to", "Projects/Grid robot.md", "Methods.md"),
        ("links_to", "Projects/Grid robot.md", "Projects/Notes.md"),
        ("links_to", "Methods.md", "Home.md"),
        ("links_to", "Board.canvas", "Projects/Grid robot.md"),
    }
    assert resolve_links(index, sid) == len(got)
    # "Missing note" has no target: it stays a fact only.
    assert "Missing note" in [f.value for f in facts(index, sid, "Projects/Grid robot.md", "link")]


def test_the_next_scan_makes_the_relations(index, sid):
    index.scan([sid])
    assert ("embeds", "Home.md", "figures/gel.png") in relations(index, sid)


def test_a_link_that_is_gone_removes_its_relation(index, sid, vault):
    resolve_links(index, sid)
    (vault / "Methods.md").write_text("# Methods\n\nNo link now. See [[Board.canvas]].\n")
    index.scan([sid])  # new version, then the jobs make the new facts
    resolve_links(index, sid)
    got = relations(index, sid)
    assert ("links_to", "Methods.md", "Home.md") not in got
    assert ("links_to", "Methods.md", "Board.canvas") in got


def test_a_deleted_note_removes_the_relations_to_it(index, sid, vault):
    resolve_links(index, sid)
    (vault / "Projects" / "Notes.md").unlink()
    index.scan([sid])
    got = relations(index, sid)
    # "Notes" now means the one note that has this name.
    assert ("links_to", "Home.md", "Archive/2024/Notes.md") in got
    assert all(dst != "Projects/Notes.md" for _, _, dst in got)


def test_resolve_does_no_work_when_nothing_changed(index, sid, monkeypatch):
    n = resolve_links(index, sid)
    monkeypatch.setattr(index, "relate", None)  # a second pass would fail here
    assert resolve_links(index, sid) == n


# ------------------------------------------------------------------- helper


def test_the_helper_watches_the_vault_and_ignores_its_settings(vault):
    assert watch_paths({"kind": "obsidian", "root": str(vault)}) == [vault]
    assert {".obsidian", ".trash"} <= WATCH_IGNORED
    assert ".git" not in WATCH_IGNORED


# ------------------------------------------------------------ folder source


def test_folder_source_exclude(index, vault):
    conn = FolderConnector(vault, exclude=["Private", "Archive/2024"])
    assert conn.config()["exclude"] == ["Archive/2024", "Private"]
    assert FolderConnector(vault).config() == {"kind": "folder", "root": str(vault.resolve())}
    sid = index.add_source(connector_from_config(conn.config()))
    index.scan([sid], process=False)
    got = keys(index, sid)
    assert "Private/Diary.md" not in got and "Archive/2024/Notes.md" not in got
    assert "Home.md" in got and ".obsidian/app.json" in got  # a folder source has no vault rules


def test_private_checks_large_notes_case_insensitive_and_bad_yaml_tags(index, vault):
    assert is_private("---\nanagram: 'FALSE'\n---\nText\n")
    assert is_private("---\nanagram: No\n---\nText\n")
    assert is_private("---\ntags: [work, private\n---\nText\n")

    # A note larger than 4 MiB that is marked private must still be excluded.
    big = vault / "HugePrivate.md"
    big.write_text("---\nanagram: false\n---\n" + ("word " * 1_000_000))
    assert big.stat().st_size > 4_000_000
    sid = index.add_source(ObsidianConnector(vault))
    index.scan([sid], process=False)
    assert "HugePrivate.md" not in keys(index, sid)
