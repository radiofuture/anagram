"""Pass 0 of understanding: rules kinds, titles, and the understanding tables."""

from __future__ import annotations

import re

import pytest
from indexkit import lab_index

from anagram.local.index.convert import Document
from anagram.local.index.enrich import ENRICHERS, FACT_KINDS, ChipsEnricher, EnrichContext, ItemInfo
from anagram.local.index.local import LocalIndex
from anagram.local.index.store import SCHEMA_VERSION
from anagram.local.sources import FolderConnector
from anagram.local.understanding import understand_schema
from anagram.local.understanding.kind_rules import KindRulesEnricher, classify
from anagram.local.understanding.kinds import (
    KIND_IDS,
    KINDS,
    current_versions,
    kind_of,
    kinds_of,
    set_override,
)
from anagram.local.understanding.titles import clean_phrase, doc_title, humanize, owner_text
from anagram.local.understanding.vocabulary import default_vocabulary

pytestmark = pytest.mark.usefixtures("no_network")

LABS = ("chen", "okafor", "varga", "helix")


def assert_clean_title(title: str | None) -> None:
    """Experience rule 9 and review items V1, V2."""
    if title is None:
        return
    assert title == title.strip() and "\n" not in title and len(title) <= 90, title
    assert "CANARY" not in title and "internal ref" not in title.lower(), title
    assert "<!--" not in title and "Slide number" not in title, title
    assert not re.search(r"[\w.-]+/[\w.-]+", title), title  # no path
    assert not title.startswith(("Re:", "RE:", "Fwd:")), title


@pytest.fixture(scope="module")
def labs(sim_community, tmp_path_factory):
    out = {}
    for slug in LABS:
        db = tmp_path_factory.mktemp("kinds") / f"{slug}.sqlite"
        index, _ = lab_index(db, sim_community.out_dir / "labs" / slug)
        index.scan()
        out[slug] = index
    yield out
    for index in out.values():
        index.close()


def _ref_of(index, ref):
    return index.store.one("SELECT ref FROM item WHERE id = ?", (int(ref[5:]),))[0]


def test_taxonomy():
    assert len(KIND_IDS) == 13 and KIND_IDS[0] == "finding" and "unknown" in KINDS
    assert {"kind", "title", "person", "claim", "entity"} <= set(FACT_KINDS)
    assert "kind_rules" in ENRICHERS and ENRICHERS.names()[0] == "chips"


def test_each_sim_item_gets_a_rules_kind(labs):
    seen = set()
    for index in labs.values():
        current = current_versions(index)
        kinds = kinds_of(index, current.values())
        for ref, vid in current.items():
            path = _ref_of(index, ref)
            got = kinds[vid]
            converted = index.document(vid) is not None
            if not converted:  # a raw file that no converter reads
                assert got.kind == "unknown" and got.by == "none"
                continue
            assert got.kind in KINDS and got.by == "rules" and 0 <= got.confidence <= 1, path
            rows = index.store.q(
                "SELECT count(*) FROM fact WHERE version_id = ? AND kind = 'kind'", (vid,)
            )
            assert rows[0][0] == 1
            seen.add(got.kind)
            if path.startswith("zotero:") or path.endswith("zotero-export.json"):
                assert got.kind == "reference" and got.confidence >= 0.9
            elif path.startswith("git:") or path.endswith(".py"):
                assert got.kind == "code"
            elif path.endswith(".eml"):
                assert got.kind == "correspondence"
            elif path.endswith(".csv"):
                assert got.kind == "data"
            elif path.endswith(".pptx"):
                assert got.kind == "draft"
            elif path.endswith(".png"):
                assert got.kind == "result" and got.stage == "observed"
    assert {"reference", "code", "correspondence", "data", "draft", "result", "note"} <= seen


def test_item_titles_are_clean_on_the_demo_fixtures(labs):
    titles = []
    for index in labs.values():
        current = current_versions(index)
        for got in kinds_of(index, current.values()).values():
            assert_clean_title(got.title)
            titles.append(got.title)
    assert sum(t is not None for t in titles) >= 60
    assert "Chen Lab: Q4 project plan" in titles
    # A "Re:" subject is the subject of the other person's mail: never a title.
    assert not any("NbT7 pocket and your affinity model" in (t or "") for t in titles)
    assert "Three states of NbT7" in titles  # a slide title, not "Outline", not joined text
    assert "Nbt7 grid screening" in titles  # a file name as words, not a path


def test_chips_do_not_change(sim_community, tmp_path):
    root = sim_community.out_dir / "labs" / "chen"
    plain, _ = lab_index(tmp_path / "a.sqlite", root, enrichers=[ChipsEnricher()])
    full, _ = lab_index(tmp_path / "b.sqlite", root)
    plain.scan()
    full.scan()
    assert "KindRulesEnricher" in [type(e).__name__ for e in full.enrichers]
    items = plain.items()
    assert items and {i.key for i in items} == {i.key for i in full.items()}
    for item in items:
        b_item = next(i for i in full.items() if i.key == item.key)
        a = plain.meaning(item.source_id, item.key)
        b = full.meaning(b_item.source_id, b_item.key)
        if a is None:
            assert b is None
            continue
        assert a.chips == b.chips and a.summary == b.summary
    assert plain.store.one("SELECT count(*) FROM fact WHERE kind = 'kind'")[0] == 0


def test_rules_read_owner_text_only():
    doc = Document(
        markdown="# Gel run\n\nWe found that X binds Y at pH 6.\n",
        title="Gel run",
        quoted="Dear colleague, please find the invoice and the budget order.",
        kind="markdown",
    )
    guess = classify(doc, ItemInfo(name="gel.md", ref="results/gel.md"))
    assert guess.kind == "finding" and guess.stage == "observed"
    assert "invoice" not in owner_text(doc.markdown)


def test_hints_and_low_confidence_for_prose():
    doc = Document(markdown="Lane 3 shows a band near 40 kDa after the second wash today.")
    plain = classify(doc, ItemInfo(name="x.md"))
    hinted = classify(doc, ItemInfo(name="x.md"), hints=[{"text": "lane", "kind": "result"}])
    assert hinted.kind == "result" and plain.confidence < 0.9 and hinted.confidence < 0.9


def test_lab_item_keeps_the_author_kind_and_facts():
    ctx = EnrichContext(
        vocab=default_vocabulary(),
        item=ItemInfo(
            source_kind="labspace",
            name="note",
            extra={
                "type": "finding",
                "facts": [
                    {"kind": "claim", "value": "X binds Y.", "score": 0.9, "data": {}},
                    {"kind": "need", "value": "not copied"},
                    {"kind": "title", "value": "X binds Y"},
                ],
            },
        ),
    )
    facts = KindRulesEnricher().enrich(Document(markdown="Some text."), ctx)
    assert [(f.kind, f.value, f.data["by"]) for f in facts] == [
        ("kind", "finding", "lab"),
        ("claim", "X binds Y.", "lab"),
        ("title", "X binds Y", "lab"),
    ]


def test_titles_never_joined_slides_refs_or_paths():
    deck = (
        "<!-- Slide number: 1 -->\nOutline\nA\nB\n\n<!-- Slide number: 2 -->\nWhat we need\n"
        "Binding-affinity prediction for pocket ligands\nInternal ref: CANARY-X-001\n"
    )
    assert doc_title(Document(markdown=deck, title="Outline", kind="slides")) == "What we need"
    assert clean_phrase("Re: Fwd: Grid order") == "Grid order"
    assert clean_phrase("mei-lin-chen/notes") is None
    assert clean_phrase("MAX_ICE_NM = 45") is None
    assert clean_phrase("Results. Internal ref: CANARY-1") == "Results"
    assert clean_phrase("x" * 40 + " " + "y" * 60) == "x" * 40
    assert humanize("lab/raw/G14_movies_stack.mrcs") == "G14 movies stack"
    assert humanize("0a1b2c3d4e5f.bin") is None


def test_override_wins_and_survives_a_new_version(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "a.md").write_text("# Plan\n\nWe will measure the band next week in the lab.\n")
    index = LocalIndex(tmp_path / "i.sqlite", bytes(32))
    sid = index.add_source(FolderConnector(root))
    index.scan()
    ref = index.item_ref(sid, "a.md")
    events = []
    got = set_override(index, int(ref[5:]), "finding", publish=lambda t, d: events.append((t, d)))
    assert got.kind == "finding" and got.by == "person"
    assert events == [
        ("item.kind", {"by": "person", "confidence": 1.0, "kind": "finding", "ref": ref,
                       "title": "Plan"}),
    ]  # fmt: skip
    (root / "a.md").write_text("# Plan\n\nWe will measure the band again in the lab.\n")
    index.scan()
    vid = current_versions(index)[ref]
    assert kind_of(index, vid).kind == "finding" and kind_of(index, vid).by == "person"
    with pytest.raises(ValueError):
        set_override(index, int(ref[5:]), "not-a-kind")


def test_tables_need_no_schema_change(tmp_path):
    index = LocalIndex(tmp_path / "i.sqlite", bytes(32))
    with index.store.transaction():
        understand_schema.ensure(index.store)
    names = {r[0] for r in index.store.q("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert set(understand_schema.TABLES) <= names
    assert SCHEMA_VERSION == 2 and index.store.get_meta("schema") == 2
