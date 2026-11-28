"""Spans in the document (net 02 step 1).

- Round trip of `Document.to_json` / `from_json` with each block kind.
- Migration: a store of schema version 2 with schema-1 documents (written by
  the code of c8586e6, `fixtures/doc_schema1/`) opens, and each old document
  reads with no loss.
- Anchor stability under a small edit, for each type: insert one paragraph
  near the start, change one cell, add one slide. At least 95 % of the
  unchanged blocks keep their anchors. Each conversion runs under the temp
  file canary scan (net 01 step 4).
- Facts get a span and `converter@version`.
"""

from __future__ import annotations

import io
import json
from collections import defaultdict
from email.message import EmailMessage
from pathlib import Path

import pytest
import sqlcipher3
from indexkit import KEY
from tempscan import canary, no_plaintext_temp

from anagram.local.index.convert import (
    DOC_SCHEMA,
    BasicConverter,
    Blob,
    Block,
    Document,
    MarkItDownConverter,
    Span,
    blocks_from_markdown,
)
from anagram.local.index.convert.document import BLOCK_KINDS, CONTAINER_KINDS, norm_text
from anagram.local.index.local import LocalIndex
from anagram.local.index.media import DOCX, IPYNB, PPTX, XLSX
from anagram.local.index.store import IndexStore, db_key, dumps
from anagram.local.sources import FolderConnector
from anagram.sim.writers import docx_bytes, normalize_zip, pdf_bytes, pdf_layout, pptx_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "doc_schema1"
STABILITY_BAR = 0.95

# ------------------------------------------------------------- round trip


def _all_kinds_document() -> Document:
    spans = {
        "page": Span(page=2),
        "slide": Span(slide=3),
        "sheet": Span(sheet="Yields"),
        "message": Span(message="<m1@lab.example>", part="1"),
        "figure": Span(page=2, bbox=(72.0, 100.5, 300.0, 280.25)),
        "caption": Span(page=2, bbox=(72.0, 284.0, 300.0, 300.0)),
        "cell_range": Span(sheet="Yields", cells="A1:C9"),
        "image": Span(page=1, bbox=(0.0, 0.0, 612.0, 792.0)),
        "heading": Span(slide=3, shape="2", lines=(1, 1)),
        "para": Span(message="<m1@lab.example>", part="1.2", lines=(3, 5)),
        "table": Span(page=2, lines=(7, 9)),
        "code": Span(lines=(11, 14)),
    }
    attrs = {
        "message": {"reply_to": "<m0@lab.example>", "from": "a@lab.example", "date": "Mon"},
        "cell_range": {"header_row": 1},
        "figure": {"caption": "caption-1"},
    }
    blocks = [
        Block(
            kind,
            "" if kind in CONTAINER_KINDS else f"text of {kind}",
            f"{kind}-1",
            2 if kind == "heading" else 0,
            None if kind in CONTAINER_KINDS else "page-1",
            spans[kind],
            attrs.get(kind, {}),
        )
        for kind in BLOCK_KINDS
    ]
    return Document(
        markdown="# T\n\nbody",
        title="T",
        blocks=blocks,
        meta={"from": "a@lab.example"},
        quoted="> old text",
        converter="test",
        converter_version="9",
        kind="email",
        prose=False,
        note="a note",
    )


def test_round_trip_each_block_kind():
    doc = _all_kinds_document()
    assert {b.kind for b in doc.blocks} == set(BLOCK_KINDS)
    back = Document.from_json(json.loads(json.dumps(doc.to_json())))
    assert back == doc and back.schema == DOC_SCHEMA == 2
    for b in doc.blocks:
        assert Block.from_json(json.loads(json.dumps(b.to_json()))) == b


def test_schema_1_json_reads():
    old = json.loads((FIXTURES / "documents.json").read_text())
    for d in old:
        doc = Document.from_json(d)
        assert doc.schema == 1
        assert [b.to_json() for b in doc.blocks] == d["blocks"]
        assert all(b.span is None and b.attrs == {} for b in doc.blocks)


def test_wire_form_of_the_reading_copy_is_unchanged():
    """The reading copy (a locked format) carries schema-1 blocks: the same
    JSON as the code of c8586e6 made from the same Markdown."""
    from anagram.local.api import wire_blocks_v1

    for d in json.loads((FIXTURES / "documents.json").read_text()):
        assert wire_blocks_v1(blocks_from_markdown(d["markdown"])) == d["blocks"], d["name"]


# -------------------------------------------------------------- migration


def _schema2_store(path: Path, docs: list[dict]) -> None:
    """A store as the code of c8586e6 made it: schema version 2, documents
    with schema-1 blocks, facts with no span."""
    db = sqlcipher3.connect(str(path), isolation_level=None)
    db.execute(f"PRAGMA key = \"x'{db_key(KEY).hex()}'\"")
    db.executescript((FIXTURES / "store-schema-2.sql").read_text())
    db.execute("INSERT INTO meta (key, value) VALUES ('schema', '2')")
    for vid, d in enumerate(docs, 1):
        db.execute(
            "INSERT INTO document (version_id, converter, converter_version, kind, title,"
            " markdown, blocks, meta, quoted, prose, note, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                vid,
                d["converter"],
                d["converter_version"],
                d["kind"],
                d["title"],
                d["markdown"],
                dumps(d["blocks"]),
                dumps(d["meta"]),
                d["quoted"],
                int(d["prose"]),
                d["note"],
                "2026-11-01T00:00:00Z",
            ),
        )
        db.execute(
            "INSERT INTO fact (version_id, kind, value, score, data, enricher, enricher_version)"
            " VALUES (?, 'topic', 'cryo-EM', 1.0, '{}', 'chips', '1')",
            (vid,),
        )
    db.close()


def test_migration_reads_each_old_document_with_no_loss(tmp_path):
    old = json.loads((FIXTURES / "documents.json").read_text())
    path = tmp_path / "index.sqlite"
    _schema2_store(path, old)
    index = LocalIndex(path, KEY)
    try:
        assert index.store.get_meta("schema") == 2
        for vid, d in enumerate(old, 1):
            doc = index.document(vid)
            got = doc.to_json()
            assert got.pop("schema") == 1
            want = {k: v for k, v in d.items() if k != "name"}
            assert got == want, d["name"]
        facts = index.store.q("SELECT span, extractor FROM fact")
        assert len(facts) == len(old) and all(r[0] is None and r[1] is None for r in facts)
    finally:
        index.store.close()
    # A second open adds nothing and changes nothing.
    store = IndexStore(path, KEY)
    cols = {r[1] for r in store.q("PRAGMA table_info(document)")}
    assert "schema" in cols
    store.close()


def test_new_store_writes_schema_2_documents_and_fact_spans(tmp_path):
    root = tmp_path / "box"
    root.mkdir()
    (root / "plan.md").write_text(
        "# Q4 plan\n\nWe need binding-affinity prediction for NbT7.\n\n"
        "## Offer\n\nWe offer cryo-EM instrument time at the core.\n"
    )
    index = LocalIndex(tmp_path / "i.sqlite", KEY)
    try:
        index.add_source(FolderConnector(root))
        index.scan()
        row = index.store.one("SELECT version_id, schema FROM document")
        assert row["schema"] == DOC_SCHEMA
        doc = index.document(row["version_id"])
        rows = index.store.q("SELECT kind, value, span, extractor FROM fact")
        assert rows and all(r["extractor"] == "basic@1" for r in rows)
        with_span = [r for r in rows if r["span"]]
        assert with_span, "no fact has a span"
        lines = doc.markdown.split("\n")
        for r in with_span:
            span = json.loads(r["span"])
            held = norm_text(" ".join(lines[span["lines"][0] - 1 : span["lines"][1]])).lower()
            assert norm_text(r["value"]).lower() in held, r["value"]
            assert any(b.anchor == span["anchor"] for b in doc.blocks)
        assert all(not r["span"] for r in rows if r["kind"] in ("summary", "kind"))
    finally:
        index.store.close()


# ----------------------------------------------------- anchor stability


def _sigs(blocks: list[Block]) -> dict[str, tuple]:
    """anchor -> content signature (kind and text; for a container, the
    signatures of its children)."""
    kids: dict[str, list[tuple]] = defaultdict(list)
    for b in blocks:
        if b.parent is not None:
            kids[b.parent].append((b.kind, norm_text(b.text)))
    return {
        b.anchor: (b.kind, tuple(kids[b.anchor]))
        if b.kind in CONTAINER_KINDS
        else (b.kind, norm_text(b.text))
        for b in blocks
    }


def anchor_stability(old: list[Block], new: list[Block]) -> tuple[float, int]:
    """The part of the unchanged blocks (same content before and after the
    edit) that keep their anchor, and the count of unchanged blocks."""
    old_s, new_s = _sigs(old), _sigs(new)
    new_by_sig: dict[tuple, set[str]] = defaultdict(set)
    for a, s in new_s.items():
        new_by_sig[s].add(a)
    unchanged = [a for a, s in old_s.items() if s in new_by_sig]
    kept = [a for a in unchanged if a in new_by_sig[old_s[a]]]
    return (len(kept) / len(unchanged) if unchanged else 1.0), len(unchanged)


SENTENCES = [
    "We have three new cryo-EM structures of the NbT7 transporter.",
    "The ligand pocket in the outward-open map is well resolved.",
    "Docking scores do not agree with our two measured Kd values.",
    "We need a small-molecule library to soak with the protein.",
    "About 40 hours per month of Krios time are free at the core.",
    "The MscQ channel maps go to the shared drive next week.",
    "Growth curves fit a logistic model with two parameters.",
    "The gut microbiome model needs germ-free mice for each arm.",
    "Screening assays ran on 384-well plates with two controls.",
    "The GPU pipeline embeds each structure in under one minute.",
]


def _paras(n: int, tag: str) -> list[str]:
    return [f"{SENTENCES[i % 10]} {SENTENCES[(i * 3 + 1) % 10]} Note {tag}{i}." for i in range(n)]


def _doc_blocks(tag: str) -> list:
    out: list = [("h1", f"Project plan {tag}")]
    for i, p in enumerate(_paras(18, tag)):
        if i % 6 == 0:
            out.append(("h2", f"Part {i // 6 + 1} of {tag}"))
        out.append(("p", p))
        if i == 9:
            out.append(
                ("table", [["sample", "yield", "unit"], ["A1", "3.2", "mg"], ["B2", "4.1", "mg"]])
            )
    return out


def _insert_para(blocks: list) -> list:
    return [blocks[0], ("p", "This paragraph is new: it came in with the edit."), *blocks[1:]]


def _markdown(blocks: list) -> str:
    out = []
    for kind, content in blocks:
        if kind == "table":
            rows = ["| " + " | ".join(r) + " |" for r in content]
            out.append("\n".join([rows[0], "| --- | --- | --- |", *rows[1:]]))
        elif kind in ("h1", "h2"):
            out.append("#" * int(kind[1]) + " " + content)
        else:
            out.append(content)
    return "\n\n".join(out) + "\n"


def _eml(body: str) -> bytes:
    msg = EmailMessage()
    msg["From"] = "mchen@northbridge.example"
    msg["To"] = "treyes@northbridge.example"
    msg["Subject"] = "Krios plan"
    msg["Date"] = "Mon, 02 Nov 2026 09:00:00 +0000"
    msg["Message-ID"] = "<plan-1@northbridge.example>"
    msg.set_content(body)
    return msg.as_bytes()


def _xlsx(cells: dict[str, list[list[object]]]) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    wb.remove(wb.active)
    for name, rows in cells.items():
        ws = wb.create_sheet(name)
        for r in rows:
            ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return normalize_zip(buf.getvalue())


def _sheets(tag: str) -> dict[str, list[list[object]]]:
    return {
        f"S{k}": [["sample", "yield", "note"]]
        + [
            [f"{tag}{k}-{i}", round(1.5 + i * 0.25 + k, 2), SENTENCES[i % 10][:20]]
            for i in range(12)
        ]
        for k in range(5)
    }


def _slides(tag: str) -> list[tuple[str, list[str]]]:
    return [(f"Slide title {tag} {i}", [SENTENCES[i % 10], f"Point {tag}{i}"]) for i in range(10)]


def _case(kind: str, tag: str) -> tuple[Blob, Blob]:
    """The file before and after a small edit, for each type."""
    if kind == "markdown":
        b = _doc_blocks(tag)
        before, after = _markdown(b).encode(), _markdown(_insert_para(b)).encode()
        return Blob(before, "p.md", "text/markdown"), Blob(after, "p.md", "text/markdown")
    if kind == "docx":
        b = _doc_blocks(tag)
        return Blob(docx_bytes(b), "p.docx", DOCX), Blob(
            docx_bytes(_insert_para(b)), "p.docx", DOCX
        )
    if kind == "pdf":
        b = _doc_blocks(tag)
        before, after = pdf_bytes(pdf_layout(b)), pdf_bytes(pdf_layout(_insert_para(b)))
        return Blob(before, "p.pdf", "application/pdf"), Blob(after, "p.pdf", "application/pdf")
    if kind == "pptx":
        s = _slides(tag)
        new = [*s[:3], ("A new slide", ["It came in with the edit."]), *s[3:]]
        return (
            Blob(pptx_bytes("Deck", "A", s), "d.pptx", PPTX),
            Blob(pptx_bytes("Deck", "A", new), "d.pptx", PPTX),
        )
    if kind == "xlsx":
        sheets = _sheets(tag)
        edited = {k: [list(r) for r in v] for k, v in sheets.items()}
        edited["S2"][4][1] = 99.5
        return Blob(_xlsx(sheets), "s.xlsx", XLSX), Blob(_xlsx(edited), "s.xlsx", XLSX)
    if kind == "email":
        paras = _paras(12, tag)
        before = "\n\n".join(paras) + "\n"
        after = "\n\n".join([paras[0], "This paragraph is new.", *paras[1:]]) + "\n"
        return Blob(_eml(before), "m.eml", "message/rfc822"), Blob(
            _eml(after), "m.eml", "message/rfc822"
        )
    if kind == "ipynb":
        paras = _paras(12, tag)

        def _nb(items: list[str]) -> bytes:
            cells = [
                {"cell_type": "markdown", "source": [f"# Notebook {tag}\n", f"\n{items[0]}"]},
                *[
                    {"cell_type": "markdown", "source": [p]}
                    if i % 3
                    else {"cell_type": "code", "source": [f"val_{i} = '{p[:24]}'\n"], "outputs": []}
                    for i, p in enumerate(items[1:], 1)
                ],
            ]
            return json.dumps({"nbformat": 4, "cells": cells}).encode("utf-8")

        return (
            Blob(_nb(paras), "a.ipynb", IPYNB),
            Blob(_nb([paras[0], "This paragraph is new.", *paras[1:]]), "a.ipynb", IPYNB),
        )
    if kind == "tex":
        paras = _paras(12, tag)

        def _tex(items: list[str]) -> bytes:
            body = [
                f"\\section{{Part {i // 4 + 1}}}\n{p}" if i % 4 == 0 else p
                for i, p in enumerate(items)
            ]
            src = (
                "\\documentclass{article}\n"
                f"\\title{{Study {tag}}}\n"
                "\\begin{document}\n" + "\n\n".join(body) + "\n\\end{document}\n"
            )
            return src.encode("utf-8")

        return (
            Blob(_tex(paras), "p.tex", "text/x-tex"),
            Blob(_tex([paras[0], "This paragraph is new.", *paras[1:]]), "p.tex", "text/x-tex"),
        )
    raise AssertionError(kind)


CONVERTER = {
    "markdown": BasicConverter,
    "email": BasicConverter,
    "ipynb": BasicConverter,
    "tex": BasicConverter,
    "docx": MarkItDownConverter,
    "pdf": MarkItDownConverter,
    "pptx": MarkItDownConverter,
    "xlsx": MarkItDownConverter,
}


@pytest.mark.parametrize("kind", sorted(CONVERTER))
def test_anchor_stability_under_a_small_edit(kind):
    tag = canary("anc")
    before, after = _case(kind, tag)
    conv = CONVERTER[kind]()
    owner = frozenset({"mchen@northbridge.example"})
    with no_plaintext_temp(tag):
        old = conv.convert(Blob(before.data, before.name, before.media_type, owner))
        new = conv.convert(Blob(after.data, after.name, after.media_type, owner))
    assert tag in old.markdown, "the canary must be in the text, or the scan proves nothing"
    stab, unchanged = anchor_stability(old.blocks, new.blocks)
    print(f"anchor stability {kind}: {stab:.3f} of {unchanged} unchanged blocks")
    assert unchanged >= 5, f"{kind}: too few unchanged blocks to measure"
    assert stab >= STABILITY_BAR, f"{kind}: {stab:.3f}"
    if kind == "pdf":
        assert any(b.kind == "page" for b in new.blocks), "the PDF must have pages"
    if kind == "pptx":
        assert [b.span.slide for b in new.blocks if b.kind == "slide"] == list(range(1, 12))


def test_spans_hold_the_text_of_their_block():
    md = (
        "# Title\n\nFirst para\nwith two lines.\n\n```py\nx = 1\n```\n\n| a | b |\n| - | - |\n"
        "\fPage two text.\n\n<!-- Slide number: 4 -->\n# On slide four\n"
    )
    lines = md.split("\n")
    blocks = blocks_from_markdown(md)
    for b in blocks:
        first, last = b.span.lines
        held = "\n".join(lines[first - 1 : last])
        for part in b.text.split("\n"):
            assert part.strip() in held, (b.kind, part)
    page2 = next(b for b in blocks if b.kind == "page" and b.span.page == 2)
    slide = next(b for b in blocks if b.kind == "slide")
    assert slide.span.slide == 4 and slide.span.page == 2
    text2 = next(b for b in blocks if b.text == "Page two text.")
    assert text2.parent == page2.anchor and text2.span.page == 2
    on4 = next(b for b in blocks if b.text == "On slide four")
    assert on4.parent == slide.anchor and on4.span.slide == 4


def test_same_text_gives_distinct_anchors():
    blocks = blocks_from_markdown("Same.\n\nSame.\n\nOther.\n\nSame.\n")
    anchors = [b.anchor for b in blocks]
    assert len(set(anchors)) == 4
    assert anchors[1] == anchors[0] + ".2" and anchors[3] == anchors[0] + ".3"


def test_tempscan_catches_planted_plaintext_temp_files():
    """`no_plaintext_temp` still fails when a temp file holding the canary is
    written into `TMPDIR` or directly into `/tmp`."""
    import tempfile

    tag = canary("leak")
    with pytest.raises(AssertionError, match="plaintext temp files hold a canary"):
        with no_plaintext_temp(tag):
            Path(tempfile.gettempdir(), "leaked.txt").write_text(f"secret {tag}")

    tag2 = canary("fixed")
    planted = Path("/tmp") / f"anagram-tempscan-{tag2}.txt"  # noqa: S108
    try:
        with pytest.raises(AssertionError, match="plaintext temp files hold a canary"):
            with no_plaintext_temp(tag2):
                planted.write_text(f"secret {tag2}")
    finally:
        planted.unlink(missing_ok=True)
