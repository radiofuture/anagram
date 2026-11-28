"""On-device extraction of each format. Deterministic, standard library only."""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

import pytest
from indexkit import lab

from anagram.local.index.extract import (
    extract_bytes,
    extract_file,
    media_type_for,
    repo_summary,
    split_quoted,
)
from anagram.local.understanding.chips import NEED, OFFER, extract_chips, split_units, unit_polarity
from anagram.local.understanding.vocabulary import default_vocabulary

pytestmark = pytest.mark.usefixtures("no_network")


def _sim_file(sim, slug, kind, suffix=""):
    lab_id = lab(sim, slug)["id"]
    rec = next(
        f
        for f in sim.ground_truth["files"]
        if f["lab_id"] == lab_id and f["kind"] == kind and f["path"].endswith(suffix)
    )
    return sim.out_dir / rec["path"]


def _canaries(sim, path, third_party=None):
    rel = path.relative_to(sim.out_dir).as_posix()
    return [
        c["canary"]
        for c in sim.canaries
        if c["path"] == rel and (third_party is None or c["third_party"] == third_party)
    ]


def test_markdown_and_text(sim_community):
    p = _sim_file(sim_community, "chen", "note", ".md")
    ex = extract_file(p)
    assert ex.kind == "markdown" and ex.prose
    assert ex.title.startswith("Chen Lab: Q4 project plan")
    assert "binding-affinity prediction" in ex.text
    t = extract_file(_sim_file(sim_community, "chen", "note", ".txt"))
    assert t.kind == "text" and "Krios" in t.text


def test_csv_header_and_sample(sim_community):
    ex = extract_file(_sim_file(sim_community, "chen", "dataset"))
    assert ex.kind == "table" and not ex.prose
    assert ex.meta["columns"][0] == "grid_id"
    assert ex.text.startswith("Columns: grid id, detergent")
    assert ex.text.count("Row:") == 5
    assert ex.meta["rows_about"] == 24


def test_pptx_slides_become_headings(sim_community):
    p = _sim_file(sim_community, "chen", "slides")
    ex = extract_file(p)
    assert ex.kind == "slides"
    assert ex.title == "NbT7 transporter: three states, one pocket"
    assert "# What we need" in ex.text
    assert "- Binding-affinity prediction for pocket ligands" in ex.text
    assert _canaries(sim_community, p)[0] in ex.text  # last slide is read too


def test_docx_text_and_headings():
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    doc = (
        f'<w:document xmlns:w="{w}"><w:body>'
        '<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Needs</w:t></w:r></w:p>'
        "<w:p><w:r><w:t>Statistics help for a mixed model.</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", doc)
    ex = extract_bytes(buf.getvalue(), "plan.docx", media_type_for("plan.docx"))
    assert ex.kind == "document"
    assert ex.text.splitlines()[0] == "# Needs"
    chips = extract_chips(ex.text, default_vocabulary())
    assert chips.needs == {"anagram:statistics-help": 1}


def test_eml_marks_quoted_third_party_text(sim_community):
    sim = sim_community
    p = _sim_file(sim, "chen", "email", "collaborator-thread.eml")
    assert extract_file(p).text == ""  # no owner address: all third-party (fail closed)
    ex = extract_file(p, owner_emails=frozenset({"mchen@northbridge.example"}))
    assert ex.kind == "email" and ex.has_third_party
    own = _canaries(sim, p, third_party=False)
    third = _canaries(sim, p, third_party=True)
    assert len(own) == 1 and len(third) == 1
    assert own[0] in ex.text and own[0] not in ex.quoted
    assert third[0] in ex.quoted and third[0] not in ex.text
    assert "Daniel Ortiz" in ex.quoted  # attribution line is quoted
    assert ex.meta["from"] == "mchen@northbridge.example"
    # Owner addresses known: a message from someone else is all third-party.
    other = extract_file(p, owner_emails=frozenset({"someone@else.example"}))
    assert other.text == "" and other.title is None and own[0] in other.quoted


def test_split_quoted_forwarded():
    own, quoted = split_quoted("Hi\n\n---- Forwarded message ----\nFrom: X\nsecret\n")
    assert own.strip() == "Hi"
    assert "secret" in quoted


def test_png_metadata_only(sim_community):
    p = _sim_file(sim_community, "chen", "image")
    ex = extract_file(p)
    assert ex.kind == "image" and not ex.prose
    assert ex.meta["width"] == 96 and ex.meta["height"] == 64
    assert ex.title.startswith("2D class averages")
    assert ex.meta["text"]["Comment"].startswith("Internal ref:")


def test_jpeg_metadata():
    def seg(marker, body):
        return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body

    data = (
        b"\xff\xd8"
        + seg(0xE1, b"Exif\x00\x00" + b"\x00" * 8)
        + seg(0xFE, b"Grid G14 overview")
        + seg(0xC0, b"\x08" + struct.pack(">HH", 480, 640) + b"\x03")
        + b"\xff\xda"
    )
    ex = extract_bytes(data, "a.jpg", "image/jpeg")
    assert ex.meta["width"] == 640 and ex.meta["height"] == 480
    assert ex.meta["exif"] is True
    assert ex.title == "Grid G14 overview"


def _pdf(content: bytes, flate: bool) -> bytes:
    body = zlib.compress(content) if flate else content
    head = (
        b"<< /Length %d /Filter /FlateDecode >>" % len(body)
        if flate
        else b"<< /Length %d >>" % len(body)
    )
    return b"%PDF-1.4\n1 0 obj\n" + head + b"\nstream\n" + body + b"\nendstream\nendobj\n%%EOF\n"


@pytest.mark.parametrize("flate", [False, True])
def test_pdf_simple_text(flate):
    content = (
        b"BT /F1 12 Tf 72 720 Td (We need GPU hours \\(about 900\\)) Tj T* "
        b"[(Second) -250 ( line)] TJ ET"
    )
    ex = extract_bytes(_pdf(content, flate), "a.pdf", "application/pdf")
    assert ex.kind == "pdf"
    assert ex.text.splitlines() == ["We need GPU hours (about 900)", "Second line"]
    assert extract_chips(ex.text, default_vocabulary()).needs == {"anagram:gpu-compute": 1}


def test_pdf_without_text_gives_a_note():
    ex = extract_bytes(b"%PDF-1.7\n%%EOF\n", "scan.pdf", "application/pdf")
    assert ex.text == "" and "no text" in ex.note


def test_csl_json_is_bibliography(sim_community):
    ex = extract_file(_sim_file(sim_community, "chen", "zotero"))
    assert ex.kind == "bibliography" and not ex.prose
    assert ex.meta["items"] == 3
    assert "Resolution limits in small membrane protein cryo-EM" in ex.text


def test_repo_summary(sim_community):
    import shutil

    from anagram.local.sources.git import git_env

    repo = _sim_file(sim_community, "okafor", "git")
    ex = repo_summary(repo, shutil.which("git"), git_env())
    assert ex.kind == "code_repo"
    assert ex.title == "okabind"
    assert "- splits.py" in ex.text and "- README.md" in ex.text
    no_git = repo_summary(repo, None, {})
    assert "- splits.py" in no_git.text and ".git" not in no_git.text.replace(".gitignore", "")


def test_unknown_binary_is_not_read(sim_community, tmp_path):
    p = _sim_file(sim_community, "chen", "large")
    ex = extract_file(p)
    assert ex.kind == "binary" and ex.text == ""


def test_polarity_cues():
    def pol(text):
        return unit_polarity(split_units(text)[-1])

    assert pol("We have no compound library.") == NEED
    assert pol("We can offer mouse studies.") == OFFER
    assert pol("Idle GPU hours last month: about 900.") == OFFER
    assert pol("Germ-free mice were colonised.") is None
    assert pol("## Offer\n\n- Time on the GPU pipeline") == OFFER
    assert pol("## Gaps\n\n- No in vivo model") == NEED
    chips = extract_chips(
        "# Plan\n\nWe are looking for a statistician.\n", default_vocabulary(), needs_offers=False
    )
    assert chips.needs == {} and chips.offers == {}


def test_extraction_is_deterministic(sim_community):
    p = _sim_file(sim_community, "helix", "slides")
    a, b = extract_file(p), extract_file(p)
    assert json.dumps(a.to_json(), sort_keys=True) == json.dumps(b.to_json(), sort_keys=True)


def test_decompression_bombs_and_pdf_octal_and_readme_symlink(tmp_path):
    from anagram.local.index import extract as ex_mod
    from anagram.local.index.media import sniff_bytes

    # PNG zTXt bomb exceeding MAX_TEXT_BYTES is skipped without unbounded expansion.
    bomb = zlib.compress(b"A" * (ex_mod.MAX_TEXT_BYTES + 10_000))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body))
            + kind
            + body
            + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"zTXt", b"Comment\x00\x00" + bomb)
        + chunk(b"IEND", b"")
    )
    got_png = extract_bytes(png, "bomb.png", "image/png")
    assert got_png.meta.get("text") == {}

    # PDF FlateDecode bomb exceeding MAX_PDF_STREAM is skipped cleanly.
    pdf_bomb = _pdf(b"(" + b"B" * (ex_mod.MAX_PDF_STREAM + 10_000) + b") Tj", flate=True)
    got_pdf = extract_bytes(pdf_bomb, "bomb.pdf", "application/pdf")
    assert got_pdf.text == ""

    # _pdf_unescape does not crash on \8 or \9 (non-octal digits).
    assert ex_mod._pdf_unescape(b"\\8\\9\\101") == b"89A"

    # Oversized ZIP entry payload is capped and rejected.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", "<w:t>" + "C" * (ex_mod.MAX_ZIP_PART + 2048) + "</w:t>")
    got_docx = extract_bytes(buf.getvalue(), "bomb.docx", media_type_for("bomb.docx"))
    assert got_docx.text == ""

    # Media sniff on EPUB-like zip with huge mimetype entry stays bounded.
    ebuf = io.BytesIO()
    with zipfile.ZipFile(ebuf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", b"x" * 100_000)
    assert sniff_bytes(ebuf.getvalue(), "huge.zip") == "application/zip"

    # Symlinked README.md in repo_summary is skipped.
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET README")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").symlink_to(secret)
    summary = repo_summary(repo, None, {})
    assert "TOP SECRET README" not in summary.text
