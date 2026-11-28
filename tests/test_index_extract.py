"""On-device extraction of each format. Deterministic, standard library only."""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

import pytest
from indexkit import lab

from anagram.local.index.convert import BasicConverter, Blob
from anagram.local.index.extract import (
    MAX_IPYNB_CELLS,
    extract_bytes,
    extract_file,
    extract_ipynb,
    extract_tex,
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


def test_ipynb_extracts_markdown_code_and_concise_outputs():
    big_b64 = "A" * 4000
    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {"kernelspec": {"language": "Python"}},
        "cells": [
            {
                "cell_type": "markdown",
                "source": ["# NbT7 Affinity Analysis\n", "\nWe need GPU hours for docking."],
            },
            {
                "cell_type": "code",
                "source": ["import numpy as np\n", "print('Kd = 12 nM')\n"],
                "outputs": [
                    {"output_type": "stream", "name": "stdout", "text": ["Kd = 12 nM\n"]},
                    {
                        "output_type": "display_data",
                        "data": {
                            "image/png": big_b64,
                            "text/html": "<div>" + big_b64 + "</div>",
                            "text/plain": ["<Figure size 640x480>", "\n" + big_b64],
                        },
                    },
                    {
                        "output_type": "execute_result",
                        "data": {"text/plain": "r2 = 0.94"},
                    },
                ],
            },
            {
                "cell_type": "code",
                "source": "doc = '''```triple```'''\n",
                "outputs": [{"output_type": "error", "ename": "ValueError", "evalue": "bad input"}],
            },
        ],
    }
    raw = json.dumps(nb).encode("utf-8")
    ex = extract_ipynb(raw)
    assert ex.kind == "notebook" and ex.prose is True
    assert ex.title == "NbT7 Affinity Analysis"
    assert ex.meta["language"] == "python"
    assert ex.meta["cells"] == 3 and ex.meta["markdown_cells"] == 1 and ex.meta["code_cells"] == 2
    assert "# NbT7 Affinity Analysis" in ex.text
    assert "```python\nimport numpy as np\nprint('Kd = 12 nM')\n```" in ex.text
    assert "Kd = 12 nM" in ex.text
    assert "r2 = 0.94" in ex.text
    assert "ValueError: bad input" in ex.text
    assert big_b64 not in ex.text
    assert "<div>" not in ex.text
    # Code cell containing triple backticks gets a 4-backtick fence.
    assert "````python" in ex.text

    # Wired into BasicConverter and chips extraction.
    mt = media_type_for("analysis.ipynb")
    assert mt == "application/x-ipynb+json"
    assert mt in BasicConverter.accepts
    doc = BasicConverter().convert(Blob(data=raw, name="analysis.ipynb", media_type=mt))
    assert doc.kind == "notebook" and doc.prose is True
    assert any(b.kind == "heading" for b in doc.blocks)
    assert any(b.kind == "code" for b in doc.blocks)
    chips = extract_chips(doc.markdown, default_vocabulary())
    assert chips.needs == {"anagram:gpu-compute": 1}


def test_ipynb_handles_malformed_and_oversized_inputs():
    bad = extract_ipynb(b"{not valid json")
    assert bad.kind == "notebook" and bad.text == "" and "does not parse" in (bad.note or "")

    no_cells = extract_ipynb(b'{"nbformat": 4}')
    assert no_cells.kind == "notebook" and "missing cells" in (no_cells.note or "")

    many_cells = {
        "cells": [
            {"cell_type": "markdown", "source": f"Cell {i}"} for i in range(MAX_IPYNB_CELLS + 5)
        ]
    }
    capped = extract_ipynb(json.dumps(many_cells).encode("utf-8"))
    assert capped.meta["truncated"] is True
    assert f"Cell {MAX_IPYNB_CELLS - 1}" in capped.text
    assert f"Cell {MAX_IPYNB_CELLS + 1}" not in capped.text


def test_tex_extracts_metadata_sections_prose_and_compact_math():
    tex = rb"""
\documentclass[11pt]{article}
\usepackage{amsmath}
\usepackage{graphicx}
% Secret preamble comment that must not leak
\title{Structure of the {NbT7} \emph{Transporter} at 2.8~\AA}
\author{Mei Chen\thanks{Northbridge} \and Tomas Reyes}

\begin{document}
\maketitle
\begin{abstract}
We resolved three states with 95\% completeness. % inline comment
We need \textbf{GPU hours} for \emph{binding-affinity} simulations.
\end{abstract}

\section{Introduction}\label{sec:intro}
\noindent The pocket binds with $K_d = 12\text{ nM}$ and 15\% variance.
See \href{https://example.org/data}{our dataset} for details.
\vspace{1cm}

\subsection{Methods}
\begin{itemize}
\item[Cryo-EM] Grids frozen at \texttt{300 kV}.
\item \textbf{\textit{Docking}} scored \underline{1,200 ligands}.
\end{itemize}

\subsubsection{Energy Model}
\paragraph{Calibration}
\begin{equation}\label{eq:kd}
\Delta G = R T \ln K_d
\end{equation}

\end{document}
Trailing notes after end document must not appear.
"""

    ex = extract_tex(tex, "paper.tex")
    assert ex.kind == "document" and ex.prose is True
    assert ex.title is not None and "NbT7 Transporter" in ex.title
    assert ex.meta["authors"] == "Mei Chen, Tomas Reyes"
    assert "95% completeness" in ex.meta["abstract"]
    assert "Secret preamble comment" not in ex.text
    assert "inline comment" not in ex.text
    assert "\\usepackage" not in ex.text
    assert "\\documentclass" not in ex.text
    assert "\\label" not in ex.text
    assert "\\vspace" not in ex.text
    assert "\\noindent" not in ex.text
    assert "Trailing notes after end document" not in ex.text
    assert "## Abstract" in ex.text
    assert "# Introduction" in ex.text
    assert "## Methods" in ex.text
    assert "### Energy Model" in ex.text
    assert "#### Calibration" in ex.text
    assert "95% completeness" in ex.text
    assert "15% variance" in ex.text
    assert "our dataset" in ex.text and "https://example.org/data" not in ex.text
    assert "- Cryo-EM: Grids frozen at 300 kV." in ex.text
    assert "- Docking scored 1,200 ligands." in ex.text
    assert "$K_d = 12 nM$" in ex.text
    assert "\\Delta G = R T \\ln K_d" in ex.text
    chips = extract_chips(ex.text, default_vocabulary())
    assert chips.needs == {"anagram:gpu-compute": 1}


def test_tex_fragment_and_unclosed_braces_are_bounded():
    fragment = (
        b"% Fragment comment\n"
        b"\\section*{Supplementary Methods}\n"
        b"Yield improved by 12\\% with \\textbf{nested {braces} and \\emph{italics}}.\n"
        b"\\textbf{unclosed brace " + b"{" * 200 + b" tail\n"
    )
    ex = extract_tex(fragment, "supp.tex")
    assert ex.kind == "document" and ex.prose is True
    assert "# Supplementary Methods" in ex.text
    assert "12% with nested {braces} and italics." in ex.text
    assert "Fragment comment" not in ex.text
    assert "tail" in ex.text


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
