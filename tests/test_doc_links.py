"""Every relative link and #heading anchor in the Markdown files of the
repository resolves to a file, folder, or heading inside the repository. A link
that leaves the repository breaks when the repository is cloned alone."""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".venv", ".git", "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache", "htmlcov"}
# [text](target) and [text](target "title"); images too. Not inside code spans.
LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
CODE_BLOCK = re.compile(r"(```|~~~).*?\1", re.DOTALL)
CODE_SPAN = re.compile(r"`[^`\n]*`")
ATX_HEADING = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+[ \t]*)?$", re.MULTILINE)
MD_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
HTML_TAG = re.compile(r"<[^>]+>")
NON_SLUG = re.compile(r"[^\w\s-]", re.UNICODE)


def _markdown_files() -> list[Path]:
    return sorted(p for p in ROOT.rglob("*.md") if not SKIP.intersection(p.relative_to(ROOT).parts))


def _github_slug(heading: str) -> str:
    """GitHub-style heading anchor slug for a single Markdown heading line."""
    text = MD_LINK.sub(r"\1", heading)
    text = HTML_TAG.sub("", text)
    text = text.replace("`", "")
    text = text.strip().lower()
    text = NON_SLUG.sub("", text)
    return text.replace(" ", "-")


@cache
def _heading_anchors(path: Path) -> frozenset[str]:
    text = CODE_BLOCK.sub("", path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for match in ATX_HEADING.finditer(text):
        base = _github_slug(match.group(1))
        if not base:
            continue
        seen = counts.get(base, 0)
        counts[base] = seen + 1
        anchors.add(base if seen == 0 else f"{base}-{seen}")
    return frozenset(anchors)


def _local_links(text: str) -> list[tuple[str, str]]:
    """Return `(file_target, anchor)` pairs for relative file and #heading links."""
    text = CODE_SPAN.sub("", CODE_BLOCK.sub("", text))
    out: list[tuple[str, str]] = []
    for target in LINK.findall(text):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target):
            continue  # external URL (https:, mailto:, ...)
        file_part, _, frag = target.partition("#")
        out.append((unquote(file_part), unquote(frag)))
    return out


def test_markdown_files_are_found():
    names = {p.relative_to(ROOT).as_posix() for p in _markdown_files()}
    assert {"README.md", "spec/index.md"} <= names


def test_github_slug_handles_formatting_and_duplicates(tmp_path: Path):
    doc = tmp_path / "sample.md"
    doc.write_text(
        "# Top: `code` & [link](other.md)\n"
        "## Faster: `--ready`\n"
        "## Repeat\n"
        "## Repeat\n"
        "```md\n"
        "# Not a heading\n"
        "```\n",
        encoding="utf-8",
    )
    anchors = _heading_anchors(doc)
    assert anchors == frozenset({"top-code--link", "faster---ready", "repeat", "repeat-1"})


@pytest.mark.parametrize("doc", _markdown_files(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_relative_links_resolve_inside_the_repository(doc: Path):
    bad = []
    for file_target, anchor in _local_links(doc.read_text(encoding="utf-8")):
        path = doc.resolve() if not file_target else (doc.parent / file_target).resolve()
        if not path.is_relative_to(ROOT):
            bad.append(f"{file_target} (outside the repository)")
            continue
        if not path.exists():
            bad.append(f"{file_target} (missing)")
            continue
        if anchor and path.is_file() and path.suffix.lower() == ".md":
            if anchor.lower() not in _heading_anchors(path):
                label = f"{file_target}#{anchor}" if file_target else f"#{anchor}"
                bad.append(f"{label} (missing heading)")
    assert not bad, bad
