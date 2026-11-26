"""Every relative link in the Markdown files of the repository resolves to a
file or folder inside the repository. A link that leaves the repository
breaks when the repository is cloned alone."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".venv", ".git", "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache", "htmlcov"}
# [text](target) and [text](target "title"); images too. Not inside code spans.
LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
CODE_BLOCK = re.compile(r"```.*?```", re.DOTALL)
CODE_SPAN = re.compile(r"`[^`\n]*`")


def _markdown_files() -> list[Path]:
    return sorted(p for p in ROOT.rglob("*.md") if not SKIP.intersection(p.relative_to(ROOT).parts))


def _relative_links(text: str) -> list[str]:
    text = CODE_SPAN.sub("", CODE_BLOCK.sub("", text))
    out = []
    for target in LINK.findall(text):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue  # a URL (https:, mailto:) or a heading on the same page
        out.append(unquote(target.split("#", 1)[0]))
    return out


def test_markdown_files_are_found():
    names = {p.relative_to(ROOT).as_posix() for p in _markdown_files()}
    assert {"README.md", "spec/index.md"} <= names


@pytest.mark.parametrize("doc", _markdown_files(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_relative_links_resolve_inside_the_repository(doc: Path):
    bad = []
    for target in _relative_links(doc.read_text(encoding="utf-8")):
        path = (doc.parent / target).resolve()
        if not path.is_relative_to(ROOT):
            bad.append(f"{target} (outside the repository)")
        elif not path.exists():
            bad.append(f"{target} (missing)")
    assert not bad, bad
