"""Short, clean titles and owner lines for people (experience rule 9).

A title that a person sees is a short phrase from the person's own words. It
is never text joined from slides, never an internal reference, and never a
path. These helpers have no model. The `understand` stage can give a better
title; these give the title when there is no model.

- `owner_lines(markdown)`: the lines of the owner's text with no HTML
  comments and no internal reference.
- `clean_phrase(text)`: one short phrase, or None if the text is not a title.
- `humanize(name)`: a file or folder name as words ("nbt7-grid-screening" ->
  "Nbt7 grid screening").
- `doc_title(doc, info)`: the best title of one item.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from anagram.local.index.convert.document import Document
    from anagram.local.index.enrich import ItemInfo

TITLE_CHARS = 90
# A title is a short phrase. More words than this is text, not a title (for
# example lines of a slide joined into one).
TITLE_WORDS = 14

GENERIC = frozenset(
    {
        "agenda",
        "background",
        "contents",
        "document",
        "intro",
        "introduction",
        "notes",
        "outline",
        "overview",
        "q&a",
        "questions",
        "readme",
        "slide",
        "summary",
        "table of contents",
        "thank you",
        "thanks",
        "title",
        "untitled",
    }
)
# "Internal ref: X" and the text after it on the same line.
_INTERNAL = re.compile(r"\binternal\s+ref(?:erence)?\b\s*[:#]?.*$", re.IGNORECASE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_SLIDE = re.compile(r"<!--\s*slide number:\s*\d+\s*-->", re.IGNORECASE)
_REPLY = re.compile(r"^(?:(?:re|fwd?|aw|sv)\s*:\s*)+", re.IGNORECASE)
_MARKUP = re.compile(r"[*_`]+")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_PATHLIKE = re.compile(r"(?:^|\s)(?:~|\.{1,2})?[\w.-]*[/\\][\w.-]+")
_CODE = re.compile(r"(?:[=;{}<>]|\(\)|\[\]|^\s*(?:import|def|class|from|return)\s)")
_HEXISH = re.compile(r"^[0-9a-f-]{8,}$", re.IGNORECASE)


def strip_internal(line: str) -> str:
    """The line with no internal reference (and no separator left before it)."""
    cut = _INTERNAL.sub("", line)
    return cut.rstrip(" \t:;,-") if cut != line else line


def owner_lines(markdown: str) -> list[str]:
    """The non-empty lines of the owner's text, with no HTML comment and no
    internal reference. Slide markers become an empty line, so each slide is
    one block."""
    text = _SLIDE.sub("\n", markdown or "")
    text = _COMMENT.sub("", text)
    out = []
    for line in text.splitlines():
        line = strip_internal(line)
        if line.strip():
            out.append(line)
    return out


def owner_text(markdown: str) -> str:
    """The owner's text for rules and prompts: `owner_lines` with the blank
    lines between blocks kept."""
    text = _SLIDE.sub("\n\n", markdown or "")
    text = _COMMENT.sub("", text)
    lines = [strip_internal(line) for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def is_slides(markdown: str) -> bool:
    return bool(_SLIDE.search(markdown or ""))


def slide_heads(markdown: str) -> list[str]:
    """The first line of each slide (the slide title)."""
    heads = []
    for part in _SLIDE.split(markdown or "")[1:]:
        lines = [x for x in (strip_internal(s) for s in part.splitlines()) if x.strip()]
        if lines:
            heads.append(lines[0])
    return heads


def cut(text: str, limit: int) -> str:
    """`text` cut at a word limit to at most `limit` characters."""
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:-")


def clean_phrase(text: str | None, limit: int = TITLE_CHARS) -> str | None:
    """One short phrase for people, or None if `text` is not a usable title:
    empty, generic ("Outline"), code, a path, an ID, a reference, or more than
    `TITLE_WORDS` words."""
    if not text:
        return None
    line = next((s for s in str(text).splitlines() if s.strip()), "")
    line = strip_internal(_COMMENT.sub("", line))
    line = _BULLET.sub("", line.strip().lstrip("#").strip())
    line = _REPLY.sub("", _MARKUP.sub("", line))
    line = " ".join(line.split()).strip(" .:;,-")
    if len(line) < 3 or not re.search(r"[A-Za-z]{2}", line):
        return None
    if line.lower() in GENERIC or _HEXISH.match(line.replace(" ", "")):
        return None
    if _PATHLIKE.search(line) or _CODE.search(line) or len(line.split()) > TITLE_WORDS:
        return None
    return cut(line, limit) or None


def humanize(name: str | None) -> str | None:
    """A file name as words: no folder, no extension, no separators."""
    if not name:
        return None
    stem = PurePosixPath(str(name).replace("\\", "/")).name
    while "." in stem.strip("."):
        head, _, ext = stem.rpartition(".")
        if not head or len(ext) > 5 or " " in ext:
            break
        stem = head
    words = " ".join(re.split(r"[-_.\s]+", stem)).strip()
    if not words or _HEXISH.match(words.replace(" ", "")):
        return None
    if words == words.lower():
        words = words[0].upper() + words[1:]
    return clean_phrase(words)


def _sluggy(text: str) -> bool:
    """A file or repository name, not words: one token with separators, or
    one token in lower case."""
    text = text.strip()
    return " " not in text and (bool(re.search(r"[-_]", text)) or text == text.lower())


def doc_title(doc: Document | None, info: ItemInfo | None = None) -> str | None:
    """The best title of one item with no model, or None."""
    candidates: list[str | None] = []
    name = info.name if info is not None else None
    if info is not None and info.kind not in ("file", "") and name:
        candidates.append(name)  # a record: the commit message, the work title
    if doc is not None:
        if doc.kind == "slides" or is_slides(doc.markdown):
            candidates += slide_heads(doc.markdown)
        if doc.title:
            title = doc.title
            candidates.append(humanize(title) if _sluggy(title) else title)
        for line in owner_lines(doc.markdown)[:3]:
            if line.lstrip().startswith("#"):
                head = line.lstrip("# ").strip()
                candidates.append(humanize(head) if _sluggy(head) else head)
    candidates.append(humanize(name))
    for c in candidates:
        got = clean_phrase(c)
        if got:
            return got
    return None
