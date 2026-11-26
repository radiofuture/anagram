"""Extractive outputs: a model chooses item text, it does not write text.

    cands = extractive.title_candidates(doc, info, text, guard)
    sents = extractive.Sentences(text)
    sents.find("a claim the model wrote")  # the item sentence(s), or None
    extractive.occurs("nbt7", text)         # a name is in the item

This is layer 1 of the defence against planted instructions (primitive
`planted-instructions.md`). Layer 2 is detection (`planted.py`). Detection
must recognise an order; it is English only, and a new wording can get
through (step 18 fix: 2 of 10 held-out orders with llama3.2 and gemma3:4b).
Layer 1 does not need to recognise the order. The model writes no free text
into a kept fact:

- Title: the code makes the candidates from the item (the rules title, the
  headings, the file name as words, the first short sentences). The model
  gives the number of one candidate. No candidate copies a flagged span.
- Claim and summary: the kept text is a sentence (or two adjacent
  sentences) of the item, word for word. The model output must be a part of
  it after normalisation (case, white space, quote marks, markup) and must
  hold at least `COVER` of its words. A paraphrase is not kept.
- Entity and person: a string that is in the item, at word limits, and in
  text that the other checks accept.

Prose is the paragraphs, headings, and list items. Table rows, fenced code,
and quoted lines ("> ", the text of another person) are not prose: no title
candidate and no claim comes from them. A CJK character counts as one word.

A planted order can then at most choose which real text of the item becomes
the title or a claim. That text is in the person's own item; text of other
people does not get to the model (primitive `third-party-text.md`), and the
rules title already shows the first heading of the item with no model.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import TYPE_CHECKING

from anagram.local.understanding import titles

if TYPE_CHECKING:
    from anagram.local.index.convert.document import Document
    from anagram.local.index.enrich import ItemInfo
    from anagram.local.understanding.planted import Guard

COVER = 0.6  # share of the words of the kept sentence(s) that the output must have
MIN_WORDS = 3  # an output with fewer words is not a claim
MAX_SENTENCES = 2  # a claim is at most two adjacent sentences
MAX_CHARS = 300
TITLES = 8  # title candidates at most
FIRST_SENTENCES = 3  # first sentences of the item that can be a title

_QUOTES = str.maketrans({"“": '"', "”": '"', "„": '"', "«": '"', "»": '"', "‘": "'",
                         "’": "'", "–": "-", "—": "-", " ": " "})  # fmt: skip
_EMPHASIS = re.compile(r"[*_`]+")
_PREFIX = re.compile(r"^\s*(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+)+")
_SPLIT = re.compile(r"(?<=[.!?])[\"')\]]*\s+(?=\S)|(?<=[。！？])")
# A CJK character is one word: these scripts put no space between words, so a
# long sentence would count as a few "words" and pass the word limits.
_CJK = r"\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
_WORD = re.compile(rf"[{_CJK}]|[^\W_{_CJK}]+", re.UNICODE)
_EDGE = " \t.,;:!?\"'()[]"


def _norm(text: str) -> str:
    """Quote marks, dashes, and spaces made plain; markup out; one space."""
    return " ".join(_EMPHASIS.sub("", (text or "").translate(_QUOTES)).split())


def _key(text: str) -> str:
    return _norm(text).casefold().strip(_EDGE)


def _words(text: str) -> list[str]:
    return _WORD.findall(text.casefold())


def blocks(text: str) -> list[str]:
    """The prose blocks of `text`: paragraphs, headings, list items. Table
    rows and fenced code are not prose. A quoted line ("> ") is the text of
    another person (primitive `third-party-text.md`). These are left out."""
    out: list[str] = []
    para: list[str] = []
    fence = False

    def flush() -> None:
        if para:
            out.append(" ".join(para))
            para.clear()

    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith(("```", "~~~")):
            flush()
            fence = not fence
            continue
        if fence or not s or s.startswith(("|", ">")):
            flush()
            continue
        if _PREFIX.match(s):
            flush()
            body = _PREFIX.sub("", s).strip()
            if body:
                out.append(body)
            continue
        para.append(s)
    flush()
    return [b for b in (_norm(b) for b in out) if b]


def headings(text: str) -> list[str]:
    """The Markdown headings of `text`, not the lines of fenced code."""
    out, fence = [], False
    for line in (text or "").splitlines():
        if line.strip().startswith(("```", "~~~")):
            fence = not fence
        elif not fence and re.match(r"#{1,6}\s", line):
            out.append(line.lstrip("#").strip())
    return [h for h in out if h]


def sentences(text: str) -> list[str]:
    """The sentences of the prose blocks of `text`, as they are in the item
    (markup out, one space)."""
    out = []
    for b in blocks(text):
        out += [s.strip() for s in _SPLIT.split(b) if s.strip()]
    return out


class Sentences:
    """The sentences of one item text, for `find`."""

    def __init__(self, text: str) -> None:
        self.items = sentences(text)
        keys = [s.casefold() for s in self.items]
        self.starts: list[int] = []
        at = 0
        for k in keys:
            self.starts.append(at)
            at += len(k) + 1
        self.joined = " ".join(keys)

    def find(self, output: str | None, cover: float = COVER) -> str | None:
        """The item sentence (or two adjacent sentences) that `output` is a
        part of, word for word after normalisation, if `output` has at least
        `cover` of their words; else None."""
        q = _key(_PREFIX.sub("", output or ""))
        got = _words(q)
        if len(got) < MIN_WORDS or not self.items:
            return None
        at = self.joined.find(q)
        while at >= 0:
            first = bisect_right(self.starts, at) - 1
            last = bisect_right(self.starts, at + len(q) - 1) - 1
            text = " ".join(self.items[first : last + 1])
            end = at + len(q)
            edges = (self.joined[at - 1 : at] if at else "") + self.joined[end : end + 1]
            if (
                not any(ch.isalnum() for ch in edges)  # at word limits
                and last - first < MAX_SENTENCES
                and len(text) <= MAX_CHARS
                and len(got) / max(1, len(_words(text))) >= cover
            ):
                return text
            at = self.joined.find(q, at + 1)
        return None


def occurs(name: str, text: str) -> int:
    """How often `name` is in `text`, at word limits (no case)."""
    key = _key(name)
    if not key or not _words(key):
        return 0
    return len(re.findall(r"(?<!\w)" + re.escape(key) + r"(?!\w)", _norm(text).casefold()))


def title_candidates(
    doc: Document, info: ItemInfo | None, text: str, guard: Guard | None = None
) -> list[str]:
    """The titles a model may choose from, made from the item by code: the
    rules title first, then the headings, the file name as words (only if
    the item has no heading), and the first sentences that are short enough
    for a title (`titles.clean_phrase`). No candidate copies a flagged span."""
    raw: list[str | None] = [titles.doc_title(doc, info)]
    heads = headings(text)
    raw += heads
    if not heads:  # with a heading, the name adds little and splits the cache of equal text
        raw.append(titles.humanize(info.name if info is not None else None))
    raw += sentences(text)[:FIRST_SENTENCES]
    out: list[str] = []
    seen: set[str] = set()
    for r in raw:
        got = titles.clean_phrase(r)
        if not got or got.casefold() in seen:
            continue
        if len(got.split()) + len(re.findall(f"[{_CJK}]", got)) > titles.TITLE_WORDS:
            continue  # a title is short, also in a CJK script (no spaces)
        if guard is not None and guard.tainted(got):
            continue
        seen.add(got.casefold())
        out.append(got)
        if len(out) >= TITLES:
            break
    return out
