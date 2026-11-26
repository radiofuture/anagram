"""The `Document` model: what a converter makes from the evidence bytes.

A document is derived meaning. It is never committed and never leaves the
device. The index keeps it for one item version (meaning is keyed by
version, so old meaning stays). The evidence bytes do not change.

- `markdown`: the owner's text as Markdown.
- `blocks`: the structure. Leaf kinds: heading, para, table, code, figure,
  caption, cell_range, image. Container kinds: slide, page, sheet, message.
  The blocks after a container have its anchor as `parent`.
- Each block has an `anchor` and a `span`. The anchor is the identity of the
  block: a hash of its text (of the text of its children for a container),
  so it stays the same when an edit changes other blocks. The span is the
  place in the file (`Span`).
- `quoted`: third-party text (for example quoted email). It is kept apart
  and never goes to chips, claims, a drafter, or embeddings.
- `converter`, `converter_version`: who made the document.
- `schema`: the document schema. 1: blocks with no span and anchors by
  position (`para-3`); old documents stay readable. 2: spans, and anchors by
  content (spec/index.md section 5.2).
"""

from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass, field

from anagram.local.index.extract import Extracted

DOC_SCHEMA = 2
LEAF_KINDS = ("heading", "para", "table", "code", "figure", "caption", "cell_range", "image")
CONTAINER_KINDS = ("slide", "page", "sheet", "message")
BLOCK_KINDS = LEAF_KINDS + CONTAINER_KINDS
_SLIDE = re.compile(r"^<!--\s*Slide number:\s*(\d+)\s*-->$", re.I)
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_HASH_HEX = 8  # 32 bits: an anchor must be unique in one document only
_EOL = "\r\n\x0b\x0c\x1c\x1d\x1e\x85  "  # what str.splitlines splits at


@dataclass(frozen=True)
class Span:
    """The place of a block in the evidence file. Each converter fills the
    fields that its type has. The other fields stay None.

    - `page`, `bbox`: page of a PDF or image (1-based) and box (x0, y0, x1,
      y1 in points, origin at the top left of the page).
    - `slide`, `shape`: slide number (1-based) and shape ID or name (pptx).
    - `sheet`, `cells`: sheet name and cell range, for example `A1:C9`
      (xlsx, CSV).
    - `message`, `part`: Message-ID and MIME part path, for example `1.2`.
    - `lines`: first and last line (1-based, inclusive) of `Document.markdown`.
    """

    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    slide: int | None = None
    shape: str | None = None
    sheet: str | None = None
    cells: str | None = None
    message: str | None = None
    part: str | None = None
    lines: tuple[int, int] | None = None

    def to_json(self) -> dict:
        out: dict = {}
        for k in Span.__dataclass_fields__:
            v = getattr(self, k)
            if v is not None:
                out[k] = list(v) if isinstance(v, tuple) else v
        return out

    @classmethod
    def from_json(cls, obj: dict) -> Span:
        kw = {k: obj[k] for k in Span.__dataclass_fields__ if obj.get(k) is not None}
        for k in ("bbox", "lines"):
            if k in kw:
                kw[k] = tuple(kw[k])
        return cls(**kw)


@dataclass(frozen=True)
class Block:
    kind: str
    text: str
    anchor: str
    level: int = 0  # heading level
    parent: str | None = None  # anchor of the container that holds it
    span: Span | None = None
    # Data of the kind, for example `reply_to`, `from` and `date` of a
    # message, `header_row` of a cell range, `caption` (an anchor) of a figure.
    attrs: dict = field(default_factory=dict, hash=False)

    def to_json(self) -> dict:
        out = {
            "anchor": self.anchor,
            "kind": self.kind,
            "level": self.level,
            "parent": self.parent,
            "text": self.text,
        }
        if self.span is not None:
            out["span"] = self.span.to_json()
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        return out

    @classmethod
    def from_json(cls, obj: dict) -> Block:
        span = obj.get("span")
        return cls(
            obj["kind"],
            obj["text"],
            obj["anchor"],
            obj.get("level", 0),
            obj.get("parent"),
            Span.from_json(span) if span is not None else None,
            dict(obj.get("attrs") or {}),
        )


def norm_text(text: str) -> str:
    """Text with each run of white space as one space."""
    return " ".join(text.split())


@dataclass
class Document:
    markdown: str
    title: str | None = None
    blocks: list[Block] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    quoted: str = ""
    converter: str = ""
    converter_version: str = ""
    kind: str = "document"
    prose: bool = True  # False: do not look for need and offer cues
    note: str | None = None
    schema: int = DOC_SCHEMA

    @property
    def has_third_party(self) -> bool:
        return bool(self.quoted.strip())

    def to_json(self) -> dict:
        return {
            "schema": self.schema,
            "markdown": self.markdown,
            "title": self.title,
            "blocks": [b.to_json() for b in self.blocks],
            "meta": self.meta,
            "quoted": self.quoted,
            "converter": self.converter,
            "converter_version": self.converter_version,
            "kind": self.kind,
            "prose": self.prose,
            "note": self.note,
        }

    @classmethod
    def from_json(cls, obj: dict) -> Document:
        return cls(
            markdown=obj["markdown"],
            title=obj.get("title"),
            blocks=[Block.from_json(b) for b in obj.get("blocks", [])],
            meta=obj.get("meta") or {},
            quoted=obj.get("quoted", ""),
            converter=obj.get("converter", ""),
            converter_version=obj.get("converter_version", ""),
            kind=obj.get("kind", "document"),
            prose=obj.get("prose", True),
            note=obj.get("note"),
            schema=obj.get("schema", 1),
        )

    def locate(self, text: str) -> Block | None:
        """The first leaf block that holds `text` (case and runs of white
        space do not matter), or None."""
        q = norm_text(text).lower()
        if not q:
            return None
        for b in self.blocks:
            if b.kind not in CONTAINER_KINDS and q in norm_text(b.text).lower():
                return b
        return None

    def span_of(self, text: str) -> dict | None:
        """The span of a fact with this text: the anchor and the parent of the
        block that holds the text, and the span of that block. None if no
        block holds it."""
        b = self.locate(text)
        if b is None:
            return None
        out: dict = {"anchor": b.anchor, "parent": b.parent}
        if b.span is not None:
            out.update(b.span.to_json())
        return out

    def to_extracted(self) -> Extracted:
        return Extracted(
            kind=self.kind,
            title=self.title,
            text=self.markdown,
            quoted=self.quoted,
            prose=self.prose,
            meta=self.meta,
            note=self.note,
        )

    @classmethod
    def from_extracted(cls, ex: Extracted, converter: str, converter_version: str) -> Document:
        return cls(
            markdown=ex.text,
            title=ex.title,
            blocks=blocks_from_markdown(ex.text),
            meta=ex.meta,
            quoted=ex.quoted,
            converter=converter,
            converter_version=converter_version,
            kind=ex.kind,
            prose=ex.prose,
            note=ex.note,
        )


def blocks_from_markdown(md: str) -> list[Block]:
    """Split Markdown into blocks, with spans and anchors by content. Form
    feeds (`\\f`) mark pages and `<!-- Slide number: N -->` comments mark
    slides (the forms that markitdown writes)."""
    out = _BlockSplitter(md)
    pos = 0
    pages = md.split("\f")
    for pno, page in enumerate(pages, 1):
        if len(pages) > 1:
            out.flush()
            out.open("page", pos, Span(page=pno))
        for line in page.splitlines(keepends=True):
            out.line(line, pos)
            pos += len(line)
        out.flush()
        out.end_code(closed=False)
        pos += 1  # the form feed
    return out.finish()


Row = tuple[str, int, int]  # text, start and end offset in the Markdown


@dataclass
class _Draft:
    """A block before its anchor is known."""

    kind: str
    text: str
    start: int
    end: int
    level: int = 0
    container: int | None = None  # index of the container draft
    span: Span = field(default_factory=Span)


class _BlockSplitter:
    """The state of `blocks_from_markdown`: the drafts so far, the open
    paragraph, table, or code fence, and the container that holds them."""

    def __init__(self, md: str) -> None:
        self.drafts: list[_Draft] = []
        self.container: int | None = None
        self.page: int | None = None
        self.para: list[Row] = []
        self.table: list[Row] = []
        self.code: list[Row] | None = None  # the open fence line first
        self.newlines = [i for i, c in enumerate(md) if c == "\n"]

    def open(self, kind: str, pos: int, span: Span) -> None:
        self.drafts.append(_Draft(kind, "", pos, pos, span=span))
        self.container = len(self.drafts) - 1
        if kind == "page":
            self.page = span.page

    def add(self, kind: str, rows: list[Row], text: str, level: int = 0) -> None:
        span = Span(page=self.page)
        if self.container is not None:
            span = self.drafts[self.container].span
        self.drafts.append(_Draft(kind, text, rows[0][1], rows[-1][2], level, self.container, span))

    def flush_para(self) -> None:
        if self.para:
            self.add("para", self.para, "\n".join(r[0] for r in self.para).strip())
            self.para.clear()

    def flush_table(self) -> None:
        if self.table:
            self.add("table", self.table, "\n".join(r[0] for r in self.table))
            self.table.clear()

    def flush(self) -> None:
        self.flush_para()
        self.flush_table()

    def end_code(self, closed: bool) -> None:
        if self.code is not None:
            body = self.code[1:-1] if closed else self.code[1:]
            self.add("code", self.code, "\n".join(r[0] for r in body))
            self.code = None

    def line(self, raw: str, pos: int) -> None:
        """Read one line of a page. `pos` is its offset in the Markdown."""
        line = raw.rstrip(_EOL)
        s = line.strip()
        row = (line, pos, pos + len(line))
        if self.code is not None:
            self.code.append(row)
            if s.startswith("```"):
                self.end_code(closed=True)
            return
        if s.startswith("```"):
            self.flush()
            self.code = [row]
            return
        if m := _SLIDE.match(s):
            self.flush()
            self.open("slide", pos, Span(page=self.page, slide=int(m.group(1))))
            return
        if m := _HEADING.match(s):
            self.flush()
            self.add("heading", [row], m.group(2).strip(), len(m.group(1)))
            return
        if s.startswith("|"):
            self.flush_para()
            self.table.append((s, row[1], row[2]))
            return
        if not s:
            self.flush()
            return
        self.flush_table()
        self.para.append((s, row[1], row[2]))

    def _line_of(self, pos: int) -> int:
        return bisect.bisect_left(self.newlines, pos) + 1

    def finish(self) -> list[Block]:
        drafts = self.drafts
        children: dict[int, list[_Draft]] = {}
        for d in drafts:
            if d.container is not None:
                children.setdefault(d.container, []).append(d)
        anchors = content_anchors(
            [
                (
                    d.kind,
                    "\n".join(f"{c.kind}:{norm_text(c.text)}" for c in children.get(i, []))
                    if d.kind in CONTAINER_KINDS
                    else d.text,
                )
                for i, d in enumerate(drafts)
            ]
        )
        out = []
        for i, d in enumerate(drafts):
            end = max([d.end] + [c.end for c in children.get(i, [])])
            lines = (self._line_of(d.start), self._line_of(max(d.start, end - 1)))
            span = Span(page=d.span.page, slide=d.span.slide, lines=lines)
            parent = anchors[d.container] if d.container is not None else None
            out.append(Block(d.kind, d.text, anchors[i], d.level, parent, span))
        return out


def content_anchors(items: list[tuple[str, str]]) -> list[str]:
    """Anchors by content for (kind, text) pairs in document order:
    `<kind>-<8 hex of SHA-256 of the text>`, with `.2`, `.3` for the next
    blocks of the same kind and text. A converter that makes its own blocks
    uses this too; for a container, the text is the text of its children."""
    seen: dict[str, int] = {}
    out = []
    for kind, text in items:
        digest = hashlib.sha256(norm_text(text).encode("utf-8")).hexdigest()[:_HASH_HEX]
        base = f"{kind}-{digest}"
        seen[base] = seen.get(base, 0) + 1
        out.append(base if seen[base] == 1 else f"{base}.{seen[base]}")
    return out


def wire_blocks_v1(blocks: list[Block]) -> list[dict]:
    """The blocks in the schema-1 form that a locked format carries (the
    reading copy, spec/sharing.md): the five fields only, and anchors by
    position (`para-3`; `slide-N` and `page-N` from the span). The anchors
    by content stay on the device. A new form of the reading copy is a
    format change and needs its own plan."""
    counts: dict[str, int] = {}
    names: dict[str, str] = {}
    out = []
    for b in blocks:
        span = b.span or Span()
        if b.kind == "slide" and span.slide is not None:
            a = f"slide-{span.slide}"
        elif b.kind == "page" and span.page is not None:
            a = f"page-{span.page}"
        else:
            counts[b.kind] = counts.get(b.kind, 0) + 1
            a = f"{b.kind}-{counts[b.kind]}"
        names[b.anchor] = a
        parent = names.get(b.parent) if b.parent is not None else None
        out.append(
            {"anchor": a, "kind": b.kind, "level": b.level, "parent": parent, "text": b.text}
        )
    return out
