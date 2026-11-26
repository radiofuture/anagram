"""Split a `Document` into chunks for full-text and vector search.

A chunk is a run of blocks with at most `MAX_CHARS` characters. A heading
starts a new chunk and stays with the text after it. A container (slide,
page, sheet, message) starts a new chunk. A long block is split at sentence or line ends. Each chunk keeps the
anchor of its first block (with the slide or page, if any), so a search hit
points to a place in the document. Quoted third-party text is not in these
chunks: `context_chunks` makes its own chunks (class `context`), which go to
a different table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from anagram.local.index.convert.document import CONTAINER_KINDS, Block, Document

MAX_CHARS = 1200
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n")


@dataclass(frozen=True)
class Chunk:
    n: int
    anchor: str
    text: str


def _pieces(text: str, limit: int) -> list[str]:
    if len(text) <= limit:
        return [text]
    out, cur = [], ""
    for part in _SPLIT.split(text):
        if not part:
            continue
        while len(part) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(part[:limit])
            part = part[limit:]
        if cur and len(cur) + 1 + len(part) > limit:
            out.append(cur)
            cur = part
        else:
            cur = f"{cur} {part}".strip()
    if cur:
        out.append(cur)
    return out


def _anchor(b: Block) -> str:
    return f"{b.parent}/{b.anchor}" if b.parent else b.anchor


def chunk_document(doc: Document, max_chars: int = MAX_CHARS) -> list[Chunk]:
    blocks = doc.blocks
    if not blocks and doc.markdown.strip():
        blocks = [Block("para", doc.markdown.strip(), "para-1")]
    chunks: list[Chunk] = []
    cur: list[str] = []
    anchor: str | None = None

    def flush() -> None:
        nonlocal anchor
        text = "\n".join(cur).strip()
        if text:
            chunks.append(Chunk(len(chunks), anchor or "doc", text))
        cur.clear()
        anchor = None

    for b in blocks:
        if b.kind in CONTAINER_KINDS:
            flush()
            continue
        text = f"{'#' * max(b.level, 1)} {b.text}" if b.kind == "heading" else b.text
        if not text.strip():
            continue
        if b.kind == "heading" and cur and any(not c.startswith("#") for c in cur):
            flush()
        if cur and sum(len(c) + 1 for c in cur) + len(text) > max_chars:
            flush()
        if len(text) > max_chars:
            flush()
            for piece in _pieces(text, max_chars):
                chunks.append(Chunk(len(chunks), _anchor(b), piece))
            continue
        if not cur:
            anchor = _anchor(b)
        cur.append(text)
    flush()
    if doc.title and chunks and doc.title not in chunks[0].text:
        first = chunks[0]
        chunks[0] = Chunk(0, first.anchor, f"{doc.title}\n{first.text}")
    return chunks


def context_chunks(doc: Document, max_chars: int = MAX_CHARS) -> list[Chunk]:
    """Chunks of `doc.quoted`: text that other people wrote (quoted mail, a
    received message). They go to the table `context_chunk` only (class
    `context`, integration 1.9). Each anchor starts with `quoted/`."""
    if not doc.quoted.strip():
        return []
    out: list[Chunk] = []
    for para in re.split(r"\n\s*\n", doc.quoted.strip()):
        for piece in _pieces(para.strip(), max_chars) if para.strip() else []:
            out.append(Chunk(len(out), f"quoted/para-{len(out) + 1}", piece))
    return out
