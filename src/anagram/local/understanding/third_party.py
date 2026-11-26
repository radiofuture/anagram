"""Items whose text another person wrote (spec/threat-model.md section 16).

The promise: text that another person wrote (a received mail, its subject and
its attachments, quoted replies, a Drive file of another owner) is searchable
only in the private space, as context. It is never own text. It never goes
into matching lines, a draft, a finding proposal, the lab space, an external model,
or an assistant (MCP) answer.

Two levels:

- Part of an item: quoted text in an own mail (`extract.split_quoted`). It
  goes to `Document.quoted`, so to `context_chunk` only.
- A full item: a connector sets `extra["third_party"] = True` (`MARK`) on the
  item (a received mail, an attachment of a received mail, a Drive file of
  another owner), and gives it a neutral name. `as_context` moves all text of
  its document to `Document.quoted`, and the document meta gets the same
  mark. `LocalIndex.items(own_only=True)` leaves the item out, and the lab
  space, the external converters, and MCP `read_item` refuse it.

Rule for a doubt: when the code is not sure that the member wrote a text, the
text is third-party (fail closed).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from anagram.local.index.convert.document import Document

MARK = "third_party"

_EXT = re.compile(r"\.[a-z0-9]{1,5}$")


def marked(extra: dict | None) -> bool:
    """True if the item hints say that another person wrote the item."""
    return bool((extra or {}).get(MARK))


def as_context(doc: Document) -> Document:
    """The same document with all its text as context: no own text, no
    title, no blocks, and a meta with the mark only (a meta value such as a
    subject or a core title is text of the other person too)."""
    title = (doc.title or "").strip()
    parts = [title if title not in doc.markdown else "", doc.markdown, doc.quoted]
    quoted = "\n\n".join(p.strip() for p in parts if p and p.strip())
    meta = {MARK: True}
    if isinstance(doc.meta.get("date"), str):
        meta["date"] = doc.meta["date"]
    return Document(
        markdown="",
        title=None,
        blocks=[],
        meta=meta,
        quoted=quoted,
        converter=doc.converter,
        converter_version=doc.converter_version,
        kind=doc.kind,
        prose=doc.prose,
        note=doc.note,
    )


def _day(ms: int | None) -> str:
    if ms is None:
        return "no date"
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%d")


def mail_name(ms: int | None) -> str:
    """A neutral item name for a received mail. The subject and the name of
    the sender are text of the other person, so the name has the date only."""
    return f"Received mail, {_day(ms)}.eml"


def attachment_name(n: int, name: str, ms: int | None) -> str:
    """A neutral item name for attachment `n` of a received mail. The file
    name is the sender's text; only a short extension stays (the converters
    use it)."""
    m = _EXT.search(name.lower())
    return f"Attachment {n} of received mail, {_day(ms)}{m.group(0) if m else ''}"


def shared_file_name(time: str | None, suffix: str = "") -> str:
    """A neutral item name for a file that another person owns."""
    day = (time or "")[:10] or "no date"
    m = _EXT.search(suffix.lower())
    return f"Shared file, {day}{m.group(0) if m else ''}"
