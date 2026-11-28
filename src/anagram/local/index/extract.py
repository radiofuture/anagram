"""On-device extraction of text and metadata. Standard library only.

Extraction makes derived meaning. It never changes the evidence bytes, and
nothing here is committed. Each extractor is deterministic.

| Format | What we read |
| --- | --- |
| text, markdown, code | the text (code: no need or offer cues) |
| LaTeX (.tex) | title, authors, abstract, headings, cleaned prose and compact math |
| Jupyter (.ipynb) | markdown cells, fenced code cells, concise plain-text outputs |
| CSV | the header and the first rows |
| .pptx, .docx | text from the zip XML parts (slide titles become headings) |
| .eml | the body; quoted third-party text is kept apart in `quoted` |
| PNG, JPEG | metadata only (size, text chunks, comments) |
| PDF | text from simple text operators in plain or Flate streams |
| CSL-JSON (Zotero) | titles, venues, notes, tags |
| Git repository | README and the file list |

PDF: there is no pure-Python PDF library in the dependencies. The small reader
here gets text from most simple PDFs. It does not read text in object streams,
in Type 3 fonts, or in fonts with custom encodings. Such a PDF gives no text and
a note. The evidence is still hashed and committed.
"""

from __future__ import annotations

import csv
import email
import email.policy
import email.utils
import io
import json
import re
import struct
import subprocess  # git is called with fixed arguments only
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from anagram.local.index.media import (  # noqa: F401
    CODE_SUFFIXES,
    IPYNB,
    MEDIA_TYPES,
    media_type_for,
)

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_ZIP_PART = 16 * 1024 * 1024
CSV_SAMPLE_ROWS = 5
MAX_IPYNB_CELLS = 2000
MAX_IPYNB_CELL_CHARS = 65_536
MAX_IPYNB_OUTPUT_CHARS = 2048
MAX_IPYNB_OUTPUTS_PER_CELL = 8
MAX_IPYNB_UNBROKEN_LINE = 512


@dataclass
class Extracted:
    kind: str
    title: str | None = None
    text: str = ""  # the owner's text, markdown-like
    quoted: str = ""  # third-party text (quoted email parts); never used for chips
    prose: bool = True  # False: do not look for need and offer cues
    meta: dict = field(default_factory=dict)
    note: str | None = None

    @property
    def has_third_party(self) -> bool:
        return bool(self.quoted.strip())

    def to_json(self) -> dict:
        return {
            "kind": self.kind,
            "meta": self.meta,
            "note": self.note,
            "prose": self.prose,
            "quoted": self.quoted,
            "text": self.text,
            "title": self.title,
        }

    @classmethod
    def from_json(cls, obj: dict) -> Extracted:
        return cls(
            kind=obj["kind"],
            title=obj["title"],
            text=obj["text"],
            quoted=obj["quoted"],
            prose=obj["prose"],
            meta=obj["meta"],
            note=obj["note"],
        )


# ------------------------------------------------------------------ text


def decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def extract_text(data: bytes, name: str, media_type: str) -> Extracted:
    text = decode_text(data)
    title = None
    for line in text.splitlines():
        if line.strip():
            title = line.strip().lstrip("#").strip()[:200]
            break
    code = media_type in ("text/x-python", "text/x-code", "text/x-r", "text/x-shellscript")
    kind = "code" if code else ("markdown" if media_type == "text/markdown" else "text")
    return Extracted(kind=kind, title=title, text=text, prose=not code)


def extract_csv(data: bytes, name: str, media_type: str) -> Extracted:
    text = decode_text(data)
    delim = "\t" if media_type == "text/tab-separated-values" else ","
    rows = []
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    try:
        for i, row in enumerate(reader):
            rows.append(row)
            if i >= CSV_SAMPLE_ROWS:
                break
    except csv.Error as exc:
        return Extracted(kind="table", note=f"csv: {exc}", prose=False)
    total = text.count("\n")
    header = rows[0] if rows else []
    lines = ["Columns: " + ", ".join(h.replace("_", " ") for h in header)]
    for row in rows[1:]:
        lines.append("Row: " + ", ".join(row))
    return Extracted(
        kind="table",
        title=Path(name).stem,
        text="\n".join(lines) + "\n",
        prose=False,
        meta={"columns": header, "rows_about": max(0, total - 1)},
    )


# ------------------------------------------------------------------ OOXML

_NS_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_NS_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_NS_P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
_NS_DC = "{http://purl.org/dc/elements/1.1/}"


def _zip_part(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_ZIP_PART:
        return None
    return zf.read(info)


def _xml(data: bytes) -> ET.Element:
    # The parts come from local files of the user. ElementTree does not load
    # external entities or DTDs.
    return ET.fromstring(data)  # noqa: S314


def _core_title(zf: zipfile.ZipFile) -> str | None:
    raw = _zip_part(zf, "docProps/core.xml")
    if raw is None:
        return None
    try:
        el = _xml(raw).find(f"{_NS_DC}title")
    except ET.ParseError:
        return None
    return el.text.strip() if el is not None and el.text else None


def extract_pptx(data: bytes, name: str, media_type: str) -> Extracted:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return Extracted(kind="slides", note="pptx: not a zip file")
    slides = []
    for n in zf.namelist():
        m = re.fullmatch(r"ppt/slides/slide(\d+)\.xml", n)
        if m:
            slides.append((int(m.group(1)), n))
    out = []
    for _num, part in sorted(slides):
        raw = _zip_part(zf, part)
        if raw is None:
            continue
        try:
            root = _xml(raw)
        except ET.ParseError:
            continue
        shapes = []
        for sp in root.iter(f"{_NS_P}sp"):
            paras = []
            for p in sp.iter(f"{_NS_A}p"):
                t = "".join(r.text or "" for r in p.iter(f"{_NS_A}t")).strip()
                if t:
                    paras.append(t)
            if paras:
                shapes.append(paras)
        if not shapes:
            continue
        # First shape is the slide title.
        out.append(f"# {' '.join(shapes[0])}")
        for paras in shapes[1:]:
            out.extend(f"- {p}" for p in paras)
        out.append("")
    title = _core_title(zf)
    return Extracted(
        kind="slides",
        title=title,
        text="\n".join(out),
        meta={"slides": len(slides)},
    )


def extract_docx(data: bytes, name: str, media_type: str) -> Extracted:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return Extracted(kind="document", note="docx: not a zip file")
    raw = _zip_part(zf, "word/document.xml")
    if raw is None:
        return Extracted(kind="document", note="docx: no word/document.xml")
    try:
        root = _xml(raw)
    except ET.ParseError as exc:
        return Extracted(kind="document", note=f"docx: {exc}")
    lines = []
    for p in root.iter(f"{_NS_W}p"):
        t = "".join(r.text or "" for r in p.iter(f"{_NS_W}t")).strip()
        if not t:
            lines.append("")
            continue
        style = p.find(f"{_NS_W}pPr/{_NS_W}pStyle")
        sval = style.get(f"{_NS_W}val", "") if style is not None else ""
        if sval.lower().startswith(("heading", "title")):
            lines.append(f"# {t}")
        else:
            lines.append(t)
            lines.append("")
    return Extracted(kind="document", title=_core_title(zf), text="\n".join(lines))


# ------------------------------------------------------------------ email

# A line that starts the quoted part of a reply or a forward. From this line
# to the end, all text is quoted (fail closed: the code does not try to find
# own text after it).
_MARKER = re.compile(
    r"^(-{2,} ?(original|forwarded) message ?-{2,}"  # Gmail, Outlook (plain)
    r"|begin forwarded message:"  # Apple Mail
    r"|_{8,}"  # Outlook: a line of underscores before the header block
    r"|-{8,})$",
    re.I,
)
# An attribution line of a reply: "On <date>, <name> wrote:" and the same in
# some other languages. It can wrap onto more lines (`_WRAP` lines).
_ATTR_START = re.compile(r"^(on|am|le|el|il|op|em|den|på)\s", re.I)
_ATTR_END = re.compile(
    r"(wrote|writes|schrieb|a écrit|escribió|ha scritto|schreef|escreveu|skrev)\s?:$", re.I
)
_WRAP = 3
# A header line of a quoted message (Outlook, Apple Mail, Thunderbird).
_HEADER = re.compile(
    r"^\*?(from|sent|date|to|cc|subject|von|gesendet|an|betreff|de|envoyé|à|objet)\*?\s?:", re.I
)
_HEADER_NAMES = re.compile(
    r"^\*?(sent|date|to|cc|subject|gesendet|an|betreff|envoyé|à|objet)\b", re.I
)


def _starts_quote(lines: list[str], i: int) -> bool:
    """True if line `i` starts the quoted part of the message."""
    s = lines[i].strip()
    if _MARKER.match(s):
        return True
    if _ATTR_END.search(s):
        return True  # one line attribution, or any line that ends in "wrote:"
    if _ATTR_START.match(s):
        for j in range(i + 1, min(len(lines), i + 1 + _WRAP)):
            t = lines[j].strip()
            if not t:
                break
            if _ATTR_END.search(t):
                return True  # an attribution that wraps
    if re.match(r"^\*?(from|von|de)\*?\s?:", s, re.I):
        # An Outlook or Apple header block: "From:" and then, in the next
        # lines, one more header ("Sent:", "Date:", "To:", "Subject:").
        for j in range(i + 1, min(len(lines), i + 5)):
            if _HEADER_NAMES.match(lines[j].strip()) and _HEADER.match(lines[j].strip()):
                return True
    return False


def split_quoted(body: str) -> tuple[str, str]:
    """Split an email body into (own text, quoted third-party text).

    Quoted: lines that start with '>', and all text from the first line that
    starts a quoted message: an attribution ("On <date>, <name> wrote:", also
    when it wraps onto more lines), a forwarded or original message marker,
    an Outlook line of underscores, or a header block ("From:" with "Sent:",
    "To:", or "Subject:"). After such a line the code does not look for own
    text again: when it is not sure, the text is quoted (fail closed)."""
    own, quoted = [], []
    lines = body.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(">"):
            quoted.append(s.lstrip("> ").rstrip() if s != ">" else "")
            continue
        if _starts_quote(lines, i):
            quoted.extend(x.rstrip() for x in lines[i:])
            break
        own.append(line)
    return "\n".join(own).strip() + "\n", "\n".join(quoted).strip()


# A subject that starts with a reply or forward prefix is the subject of the
# other person's message.
_REPLY_SUBJECT = re.compile(r"^\s*(re|fw|fwd|aw|wg|tr|sv|vs|r|rif|enc|res)\s*(\[\d+\])?\s*:", re.I)


def extract_eml(
    data: bytes,
    name: str,
    media_type: str,
    owner_emails: frozenset[str] = frozenset(),
    own: bool | None = None,
) -> Extracted:
    """A mail. `own` is a hint of the source: True when the source knows that
    the member wrote the message (the Gmail label SENT), False when it knows
    that another person wrote it. With no hint, the message is own only if
    its sender is in `owner_emails`. With no owner address or no sender, the
    message is third-party (fail closed).

    A third-party message has no own text, no title, and no subject in the
    meta: the subject and the body go to `quoted`. In an own message, a
    subject that starts with "Re:" or "Fwd:" is quoted too."""
    msg = email.message_from_bytes(data, policy=email.policy.default)
    part = msg.get_body(preferencelist=("plain",))
    body = part.get_content() if part is not None else ""
    mine, quoted = split_quoted(body)
    sender = email.utils.parseaddr(str(msg.get("From", "")))[1].lower()
    subject = " ".join(str(msg.get("Subject", "")).split())
    if own is None:
        own = bool(owner_emails and sender and sender in owner_emails)
    if not own:
        text = "\n\n".join(p for p in (subject, mine.strip(), quoted) if p)
        return Extracted(
            kind="email",
            title=None,
            text="",
            quoted=text,
            meta={"date": str(msg.get("Date", "")), "third_party": True},
            note="the member did not write this message: all text is third-party",
        )
    meta = {"date": str(msg.get("Date", "")), "from": sender, "subject": subject}
    if subject and _REPLY_SUBJECT.match(subject):
        quoted = "\n\n".join(p for p in (subject, quoted) if p)
        meta["subject"] = ""
        subject = ""
    text = f"# {subject}\n\n{mine}" if subject else mine
    return Extracted(kind="email", title=subject or None, text=text, quoted=quoted, meta=meta)


# ------------------------------------------------------------------ images


def extract_png(data: bytes, name: str, media_type: str) -> Extracted:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return Extracted(kind="image", note="png: bad signature", prose=False)
    pos, meta, texts = 8, {}, {}
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        kind = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR" and len(body) >= 8:
            meta["width"], meta["height"] = struct.unpack(">II", body[:8])
        elif kind == b"tEXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            texts[k.decode("latin-1")] = v.decode("latin-1")
        elif kind == b"zTXt" and b"\x00" in body:
            k, rest = body.split(b"\x00", 1)
            try:
                texts[k.decode("latin-1")] = zlib.decompress(rest[1:]).decode("latin-1")
            except zlib.error:
                pass
        elif kind == b"iTXt" and b"\x00" in body:
            k, rest = body.split(b"\x00", 1)
            flag = rest[0] if rest else 0
            parts = rest[2:].split(b"\x00", 2)
            if len(parts) == 3:
                raw = parts[2]
                try:
                    raw = zlib.decompress(raw) if flag else raw
                    texts[k.decode("latin-1")] = raw.decode("utf-8")
                except (zlib.error, UnicodeDecodeError):
                    pass
        elif kind == b"IEND":
            break
    meta["text"] = texts
    title = texts.get("Title") or texts.get("Description")
    lines = [f"{k}: {v}" for k, v in sorted(texts.items())]
    return Extracted(kind="image", title=title, text="\n".join(lines), prose=False, meta=meta)


def extract_jpeg(data: bytes, name: str, media_type: str) -> Extracted:
    if not data.startswith(b"\xff\xd8"):
        return Extracted(kind="image", note="jpeg: bad signature", prose=False)
    pos, meta, comments = 2, {}, []
    exif = False
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):  # end of image, start of scan
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        (length,) = struct.unpack(">H", data[pos + 2 : pos + 4])
        body = data[pos + 4 : pos + 2 + length]
        if marker == 0xFE:
            comments.append(body.decode("utf-8", "replace"))
        elif marker == 0xE1 and body.startswith(b"Exif\x00"):
            exif = True
        elif marker in (0xC0, 0xC1, 0xC2) and len(body) >= 5:
            meta["height"], meta["width"] = struct.unpack(">HH", body[1:5])
        pos += 2 + length
    meta["exif"] = exif
    meta["comments"] = comments
    return Extracted(
        kind="image",
        title=comments[0][:200] if comments else None,
        text="\n".join(comments),
        prose=False,
        meta=meta,
    )


# ------------------------------------------------------------------ PDF

_STREAM = re.compile(rb"<<(.{0,2000}?)>>\s*stream\r?\n(.*?)\r?\nendstream", re.S)
_TJ = re.compile(rb"\((?:\\.|[^\\)])*\)\s*(?:Tj|'|\")|\[(?:[^\]]*)\]\s*TJ|T\*|ET")
_STR = re.compile(rb"\(((?:\\.|[^\\)])*)\)")
_ESC = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}


def _pdf_unescape(s: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i : i + 1]
        if c == b"\\" and i + 1 < len(s):
            n = s[i + 1 : i + 2]
            if n in _ESC:
                out += _ESC[n]
                i += 2
            elif n.isdigit():
                m = re.match(rb"[0-7]{1,3}", s[i + 1 : i + 4])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
            else:
                out += n
                i += 2
        else:
            out += c
            i += 1
    return bytes(out)


def extract_pdf(data: bytes, name: str, media_type: str) -> Extracted:
    if not data.startswith(b"%PDF-"):
        return Extracted(kind="pdf", note="pdf: bad signature")
    lines: list[str] = []
    for m in _STREAM.finditer(data):
        head, body = m.group(1), m.group(2)
        if b"/FlateDecode" in head:
            try:
                body = zlib.decompress(body)
            except zlib.error:
                continue
        elif b"/Filter" in head:
            continue  # other filters are not read
        if b"BT" not in body:
            continue
        cur: list[bytes] = []
        for op in _TJ.finditer(body):
            tok = op.group(0)
            if tok in (b"T*", b"ET"):
                if cur:
                    lines.append(b"".join(cur).decode("latin-1"))
                    cur = []
                continue
            for s in _STR.finditer(tok):
                cur.append(_pdf_unescape(s.group(1)))
            if tok.rstrip().endswith((b"'", b'"')) and cur:
                lines.append(b"".join(cur).decode("latin-1"))
                cur = []
        if cur:
            lines.append(b"".join(cur).decode("latin-1"))
    text = "\n".join(line.strip() for line in lines if line.strip())
    note = None if text else "pdf: no text found by the simple reader"
    title = text.splitlines()[0][:200] if text else None
    return Extracted(kind="pdf", title=title, text=text, note=note)


# ------------------------------------------------------------------ CSL-JSON


def is_csl_json(obj: object) -> bool:
    return (
        isinstance(obj, list)
        and bool(obj)
        and all(isinstance(i, dict) and ("title" in i or "type" in i) for i in obj)
    )


def csl_item_text(item: dict) -> str:
    parts = []
    for key in ("title", "container-title", "abstract", "note"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            parts.append(v.strip())
    tags = item.get("keyword") or item.get("tags")
    if isinstance(tags, str):
        parts.append(tags)
    elif isinstance(tags, list):
        parts.extend(str(t.get("tag", t)) if isinstance(t, dict) else str(t) for t in tags)
    return "\n".join(parts)


def extract_json(data: bytes, name: str, media_type: str) -> Extracted:
    try:
        obj = json.loads(data)
    except ValueError:
        return Extracted(kind="data", note="json: does not parse", prose=False)
    if is_csl_json(obj):
        texts = [csl_item_text(i) for i in obj]
        return Extracted(
            kind="bibliography",
            title=Path(name).stem,
            text="\n\n".join(texts),
            prose=False,
            meta={"items": len(obj)},
        )
    if isinstance(obj, dict) and obj.get("schema") == "anagram.index.record.v1":
        rec = obj.get("record", {})
        return Extracted(
            kind=obj.get("kind", "record"),
            title=obj.get("title"),
            text=obj.get("text", ""),
            prose=bool(obj.get("prose", False)),
            meta={"ref": rec.get("ref")} if isinstance(rec, dict) else {},
        )
    return Extracted(kind="data", prose=False, meta={"json_type": type(obj).__name__})


# ------------------------------------------------------------------ Jupyter (.ipynb)


def _ipynb_join(value: object, limit: int) -> str:
    """Join a Jupyter string-or-list-of-strings field, capped at `limit` chars."""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, list):
        parts: list[str] = []
        total = 0
        for item in value:
            if not isinstance(item, str):
                continue
            rem = limit - total
            if rem <= 0:
                break
            parts.append(item[:rem])
            total += len(parts[-1])
        return "".join(parts)
    return ""


def _ipynb_language(metadata: object) -> str:
    if not isinstance(metadata, dict):
        return ""
    ks = metadata.get("kernelspec")
    raw = ks.get("language") if isinstance(ks, dict) else None
    if not isinstance(raw, str) or not raw.strip():
        li = metadata.get("language_info")
        raw = li.get("name") if isinstance(li, dict) else None
    if not isinstance(raw, str):
        return ""
    cleaned = re.sub(r"[^a-zA-Z0-9_+#.-]", "", raw.strip().lower())
    return cleaned[:32]


def _ipynb_fence(code: str, lang: str) -> str:
    """Wrap `code` in a Markdown code fence that does not collide with backticks inside it."""
    longest = 0
    for match in re.finditer(r"`+", code):
        longest = max(longest, len(match.group(0)))
    fence = "`" * max(3, longest + 1)
    body = code.rstrip("\n")
    return f"{fence}{lang}\n{body}\n{fence}"


def _clean_plain_output(text: str) -> str:
    """Keep concise plain-text lines; drop huge unbroken base64-like lines."""
    lines = [
        line.rstrip()
        for line in text.replace("\r\n", "\n").splitlines()
        if len(line.strip()) <= MAX_IPYNB_UNBROKEN_LINE or " " in line.strip()
    ]
    return "\n".join(lines).strip()


def _ipynb_cell_outputs(outputs: object) -> list[str]:
    """Extract concise plain-text outputs, skipping binary/image/HTML blobs."""
    if not isinstance(outputs, list):
        return []
    out: list[str] = []
    for item in outputs[:MAX_IPYNB_OUTPUTS_PER_CELL]:
        if not isinstance(item, dict):
            continue
        otype = item.get("output_type")
        text = ""
        if otype == "stream":
            text = _ipynb_join(item.get("text"), MAX_IPYNB_OUTPUT_CHARS)
        elif otype in ("execute_result", "display_data"):
            data = item.get("data")
            if isinstance(data, dict) and "text/plain" in data:
                text = _ipynb_join(data.get("text/plain"), MAX_IPYNB_OUTPUT_CHARS)
        elif otype == "error":
            ename = str(item.get("ename") or "").strip()
            evalue = str(item.get("evalue") or "").strip()
            if ename or evalue:
                text = f"{ename}: {evalue}" if ename and evalue else (ename or evalue)
        cleaned = _clean_plain_output(text)
        if cleaned:
            out.append(cleaned[:MAX_IPYNB_OUTPUT_CHARS])
    return out


def _first_title_line(text: str) -> str | None:
    for line in text.splitlines():
        s = line.strip().lstrip("#").strip()
        if s:
            return s[:200]
    return None


def _ipynb_cell_chunk(cell: dict, lang: str) -> tuple[str, str]:
    """Return `(cell_type, markdown_chunk)` for one notebook cell."""
    ctype = str(cell.get("cell_type") or "")
    src = _ipynb_join(cell.get("source"), MAX_IPYNB_CELL_CHARS).replace("\r\n", "\n").strip()
    if ctype == "markdown":
        return ctype, src
    if ctype == "code":
        pieces: list[str] = []
        if src:
            pieces.append(_ipynb_fence(src, lang))
        outs = _ipynb_cell_outputs(cell.get("outputs"))
        if outs:
            pieces.append("Output:\n" + "\n".join(outs))
        return ctype, "\n\n".join(pieces)
    if ctype == "raw":
        return ctype, src
    return ctype, ""


def extract_ipynb(data: bytes, name: str = "notebook.ipynb", media_type: str = IPYNB) -> Extracted:
    """Extract markdown cells, fenced code cells, and concise plain-text outputs
    from a Jupyter notebook (`.ipynb`). Standard library only."""
    try:
        obj = json.loads(decode_text(data))
    except ValueError:
        return Extracted(kind="notebook", prose=True, note="ipynb: does not parse")
    if not isinstance(obj, dict) or not isinstance(obj.get("cells"), list):
        return Extracted(kind="notebook", prose=True, note="ipynb: missing cells list")

    cells = obj["cells"]
    lang = _ipynb_language(obj.get("metadata"))
    parts: list[str] = []
    title: str | None = None
    md_count = 0
    code_count = 0
    total_chars = 0
    truncated = len(cells) > MAX_IPYNB_CELLS

    for cell in cells[:MAX_IPYNB_CELLS]:
        if not isinstance(cell, dict):
            continue
        ctype, chunk = _ipynb_cell_chunk(cell, lang)
        if ctype == "markdown":
            md_count += 1
            if chunk and title is None:
                title = _first_title_line(chunk)
        elif ctype == "code":
            code_count += 1
        if not chunk:
            continue
        if total_chars + len(chunk) > MAX_TEXT_BYTES:
            truncated = True
            break
        parts.append(chunk)
        total_chars += len(chunk) + 2

    text = "\n\n".join(parts)
    if text:
        text += "\n"
    meta: dict = {
        "cells": len(cells),
        "code_cells": code_count,
        "language": lang,
        "markdown_cells": md_count,
    }
    if truncated:
        meta["truncated"] = True
    return Extracted(
        kind="notebook",
        title=title or (Path(name).stem if name else None),
        text=text,
        prose=True,
        meta=meta,
    )


# ------------------------------------------------------------------ LaTeX (.tex)

_TEX_SECTIONS: tuple[tuple[str, str], ...] = (
    ("chapter", "#"),
    ("section", "#"),
    ("subsection", "##"),
    ("subsubsection", "###"),
    ("paragraph", "####"),
)
_TEX_UNWRAP: tuple[str, ...] = (
    "textbf",
    "textit",
    "emph",
    "texttt",
    "text",
    "textrm",
    "textsf",
    "textsc",
    "underline",
    "mbox",
    "hbox",
    "mathrm",
    "mathbf",
    "mathit",
    "mathsf",
    "mathcal",
    "operatorname",
    "caption",
    "footnote",
)
_TEX_DROP_2: tuple[str, ...] = (
    "setlength",
    "setcounter",
    "newcommand",
    "renewcommand",
    "providecommand",
    "addtolength",
)
_TEX_DROP_1: tuple[str, ...] = (
    "label",
    "vspace",
    "hspace",
    "usepackage",
    "documentclass",
    "bibliographystyle",
    "bibliography",
    "pagestyle",
    "thispagestyle",
    "graphicspath",
    "includegraphics",
    "input",
    "include",
    "thanks",
    "affil",
    "institute",
    "hypersetup",
    "geometry",
)
_TEX_STANDALONE_RE = re.compile(
    r"\\(?:maketitle|tableofcontents|listoffigures|listoftables|centering|noindent|"
    r"newpage|clearpage|pagebreak|medskip|bigskip|smallskip|hfill|vfill|hline|"
    r"toprule|midrule|bottomrule|quad|qquad|small|normalsize|large|Large|LARGE|"
    r"footnotesize|tiny|bfseries|itshape|rmfamily)\b[ \t]*"
)
_TEX_ENV_WRAPPER_RE = re.compile(
    r"\\(?:begin|end)\{(?:itemize|enumerate|description|figure\*?|table\*?|center|"
    r"quote|quotation|minipage|equation\*?|align\*?|gather\*?|multline\*?|tabular|"
    r"verbatim)\}(?:\[[^\]\n]{0,64}\])?(?:\{[^}\n]{0,64}\})?"
)
_TEX_ABSTRACT_RE = re.compile(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", re.S)
_TEX_ITEM_OPT_RE = re.compile(r"\\item\s*\[([^\]\n]{1,120})\]\s*")
_TEX_ITEM_RE = re.compile(r"\\item\b[ \t]*")
_TEX_LINEBREAK_RE = re.compile(r"\\\\(?:\[[^\]\n]{0,32}\])?")


def _strip_tex_comments(text: str) -> str:
    """Remove unescaped `%` line comments while preserving `\\%`."""
    out: list[str] = []
    for line in text.splitlines():
        cut: int | None = None
        i = 0
        n = len(line)
        while i < n:
            if line[i] == "%":
                bs = 0
                j = i - 1
                while j >= 0 and line[j] == "\\":
                    bs += 1
                    j -= 1
                if bs % 2 == 0:
                    cut = i
                    break
            i += 1
        out.append(line if cut is None else line[:cut].rstrip())
    return "\n".join(out)


def _read_balanced(
    text: str, pos: int, open_ch: str = "{", close_ch: str = "}"
) -> tuple[str, int] | None:
    """Read a balanced delimiter group starting at `pos`, skipping escaped delimiters."""
    n = len(text)
    if pos >= n or text[pos] != open_ch:
        return None
    depth = 0
    i = pos
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[pos + 1 : i], i + 1
        i += 1
    return None


def _skip_ws(text: str, pos: int) -> int:
    n = len(text)
    while pos < n and text[pos] in " \t\n":
        pos += 1
    return pos


def _read_tex_arg(text: str, pos: int) -> tuple[str, int] | None:
    """Read optional `*`, optional `[...]`, then required `{...}` after a command name."""
    n = len(text)
    if pos < n and text[pos] == "*":
        pos += 1
    pos = _skip_ws(text, pos)
    if pos < n and text[pos] == "[":
        opt = _read_balanced(text, pos, "[", "]")
        if opt is None:
            return None
        pos = _skip_ws(text, opt[1])
    return _read_balanced(text, pos, "{", "}")


def _find_tex_command(text: str, cmd: str, start: int = 0) -> int:
    """Return index of `\\cmd` followed by a non-letter (or -1)."""
    needle = "\\" + cmd
    n = len(text)
    pos = start
    while True:
        idx = text.find(needle, pos)
        if idx == -1:
            return -1
        end = idx + len(needle)
        if end < n and text[end].isalpha():
            pos = end
            continue
        # Ensure the backslash itself is not escaped (`\\cmd`).
        bs = 0
        j = idx - 1
        while j >= 0 and text[j] == "\\":
            bs += 1
            j -= 1
        if bs % 2 == 1:
            pos = end
            continue
        return idx


def _extract_tex_command(text: str, cmd: str) -> str | None:
    idx = _find_tex_command(text, cmd)
    if idx == -1:
        return None
    arg = _read_tex_arg(text, idx + 1 + len(cmd))
    return arg[0] if arg is not None else None


def _replace_tex_command(
    text: str,
    cmd: str,
    transform: Callable[[str], str],
    *,
    second_arg: bool = False,
) -> str:
    """Replace every `\\cmd[*][...]{arg}` (or `{arg1}{arg2}` when `second_arg=True`)."""
    out: list[str] = []
    pos = 0
    while True:
        idx = _find_tex_command(text, cmd, pos)
        if idx == -1:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:idx])
        after_cmd = idx + 1 + len(cmd)
        first = _read_tex_arg(text, after_cmd)
        if first is None:
            out.append(text[idx:after_cmd])
            pos = after_cmd
            continue
        val, next_pos = first
        if second_arg:
            second = _read_balanced(text, _skip_ws(text, next_pos))
            if second is None:
                out.append(text[idx:next_pos])
                pos = next_pos
                continue
            val, next_pos = second
        out.append(transform(val))
        pos = next_pos


def _drop_tex_command(text: str, cmd: str, nargs: int = 1) -> str:
    """Drop `\\cmd[*][...]{arg1}...{argN}` cleanly."""
    out: list[str] = []
    pos = 0
    while True:
        idx = _find_tex_command(text, cmd, pos)
        if idx == -1:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:idx])
        cur = idx + 1 + len(cmd)
        ok = True
        for i in range(nargs):
            arg = _read_tex_arg(text, cur) if i == 0 else _read_balanced(text, _skip_ws(text, cur))
            if arg is None:
                ok = False
                break
            cur = arg[1]
        if not ok:
            out.append(text[idx : idx + 1 + len(cmd)])
            pos = idx + 1 + len(cmd)
        else:
            pos = cur


def _clean_tex_inline(text: str) -> str:
    """Unwrap inline formatting macros, strip noisy layout commands, and unescape."""
    s = _replace_tex_command(text, "href", lambda v: v, second_arg=True)
    s = _replace_tex_command(s, "url", lambda v: v)
    for cmd in _TEX_DROP_2:
        s = _drop_tex_command(s, cmd, nargs=2)
    for cmd in _TEX_DROP_1:
        s = _drop_tex_command(s, cmd, nargs=1)
    for _ in range(6):
        prev = s
        for cmd in _TEX_UNWRAP:
            s = _replace_tex_command(s, cmd, lambda v: v)
        if s == prev:
            break
    s = _TEX_STANDALONE_RE.sub("", s)
    s = re.sub(r"\\par\b[ \t]*", "\n\n", s)
    s = _TEX_ITEM_OPT_RE.sub(r"- \1: ", s)
    s = _TEX_ITEM_RE.sub("- ", s)
    s = _TEX_LINEBREAK_RE.sub("\n", s)
    s = s.replace("~", " ")
    for esc, rep in (("\\%", "%"), ("\\&", "&"), ("\\#", "#"), ("\\_", "_"), ("\\$", "$")):
        s = s.replace(esc, rep)
    return s


def _clean_tex_meta_value(raw: str) -> str:
    cleaned = _clean_tex_inline(re.sub(r"\s*\\and\b\s*", ", ", raw))
    cleaned = cleaned.replace("{", "").replace("}", "")
    cleaned = re.sub(r"\s+,", ",", cleaned)
    return " ".join(cleaned.split())


def _normalize_tex_whitespace(text: str) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    collapsed = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    return collapsed + "\n" if collapsed else ""


def extract_tex(
    data: bytes, name: str = "document.tex", media_type: str = "text/x-tex"
) -> Extracted:
    """Clean LaTeX source into readable Markdown prose and metadata. Standard
    library only, with linear-time brace scanning."""
    raw = _strip_tex_comments(decode_text(data).replace("\r\n", "\n"))
    raw_title = _extract_tex_command(raw, "title")
    raw_author = _extract_tex_command(raw, "author")
    title = _clean_tex_meta_value(raw_title)[:200] if raw_title else None
    authors = _clean_tex_meta_value(raw_author) if raw_author else None

    begin = raw.find("\\begin{document}")
    if begin != -1:
        body = raw[begin + len("\\begin{document}") :]
        end = body.find("\\end{document}")
        if end != -1:
            body = body[:end]
    else:
        body = raw

    abstract: str | None = None
    abs_match = _TEX_ABSTRACT_RE.search(body)
    if abs_match is not None:
        abstract = _normalize_tex_whitespace(_clean_tex_inline(abs_match.group(1))).strip()
        body = body[: abs_match.start()] + "\n\n" + body[abs_match.end() :]

    for cmd, hashes in _TEX_SECTIONS:
        body = _replace_tex_command(
            body,
            cmd,
            lambda val, h=hashes: f"\n\n{h} {' '.join(_clean_tex_inline(val).split())}\n\n",
        )
    body = _TEX_ENV_WRAPPER_RE.sub("\n", body)
    body = _normalize_tex_whitespace(_clean_tex_inline(body)).strip()

    sections: list[str] = []
    if title:
        sections.append(f"# {title}")
    if abstract:
        sections.append(f"## Abstract\n\n{abstract}")
    if body:
        sections.append(body)
    text = _normalize_tex_whitespace("\n\n".join(sections))
    meta: dict = {"format": "tex"}
    if authors:
        meta["authors"] = authors
    if abstract:
        meta["abstract"] = abstract
    return Extracted(
        kind="document",
        title=title or _first_title_line(text),
        text=text,
        prose=True,
        meta=meta,
    )


# ------------------------------------------------------------------ dispatch

_EXTRACTORS = {
    "text/markdown": extract_text,
    "text/plain": extract_text,
    "text/x-tex": extract_tex,
    "text/x-python": extract_text,
    "text/x-code": extract_text,
    "text/x-r": extract_text,
    "text/x-shellscript": extract_text,
    "text/yaml": extract_text,
    "text/csv": extract_csv,
    "text/tab-separated-values": extract_csv,
    IPYNB: extract_ipynb,
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": extract_pptx,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": extract_docx,
    "image/png": extract_png,
    "image/jpeg": extract_jpeg,
    "application/pdf": extract_pdf,
    "application/json": extract_json,
    "application/vnd.citationstyles.csl+json": extract_json,
}
EXTRACTED_TYPES = frozenset(_EXTRACTORS)  # the media types that have an extractor


def extract_bytes(
    data: bytes,
    name: str,
    media_type: str,
    owner_emails: frozenset[str] = frozenset(),
    own: bool | None = None,
) -> Extracted:
    if media_type == "message/rfc822":
        return extract_eml(data, name, media_type, owner_emails, own)
    fn = _EXTRACTORS.get(media_type)
    if fn is None:
        return Extracted(kind="binary", prose=False, note=f"no extractor for {media_type}")
    return fn(data, name, media_type)


def extract_file(
    path: Path, media_type: str | None = None, owner_emails: frozenset[str] = frozenset()
) -> Extracted:
    media_type = media_type or media_type_for(path.name)
    if media_type != "message/rfc822" and media_type not in _EXTRACTORS:
        return Extracted(kind="binary", prose=False, note=f"no extractor for {media_type}")
    size = path.stat().st_size
    limit = MAX_TEXT_BYTES if media_type.startswith("text/") else 4 * MAX_TEXT_BYTES
    if size > limit:
        return Extracted(kind="binary", prose=False, note=f"too large to extract ({size} bytes)")
    return extract_bytes(path.read_bytes(), path.name, media_type, owner_emails)


# ------------------------------------------------------------------ code repos

README_NAMES = ("README.md", "README.rst", "README.txt", "README")


def repo_summary(repo: Path, git: str | None, env: dict[str, str]) -> Extracted:
    """README text and the file list of a code repository (HEAD if Git, else
    the working files). `ls-tree` reads only objects: unlike `ls-files`, it does
    not touch the index, so `core.fsmonitor` of the repository does not run.
    Pass `anagram.local.sources.git.git_env()` as `env`."""
    files: list[str] = []
    if git is not None:
        res = subprocess.run(  # noqa: S603 - fixed program and arguments
            [git, "-C", str(repo), "ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD"],
            env=env,
            capture_output=True,
            check=False,
        )
        if res.returncode == 0:
            files = sorted(f for f in res.stdout.decode("utf-8", "replace").split("\0") if f)
    if not files:
        files = sorted(
            p.relative_to(repo).as_posix()
            for p in repo.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(repo).parts
        )
    readme = ""
    for n in README_NAMES:
        p = repo / n
        if p.is_file() and p.stat().st_size <= MAX_TEXT_BYTES:
            readme = decode_text(p.read_bytes())
            break
    text = readme + "\n\n# Files\n" + "\n".join(f"- {f}" for f in files[:500])
    title = None
    for line in readme.splitlines():
        if line.strip():
            title = line.strip().lstrip("#").strip()
            break
    return Extracted(
        kind="code_repo",
        title=title or repo.name,
        text=text,
        prose=True,
        meta={"files": len(files)},
    )
