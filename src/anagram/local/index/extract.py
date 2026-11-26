"""On-device extraction of text and metadata. Standard library only.

Extraction makes derived meaning. It never changes the evidence bytes, and
nothing here is committed. Each extractor is deterministic.

| Format | What we read |
| --- | --- |
| text, markdown, code | the text (code: no need or offer cues) |
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
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from anagram.local.index.media import CODE_SUFFIXES, MEDIA_TYPES, media_type_for  # noqa: F401

MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_ZIP_PART = 16 * 1024 * 1024
CSV_SAMPLE_ROWS = 5


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


# ------------------------------------------------------------------ dispatch

_EXTRACTORS = {
    "text/markdown": extract_text,
    "text/plain": extract_text,
    "text/x-tex": extract_text,
    "text/x-python": extract_text,
    "text/x-code": extract_text,
    "text/x-r": extract_text,
    "text/x-shellscript": extract_text,
    "text/yaml": extract_text,
    "text/csv": extract_csv,
    "text/tab-separated-values": extract_csv,
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
