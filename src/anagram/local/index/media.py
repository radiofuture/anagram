"""Media type of a file: magic bytes first, the file extension as fallback.

A file name can be wrong (a PDF saved as `notes.txt`, a `.docx` that is a
renamed `.doc`). The converters choose by media type, so the index reads the
first bytes of the file:

| Magic bytes | Media type |
| --- | --- |
| `%PDF-` | application/pdf |
| `\\x89PNG` | image/png |
| `\\xff\\xd8\\xff` | image/jpeg |
| `GIF8` | image/gif |
| `RIFF....WEBP` | image/webp |
| `II*\\0`, `MM\\0*` | image/tiff |
| `PK\\x03\\x04` (ZIP) | docx, pptx, xlsx (OOXML parts), epub, OpenDocument, else application/zip |
| `\\xd0\\xcf\\x11\\xe0` (OLE) | .doc, .xls, .ppt, .msg by extension |
| `\\x1f\\x8b` | application/gzip |
| `{\\rtf` | application/rtf |
| `<!doctype html`, `<html` | text/html |

Text (no NUL byte in the head) and unknown bytes use the extension. The
sniffer reads at most `HEAD_BYTES` and, for a ZIP file, the list of names in
the archive. It never reads the full file.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

HEAD_BYTES = 4096

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
EPUB = "application/epub+zip"
ZIP = "application/zip"
OCTET = "application/octet-stream"

MEDIA_TYPES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
    ".rst": "text/plain",
    ".tex": "text/x-tex",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".eml": "message/rfc822",
    ".pptx": PPTX,
    ".docx": DOCX,
    ".xlsx": XLSX,
    ".epub": EPUB,
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".msg": "application/vnd.ms-outlook",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".rtf": "application/rtf",
    ".zip": ZIP,
    ".gz": "application/gzip",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".py": "text/x-python",
    ".r": "text/x-r",
    ".ipynb": "application/x-ipynb+json",
    ".sh": "text/x-shellscript",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".toml": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
}
CODE_SUFFIXES = {".py", ".r", ".sh", ".js", ".ts", ".c", ".h", ".cpp", ".rs", ".go", ".jl", ".m"}
OLE_TYPES = {
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    ".msg": "application/vnd.ms-outlook",
}
ODF_TYPES = {
    b"application/vnd.oasis.opendocument.text",
    b"application/vnd.oasis.opendocument.spreadsheet",
    b"application/vnd.oasis.opendocument.presentation",
}


def media_type_for(name: str) -> str:
    """Media type from the file extension only."""
    suffix = Path(name).suffix.lower()
    if suffix in MEDIA_TYPES:
        return MEDIA_TYPES[suffix]
    if suffix in CODE_SUFFIXES:
        return "text/x-code"
    return OCTET


def _zip_type(names: list[str], mimetype: bytes | None) -> str:
    if mimetype is not None:
        mt = mimetype.strip()
        if mt == EPUB.encode():
            return EPUB
        if mt in ODF_TYPES:
            return mt.decode()
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return DOCX
        if any(n.startswith("ppt/") for n in names):
            return PPTX
        if any(n.startswith("xl/") for n in names):
            return XLSX
    return ZIP


def _zip_info(zf: zipfile.ZipFile) -> str:
    names = zf.namelist()
    mimetype = None
    if "mimetype" in names:
        info = zf.getinfo("mimetype")
        if info.file_size <= 200:
            with zf.open(info) as fh:
                raw = fh.read(201)
            if len(raw) <= 200:
                mimetype = raw
    return _zip_type(names, mimetype)


def sniff(head: bytes, name: str, zip_source: object | None = None) -> str:
    """Media type from the first bytes `head` and the name.

    `zip_source` is a path or a file object for the whole file. The sniffer
    needs it only to tell OOXML and EPUB apart from a plain ZIP file."""
    by_ext = media_type_for(name)
    for magic, media_type in _MAGIC:
        if head.startswith(magic):
            return media_type
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"PK\x03\x04"):
        return _zip_sniff(by_ext, zip_source)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return OLE_TYPES.get(Path(name).suffix.lower(), "application/x-ole-storage")
    if b"\x00" in head:
        # Binary with no known magic: trust a binary extension only.
        return by_ext if not by_ext.startswith("text/") else OCTET
    return _text_type(head, by_ext)


# Magic prefixes (they do not overlap) and their media types.
_MAGIC = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"\x1f\x8b", "application/gzip"),
    (b"{\\rtf", "application/rtf"),
)


def _zip_sniff(by_ext: str, zip_source: object | None) -> str:
    """The media type of a ZIP file: OOXML, EPUB, ODF, or plain ZIP."""
    if zip_source is None:
        return by_ext if by_ext in (DOCX, PPTX, XLSX, EPUB) else ZIP
    try:
        with zipfile.ZipFile(zip_source) as zf:
            return _zip_info(zf)
    except (zipfile.BadZipFile, OSError, KeyError):
        return ZIP


def _text_type(head: bytes, by_ext: str) -> str:
    """The media type of a file with no binary magic and no zero byte."""
    lead = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if lead.startswith((b"<!doctype html", b"<html")):
        return "text/html"
    if by_ext == OCTET and head:
        try:
            head.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.start < len(head) - 4:  # not only a cut multi-byte char at the end
                return OCTET
        return "text/plain"
    return by_ext


def sniff_bytes(data: bytes, name: str) -> str:
    return sniff(data[:HEAD_BYTES], name, io.BytesIO(data))


def sniff_file(path: str | Path) -> str:
    p = Path(path)
    try:
        with p.open("rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return media_type_for(p.name)
    return sniff(head, p.name, p)
