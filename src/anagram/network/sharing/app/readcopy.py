"""The reading copy (spec/vault.md section 14).

`build` makes one `anagram.reading_copy.v1` document from the evidence of one
finding version, with local converters only (a `Router` with no external
opt-in). A converter error gives view `file` for that item. It never stops a
share. The original file stays the proven item; the reading copy is derived
data and is never committed.

`seal` and `unseal` encrypt the document as one blob with the reading key (a
key that only a holder of the content key can compute).
"""

from __future__ import annotations

import base64
import csv
import io
import json
import logging
import re
import zipfile
from pathlib import Path, PurePosixPath

from anagram.core.canonical import canonical_json, loads_canonical
from anagram.core.crypto.blob import decrypt_bytes, encrypt_bytes
from anagram.network.formats.sharing import (
    READING_COPY_SCHEMA,
    READING_FIGURES_MAX,
    READING_SLOT,
    TABLE_ROWS_MAX,
    reading_evidence_root,
    reading_key,
    validate_reading_copy,
)
from anagram.proofs.records import OpeningDocument

log = logging.getLogger("anagram.client")

MADE_BY = "anagram.readcopy.v1"
CHUNK_SIZE = 1 << 20
_TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".json", ".py", ".r", ".sh", ".tex", ".yaml", ".yml",
    ".toml", ".c", ".h", ".cpp", ".js", ".ts", ".rs", ".go", ".java", ".jl", ".m",
}  # fmt: skip
_IMAGE_SUFFIXES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}
_DOC_SUFFIXES = {".docx", ".html", ".htm", ".odt"}
_CELL_MAX = 4096
_COLUMN_MAX = 1024
_FIGURE_ID_BAD = re.compile(r"[^A-Za-z0-9_-]")


def view_for(name: str, media_type: str) -> str:
    suffix = PurePosixPath(name or "").suffix.lower()
    if suffix == ".pdf" or media_type == "application/pdf":
        return "pdf"
    if suffix in _IMAGE_SUFFIXES or media_type.startswith("image/"):
        return "image"
    if suffix in (".csv", ".tsv", ".xlsx"):
        return "table"
    if suffix == ".pptx":
        return "slides"
    if suffix in _DOC_SUFFIXES or suffix == ".ipynb":
        return "document"
    if suffix in _TEXT_SUFFIXES or media_type.startswith("text/"):
        return "text"
    return "file"


def file_media_type(name: str, media_type: str) -> str:
    """The media type of a file: the given one, or one from the file name."""
    suffix = PurePosixPath(name or "").suffix.lower()
    if media_type in ("", "application/octet-stream"):
        from anagram.local.api import media_type_for

        return media_type_for(name or "") or _IMAGE_SUFFIXES.get(suffix) or media_type
    return media_type


def _blocks(markdown: str) -> list[dict]:
    # A late import: `anagram.local.index` imports the client package.
    from anagram.local.api import blocks_from_markdown, wire_blocks_v1

    # The reading copy is a locked format: schema-1 blocks (spec/sharing.md).
    return wire_blocks_v1(blocks_from_markdown(markdown))


def _cell(value, limit: int = _CELL_MAX) -> str:
    return "" if value is None else str(value)[:limit]


def _table(rows: list[list]) -> dict:
    head, body = (rows[0], rows[1:]) if rows else ([], [])
    return {
        "columns": [_cell(c, _COLUMN_MAX) for c in head],
        "rows": [[_cell(c) for c in r] for r in body[:TABLE_ROWS_MAX]],
        "total_rows": len(body),
    }


def _table_csv(data: bytes, delimiter: str) -> dict:
    text = data.decode("utf-8-sig", errors="replace")
    return _table(list(csv.reader(io.StringIO(text), delimiter=delimiter)))


def _table_xlsx(data: bytes) -> dict:
    """The first sheet. Other sheets are not in the reading copy (the
    original file has them)."""
    import openpyxl

    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    try:
        ws = wb.worksheets[0]
        rows = [list(r) for r in ws.iter_rows(values_only=True)]
    finally:
        wb.close()
    return _table(rows)


def _zip_figures(data: bytes, folder: str) -> list[tuple[str, str, bytes]]:
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            p = PurePosixPath(info.filename)
            mt = _IMAGE_SUFFIXES.get(p.suffix.lower())
            if str(p.parent) == folder and mt and info.file_size <= READING_FIGURES_MAX:
                out.append((p.stem, mt, zf.read(info)))
    return out


def _notebook(data: bytes) -> tuple[list[dict], list[tuple[str, str, bytes]]]:
    """Cells as blocks. The figure ID `code-<k>-<j>` names output `j` of the
    code cell whose block has the anchor `code-<k>`, so that the reading view
    shows the figure under its code."""
    nb = json.loads(data.decode("utf-8"))
    md, figures = [], []
    code = 0  # the number of code blocks so far (code anchors count from 1)
    for cell in nb.get("cells", []):
        src = cell.get("source", "")
        src = "".join(src) if isinstance(src, list) else str(src)
        if cell.get("cell_type") == "markdown":
            md.append(src)
            code += sum(1 for b in _blocks(src) if b["kind"] == "code")
        elif cell.get("cell_type") == "code":
            md.append("```\n" + src + "\n```")
            code += 1
            for j, out in enumerate(cell.get("outputs", [])):
                png = (out.get("data") or {}).get("image/png")
                if isinstance(png, list):
                    png = "".join(png)
                if isinstance(png, str):
                    try:
                        figures.append((f"code-{code}-{j}", "image/png", base64.b64decode(png)))
                    except ValueError:
                        continue
    return _blocks("\n\n".join(md)), figures


def _converted(router, data: bytes, name: str, media_type: str) -> list[dict]:
    from anagram.local.api import Blob, Skipped, wire_blocks_v1

    try:
        doc = router.convert(Blob(data=data, name=name, media_type=media_type))
    except Skipped:
        return []
    return wire_blocks_v1(doc.blocks)


def _item(slot: int, ev_fields: dict, data: bytes, router) -> tuple[dict, list]:
    name = ev_fields.get("name") or f"evidence {slot}"
    media_type = file_media_type(name, ev_fields.get("media_type") or "application/octet-stream")
    view = view_for(name, media_type)
    item = {
        "blocks": None,
        "figures": [],
        "media_type": media_type,
        "name": PurePosixPath(name).name[:255],
        "size": len(data),
        "slot": slot,
        "table": None,
        "truncated": False,
        "view": view,
    }
    figures: list[tuple[str, str, bytes]] = []
    suffix = PurePosixPath(name).suffix.lower()
    if view == "table":
        if suffix == ".xlsx":
            item["table"] = _table_xlsx(data)
        else:
            item["table"] = _table_csv(data, "\t" if suffix == ".tsv" else ",")
    elif view == "text":
        text = data.decode("utf-8", errors="replace")
        if suffix in (".md", ".markdown"):
            item["blocks"] = _blocks(text)
        else:
            item["blocks"] = [
                {"anchor": "code-1", "kind": "code", "level": 0, "parent": None, "text": text}
            ]
    elif view == "document" and suffix == ".ipynb":
        item["blocks"], figures = _notebook(data)
    elif view == "document":
        item["blocks"] = _converted(router, data, name, media_type)
        if suffix == ".docx":
            figures = _zip_figures(data, "word/media")
    elif view == "slides":
        item["blocks"] = _converted(router, data, name, media_type)
        figures = _zip_figures(data, "ppt/media")
    elif view == "pdf":
        # The reader shows the original PDF; the blocks are the text for
        # search and for a reader with no PDF view.
        item["blocks"] = _converted(router, data, name, media_type)
    return item, figures


def build(
    doc: OpeningDocument,
    files: dict[int, bytes],
    router=None,
    *,
    title: str | None = None,
) -> dict:
    """The reading copy of one finding version. `files` maps an evidence slot to
    the bytes of the file (a missing slot is left out). `router` defaults to
    the local converters only."""
    if router is None:
        from anagram.local.api import Router

        router = Router(allow_external=())
    if title is None:
        claim = doc.finding.fields.get("claim")
        title = claim.strip().splitlines()[0][:160] if isinstance(claim, str) and claim else None
    items, spent = [], 0
    for slot, ev in enumerate(doc.evidence):
        if slot not in files:
            continue
        try:
            item, figures = _item(slot, ev.fields, files[slot], router)
        except Exception as exc:  # a bad file gives view `file`, never a stop
            log.info("reading copy: slot %d gives view file (%s)", slot, type(exc).__name__)
            item, figures = _item(slot, {**ev.fields, "name": "file"}, b"", router)
            name = ev.fields.get("name") or f"evidence {slot}"
            item.update(
                blocks=None,
                name=PurePosixPath(name).name[:255],
                size=len(files[slot]),
                table=None,
                view="file",
            )
            figures = []
        ids: set[str] = set()
        for n, (fid, mt, raw) in enumerate(figures):
            if spent + len(raw) > READING_FIGURES_MAX:
                item["truncated"] = True
                break
            spent += len(raw)
            safe = _FIGURE_ID_BAD.sub("_", fid)[:56] or "figure"
            if safe in ids:
                safe = f"{safe}-{n}"
            ids.add(safe)
            item["figures"].append(
                {"data": base64.b64encode(raw).decode("ascii"), "id": safe, "media_type": mt}
            )
        items.append(item)
    copy = {"items": items, "made_by": MADE_BY, "schema": READING_COPY_SCHEMA, "title": title}
    return validate_reading_copy(copy)


def seal(copy: dict, content_key: bytes, finding_root: bytes) -> bytes:
    return encrypt_bytes(
        canonical_json(copy),
        content_key=reading_key(content_key, finding_root),
        finding_root=finding_root,
        evidence_root=reading_evidence_root(),
        slot=READING_SLOT,
        chunk_size=CHUNK_SIZE,
    )


def unseal(blob: bytes, content_key: bytes, finding_root: bytes) -> dict:
    plain = decrypt_bytes(
        blob,
        content_key=reading_key(content_key, finding_root),
        finding_root=finding_root,
        evidence_root=reading_evidence_root(),
        slot=READING_SLOT,
        chunk_size=CHUNK_SIZE,
    )
    return validate_reading_copy(loads_canonical(plain))


def read_files(doc: OpeningDocument, paths: dict[int, str | Path]) -> dict[int, bytes]:
    """The bytes of the local evidence files that still match the commitment."""
    from anagram.core.crypto.chunked import ContentDigest, hash_bytes

    out = {}
    for slot, p in paths.items():
        if slot >= len(doc.evidence) or not p or not Path(p).is_file():
            continue
        data = Path(p).read_bytes()
        expected = ContentDigest.from_json(doc.evidence[slot].fields["content"])
        if hash_bytes(data, expected.chunk_size).digest == expected.digest:
            out[slot] = data
    return out
