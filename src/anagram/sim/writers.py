"""Small, deterministic file writers for the synthetic community.

Only the standard library is used. Each writer gives the same bytes for the
same input: zip entries have a fixed date, emails have fixed headers, and Git
commits have fixed author and committer dates.
"""

from __future__ import annotations

import hashlib
import io
import os
import random
import shutil
import struct
import subprocess  # git is called with fixed arguments only
import zipfile
import zlib
from collections.abc import Callable, Sequence
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from xml.sax.saxutils import escape

ZIP_DATE = (1980, 1, 1, 0, 0, 0)
LARGE_CHUNK = 256 * 1024

# --- PNG -------------------------------------------------------------------


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def png_bytes(width: int, height: int, pixels: bytes, text: dict[str, str]) -> bytes:
    """Return an 8-bit greyscale PNG. `pixels` has width*height bytes."""
    if len(pixels) != width * height:
        raise ValueError("pixel count does not agree with the size")
    raw = b"".join(b"\x00" + pixels[y * width : (y + 1) * width] for y in range(height))
    out = [b"\x89PNG\r\n\x1a\n"]
    out.append(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)))
    for key, value in text.items():
        out.append(_png_chunk(b"tEXt", key.encode("latin-1") + b"\x00" + value.encode("latin-1")))
    out.append(_png_chunk(b"IDAT", zlib.compress(raw, 9)))
    out.append(_png_chunk(b"IEND", b""))
    return b"".join(out)


def figure_pixels(rng: random.Random, width: int, height: int, style: str) -> bytes:
    """Return a fake micrograph (noise with blobs) or a bar chart."""
    px = bytearray(width * height)
    if style == "bars":
        px[:] = b"\xff" * (width * height)
        n = 8
        bar_w = width // (n * 2)
        for i in range(n):
            h = rng.randint(height // 6, height - 4)
            x0 = bar_w // 2 + i * bar_w * 2
            for y in range(height - h, height):
                for x in range(x0, x0 + bar_w):
                    px[y * width + x] = 40
        return bytes(px)
    for i in range(width * height):
        px[i] = 110 + rng.randint(-25, 25)
    for _ in range(14):
        cx, cy, r = rng.randrange(width), rng.randrange(height), rng.randint(3, 7)
        for y in range(max(0, cy - r), min(height, cy + r + 1)):
            for x in range(max(0, cx - r), min(width, cx + r + 1)):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                    px[y * width + x] = 220
    return bytes(px)


# --- OOXML (pptx) ----------------------------------------------------------

NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_P = "http://schemas.openxmlformats.org/presentationml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_PML = "application/vnd.openxmlformats-officedocument.presentationml"
XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
NSDECL = f'xmlns:a="{NS_A}" xmlns:r="{NS_R}" xmlns:p="{NS_P}"'


def _rels(items: list[tuple[str, str, str]]) -> str:
    body = "".join(
        f'<Relationship Id="{rid}" Type="{kind}" Target="{target}"/>' for rid, kind, target in items
    )
    return f'{XML_HEAD}<Relationships xmlns="{PKG_REL}">{body}</Relationships>'


def _zip(members: Sequence[tuple[str, str | bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data.encode("utf-8") if isinstance(data, str) else data)
    return buf.getvalue()


_EMPTY_TREE = (
    '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
    '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
    '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
)


def _text_box(shape_id: int, name: str, y: int, cy: int, size: int, lines: list[str]) -> str:
    paras = "".join(
        f'<a:p><a:r><a:rPr lang="en-US" sz="{size}"/><a:t>{escape(line)}</a:t></a:r></a:p>'
        for line in lines
    )
    return (
        f'<p:sp><p:nvSpPr><p:cNvPr id="{shape_id}" name="{name}"/><p:cNvSpPr txBox="1"/>'
        f'<p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="457200" y="{y}"/>'
        f'<a:ext cx="8229600" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/>'
        f'</a:prstGeom></p:spPr><p:txBody><a:bodyPr wrap="square"/><a:lstStyle/>'
        f"{paras}</p:txBody></p:sp>"
    )


def _theme() -> str:
    colours = (
        ("dk1", "000000"), ("lt1", "FFFFFF"), ("dk2", "1F2937"), ("lt2", "F3F4F6"),
        ("accent1", "2563EB"), ("accent2", "059669"), ("accent3", "D97706"),
        ("accent4", "DC2626"), ("accent5", "7C3AED"), ("accent6", "0891B2"),
        ("hlink", "1D4ED8"), ("folHlink", "6D28D9"),
    )  # fmt: skip
    clr = "".join(f'<a:{k}><a:srgbClr val="{v}"/></a:{k}>' for k, v in colours)
    font = '<a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/>'
    fill = '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    line = f'<a:ln w="9525">{fill}</a:ln>'
    eff = "<a:effectStyle><a:effectLst/></a:effectStyle>"
    return (
        f'{XML_HEAD}<a:theme xmlns:a="{NS_A}" name="Sim"><a:themeElements>'
        f'<a:clrScheme name="Sim">{clr}</a:clrScheme>'
        f'<a:fontScheme name="Sim"><a:majorFont>{font}</a:majorFont>'
        f"<a:minorFont>{font}</a:minorFont></a:fontScheme>"
        f'<a:fmtScheme name="Sim"><a:fillStyleLst>{fill * 3}</a:fillStyleLst>'
        f"<a:lnStyleLst>{line * 3}</a:lnStyleLst>"
        f"<a:effectStyleLst>{eff * 3}</a:effectStyleLst>"
        f"<a:bgFillStyleLst>{fill * 3}</a:bgFillStyleLst></a:fmtScheme>"
        "</a:themeElements></a:theme>"
    )


def pptx_bytes(
    title: str, author: str, slides: list[tuple[str, list[str]]], notes_comment: str = ""
) -> bytes:
    """Return a minimal valid .pptx with one text slide per item.

    `notes_comment` goes into docProps/core.xml as the description.
    """
    n = len(slides)
    ct = (
        f'{XML_HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'<Override PartName="/ppt/presentation.xml" ContentType="{CT_PML}.presentation.main+xml"/>'
        f'<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="{CT_PML}.slideMaster+xml"/>'
        f'<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="{CT_PML}.slideLayout+xml"/>'
        '<Override PartName="/ppt/theme/theme1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
        + "".join(
            f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="{CT_PML}.slide+xml"/>'
            for i in range(1, n + 1)
        )
        + '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'
    )
    root_rels = _rels(
        [
            ("rId1", f"{REL}/officeDocument", "ppt/presentation.xml"),
            (
                "rId2",
                "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
                "docProps/core.xml",
            ),
        ]
    )
    core = (
        f"{XML_HEAD}<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{escape(title)}</dc:title><dc:creator>{escape(author)}</dc:creator>"
        f"<dc:description>{escape(notes_comment)}</dc:description>"
        '<dcterms:created xsi:type="dcterms:W3CDTF">2026-10-01T00:00:00Z</dcterms:created>'
        "</cp:coreProperties>"
    )
    sld_ids = "".join(f'<p:sldId id="{255 + i}" r:id="rId{i + 2}"/>' for i in range(1, n + 1))
    pres = (
        f"{XML_HEAD}<p:presentation {NSDECL}>"
        '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
        f"<p:sldIdLst>{sld_ids}</p:sldIdLst>"
        '<p:sldSz cx="9144000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/>'
        "</p:presentation>"
    )
    pres_rels = _rels(
        [
            ("rId1", f"{REL}/slideMaster", "slideMasters/slideMaster1.xml"),
            ("rId2", f"{REL}/theme", "theme/theme1.xml"),
        ]
        + [(f"rId{i + 2}", f"{REL}/slide", f"slides/slide{i}.xml") for i in range(1, n + 1)]
    )
    master = (
        f"{XML_HEAD}<p:sldMaster {NSDECL}><p:cSld><p:spTree>{_EMPTY_TREE}</p:spTree></p:cSld>"
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
        'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" '
        'hlink="hlink" folHlink="folHlink"/>'
        '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
        "</p:sldMaster>"
    )
    master_rels = _rels(
        [
            ("rId1", f"{REL}/slideLayout", "../slideLayouts/slideLayout1.xml"),
            ("rId2", f"{REL}/theme", "../theme/theme1.xml"),
        ]
    )
    layout = (
        f'{XML_HEAD}<p:sldLayout {NSDECL} type="blank" preserve="1"><p:cSld name="Blank">'
        f"<p:spTree>{_EMPTY_TREE}</p:spTree></p:cSld>"
        "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"
    )
    layout_rels = _rels([("rId1", f"{REL}/slideMaster", "../slideMasters/slideMaster1.xml")])
    slide_rels = _rels([("rId1", f"{REL}/slideLayout", "../slideLayouts/slideLayout1.xml")])

    members: list[tuple[str, str | bytes]] = [
        ("[Content_Types].xml", ct),
        ("_rels/.rels", root_rels),
        ("docProps/core.xml", core),
        ("ppt/presentation.xml", pres),
        ("ppt/_rels/presentation.xml.rels", pres_rels),
        ("ppt/slideMasters/slideMaster1.xml", master),
        ("ppt/slideMasters/_rels/slideMaster1.xml.rels", master_rels),
        ("ppt/slideLayouts/slideLayout1.xml", layout),
        ("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels),
        ("ppt/theme/theme1.xml", _theme()),
    ]
    for i, (head, bullets) in enumerate(slides, start=1):
        tree = (
            _EMPTY_TREE
            + _text_box(2, "Title", 365760, 914400, 3200, [head])
            + _text_box(3, "Body", 1463040, 4572000, 2000, bullets)
        )
        slide = (
            f"{XML_HEAD}<p:sld {NSDECL}><p:cSld><p:spTree>{tree}</p:spTree></p:cSld>"
            "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"
        )
        members.append((f"ppt/slides/slide{i}.xml", slide))
        members.append((f"ppt/slides/_rels/slide{i}.xml.rels", slide_rels))
    return _zip(members)


# --- Email -----------------------------------------------------------------


def eml_bytes(
    *,
    sender: tuple[str, str],
    to: tuple[str, str],
    subject: str,
    date: str,
    message_id: str,
    body: str,
) -> bytes:
    """Return an RFC 5322 message with a plain text body."""
    msg = EmailMessage()
    msg["From"] = formataddr(sender)
    msg["To"] = formataddr(to)
    msg["Subject"] = subject
    msg["Date"] = date
    msg["Message-ID"] = message_id
    msg.set_content(body, cte="7bit")
    return msg.as_bytes()


# --- Zip, docx, PDF (extraction corpus) ------------------------------------


def normalize_zip(data: bytes, fix: Callable[[str, bytes], bytes] | None = None) -> bytes:
    """The same zip with a fixed date on each entry, in the same order, so a
    writer that puts the time of day in a zip (openpyxl, python-pptx) gives
    the same bytes each time. `fix(name, body)` can change a member (for
    example a save time in `docProps/core.xml`)."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [(i.filename, zf.read(i.filename)) for i in zf.infolist()]
    if fix is not None:
        members = [(name, fix(name, body)) for name, body in members]
    return _zip(members)


NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CT_WML = "application/vnd.openxmlformats-officedocument.wordprocessingml"

DocxBlock = tuple[str, str | list[list[str]]]  # ("h1" | "h2" | "p", text) or ("table", rows)


def _w_para(text: str, style: str | None = None) -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f'<w:p>{ppr}<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def docx_bytes(blocks: list[DocxBlock], title: str = "") -> bytes:
    """Return a minimal valid .docx: headings (`h1`, `h2`), paragraphs (`p`),
    and tables (`table`, a list of rows of cell text)."""
    body = []
    for kind, content in blocks:
        if kind == "table":
            rows = "".join(
                "<w:tr>" + "".join(f"<w:tc>{_w_para(c)}</w:tc>" for c in row) + "</w:tr>"
                for row in content
            )
            body.append(f"<w:tbl><w:tblPr/>{rows}</w:tbl>")
        elif kind in ("h1", "h2"):
            body.append(_w_para(str(content), "Heading" + kind[1]))
        else:
            body.append(_w_para(str(content)))
    ct = (
        f'{XML_HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
        'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
        f'<Override PartName="/word/document.xml" ContentType="{CT_WML}.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'
    )
    rels = _rels(
        [
            ("rId1", f"{REL}/officeDocument", "word/document.xml"),
            (
                "rId2",
                "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
                "docProps/core.xml",
            ),
        ]
    )
    core = (
        f"{XML_HEAD}<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:title>{escape(title)}</dc:title></cp:coreProperties>"
    )
    doc = f'{XML_HEAD}<w:document xmlns:w="{NS_W}"><w:body>{"".join(body)}</w:body></w:document>'
    return _zip(
        [
            ("[Content_Types].xml", ct),
            ("_rels/.rels", rels),
            ("docProps/core.xml", core),
            ("word/document.xml", doc),
        ]
    )


PdfText = tuple[float, float, float, str]  # x, y from the top, font size, text
PDF_PAGE = (612.0, 792.0)  # US Letter, points
PDF_BOLD_SIZE = 14.0  # text at this size or larger is bold


def _pdf_str(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def pdf_layout(
    blocks: list[DocxBlock],
    size: tuple[float, float] = PDF_PAGE,
    margin: float = 72.0,
    columns: int = 1,
    gap: float = 24.0,
) -> list[list[PdfText]]:
    """Lay out the blocks of `docx_bytes` on pages: headings at 16 and 14
    points, text at 11 points wrapped in the column, table cells in columns
    of the same width. A block that does not fit goes to the next column or
    page. The order of the items is the reading order."""
    w, h = size
    col_w = (w - 2 * margin - gap * (columns - 1)) / columns
    pages: list[list[PdfText]] = [[]]
    y, col = margin, 0

    def need(height: float) -> float:
        """The left edge of the frame where the block goes."""
        nonlocal y, col
        if y + height > h - margin and y > margin:
            col += 1
            y = margin
            if col == columns:
                pages.append([])
                col = 0
        return margin + col * (col_w + gap)

    for kind, content in blocks:
        if kind == "table":
            rows = [list(r) for r in content]
            cell_w = col_w / max(1, max(len(r) for r in rows))
            x0 = need(14.0 * len(rows) + 8)
            for row in rows:
                y += 14.0
                for j, cell in enumerate(row):
                    pages[-1].append((x0 + j * cell_w, y, 10.0, cell[: int(cell_w / 5.2)]))
            y += 8
            continue
        size_pt = {"h1": 16.0, "h2": 14.0}.get(kind, 11.0)
        lines = _wrap(str(content), int(col_w / (size_pt * 0.52)))
        lead = size_pt * 1.3
        x0 = need(lead * len(lines) + 8)
        for line in lines:
            y += lead
            pages[-1].append((x0, y, size_pt, line))
        y += 8
    return pages


def _wrap(text: str, width: int) -> list[str]:
    lines, cur = [], ""
    for word in text.split():
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    return [*lines, cur] if cur else lines


def _pdf_show(text: str, kern: bool) -> bytes:
    """`(text) Tj`, or with `kern` one `TJ` array with each word apart and
    no space character (a reader must find the spaces from the gaps)."""
    if not kern:
        return _pdf_str(text) + b" Tj"
    return b"[" + b" -280 ".join(_pdf_str(word) for word in text.split()) + b"] TJ"


def pdf_bytes(
    pages: list[list[PdfText]],
    size: tuple[float, float] = PDF_PAGE,
    compress: bool = False,
    kern: bool = False,
) -> bytes:
    """Return a born-digital PDF: text only, in Helvetica (bold from
    `PDF_BOLD_SIZE`), WinAnsi encoding. Each page is a list of (x, y, size,
    text) with y from the top of the page. `compress`: Flate content streams
    (as most PDF tools write); `kern`: words as `TJ` arrays. No date, so the
    bytes are fixed."""
    w, h = size
    fonts = (
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>",
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold/Encoding/WinAnsiEncoding>>",
    )
    objs: list[bytes] = [b"<</Type/Catalog/Pages 2 0 R>>", b"", *fonts]
    kids = []
    for page in pages:
        ops = []
        for x, y, sz, text in page:
            font = b"/F2" if sz >= PDF_BOLD_SIZE else b"/F1"
            ops.append(
                b"BT %s %g Tf 1 0 0 1 %g %g Tm %s ET"
                % (font, sz, round(x, 2), round(h - y, 2), _pdf_show(text, kern))
            )
        stream = b"\n".join(ops)
        flate = b""
        if compress:
            stream, flate = zlib.compress(stream, 9), b"/Filter/FlateDecode"
        objs.append(b"<<%s/Length %d>>stream\n%s\nendstream" % (flate, len(stream), stream))
        content = len(objs)
        objs.append(
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 %g %g]/Contents %d 0 R"
            b"/Resources<</Font<</F1 3 0 R/F2 4 0 R>>>>>>" % (w, h, content)
        )
        kids.append(b"%d 0 R" % len(objs))
    objs[1] = b"<</Type/Pages/Kids[%s]/Count %d>>" % (b" ".join(kids), len(kids))
    return _pdf_file(objs)


def image_pdf_bytes(pages: list[tuple[bytes, int, int]], dpi: float) -> bytes:
    """Return a PDF with one grey-scale JPEG image on each page, as a
    scanner makes it: (JPEG bytes, width and height in pixels). No text
    layer and no date."""
    objs: list[bytes] = [b"<</Type/Catalog/Pages 2 0 R>>", b""]
    kids = []
    for jpeg, wpx, hpx in pages:
        w, h = wpx * 72.0 / dpi, hpx * 72.0 / dpi
        objs.append(
            b"<</Type/XObject/Subtype/Image/Width %d/Height %d/ColorSpace/DeviceGray"
            b"/BitsPerComponent 8/Filter/DCTDecode/Length %d>>stream\n%s\nendstream"
            % (wpx, hpx, len(jpeg), jpeg)
        )
        image = len(objs)
        draw = b"q %g 0 0 %g 0 0 cm /Im0 Do Q" % (round(w, 3), round(h, 3))
        objs.append(b"<</Length %d>>stream\n%s\nendstream" % (len(draw), draw))
        objs.append(
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 %g %g]/Contents %d 0 R"
            b"/Resources<</XObject<</Im0 %d 0 R>>>>>>"
            % (round(w, 3), round(h, 3), image + 1, image)
        )
        kids.append(b"%d 0 R" % len(objs))
    objs[1] = b"<</Type/Pages/Kids[%s]/Count %d>>" % (b" ".join(kids), len(kids))
    return _pdf_file(objs)


def _pdf_file(objs: list[bytes]) -> bytes:
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


# --- Git -------------------------------------------------------------------


def git_available() -> bool:
    return shutil.which("git") is not None


def _git_env(date: str | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    return env


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not available")
    result = subprocess.run(  # noqa: S603 - fixed program, no shell
        [git, "-C", str(repo), *args],
        env=_git_env(date),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_git_repo(
    repo: Path,
    author: tuple[str, str],
    commits: list[tuple[str, dict[str, str], str]],
) -> str | None:
    """Write files and make one commit per item. Return HEAD, or None without git.

    Each commit is (message, {path: text}, date). The date is an ISO 8601
    string with a zone, for example "2026-09-01T10:00:00+00:00".
    Without git, the files of all commits are written in order and no
    history exists.
    """
    repo.mkdir(parents=True, exist_ok=True)
    use_git = git_available()
    if use_git:
        _git(repo, "init", "-q", "--template=", "-b", "main")
        _git(repo, "config", "user.name", author[0])
        _git(repo, "config", "user.email", author[1])
        _git(repo, "config", "commit.gpgsign", "false")
        _git(repo, "config", "core.autocrlf", "false")
    for message, files, date in commits:
        for rel, text in files.items():
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.encode("utf-8"))
        if use_git:
            _git(repo, "add", "--", *sorted(files))
            _git(repo, "commit", "-q", "--no-verify", "-m", message, date=date)
    return _git(repo, "rev-parse", "HEAD") if use_git else None


# --- Large file ------------------------------------------------------------


def write_large_file(
    path: Path, size: int, seed_text: str, header: bytes, chunk: int = LARGE_CHUNK
) -> str:
    """Write `size` bytes: `header`, then seeded pseudo-random bytes.

    The file is written in chunks, so memory use does not grow with `size`.
    Return the SHA-256 hex digest. If `size` is smaller than the header,
    the file is the header only.
    """
    rng = random.Random(seed_text)  # noqa: S311 - test data, not secrets
    digest = hashlib.sha256()
    with path.open("wb") as f:
        f.write(header)
        digest.update(header)
        left = max(0, size - len(header))
        while left:
            n = min(chunk, left)
            block = rng.randbytes(n)
            f.write(block)
            digest.update(block)
            left -= n
    return digest.hexdigest()
