"""Built-in converters: `basic`, `markitdown`, `indra`, and the `datalab` stub."""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import io
import logging
import math
import os
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import ClassVar

from anagram.local.index import extract
from anagram.local.index.convert.base import CHEAP, HEAVY, REMOTE, Blob, ConversionError, Converter
from anagram.local.index.convert.document import (
    Block,
    Document,
    Span,
    blocks_from_markdown,
    content_anchors,
    norm_text,
)
from anagram.local.index.media import DOCX, EPUB, PPTX, XLSX

log = logging.getLogger("anagram.local.index")

PDF = "application/pdf"
INDRA_MAX_BYTES = 64 * 1024 * 1024
INDRA_MAX_PAGES = 200
INDRA_MAX_PIXELS = 40_000_000
INDRA_PDF_DPI = 150.0
_INDRA_REPO_CACHE_DIR = "models--datalab-to--indra-ocr"
_INDRA_LABEL_MAP: dict[str, tuple[str, int]] = {
    "title": ("heading", 1),
    "section_header": ("heading", 2),
    "section-header": ("heading", 2),
    "heading": ("heading", 2),
    "header": ("heading", 2),
    "table": ("table", 0),
    "code": ("code", 0),
    "figure": ("figure", 0),
    "picture": ("figure", 0),
    "caption": ("caption", 0),
    "image": ("image", 0),
}


class BasicConverter(Converter):
    """Today's standard-library extractors (`anagram.local.index.extract`). It keeps
    quoted email text apart. It reads simple PDFs only."""

    name = "basic"
    version = "1"
    cost = CHEAP
    accepts = extract.EXTRACTED_TYPES | {"message/rfc822"}

    def convert(self, blob: Blob) -> Document:
        mt = blob.media_type
        limit = extract.MAX_TEXT_BYTES if mt.startswith("text/") else 4 * extract.MAX_TEXT_BYTES
        if len(blob.data) > limit:
            raise ConversionError(f"too large for the basic converter ({len(blob.data)} bytes)")
        own = blob.extra.get("own")
        own = own if isinstance(own, bool) else None
        ex = extract.extract_bytes(blob.data, blob.name, mt, blob.owner_emails, own)
        return Document.from_extracted(ex, self.name, self.version_id())


class MarkItDownConverter(Converter):
    """Microsoft markitdown (MIT licence), on this computer. The default for
    PDF, Word, PowerPoint, Excel, HTML, and EPUB. Plug-ins of markitdown are
    off, and it gets bytes only (never a URL), so it does not use the network."""

    name = "markitdown"
    version = "1"
    cost = HEAVY
    accepts = frozenset({PDF, DOCX, PPTX, XLSX, EPUB, "text/html"})
    _md = None

    def available(self) -> bool:
        try:
            import markitdown  # noqa: F401
        except ImportError:
            return False
        return True

    def version_id(self) -> str:
        import markitdown

        return f"{markitdown.__version__}+anagram.{self.version}"

    def _engine(self):
        if MarkItDownConverter._md is None:
            from markitdown import MarkItDown

            MarkItDownConverter._md = MarkItDown(enable_plugins=False)
        return MarkItDownConverter._md

    def convert(self, blob: Blob) -> Document:
        from markitdown import StreamInfo

        ext = {
            PDF: ".pdf",
            DOCX: ".docx",
            PPTX: ".pptx",
            XLSX: ".xlsx",
            EPUB: ".epub",
            "text/html": ".html",
        }[blob.media_type]
        info = StreamInfo(mimetype=blob.media_type, extension=ext, filename=blob.name)
        try:
            res = self._engine().convert_stream(io.BytesIO(blob.data), stream_info=info)
        except Exception as exc:  # markitdown raises many types
            raise ConversionError(f"markitdown: {type(exc).__name__}: {exc}") from exc
        md = (res.markdown or "").replace("\r\n", "\n")
        title = res.title
        if not title:
            for line in md.splitlines():
                s = line.strip().lstrip("#").strip()
                if s and not s.startswith("<!--"):
                    title = s[:200]
                    break
        kind = {
            PDF: "pdf",
            DOCX: "document",
            PPTX: "slides",
            XLSX: "table",
            EPUB: "book",
            "text/html": "web",
        }[blob.media_type]
        return Document(
            markdown=md,
            title=title,
            blocks=blocks_from_markdown(md),
            meta={},
            converter=self.name,
            converter_version=self.version_id(),
            kind=kind,
            prose=blob.media_type != XLSX,
            note=None if md.strip() else "markitdown: no text",
        )


def _hf_offline() -> bool:
    val = os.environ.get("HF_HUB_OFFLINE", "").strip().lower()
    return val in ("1", "true", "yes")


def _hf_cache_roots() -> list[Path]:
    roots: list[Path] = []
    for env in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"):
        raw = os.environ.get(env)
        if raw:
            roots.append(Path(raw))
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        roots.append(Path(hf_home) / "hub")
    roots.append(Path.home() / ".cache" / "huggingface" / "hub")
    return roots


def _indra_weights_cached() -> bool:
    for root in _hf_cache_roots():
        snapshots = root / _INDRA_REPO_CACHE_DIR / "snapshots"
        try:
            if snapshots.is_dir() and any(snapshots.iterdir()):
                return True
        except OSError:
            continue
    return False


def _scale_bbox(raw: object, scale: float) -> tuple[float, float, float, float] | None:
    if not isinstance(raw, list | tuple) or len(raw) != 4:
        return None
    inv = 1.0 / scale if scale > 0 else 1.0
    coords: list[float] = []
    for v in raw:
        try:
            f = float(v) * inv
        except (TypeError, ValueError):
            return None
        if not math.isfinite(f):
            return None
        coords.append(round(f, 2))
    return (coords[0], coords[1], coords[2], coords[3])


def _extract_raw_blocks(page: object) -> list[dict]:
    blocks = getattr(page, "blocks", None)
    if not isinstance(blocks, list):
        return []
    out: list[dict] = []
    for b in blocks:
        if isinstance(b, dict):
            label = str(b.get("label") or b.get("kind") or "para").strip().lower()
            text = str(b.get("markdown") or b.get("text") or "").strip()
            bbox = b.get("bbox") if b.get("bbox") is not None else b.get("box")
        else:
            label = str(getattr(b, "label", None) or getattr(b, "kind", "para")).strip().lower()
            text = str(getattr(b, "markdown", None) or getattr(b, "text", "") or "").strip()
            bbox = getattr(b, "bbox", None)
            if bbox is None:
                bbox = getattr(b, "box", None)
        if text:
            out.append({"label": label, "text": text, "bbox": bbox})
    return out


def _page_markdown_text(page: object) -> str:
    if isinstance(page, str):
        return page.replace("\r\n", "\n")
    md = getattr(page, "markdown", None)
    if isinstance(md, str) and md.strip():
        return md.replace("\r\n", "\n")
    txt = getattr(page, "text", None)
    if isinstance(txt, str):
        return txt.replace("\r\n", "\n")
    return ""


def _render_block_md(kind: str, level: int, text: str) -> str:
    if kind == "heading":
        stripped = text.lstrip("#").strip()
        return f"{'#' * max(1, min(6, level or 2))} {stripped}"
    if kind == "code" and not text.startswith("```"):
        return f"```\n{text}\n```"
    return text


def _build_structured_document(
    pages: list[tuple[int, float, list[dict]]],
    *,
    kind: str,
    converter_name: str,
    converter_version: str,
    meta: dict,
) -> Document:
    """Assemble `Document` with `page` containers, `Span(page=..., bbox=..., lines=...)`,
    and content-based anchors."""
    md_pages: list[str] = []
    drafts: list[tuple[str, str, int, int | None, Span]] = []
    children: dict[int, list[tuple[str, str]]] = {}
    line_no = 1

    for pno, scale, raw_blocks in pages:
        page_idx = len(drafts)
        page_start = line_no
        drafts.append(("page", "", 0, None, Span(page=pno, lines=(page_start, page_start))))
        page_chunks: list[str] = []
        for rb in raw_blocks:
            bkind, level = _INDRA_LABEL_MAP.get(rb["label"], ("para", 0))
            clean_text = rb["text"].lstrip("#").strip() if bkind == "heading" else rb["text"]
            rendered = _render_block_md(bkind, level, clean_text)
            if page_chunks:
                line_no += 1  # blank separator line between blocks
            start_line = line_no
            end_line = start_line + rendered.count("\n")
            line_no = end_line + 1
            bbox = _scale_bbox(rb["bbox"], scale)
            span = Span(page=pno, bbox=bbox, lines=(start_line, end_line))
            drafts.append((bkind, clean_text, level, page_idx, span))
            children.setdefault(page_idx, []).append((bkind, clean_text))
            page_chunks.append(rendered)
        page_end = max(page_start, line_no - 1)
        drafts[page_idx] = ("page", "", 0, None, Span(page=pno, lines=(page_start, page_end)))
        md_pages.append("\n\n".join(page_chunks))

    markdown = "\f\n".join(md_pages)
    anchors = content_anchors(
        [
            (
                dkind,
                "\n".join(f"{ck}:{norm_text(ct)}" for ck, ct in children.get(i, []))
                if dkind == "page"
                else dtext,
            )
            for i, (dkind, dtext, _lvl, _par, _sp) in enumerate(drafts)
        ]
    )
    blocks = [
        Block(
            kind=dkind,
            text=dtext,
            anchor=anchors[i],
            level=dlvl,
            parent=anchors[dpar] if dpar is not None else None,
            span=dspan,
        )
        for i, (dkind, dtext, dlvl, dpar, dspan) in enumerate(drafts)
    ]
    title = _first_markdown_title(markdown)
    return Document(
        markdown=markdown,
        title=title,
        blocks=blocks,
        meta=meta,
        converter=converter_name,
        converter_version=converter_version,
        kind=kind,
        prose=True,
        note=None if markdown.strip() else "indra: no text",
    )


def _first_markdown_title(md: str) -> str | None:
    for line in md.splitlines():
        s = line.strip().lstrip("#").strip()
        if s and not s.startswith("<!--"):
            return s[:200]
    return None


def _ensure_page_spans(blocks: list[Block], page: int = 1) -> list[Block]:
    out: list[Block] = []
    for b in blocks:
        sp = b.span
        if sp is None:
            new_span = Span(page=page)
        elif sp.page is None:
            new_span = Span(
                page=page,
                bbox=sp.bbox,
                slide=sp.slide,
                shape=sp.shape,
                sheet=sp.sheet,
                cells=sp.cells,
                message=sp.message,
                part=sp.part,
                lines=sp.lines,
            )
        else:
            new_span = sp
        out.append(Block(b.kind, b.text, b.anchor, b.level, b.parent, new_span, dict(b.attrs)))
    return out


class IndraConverter(Converter):
    """Local CPU / Apple Silicon ONNX OCR via Datalab Indra (`indra-ocr`).

    Runs 100% locally (`external = False`) with zero plaintext temp files:
    images are decoded from memory via Pillow and PDFs are rendered page-by-page
    in memory via `pypdfium2`. Optional dependency: when `indra-ocr` is not
    installed (or offline without cached weights), `available()` is False and
    the router transparently falls back to `markitdown` and `basic`."""

    name = "indra"
    version = "1"
    external = False
    cost = HEAVY
    accepts = frozenset({PDF, "image/png", "image/jpeg", "image/webp", "image/tiff"})

    _lock: ClassVar[threading.Lock] = threading.Lock()
    _cached_engine: ClassVar[object | None] = None

    def __init__(
        self,
        *,
        loader: Callable[[], object] | None = None,
        max_pages: int = INDRA_MAX_PAGES,
        max_pixels: int = INDRA_MAX_PIXELS,
        dpi: float = INDRA_PDF_DPI,
    ) -> None:
        self._loader = loader
        self._instance_engine: object | None = None
        self.max_pages = max_pages
        self.max_pixels = max_pixels
        self.dpi = dpi

    @classmethod
    def clear_cache(cls) -> None:
        with cls._lock:
            cls._cached_engine = None

    def available(self) -> bool:
        if self._loader is not None:
            return True
        if importlib.util.find_spec("indra_ocr") is None:
            return False
        return not (_hf_offline() and not _indra_weights_cached())

    def version_id(self) -> str:
        mod = sys.modules.get("indra_ocr")
        ver = getattr(mod, "__version__", None) if mod is not None else None
        if not isinstance(ver, str) or not ver:
            try:
                ver = importlib.metadata.version("indra-ocr")
            except importlib.metadata.PackageNotFoundError:
                ver = "0"
        return f"{ver}+anagram.{self.version}"

    def _load_converter(self) -> object:
        if self._loader is not None:
            with self._lock:
                if self._instance_engine is None:
                    self._instance_engine = self._loader()
                return self._instance_engine
        with IndraConverter._lock:
            if IndraConverter._cached_engine is None:
                mod = importlib.import_module("indra_ocr")
                IndraConverter._cached_engine = mod.load()
            return IndraConverter._cached_engine

    def _to_ocr_input(self, pil_img: object) -> object:
        gray = pil_img.convert("L")  # type: ignore[attr-defined]
        try:
            import numpy as np

            return np.asarray(gray, dtype=np.uint8)
        except ImportError:
            return gray

    def _safe_scale(self, width_pt: float, height_pt: float) -> float:
        base = self.dpi / 72.0
        area = max(width_pt, 1.0) * max(height_pt, 1.0)
        if area * base * base <= self.max_pixels:
            return base
        return math.sqrt(self.max_pixels / area)

    def _iter_pdf_pages(self, data: bytes) -> tuple[int, Iterator[tuple[int, object, float]]]:
        if not data.startswith(b"%PDF-"):
            raise ConversionError("indra: invalid PDF signature")
        try:
            import pypdfium2 as pdfium
        except ImportError as exc:
            raise ConversionError("indra: pypdfium2 is required for PDF OCR") from exc
        try:
            pdf = pdfium.PdfDocument(data)
        except Exception as exc:
            raise ConversionError(f"indra: failed to open PDF: {exc}") from exc
        total = len(pdf)
        limit = min(total, self.max_pages)

        def _gen() -> Iterator[tuple[int, object, float]]:
            try:
                for idx in range(limit):
                    page = pdf[idx]
                    bitmap = None
                    try:
                        w_pt, h_pt = page.get_size()
                        scale = self._safe_scale(float(w_pt), float(h_pt))
                        bitmap = page.render(scale=scale)
                        pil_img = bitmap.to_pil()
                    finally:
                        if bitmap is not None:
                            bitmap.close()
                        page.close()
                    yield (idx + 1, pil_img, scale)
            finally:
                pdf.close()

        return total, _gen()

    def _iter_image_pages(self, data: bytes) -> tuple[int, Iterator[tuple[int, object, float]]]:
        try:
            from PIL import Image
        except ImportError as exc:
            raise ConversionError("indra: Pillow is required for image OCR") from exc
        try:
            img = Image.open(io.BytesIO(data))
        except Exception as exc:
            raise ConversionError(f"indra: failed to open image: {exc}") from exc
        total = max(1, int(getattr(img, "n_frames", 1)))
        limit = min(total, self.max_pages)

        def _gen() -> Iterator[tuple[int, object, float]]:
            try:
                for idx in range(limit):
                    if idx > 0:
                        img.seek(idx)
                    if img.width * img.height > self.max_pixels:
                        raise ConversionError(
                            f"indra: image exceeds pixel limit ({img.width}x{img.height})"
                        )
                    yield (idx + 1, img.copy(), 1.0)
            finally:
                img.close()

        return total, _gen()

    def _ocr_page(self, engine: object, pil_img: object) -> object:
        arr = self._to_ocr_input(pil_img)
        ocr_fn = getattr(engine, "ocr", None)
        if callable(ocr_fn):
            return ocr_fn(arr)
        if callable(engine):
            return engine(arr)
        raise ConversionError("indra: loaded converter has no callable ocr() method")

    def convert(self, blob: Blob) -> Document:
        if len(blob.data) > INDRA_MAX_BYTES:
            raise ConversionError(f"indra: too large ({len(blob.data)} bytes)")
        try:
            engine = self._load_converter()
        except ConversionError:
            raise
        except Exception as exc:
            raise ConversionError(f"indra: load failed: {type(exc).__name__}: {exc}") from exc

        is_pdf = blob.media_type == PDF
        total_pages, page_iter = (
            self._iter_pdf_pages(blob.data) if is_pdf else self._iter_image_pages(blob.data)
        )
        structured_pages: list[tuple[int, float, list[dict]]] = []
        markdown_pages: list[str] = []
        has_structured = False
        processed = 0

        try:
            for pno, pil_img, scale in page_iter:
                page_res = self._ocr_page(engine, pil_img)
                processed += 1
                raw_blocks = _extract_raw_blocks(page_res)
                if raw_blocks:
                    has_structured = True
                structured_pages.append((pno, scale, raw_blocks))
                markdown_pages.append(_page_markdown_text(page_res))
        except ConversionError:
            raise
        except Exception as exc:
            raise ConversionError(f"indra: {type(exc).__name__}: {exc}") from exc

        meta: dict = {"pages": processed, "total_pages": total_pages}
        if total_pages > self.max_pages:
            meta["truncated_pages"] = True
        kind = "pdf" if is_pdf else "image"

        if has_structured:
            return _build_structured_document(
                structured_pages,
                kind=kind,
                converter_name=self.name,
                converter_version=self.version_id(),
                meta=meta,
            )

        md = "\f".join(markdown_pages)
        blocks = blocks_from_markdown(md)
        if len(markdown_pages) == 1:
            blocks = _ensure_page_spans(blocks, page=1)
        return Document(
            markdown=md,
            title=_first_markdown_title(md),
            blocks=blocks,
            meta=meta,
            converter=self.name,
            converter_version=self.version_id(),
            kind=kind,
            prose=True,
            note=None if md.strip() else "indra: no text",
        )


class DatalabConverter(Converter):
    """Stub only. Datalab (datalab.to) is a remote converter for hard PDFs and
    scans (for local CPU/Apple Silicon ONNX OCR, see `IndraConverter`). It is a
    disclosure recipient: it reads the files of each source that the user turns
    it on for. It is off by default and not built: `available()` is False, so
    the router never selects it. Before it is built, Datalab must confirm in
    writing that it keeps no input (plan, open questions)."""

    name = "datalab"
    version = "0"
    external = True
    recipient = "Datalab (datalab.to)"
    reads = "the files of the sources that you turn it on for"
    paid = True
    cost = REMOTE
    accepts = frozenset({PDF, DOCX, PPTX, "image/png", "image/jpeg", "image/tiff"})

    def available(self) -> bool:
        return False

    def convert(self, blob: Blob) -> Document:
        raise ConversionError("the Datalab converter is not built")
