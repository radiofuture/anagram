"""Unit tests for the local Datalab Indra ONNX OCR converter (`IndraConverter`).

Runs 100% offline with injected fakes plus real Pillow / pypdfium2 in-memory
decoding/rendering and the plaintext temp-file canary scan (`no_plaintext_temp`).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import threading
from dataclasses import dataclass, field

import pytest
from PIL import Image
from tempscan import canary, no_plaintext_temp

from anagram.local.index.convert import (
    CONVERTERS,
    BasicConverter,
    Blob,
    ConversionError,
    IndraConverter,
    MarkItDownConverter,
    Router,
)
from anagram.local.index.convert.document import norm_text
from anagram.sim.writers import pdf_bytes, pdf_layout

pytestmark = pytest.mark.usefixtures("no_network")


@dataclass
class _FakePage:
    markdown: str = ""
    text: str = ""
    blocks: list[dict] = field(default_factory=list)


class _FakeEngine:
    def __init__(self, pages: list[_FakePage]) -> None:
        self.pages = pages
        self.calls: list[tuple[int, int]] = []

    def ocr(self, img) -> _FakePage:
        shape = getattr(img, "shape", None)
        if shape is not None:
            self.calls.append((int(shape[0]), int(shape[1])))
        else:
            self.calls.append(img.size)
        idx = min(len(self.calls) - 1, len(self.pages) - 1)
        return self.pages[idx]


def _make_image(fmt: str, size: tuple[int, int] = (80, 60), frames: int = 1) -> bytes:
    buf = io.BytesIO()
    if frames > 1 and fmt == "TIFF":
        imgs = [Image.new("RGB", size, color=(i * 40 % 255, 120, 200)) for i in range(frames)]
        imgs[0].save(buf, format="TIFF", save_all=True, append_images=imgs[1:])
    else:
        Image.new("RGB", size, color=(240, 240, 240)).save(buf, format=fmt)
    return buf.getvalue()


def _make_pdf(pages: int, tag: str) -> bytes:
    # Build enough paragraphs to span `pages` pages cleanly via pdf_layout.
    blocks: list = [("h1", f"Cryo Study {tag}")]
    for i in range(pages * 16):
        blocks.append(("p", f"Measurement {i} for {tag}: binding affinity Kd = 12 nM."))
    return pdf_bytes(pdf_layout(blocks))


def test_unavailable_by_default_and_registered_cleanly():
    conv = IndraConverter()
    assert conv.name == "indra"
    assert conv.external is False
    assert conv.cost == "heavy"
    assert "application/pdf" in conv.accepts
    assert {"image/png", "image/jpeg", "image/webp", "image/tiff"} <= conv.accepts
    # In standard test/CI environments, indra_ocr is not installed.
    assert conv.available() is False
    assert "indra" in CONVERTERS.names()
    assert CONVERTERS.names()[:3] == ["markitdown", "basic", "datalab"]


def test_offline_guard_respects_hf_hub_cache(monkeypatch, tmp_path):
    fake_spec = importlib.machinery.ModuleSpec("indra_ocr", loader=None)
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name: fake_spec if name == "indra_ocr" else None
    )
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path))
    monkeypatch.delenv("HUGGINGFACE_HUB_CACHE", raising=False)
    monkeypatch.delenv("HF_HOME", raising=False)

    conv = IndraConverter()
    assert conv.available() is False  # offline and weights not cached

    snap = tmp_path / "models--datalab-to--indra-ocr" / "snapshots" / "abc123"
    snap.mkdir(parents=True)
    assert conv.available() is True  # weights cached locally

    monkeypatch.setenv("HF_HUB_OFFLINE", "0")
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "empty"))
    assert conv.available() is True  # online allowed


def test_pdf_structured_blocks_spans_and_no_plaintext_temp():
    tag = canary("indra-pdf")
    raw_pdf = _make_pdf(2, tag)
    engine = _FakeEngine(
        [
            _FakePage(
                blocks=[
                    {"label": "title", "bbox": [100, 50, 500, 120], "text": f"Study {tag}"},
                    {
                        "label": "text",
                        "bbox": [100, 140, 500, 220],
                        "text": f"We need GPU hours for {tag}.",
                    },
                ]
            ),
            _FakePage(
                blocks=[
                    {"label": "section_header", "bbox": [100, 60, 420, 110], "text": "Results"},
                    {
                        "label": "table",
                        "bbox": [100, 130, 520, 260],
                        "text": "| a | b |\n| 1 | 2 |",
                    },
                    {"label": "caption", "bbox": [100, 270, 520, 300], "text": "Table 1 summary."},
                ]
            ),
        ]
    )
    conv = IndraConverter(loader=lambda: engine, dpi=144.0)  # scale = 2.0
    assert conv.available() is True

    with no_plaintext_temp(tag):
        doc = conv.convert(Blob(data=raw_pdf, name="scan.pdf", media_type="application/pdf"))

    assert doc.converter == "indra"
    assert doc.kind == "pdf" and doc.prose is True
    assert doc.title == f"Study {tag}"
    assert len(engine.calls) >= 2
    assert doc.meta["pages"] == len(engine.calls)

    page_blocks = [b for b in doc.blocks if b.kind == "page"]
    assert [p.span.page for p in page_blocks[:2]] == [1, 2]

    heading = next(b for b in doc.blocks if b.kind == "heading" and tag in b.text)
    assert heading.level == 1
    assert heading.parent == page_blocks[0].anchor
    assert heading.span.page == 1
    # dpi=144 -> scale=2.0 -> pixel bbox halved into PDF points.
    assert heading.span.bbox == (50.0, 25.0, 250.0, 60.0)

    lines = doc.markdown.split("\n")
    for b in doc.blocks:
        if b.kind != "page":
            first, last = b.span.lines
            held = norm_text(" ".join(lines[first - 1 : last]))
            assert norm_text(b.text) in held


def test_markdown_fallback_gives_page_spans_for_single_and_multi_page():
    # Single-page image fallback -> Span(page=1) on every block.
    tag = canary("indra-img")
    png = _make_image("PNG")
    engine = _FakeEngine([_FakePage(markdown=f"# Gel {tag}\n\nBand intensity measured.")])
    conv = IndraConverter(loader=lambda: engine)
    with no_plaintext_temp(tag):
        doc = conv.convert(Blob(data=png, name="gel.png", media_type="image/png"))
    assert doc.kind == "image" and doc.prose is True
    assert doc.title == f"Gel {tag}"
    assert doc.blocks and all(b.span is not None and b.span.page == 1 for b in doc.blocks)

    # Multi-frame TIFF fallback -> pages 1 and 2 via \f page breaks.
    tiff = _make_image("TIFF", frames=2)
    engine2 = _FakeEngine(
        [
            _FakePage(markdown="# Frame One\n\nFirst scan."),
            _FakePage(markdown="# Frame Two\n\nSecond scan."),
        ]
    )
    doc2 = IndraConverter(loader=lambda: engine2).convert(
        Blob(data=tiff, name="stack.tiff", media_type="image/tiff")
    )
    assert doc2.meta == {"pages": 2, "total_pages": 2}
    pages = [b for b in doc2.blocks if b.kind == "page"]
    assert [p.span.page for p in pages] == [1, 2]
    assert any(b.span.page == 2 and "Second scan." in b.text for b in doc2.blocks)


@pytest.mark.parametrize(
    ("fmt", "mt", "name"),
    [("JPEG", "image/jpeg", "a.jpg"), ("WEBP", "image/webp", "a.webp")],
)
def test_decodes_jpeg_and_webp_in_memory(fmt, mt, name):
    raw = _make_image(fmt, size=(64, 48))
    engine = _FakeEngine([_FakePage(text="Scanned lab note.")])
    doc = IndraConverter(loader=lambda: engine).convert(Blob(data=raw, name=name, media_type=mt))
    assert doc.markdown == "Scanned lab note."
    assert engine.calls == [(48, 64)]


def test_lazy_thread_safe_model_cache():
    loads = 0
    gate = threading.Barrier(4)
    engine = _FakeEngine([_FakePage(markdown="ok")])

    def load_once():
        nonlocal loads
        loads += 1
        return engine

    conv = IndraConverter(loader=load_once)
    png = _make_image("PNG")
    results: list[str] = []

    def worker():
        gate.wait()
        doc = conv.convert(Blob(data=png, name="a.png", media_type="image/png"))
        results.append(doc.markdown)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert loads == 1
    assert results == ["ok"] * 4


def test_dos_bounds_and_invalid_inputs():
    engine = _FakeEngine([_FakePage(markdown="page")])
    # Pixel bomb rejected before decoding.
    tiny_limit = IndraConverter(loader=lambda: engine, max_pixels=100)
    with pytest.raises(ConversionError, match="pixel limit"):
        tiny_limit.convert(
            Blob(data=_make_image("PNG", (20, 20)), name="big.png", media_type="image/png")
        )

    # PDF page cap truncates cleanly with metadata flag.
    raw_pdf = _make_pdf(3, "cap")
    capped = IndraConverter(loader=lambda: engine, max_pages=1)
    doc = capped.convert(Blob(data=raw_pdf, name="many.pdf", media_type="application/pdf"))
    assert doc.meta["pages"] == 1
    assert doc.meta["total_pages"] >= 2
    assert doc.meta["truncated_pages"] is True

    # Invalid PDF signature / corrupt image raise ConversionError.
    conv = IndraConverter(loader=lambda: engine)
    with pytest.raises(ConversionError, match="invalid PDF"):
        conv.convert(Blob(data=b"not a pdf", name="bad.pdf", media_type="application/pdf"))
    with pytest.raises(ConversionError, match="failed to open image"):
        conv.convert(Blob(data=b"not an image", name="bad.png", media_type="image/png"))


def test_router_priority_preference_and_fallback():
    raw_pdf = _make_pdf(1, "route")
    ok_indra = IndraConverter(loader=lambda: _FakeEngine([_FakePage(markdown="OCR text")]))
    convs = [MarkItDownConverter(), BasicConverter(), ok_indra]

    # When Indra is available, Router tries it ahead of MarkItDown and Basic.
    r = Router(convs)
    assert [c.name for c in r.candidates("application/pdf")] == ["indra", "markitdown", "basic"]
    assert (
        r.convert(Blob(data=raw_pdf, name="p.pdf", media_type="application/pdf")).converter
        == "indra"
    )

    # Explicit user preference overrides default priority.
    pref = Router(convs, prefer=["markitdown"])
    assert [c.name for c in pref.candidates("application/pdf")] == ["markitdown", "indra", "basic"]

    # When Indra fails (e.g., offline weights missing or runtime error), Router falls back.
    def broken_loader():
        raise OSError("LocalEntryNotFoundError: weights not cached offline")

    failing_indra = IndraConverter(loader=broken_loader)
    fb = Router([MarkItDownConverter(), BasicConverter(), failing_indra])
    doc = fb.convert(Blob(data=raw_pdf, name="p.pdf", media_type="application/pdf"))
    assert doc.converter == "markitdown"
    assert "Cryo Study route" in doc.markdown
