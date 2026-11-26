"""Built-in converters: `basic`, `markitdown`, and the `datalab` stub."""

from __future__ import annotations

import io
import logging

from anagram.local.index import extract
from anagram.local.index.convert.base import CHEAP, HEAVY, REMOTE, Blob, ConversionError, Converter
from anagram.local.index.convert.document import Document, blocks_from_markdown
from anagram.local.index.media import DOCX, EPUB, PPTX, XLSX

log = logging.getLogger("anagram.local.index")

PDF = "application/pdf"


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


class DatalabConverter(Converter):
    """Stub only. Datalab (datalab.to) is a remote converter for hard PDFs and
    scans. It is a disclosure recipient: it reads the files of each source that
    the user turns it on for. It is off by default and not built: `available()`
    is False, so the router never selects it. Before it is built, Datalab must
    confirm in writing that it keeps no input (plan, open questions)."""

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
