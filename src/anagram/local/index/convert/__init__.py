"""Converters: evidence bytes -> `Document`. See `base.py` and spec/index.md.

`CONVERTERS` is the registry (`anagram.converters` entry points plus the
built-ins `markitdown`, `basic`, `datalab`). `Router` picks the converter for
one blob:

1. the converters that the user prefers for the source (in order),
2. then the local converters, in registry order (`markitdown` before `basic`,
   so markitdown is the default for the formats that it reads),
3. then the remote converters, only if the user opted in for the source.

The first converter that accepts the media type and gives a document wins. If
it fails, the next one tries. If none gives a document, the item stays as
evidence and goes into the skipped report with a reason and a fix.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from anagram.local.index.convert.base import (
    CHEAP,
    COSTS,
    HEAVY,
    REMOTE,
    Blob,
    ConversionError,
    Converter,
    ConverterRefused,
    check_converter,
)
from anagram.local.index.convert.builtin import (
    BasicConverter,
    DatalabConverter,
    MarkItDownConverter,
)
from anagram.local.index.convert.document import (
    DOC_SCHEMA,
    Block,
    Document,
    Span,
    blocks_from_markdown,
    content_anchors,
)
from anagram.local.index.registry import GROUP_CONVERTERS, Registry

log = logging.getLogger("anagram.local.index")

CONVERTERS: Registry[type[Converter]] = Registry(GROUP_CONVERTERS)
for _cls in (MarkItDownConverter, BasicConverter, DatalabConverter):
    CONVERTERS.register(_cls.name, _cls, builtin=True)


def all_converters() -> list[Converter]:
    """One instance of each registered converter (available or not)."""
    out = []
    for name, cls in CONVERTERS:
        try:
            out.append(cls())
        except Exception:  # a bad plug-in must not stop the index
            log.exception("converter %r does not start", name)
    return out


@dataclass(frozen=True)
class Skip:
    """Why no converter made a document, and what the person can do."""

    reason: str
    fix: str


class Skipped(Exception):
    def __init__(self, skip: Skip) -> None:
        super().__init__(skip.reason)
        self.skip = skip


# on_external(converter, blob): called before an external converter reads the
# bytes. The index writes a disclosure log row.
ExternalHook = Callable[[Converter, Blob], None]


class Router:
    def __init__(
        self,
        converters: Iterable[Converter] | None = None,
        *,
        prefer: Iterable[str] = (),
        allow_external: Iterable[str] = (),
        on_external: ExternalHook | None = None,
    ) -> None:
        self.converters = list(converters) if converters is not None else all_converters()
        self.prefer = list(prefer)
        self.allow_external = frozenset(allow_external)
        self.on_external = on_external

    def candidates(self, media_type: str) -> list[Converter]:
        ok = [c for c in self.converters if c.available() and c.accepts_type(media_type)]
        by_name = {c.name: c for c in ok}
        out = [by_name[n] for n in self.prefer if n in by_name]
        out += [c for c in ok if not c.external and c not in out]
        out += [c for c in ok if c.external and c.name in self.allow_external and c not in out]
        return [c for c in out if not c.external or c.name in self.allow_external]

    def refused(self, media_type: str) -> list[Converter]:
        """External converters that accept the type but have no opt-in."""
        return [
            c
            for c in self.converters
            if c.external
            and c.available()
            and c.accepts_type(media_type)
            and c.name not in self.allow_external
        ]

    def convert(self, blob: Blob) -> Document:
        """The document from the first converter that works. Raise `Skipped`
        if none does."""
        errors = []
        for conv in self.candidates(blob.media_type):
            check_converter(conv, conv.name in self.allow_external)
            if conv.external and self.on_external is not None:
                self.on_external(conv, blob)
            try:
                doc = conv.convert(blob)
            except ConversionError as exc:
                errors.append(f"{conv.name}: {exc}")
                continue
            doc.converter = doc.converter or conv.name
            doc.converter_version = doc.converter_version or conv.version_id()
            return doc
        if errors:
            raise Skipped(
                Skip(
                    "conversion failed (" + "; ".join(errors) + ")",
                    "The file stays as evidence. Open and save it again, or export it as PDF.",
                )
            )
        refused = self.refused(blob.media_type)
        if refused:
            names = ", ".join(c.recipient or c.name for c in refused)
            raise Skipped(
                Skip(
                    f"only an outside converter reads {blob.media_type}",
                    f"Turn on {names} for this source in Settings, if you agree that it"
                    " reads these files.",
                )
            )
        raise Skipped(
            Skip(
                f"no converter reads {blob.media_type}",
                "The file stays as evidence and keeps its date proof. Install a converter"
                " plug-in for this type to search it.",
            )
        )


__all__ = [
    "CHEAP",
    "CONVERTERS",
    "COSTS",
    "DOC_SCHEMA",
    "HEAVY",
    "REMOTE",
    "BasicConverter",
    "Blob",
    "Block",
    "ConversionError",
    "Converter",
    "ConverterRefused",
    "DatalabConverter",
    "Document",
    "MarkItDownConverter",
    "Router",
    "Skip",
    "Skipped",
    "Span",
    "all_converters",
    "blocks_from_markdown",
    "check_converter",
    "content_anchors",
]
