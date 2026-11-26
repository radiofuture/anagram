"""The converter plug-in contract (spec/index.md section 3).

A converter reads the evidence bytes of one item version and returns a
`Document`. It never changes the evidence. The evidence is committed before
any conversion.

A converter that sends bytes off the device (`external = True`) is a
**disclosure recipient** (docs/design/disclosure-recipient.md):

- It names `recipient` (the party that reads the bytes).
- The index refuses it unless the user opted in for that source
  (`check_converter`). The default is off.
- A paid converter (`paid = True`) also needs an approved budget. No paid
  converter is active in this step.
- Each external call writes a local log row (`disclosure` table).
- Tests use local fakes only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from anagram.local.index.convert.document import Document

CHEAP = "cheap"  # standard library, fast
HEAVY = "heavy"  # local, slower (parsers, models)
REMOTE = "remote"  # bytes leave the device
COSTS = (CHEAP, HEAVY, REMOTE)


class ConversionError(Exception):
    """The converter accepted the type but could not read the bytes."""


class ConverterRefused(Exception):
    """An external converter without the user's opt-in."""


@dataclass(frozen=True)
class Blob:
    """The exact evidence bytes of one item version, with hints."""

    data: bytes
    name: str
    media_type: str
    owner_emails: frozenset[str] = frozenset()
    path: Path | None = None
    extra: dict = field(default_factory=dict)


class Converter(ABC):
    name: ClassVar[str] = ""
    version: ClassVar[str] = "1"
    external: ClassVar[bool] = False  # True: bytes leave the device
    recipient: ClassVar[str | None] = None  # who reads the bytes, for the UI
    reads: ClassVar[str] = "the files of the sources you turn it on for"
    paid: ClassVar[bool] = False
    cost: ClassVar[str] = CHEAP
    accepts: ClassVar[frozenset[str]] = frozenset()

    def available(self) -> bool:
        """False when a needed package is not installed (or the converter is
        a stub). The router leaves it out."""
        return True

    def accepts_type(self, media_type: str) -> bool:
        return media_type in self.accepts

    def version_id(self) -> str:
        return self.version

    @abstractmethod
    def convert(self, blob: Blob) -> Document:
        """Return the document. Raise `ConversionError` if the bytes do not
        read."""


def check_converter(conv: Converter, allowed: bool) -> None:
    """Refuse an external converter unless the user opted in (the same rule
    as `check_drafter`)."""
    if conv.external and not allowed:
        raise ConverterRefused(
            f"converter {conv.name!r} sends files to {conv.recipient or 'an outside service'};"
            " the user must opt in for this source"
        )
