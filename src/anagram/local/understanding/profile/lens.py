"""The `profile` lens (primitive `purpose-lens`).

    lens = ProfileLens(model, embedder)
    view = lens.view(items, today=date.today(), grant={"discoverable", "shared"})
    view.offers, view.wants      # beacon draft lines
    view.readings                # person-level readings with a basis
    lens.view(items + [new], ...)  # reads only the new item again

Contract fields: `name`, `version`, `purpose`, `inputs`, `output_schema`,
`cost`, `recipient`, `tiers`. The 03a registry (`LENSES`, entry points) is
not built yet; this lens has the fields that the registry will read.

Rules:

- Tiers: the lens reads `discoverable` and `shared`
  items, never `private` ones (received mail and other third-party text are
  private). A caller whose grant does not hold all lens tiers gets
  `TierRefused`. An item of a tier outside the grant is not read.
- Received items (role `received`) give no signal and no reading.
- Cache: item signals by (item ID, digest of text, role, date); the view by
  (lens version, digest of inputs, policy version). One new item makes one
  item read and one combine (no model call in combine).
- Indexing is product-defined: the person removes or edits a line
  in the beacon draft, but cannot change how the lens reads.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, MutableMapping, Sequence
from dataclasses import dataclass, field
from datetime import date

from anagram.local.understanding.profile.combine import combine, draft
from anagram.local.understanding.profile.schema import (
    CLASSES,
    MATCH,
    READINGS,
    LensItem,
    Line,
    Reading,
)
from anagram.local.understanding.profile.signals import PROMPT_VERSION, ItemSignals, read_item
from anagram.models import TextModel
from anagram.models.embed import Embedder

POLICY_VERSION = "n5.c20.v1"
_LINE = {
    "type": "object",
    "properties": {
        "class": {"type": "string", "enum": list(CLASSES)},
        "match_types": {"type": "array", "items": {"type": "string", "enum": list(MATCH)}},
        "scope": {"type": "string", "enum": ["inside", "outside", "both"]},
        "side": {"type": "string", "enum": ["offer", "want"]},
        "text": {"type": "string", "maxLength": 140},
    },
    "required": ["class", "match_types", "scope", "side", "text"],
}
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "offers": {"type": "array", "items": _LINE, "maxItems": 5},
        "wants": {"type": "array", "items": _LINE, "maxItems": 5},
        "readings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"kind": {"type": "string", "enum": list(READINGS)}},
            },
        },
    },
    "required": ["offers", "wants"],
}


class TierRefused(PermissionError):
    """The lens needs a tier that its caller may not read."""


@dataclass
class ProfileView:
    readings: list[Reading]
    offers: list[Line]
    wants: list[Line]
    read: int = 0  # items read by the model for this view
    calls: int = 0
    errors: int = 0
    signals: dict[str, ItemSignals] = field(default_factory=dict, repr=False)

    def draft_json(self) -> dict:
        """The beacon draft as the app shows it (no basis, no item ID)."""
        return {
            "offers": [ln.public() for ln in self.offers],
            "wants": [ln.public() for ln in self.wants],
        }


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _item_key(item: LensItem) -> str:
    return _digest(item.id, item.role, item.date, item.text)


class ProfileLens:
    name = "profile"
    version = "1"
    purpose = "What you work on, where you are stuck, what you ask for, and what you can offer."
    inputs = ("item text", "item role", "item date")
    output_schema = OUTPUT_SCHEMA
    cost = "local_model"
    recipient = ""
    tiers = frozenset({"discoverable", "shared"})

    def __init__(
        self,
        model: TextModel,
        embedder: Embedder,
        *,
        answers: MutableMapping[str, str] | None = None,
    ) -> None:
        if model.external:
            raise TierRefused("the profile lens runs on a local model only")
        self.model = model
        self.embedder = embedder
        self.answers = answers if answers is not None else {}  # model answer cache
        self._signals: dict[str, ItemSignals] = {}  # by _item_key
        self._views: dict[str, ProfileView] = {}

    def cache_key(
        self, items: Sequence[LensItem], today: date, published: Iterable[str] | None = None
    ) -> str:
        inputs = _digest(*sorted(_item_key(i) + i.tier for i in items))
        pub = _digest(*sorted(published or ()))
        return _digest(
            self.name, self.version, PROMPT_VERSION, inputs, POLICY_VERSION, str(today), pub
        )

    def view(
        self,
        items: Iterable[LensItem],
        *,
        today: date,
        grant: Iterable[str] = ("discoverable", "shared"),
        published: set[str] | None = None,
    ) -> ProfileView:
        grant = frozenset(grant)
        if not self.tiers <= grant:
            raise TierRefused(f"the {self.name} lens reads {sorted(self.tiers)}")
        usable = [i for i in items if i.tier in self.tiers and i.role != "received"]
        key = self.cache_key(usable, today, published)
        if key in self._views:
            return self._views[key]
        got: dict[str, ItemSignals] = {}
        read = calls = errors = 0
        for item in usable:
            k = _item_key(item)
            if k not in self._signals:
                s = read_item(self.model, item, self.answers)
                read, calls, errors = read + 1, calls + s.calls, errors + s.errors
                if s.errors == 0:
                    self._signals[k] = s
            else:
                s = self._signals[k]
            got[item.id] = s
        readings = combine(usable, got, self.embedder, today)
        offers, wants = draft(readings, published)
        out = ProfileView(readings, offers, wants, read, calls, errors, got)
        if errors == 0:
            self._views[key] = out
        return out
