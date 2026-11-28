"""Types of the `profile` lens.

The lens reads the own items of one person and gives person-level readings
and a draft of typed OFFERS and WANTS lines for a person beacon.

- Item signal kinds (one model question each, `signals.py`): `ask`, `offer`,
  `stuck`, `method`.
- Reading kinds (person level, `combine.py`): `asks`, `offers`, `stuck_on`,
  `tacit_skill`, `trajectory`.
- Line class: `problem`, `method`, `skill`, `instrument`,
  `data`, `material`, `replication`, `supervision`.
- Match types: T1 to T6. Each line names the types that it
  serves, from its side and its class (`MATCH_TYPES`).

The line text is one own sentence of the person, word for word, cut to 140
characters at a word limit. The model writes no text (layer 1 of primitive
`planted-instructions`); it only chooses sentence numbers and enum values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SIGNALS = ("ask", "offer", "stuck", "method")
READINGS = ("asks", "offers", "stuck_on", "tacit_skill", "trajectory")
CLASSES = (
    "problem",
    "method",
    "skill",
    "instrument",
    "data",
    "material",
    "replication",
    "supervision",
)
MATCH = {
    "T1": "research_fit",
    "T2": "method_help",
    "T3": "instrument_access",
    "T4": "data_material_share",
    "T5": "replication",
    "T6": "co_supervision",
}
# (side, class) -> the match types that a line serves.
MATCH_TYPES: dict[tuple[str, str], tuple[str, ...]] = {
    ("want", "problem"): ("T1", "T2"),
    ("want", "method"): ("T1", "T2"),
    ("want", "skill"): ("T1", "T2"),
    ("offer", "method"): ("T1", "T2"),
    ("offer", "skill"): ("T1", "T2"),
    ("offer", "problem"): ("T1",),
    ("want", "instrument"): ("T3",),
    ("offer", "instrument"): ("T3",),
    ("want", "data"): ("T4",),
    ("offer", "data"): ("T4",),
    ("want", "material"): ("T4",),
    ("offer", "material"): ("T4",),
    ("want", "replication"): ("T5",),
    ("offer", "replication"): ("T5",),
    ("want", "supervision"): ("T6",),
    ("offer", "supervision"): ("T6",),
}
# Classes that can meet: a want of the key class can be met by an offer of these.
MEETS: dict[str, frozenset[str]] = {
    "problem": frozenset({"method", "skill", "problem"}),
    "method": frozenset({"method", "skill"}),
    "skill": frozenset({"method", "skill"}),
    "instrument": frozenset({"instrument"}),
    "data": frozenset({"data"}),
    "material": frozenset({"material"}),
    "replication": frozenset({"replication"}),
    "supervision": frozenset({"supervision"}),
}
LINE_CHARS = 140
MAX_LINES = 5  # person beacon: at most 5 offers and 5 wants
HALF_LIFE_DAYS = 365.0  # recency weight half-life

# Roles of an item, from its source and its kind (`items.py`).
ROLES = ("sent", "doc", "code", "notebook", "protocol", "publication", "received")
OWN_ROLES = frozenset(ROLES) - {"received"}
WORK_ROLES = frozenset({"code", "notebook", "protocol"})  # where a tacit skill shows


@dataclass(frozen=True)
class LensItem:
    """One item as the lens reads it. `text` is own text only: the index
    gives `Document.markdown`, never `Document.quoted`."""

    id: str
    role: str
    date: str  # YYYY-MM-DD
    text: str
    tier: str = "discoverable"  # "private", "discoverable", or "shared"
    published: bool = False


@dataclass(frozen=True)
class Basis:
    item: str
    sentence: str
    date: str
    role: str


@dataclass
class Reading:
    """A person-level reading (two-layer reading: subjective, with a basis)."""

    kind: str  # one of READINGS
    cls: str  # one of CLASSES, or "" for trajectory
    text: str  # an own sentence, or a topic phrase for trajectory
    basis: list[Basis]
    weight: float
    value: dict = field(default_factory=dict)  # trajectory: direction and counts

    @property
    def items(self) -> list[str]:
        return sorted({b.item for b in self.basis})


@dataclass
class Line:
    """One beacon draft line. The basis stays on the app."""

    side: str  # "offer" or "want"
    cls: str
    match_types: tuple[str, ...]
    text: str
    scope: str  # "inside" or "both" (default "inside")
    weight: float
    reading: str  # the reading kind that made the line
    basis: list[Basis]

    def public(self) -> dict:
        """The fields that may go into a beacon after the person approves the
        line: no item ID, no file name, no basis."""
        return {
            "class": self.cls,
            "match_types": list(self.match_types),
            "scope": self.scope,
            "side": self.side,
            "text": self.text,
        }


def match_types(side: str, cls: str) -> tuple[str, ...]:
    return MATCH_TYPES.get((side, cls), ("T1",))


def cut(text: str, limit: int = LINE_CHARS) -> str:
    """`text` cut at a word limit to at most `limit` characters."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    head = text[: limit - 1].rsplit(" ", 1)[0].rstrip(",;:")
    return head + "…"
