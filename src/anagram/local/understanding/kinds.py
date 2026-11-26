"""The item kind taxonomy `anagram.item_kind.v1` (spec/understanding.md).

A kind is the role of an item in research, not its file format. The
definitions use no words of one discipline.

The kind of an item comes from four places. The first that exists wins:

1. `person`: the person corrected the kind (table `kind_override`). It is per
   item, so it stays for a new version. Nothing overwrites it.
2. `model`: the `understand` stage (fact `kind`, enricher `understand`).
3. `lab`: the kind that the author's app gave to a lab item (enricher
   `kind_rules`, `data.by = "lab"`).
4. `rules`: the rules pass (`kind_rules.py`, no model).

No kind fact gives `unknown`.

A `finding` or a `result` can also have a polarity (`POLARITY`, in
`data.polarity` of the kind fact). The kinds do not change:
a negative result is a finding or a result with the polarity "negative".
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from anagram.core.timefmt import iso_seconds
from anagram.local.index.store import loads
from anagram.local.understanding import understand_schema

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

TAXONOMY = "anagram.item_kind.v1"

# id -> (word for people, definition for the model)
KINDS: dict[str, tuple[str, str]] = {
    "finding": (
        "Finding",
        "States a new claim of the person or lab, with support. A person can stamp it.",
    ),
    "result": ("Result", "An observed outcome with no interpreted claim yet."),
    "method": ("Method", "How to do a thing: protocol, procedure, pipeline description, guide."),
    "note": ("Note", "Working notes, a notebook page, meeting notes, ideas."),
    "draft": (
        "Draft",
        "A text for readers that is not final: manuscript, chapter, poster, slides.",
    ),
    "plan": ("Plan", "Work that is not done: proposal, grant text, aims, pre-registration."),
    "correspondence": ("Message", "Email, chat export, letter, review exchange."),
    "data": ("Data", "Raw or processed data with little prose."),
    "code": ("Code", "Source code, notebooks with mostly code, configuration."),
    "reference": ("Reference", "Work of other people or work that is already public."),
    "admin": ("Admin", "Forms, budgets, schedules, orders, staff and teaching logistics."),
    "noise": ("Other", "Empty, duplicate, generated, or system files."),
    "unknown": ("Unsorted", "Not enough text to decide."),
}
KIND_IDS = tuple(KINDS)
EXTRACT_KINDS = frozenset({"finding", "result", "method", "note", "draft", "plan"})
SEED_KINDS = frozenset({"finding", "result"})
REFERENCE = "reference"
UNKNOWN = "unknown"
STAGES = ("observed", "replicated", "hypothesis")
CLAIM_STATUS = ("observed", "hypothesis", "planned")
# The outcome of a `finding` or a `result`: "negative" is a
# null or negative outcome (no effect, no difference, a failed repeat),
# "positive" an effect, "unclear" values only or a mixed outcome. A closed
# set, so the model writes no text for it. Other kinds have no polarity.
POLARITY = ("positive", "negative", "unclear")
NEGATIVE = "negative"
ENTITY_TYPES = (
    "method",
    "instrument",
    "material",
    "organism",
    "dataset",
    "concept",
    "place",
    "org",
    "grant",
)
PERSON_ROLES = ("author", "mentioned", "correspondent")
BY = ("person", "model", "lab", "rules")
# Facts of the author that a lab item carries (`extra.facts`) and that the
# rules pass copies.
FACT_KINDS_FROM_LAB = frozenset({"title", "claim", "entity", "person", "summary"})
MAX_HINTS = 10


def label(kind: str | None) -> str:
    return KINDS.get(kind or UNKNOWN, KINDS[UNKNOWN])[0]


def check_kind(kind: object) -> str:
    if kind not in KINDS:
        raise ValueError("not a kind of the taxonomy")
    return kind  # type: ignore[return-value]


@dataclass(frozen=True)
class ItemKind:
    kind: str
    confidence: float
    by: str  # "person" | "model" | "lab" | "rules" | "none"
    stage: str | None = None
    second: str | None = None
    title: str | None = None
    polarity: str | None = None  # `POLARITY`, only for a kind of `SEED_KINDS`


def polarity_of(kind: str, data: dict) -> str | None:
    """The polarity of a kind fact: a value of `POLARITY` for a kind of
    `SEED_KINDS`, else None."""
    value = data.get("polarity")
    return value if kind in SEED_KINDS and value in POLARITY else None


def _rank(enricher: str, by: str | None) -> int:
    if enricher == "understand":
        return 0
    if by == "lab":
        return 1
    return 2


def kinds_of(index: LocalIndex, vids: Iterable[int]) -> dict[int, ItemKind]:
    """The kind of each version (see the module text). One query for all."""
    vids = list(dict.fromkeys(vids))
    if not vids:
        return {}
    understand_schema.ensure(index.store)
    out: dict[int, ItemKind] = {}
    for start in range(0, len(vids), 500):
        part = vids[start : start + 500]
        marks = ",".join("?" for _ in part)
        best: dict[int, tuple[int, ItemKind]] = {}
        titles: dict[int, tuple[int, str]] = {}
        for r in index.store.q(
            "SELECT version_id, kind, value, score, data, enricher FROM fact"  # noqa: S608
            f" WHERE kind IN ('kind', 'title') AND version_id IN ({marks})",
            part,
        ):
            data = loads(r["data"]) or {}
            rank = _rank(r["enricher"], data.get("by"))
            vid = r["version_id"]
            if r["kind"] == "title":
                if vid not in titles or rank < titles[vid][0]:
                    titles[vid] = (rank, r["value"])
                continue
            if r["value"] not in KINDS:
                continue
            by = "model" if rank == 0 else ("lab" if rank == 1 else "rules")
            got = ItemKind(
                r["value"],
                float(r["score"]),
                by,
                data.get("stage"),
                data.get("second"),
                polarity=polarity_of(r["value"], data),
            )
            if vid not in best or rank < best[vid][0]:
                best[vid] = (rank, got)
        overrides = {
            r[0]: r[1]
            for r in index.store.q(
                "SELECT v.id, o.kind FROM version v JOIN kind_override o"  # noqa: S608
                f" ON o.item_id = v.item_id WHERE v.id IN ({marks})",
                part,
            )
        }
        for vid in part:
            title = titles.get(vid, (9, None))[1]
            if vid in overrides:
                # A correction keeps the polarity of the model for a seed kind.
                was = best[vid][1].polarity if vid in best else None
                got = ItemKind(overrides[vid], 1.0, "person",
                               polarity=was if overrides[vid] in SEED_KINDS else None)  # fmt: skip
            elif vid in best:
                got = best[vid][1]
            else:
                got = ItemKind(UNKNOWN, 0.0, "none")
            out[vid] = ItemKind(
                got.kind, got.confidence, got.by, got.stage, got.second, title, got.polarity
            )
    return out


def kind_of(index: LocalIndex, vid: int) -> ItemKind:
    return kinds_of(index, [vid])[vid]


def current_versions(index: LocalIndex, *, own_only: bool = False) -> dict[str, int]:
    """item ref (`item:<id>`) -> the ID of its current version, for present items."""
    own = set(index.own_sources()) if own_only else None
    out = {}
    for r in index.store.q(
        "SELECT i.id, i.source_id, (SELECT id FROM version WHERE item_id = i.id"
        " ORDER BY n DESC LIMIT 1) AS vid FROM item i WHERE i.present = 1"
    ):
        if r["vid"] is not None and (own is None or r["source_id"] in own):
            out[f"item:{r['id']}"] = r["vid"]
    return out


def set_override(
    index: LocalIndex,
    item_id: int,
    kind: str,
    *,
    publish: Callable[[str, dict], None] | None = None,
) -> ItemKind:
    """The person's correction. It wins over each other kind, also for a later
    version of the item."""
    check_kind(kind)
    understand_schema.ensure(index.store)
    at = iso_seconds(index.clock())
    index.store.x(
        "INSERT INTO kind_override (item_id, kind, at) VALUES (?, ?, ?)"
        " ON CONFLICT (item_id) DO UPDATE SET kind = excluded.kind, at = excluded.at",
        (item_id, kind, at),
    )
    row = index.store.one(
        "SELECT id FROM version WHERE item_id = ? ORDER BY n DESC LIMIT 1", (item_id,)
    )
    got = kind_of(index, row[0]) if row else ItemKind(kind, 1.0, "person")
    if publish is not None:
        publish(
            "item.kind",
            {
                "by": got.by,
                "confidence": got.confidence,
                "kind": got.kind,
                "ref": f"item:{item_id}",
                "title": got.title,
            },
        )
    return got
