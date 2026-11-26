"""The decision table of a sweep (spec/matching.md 4).

`funnel` makes one row for each judged pair. A row holds no pack text and
no score: the two subjects, the decision, the match type of each side, and
a hash of what the decision used. The audit counts the rows.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Row:
    """One decision. `a < b`. `reason_a` is the code that `a` can see (how
    `b` helps `a`); `reason_b` is the code for `b`. `evidence` is a hash of
    what the decision used (hex)."""

    a: str
    b: str
    mutual: bool
    reason_a: str | None
    reason_b: str | None
    evidence: str

    @classmethod
    def make(
        cls,
        x: str,
        y: str,
        mutual: bool,
        reason_x: str | None = None,
        reason_y: str | None = None,
        evidence: str = "",
    ) -> Row:
        if x < y:
            return cls(x, y, mutual, reason_x, reason_y, evidence)
        return cls(y, x, mutual, reason_y, reason_x, evidence)


@dataclass
class Decisions:
    """The decision table of one sweep: one row for each pair, a < b."""

    rows: dict[tuple[str, str], Row] = field(default_factory=dict)

    @classmethod
    def of(cls, rows: Iterable[Row]) -> Decisions:
        table: dict[tuple[str, str], Row] = {}
        for r in rows:
            if r.a >= r.b or (r.a, r.b) in table:
                raise ValueError("decision rows must be unique pairs with a < b")
            table[(r.a, r.b)] = r
        return cls(table)
