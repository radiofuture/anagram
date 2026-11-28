"""Person-level readings across items and over time, and the beacon draft.

    readings = combine(items, signals, embedder, today)
    offers, wants = draft(readings)

No model call here: this step joins the item signals (`signals.py`) of many
items. Sentences of one kind group (single link) when they are near in
meaning (cosine of the embedder at least `SAME`) or share a rare term of
the person (`_Terms`), so one reading can rest on fragments in many files.
Rules:

- `asks`: ask sentences of sent mail only.
- `offers`: offer sentences of any own item.
- `stuck_on`: stuck sentences of any own item, unless a sentence of the
  same or a newer date says that the problem is solved.
- `tacit_skill`: method sentences of code, notebooks and protocols, in at
  least `TACIT_ITEMS` items, and not near a method sentence of a
  publication (a method with a paper is not tacit).
- `trajectory`: the topic phrases of the model are counted in the own text
  of all items, by quarter, over the last `QUARTERS` quarters; a topic is
  rising or falling when its share of the items moves by at least `TREND`
  between the first and the second half.

Weight: each basis item adds 0.5 ** (age / half-life), so a reading of many
recent items ranks first (half-life 12 months).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import date

from anagram.local.understanding.extractive import occurs
from anagram.local.understanding.profile.schema import (
    HALF_LIFE_DAYS,
    MAX_LINES,
    OWN_ROLES,
    WORK_ROLES,
    Basis,
    LensItem,
    Line,
    Reading,
    cut,
    match_types,
)
from anagram.local.understanding.profile.signals import ItemSignals, own_sentences
from anagram.models.embed import Embedder

SAME = 0.80  # cosine for "the same thing" (bge-small-en-v1.5)
RARE = 4  # a shared content word in at most this many own sentences links two sentences
PUBLISHED = 0.85  # a work method this near a paper method is not tacit
TACIT_ITEMS = 2
QUARTERS = 8
TREND = 0.15
TOPIC_ITEMS = 3


def _day(text: str) -> date:
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return date(1970, 1, 1)


def recency(when: str, today: date, half_life: float = HALF_LIFE_DAYS) -> float:
    age = max(0, (today - _day(when)).days)
    return 0.5 ** (age / half_life)


class _Vectors:
    def __init__(self, embedder: Embedder) -> None:
        self.embedder = embedder
        self.seen: dict[str, list[float]] = {}

    def prime(self, texts: Iterable[str]) -> None:
        new = [t for t in dict.fromkeys(texts) if t not in self.seen]
        for t, v in zip(new, self.embedder.embed(new) if new else [], strict=True):
            n = math.sqrt(sum(x * x for x in v)) or 1.0
            self.seen[t] = [x / n for x in v]

    def cos(self, a: str, b: str) -> float:
        return sum(x * y for x, y in zip(self.seen[a], self.seen[b], strict=True))


_STOP = frozenset(
    "the a an of to in on for and or with by at from is are was were be been it its this"
    " that these those our we us you your their they each every before after then than"
    " when so not no yet still into over under about more most less all any some can could"
    " would will need have has had do does did one two three four five six new full good"
    " other others also only very much many there here what which who how why".split()
)
_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]*")
# Words that name a kind of document or work, not a research topic.
_GENERIC = frozenset(
    "paper note background meeting group result draft protocol notebook analysi quarter"
    " time work next plan section abstract update question request lab".split()
)


def _tokens(text: str) -> list[str]:
    return [
        w[:-1] if len(w) > 4 and w.endswith("s") else w for w in _TOKEN.findall(text.casefold())
    ]


def _content(text: str) -> set[str]:
    return {w for w in _tokens(text) if len(w) >= 5 and w not in _STOP}


def _bigrams(text: str) -> set[str]:
    w = _tokens(text)
    ok = [len(x) >= 3 and x not in _STOP for x in w]
    return {f"{w[i]} {w[i + 1]}" for i in range(len(w) - 1) if ok[i] and ok[i + 1]}


class _Terms:
    """Shared terms between two sentences: a content bigram, or a content
    word that is rare in the own sentences of the person (in at most
    `RARE` of them). A person names one problem or method with the same
    term in many files; a rare shared term links the fragments."""

    def __init__(self, corpus: Iterable[str]) -> None:
        self.df: Counter[str] = Counter()
        for s in set(corpus):
            self.df.update(_content(s))

    def link(self, a: str, b: str) -> bool:
        if _bigrams(a) & _bigrams(b):
            return True
        return any(self.df[w] <= RARE for w in _content(a) & _content(b))


def _groups(
    texts: Sequence[str], vec: _Vectors, same: float, terms: _Terms | None = None
) -> list[list[int]]:
    """Single-link groups of `texts` (indexes): near in meaning, or a shared
    rare term."""
    parent = list(range(len(texts)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(texts)):
        for j in range(i):
            if (
                texts[i] == texts[j]
                or vec.cos(texts[i], texts[j]) >= same
                or (terms is not None and terms.link(texts[i], texts[j]))
            ):
                parent[root(i)] = root(j)
    out: dict[int, list[int]] = {}
    for i in range(len(texts)):
        out.setdefault(root(i), []).append(i)
    return list(out.values())


def _central(texts: Sequence[str], vec: _Vectors) -> str:
    """The text nearest to all others (the shortest on a tie)."""
    return max(texts, key=lambda t: (sum(vec.cos(t, u) for u in texts), -len(t)))


def _quarter(d: date) -> int:
    return d.year * 4 + (d.month - 1) // 3


def combine(
    items: Sequence[LensItem],
    signals: dict[str, ItemSignals],
    embedder: Embedder,
    today: date,
) -> list[Reading]:
    """The person-level readings of the own `items` (a received item gives
    no reading)."""
    own = {i.id: i for i in items if i.role in OWN_ROLES}
    vec = _Vectors(embedder)
    pool: dict[str, list[tuple[Basis, str]]] = {
        k: [] for k in ("ask", "offer", "stuck", "method", "solved")
    }
    paper_methods: list[str] = []
    for iid, item in own.items():
        got = signals.get(iid)
        if got is None:
            continue
        for s in got.signals:
            if s.kind == "method" and item.role == "publication":
                paper_methods.append(s.sentence)
                continue
            if s.kind == "ask" and item.role != "sent":
                continue
            if s.kind == "method" and item.role not in WORK_ROLES:
                continue
            pool[s.kind].append((Basis(iid, s.sentence, item.date, item.role), s.cls))
    vec.prime([b.sentence for rows in pool.values() for b, _ in rows] + paper_methods)
    terms = _Terms(s for item in own.values() for s in own_sentences(item.text, item.role))
    out: list[Reading] = []
    for kind, reading in (
        ("ask", "asks"),
        ("offer", "offers"),
        ("stuck", "stuck_on"),
        ("method", "tacit_skill"),
    ):
        rows = pool[kind]
        texts = [b.sentence for b, _ in rows]
        for group in _groups(texts, vec, SAME, terms):
            basis = [rows[i][0] for i in group]
            items_in = {b.item for b in basis}
            members = [texts[i] for i in group]
            if reading == "tacit_skill":
                if len(items_in) < TACIT_ITEMS:
                    continue
                if any(vec.cos(m, p) >= PUBLISHED for m in members for p in paper_methods):
                    continue
            if reading == "stuck_on" and _solved_later(basis, pool["solved"], vec, terms):
                continue
            cls = Counter(rows[i][1] for i in group).most_common(1)[0][0]
            if reading == "tacit_skill":
                cls = "skill"
            weight = sum(recency(own[i].date, today) for i in items_in)
            out.append(Reading(reading, cls, cut(_central(members, vec)), basis, weight))
    out += _trajectory(own, signals, today)
    return out


def _solved_later(
    basis: Sequence[Basis], solved: Sequence[tuple[Basis, str]], vec: _Vectors, terms: _Terms
) -> bool:
    """True if a newer own sentence says that this problem is solved."""
    newest = max(b.date for b in basis)
    return any(
        s.date >= newest
        and any(
            vec.cos(s.sentence, b.sentence) >= SAME or terms.link(s.sentence, b.sentence)
            for b in basis
        )
        for s, _ in solved
    )


def _topic_words(phrase: str) -> set[str]:
    return {w for w in _tokens(phrase) if len(w) >= 4 and w not in _STOP and w not in _GENERIC}


def _trajectory(
    own: dict[str, LensItem], signals: dict[str, ItemSignals], today: date
) -> list[Reading]:
    """Topic phrases of the model are candidates. Each candidate is counted
    in the own text of all items (not only where the model named it), so a
    topic is read across documents. A rising or falling topic is a reading."""
    last = _quarter(today) - 1  # the last full quarter
    first = last - QUARTERS + 1
    texts: dict[str, list[str]] = {}  # item -> own sentences in the window
    per_q: Counter[int] = Counter()
    for iid, item in own.items():
        q = _quarter(_day(item.date))
        if first <= q <= last:
            per_q[q] += 1
            texts[iid] = own_sentences(item.text, item.role)
    names: dict[str, str] = {}
    for iid in texts:
        for t in signals[iid].topics if iid in signals else []:
            if _topic_words(t):
                names.setdefault(t.casefold(), t)
    found: list[tuple[str, dict[str, str]]] = []  # (phrase, item -> sentence)
    for key in names:
        hits = {}
        for iid, sents in texts.items():
            s = next((s for s in sents if occurs(key, s)), None)
            if s is not None:
                hits[iid] = s
        if len(hits) >= TOPIC_ITEMS:
            found.append((key, hits))
    # One reading for one topic: a phrase that shares a word and most items
    # with a phrase already kept is the same topic.
    found.sort(key=lambda f: (-len(f[1]), -len(f[0]), f[0]))
    kept: list[tuple[str, dict[str, str]]] = []
    for key, hits in found:
        same = any(
            _topic_words(key) & _topic_words(k)
            and len(set(hits) & set(h)) >= 0.5 * min(len(hits), len(h))
            for k, h in kept
        )
        if not same:
            kept.append((key, hits))
    half = QUARTERS // 2
    out = []
    for key, hits in kept:
        by_q: Counter[int] = Counter(_quarter(_day(own[i].date)) for i in hits)
        share = [by_q[q] / per_q[q] if per_q[q] else 0.0 for q in range(first, last + 1)]
        early, late = sum(share[:half]) / half, sum(share[half:]) / half
        if late - early >= TREND:
            direction = "rising"
        elif early - late >= TREND:
            direction = "falling"
        else:
            continue
        basis = [Basis(i, s, own[i].date, own[i].role) for i, s in hits.items()]
        weight = sum(recency(own[i].date, today) for i in hits)
        value = {
            "direction": direction,
            "early": round(early, 3),
            "late": round(late, 3),
            "by_quarter": [by_q[q] for q in range(first, last + 1)],
        }
        out.append(Reading("trajectory", "", names[key], basis, weight, value))
    return out


def draft(readings: Sequence[Reading], published: set[str] | None = None) -> tuple[list, list]:
    """The beacon draft: (offers, wants), each at most
    `MAX_LINES` lines, by weight. `published`: IDs of published items; a
    line with any other basis item defaults to scope `inside`."""
    published = published or set()
    side_of = {"asks": "want", "stuck_on": "want", "offers": "offer", "tacit_skill": "offer"}
    lines: dict[str, list[Line]] = {"offer": [], "want": []}
    for r in readings:
        side = side_of.get(r.kind)
        if side is None:
            continue
        cls = "problem" if r.kind == "stuck_on" else r.cls
        scope = "both" if set(r.items) <= published else "inside"
        lines[side].append(
            Line(side, cls, match_types(side, cls), r.text, scope, r.weight, r.kind, r.basis)
        )
    for side in lines:
        lines[side].sort(key=lambda ln: (-ln.weight, ln.text))
        del lines[side][MAX_LINES:]
    return lines["offer"], lines["want"]
