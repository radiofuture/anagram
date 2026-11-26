"""Deterministic chip extraction: topics, needs, and offers from text.

No model, no network. The same text and vocabulary always give the same chips.

Method:

1. Split the owner's text into units (sentences and bullets). Headings set a
   section: a "Need" or "Gaps" heading makes a need section, an "Offer" or
   "Assets" heading makes an offer section.
2. Each unit gets a polarity from cue words, else from its section:
   strong offer cues ("we can offer", "can provide"), then need cues
   ("we need", "looking for", "we have no", "cannot"), then weak offer cues
   ("we have", "idle", "unused", "free").
3. A capability phrase in a unit with a polarity counts one hit for that need
   or offer. A unit with no polarity gives no need or offer.
4. Topic phrases (OpenAlex topic names and keywords) count over all units,
   as whole words. Each item keeps its phrase hits (`topic_phrases`).
5. `select_topics` picks topics from the phrase hits of one or more items:
   each phrase weighs its word count times its vocabulary weight (generic
   words weigh less); a topic needs enough evidence (two distinct phrases, or
   one curated phrase or long phrase); a topic must reach a part of the best
   score; and a topic in a field that the other hits do not support needs
   strong evidence of its own.

Quoted third-party text (for example the quoted part of an email) is never
used here. The caller passes only the owner's text.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from anagram.local.understanding.vocabulary import Vocabulary, normalise

NEED = "need"
OFFER = "offer"

_NEED_HEADINGS = (
    "need",
    "needs",
    "gap",
    "gaps",
    "ask",
    "asks",
    "blocks us",
    "blockers",
    "wanted",
    "looking for",
    "wish list",
    "wishlist",
    "requests",
)
_OFFER_HEADINGS = (
    "offer",
    "offers",
    "assets",
    "resources",
    "available",
    "can provide",
    "what we have",
    "can share",
)

_STRONG_OFFER = re.compile(
    r"\b(we can offer|we offer|i can offer|can provide|we provide|we can host|we can share|"
    r"happy to share|available to|available for|free for|open to external)\b"
)
_NEED = re.compile(
    r"\b((we|i) (still )?(have|has) (almost |still )?no|no way to|cannot|can not|"
    r"(we|i) (still |also |urgently )?(need|want|lack|require|are missing)|needs?|"
    r"looking for|look for|seeking|in search of|wanted)\b"
)
_WEAK_OFFER = re.compile(
    r"\b(we have|we hold|we run|our own|idle|unused|spare|(?<!-)free|offer|offers|on offer)\b"
)

_SENTENCE = re.compile(r"(?<=[.!?;])\s+(?=[A-Z0-9(\"'])")
_BULLET = re.compile(r"^\s*([-*•]|\d+[.)])\s+")
MAX_TOPIC_WORDS = 8
# Each phrase counts at most this many times in one item.
PHRASE_CAP = 2


@dataclass(frozen=True)
class Unit:
    text: str
    section: str | None  # NEED, OFFER, or None
    heading: bool = False


def _heading_polarity(text: str) -> str | None:
    words = f" {normalise(text)} "
    need = any(f" {h} " in words for h in _NEED_HEADINGS)
    offer = any(f" {h} " in words for h in _OFFER_HEADINGS)
    if need and not offer:
        return NEED
    if offer and not need:
        return OFFER
    return None


def split_units(text: str) -> list[Unit]:
    """Split markdown-like text into units. Lines that start with '#' are
    headings. Bullets start a new block. Other lines continue the block."""
    units: list[Unit] = []
    section: str | None = None
    block: list[str] = []

    def flush() -> None:
        if block:
            joined = " ".join(s.strip() for s in block)
            for sent in _SENTENCE.split(joined):
                if sent.strip():
                    units.append(Unit(sent.strip(), section))
            block.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if stripped.startswith("#"):
            flush()
            head = stripped.lstrip("#").strip()
            section = _heading_polarity(head)
            units.append(Unit(head, None, heading=True))
            continue
        if _BULLET.match(line):
            flush()
            block.append(_BULLET.sub("", line, count=1))
            continue
        block.append(stripped)
    flush()
    return units


def unit_polarity(unit: Unit) -> str | None:
    if unit.heading:
        return None
    low = " ".join(unit.text.lower().split())
    if _STRONG_OFFER.search(low):
        return OFFER
    if _NEED.search(low):
        return NEED
    if unit.section is not None:
        return unit.section
    if _WEAK_OFFER.search(low):
        return OFFER
    return None


_ORIG_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _phrases(
    norm: str,
    index: dict[str, tuple[str, ...]],
    max_words: int,
    exact: dict[str, frozenset[str]] | None = None,
    original: str = "",
) -> list[str]:
    """All vocabulary phrases in a normalised text (whole words), in order.
    A phrase in `exact` must have one of its exact forms in `original`."""
    tokens = norm.split()
    orig = [t for t in _ORIG_SPLIT.split(original) if t] if exact else []
    found = []
    for i in range(len(tokens)):
        for n in range(1, min(max_words, len(tokens) - i) + 1):
            p = " ".join(tokens[i : i + n])
            if p not in index:
                continue
            if exact and p in exact and (len(orig) != len(tokens) or orig[i] not in exact[p]):
                continue
            found.append(p)
    return found


@dataclass
class ItemChips:
    """Chip scores of one item. Keys are vocabulary IDs."""

    topics: dict[str, int] = field(default_factory=dict)  # raw word-count scores
    needs: dict[str, int] = field(default_factory=dict)
    offers: dict[str, int] = field(default_factory=dict)
    # normalised topic phrase -> hits (at most PHRASE_CAP). None: an old
    # stored record without phrase hits (the index derives it again).
    topic_phrases: dict[str, int] | None = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "needs": dict(sorted(self.needs.items())),
            "offers": dict(sorted(self.offers.items())),
            "topic_phrases": dict(sorted((self.topic_phrases or {}).items())),
            "topics": dict(sorted(self.topics.items())),
        }

    @classmethod
    def from_json(cls, obj: dict) -> ItemChips:
        phrases = obj.get("topic_phrases")
        return cls(
            dict(obj["topics"]),
            dict(obj["needs"]),
            dict(obj["offers"]),
            dict(phrases) if phrases is not None else None,
        )


def _topic_weight(phrase: str) -> int:
    words = phrase.split()
    if len(words) == 1:
        return 1 if len(phrase) >= 4 and not phrase.isdigit() else 0
    return len(words)


def extract_chips(text: str, vocab: Vocabulary, *, needs_offers: bool = True) -> ItemChips:
    """Chips of one item. Set `needs_offers=False` for text that is not the
    owner's own prose (for example bibliographic titles or table cells)."""
    out = ItemChips()
    units = split_units(text)
    needs: Counter[str] = Counter()
    offers: Counter[str] = Counter()
    phrase_count: Counter[str] = Counter()
    topics: Counter[str] = Counter()
    for unit in units:
        norm = normalise(unit.text)
        if not norm:
            continue
        if needs_offers:
            pol = unit_polarity(unit)
            if pol is not None:
                ids = set()
                for p in _phrases(norm, vocab.capability_index, vocab.max_capability_words):
                    ids.update(vocab.capability_index[p])
                for cid in ids:
                    (needs if pol == NEED else offers)[cid] += 1
        max_words = min(vocab.max_topic_words, MAX_TOPIC_WORDS)
        for p in _phrases(norm, vocab.topic_index, max_words, vocab.topic_exact, unit.text):
            if phrase_count[p] >= PHRASE_CAP:
                continue
            w = _topic_weight(p)
            if not w:
                continue
            phrase_count[p] += 1
            for tid in vocab.topic_index[p]:
                topics[tid] += w
    out.needs, out.offers, out.topics = dict(needs), dict(offers), dict(topics)
    out.topic_phrases = dict(phrase_count)
    return out


def merge(chips: list[ItemChips]) -> ItemChips:
    total = ItemChips()
    for kind in ("topics", "needs", "offers", "topic_phrases"):
        acc: Counter[str] = Counter()
        for c in chips:
            acc.update(getattr(c, kind))
        setattr(total, kind, dict(acc))
    return total


def top(scores: dict[str, int], k: int, min_score: int = 1) -> list[tuple[str, int]]:
    """Top k (id, score) with score >= min_score. Ties break by ID."""
    ranked = sorted(
        ((i, s) for i, s in scores.items() if s >= min_score), key=lambda x: (-x[1], x[0])
    )
    return ranked[:k]


# Topic selection. A topic is suggested only with enough evidence:
# - two distinct phrases, or one curated phrase (the topic name or a hand-made
#   alias), or one phrase of LONG_PHRASE words or more. One two-word OpenAlex
#   keyword alone ("ice thickness", "particle filter") is not enough;
# - a score of at least REL_MIN of the best topic;
# - a field that the hits support (FIELD_MIN of all candidate weight), or, for
#   a topic in another field, two distinct phrases and OFF_FIELD_MIN of the
#   best score.
LONG_PHRASE = 3
REL_MIN = 0.25
FIELD_MIN = 0.25
OFF_FIELD_MIN = 0.5


def select_topics(
    chips: list[ItemChips], vocab: Vocabulary, k: int, min_score: float = 0
) -> list[tuple[str, float]]:
    """Top k (topic ID, score) from the phrase hits of the items. Deterministic:
    ties break by ID."""
    count: Counter[str] = Counter()
    for c in chips:
        count.update(c.topic_phrases or {})
    weight = {p: n * len(p.split()) * vocab.phrase_weight(p) for p, n in count.items() if n > 0}
    by_topic: dict[str, list[str]] = {}
    for p in sorted(weight):
        for tid in vocab.topic_index.get(p, ()):
            by_topic.setdefault(tid, []).append(p)

    def enough(tid: str) -> bool:
        phrases = by_topic[tid]
        if len(phrases) >= 2:
            return True
        curated = vocab.topics[tid].curated if tid in vocab.topics else ()
        p = phrases[0]
        return p in curated or len(p.split()) >= LONG_PHRASE

    score = {t: sum(weight[p] for p in ps) for t, ps in by_topic.items()}
    candidates = sorted(t for t in by_topic if enough(t))
    in_play = set(candidates)
    if not candidates:
        return []
    best = max(score[t] for t in candidates)

    def group(tid: str) -> str:
        return vocab.topics[tid].group if tid in vocab.topics else ""

    # Weight of the field: each phrase counts once in each field it supports.
    field_w: Counter[str] = Counter()
    for p in sorted(weight):
        for f in sorted({group(t) for t in vocab.topic_index.get(p, ()) if t in in_play}):
            field_w[f] += weight[p]
    total = sum(field_w.values()) or 1.0
    keep = []
    for t in candidates:
        if score[t] < max(min_score, REL_MIN * best):
            continue
        agrees = field_w[group(t)] / total >= FIELD_MIN
        strong = len(by_topic[t]) >= 2 and score[t] >= OFF_FIELD_MIN * best
        if agrees or strong:
            keep.append((t, round(score[t], 2)))
    keep.sort(key=lambda x: (-x[1], x[0]))
    return keep[:k]
