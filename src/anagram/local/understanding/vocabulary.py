"""Bundled, versioned vocabulary for chips (topics, needs, and offers of an item).

Two parts, both shipped with the package and read only on the device:

- Topics: an OpenAlex Topics snapshot (CC0), file `vocab/openalex-topics-<date>.json.gz`.
  Topic IDs have the form `openalex:t10044`.
- Needs and offers: a curated Anagram list, file `vocab/capabilities-v1.json`.
  One ID (for example `anagram:cryo-em-time`) is both a need and an offer.

IDs use ":" and "-" only, never "/".

`VOCAB_VERSION` names both parts.

Anagram never sends private text to OpenAlex. Matching of text to topics runs
here, on the device.
"""

from __future__ import annotations

import gzip
import json
import math
import re
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

TOPICS_DATE = "2026-10-15"
TOPICS_FILE = f"openalex-topics-{TOPICS_DATE}.json.gz"
CAPABILITIES_FILE = "capabilities-v1.json"
ALIASES_FILE = "topic-aliases-v1.json"
CAPABILITIES_VERSION = "1"
# Format: anagram-vocab.<capabilities version>.oa-<topics date, no dashes>.
VOCAB_VERSION = f"anagram-vocab.{CAPABILITIES_VERSION}.oa-{TOPICS_DATE.replace('-', '')}"

_NON_WORD = re.compile(r"[^a-z0-9]+")


def normalise(text: str) -> str:
    """Lower case; every run of other characters becomes one space."""
    return _NON_WORD.sub(" ", text.lower()).strip()


@dataclass(frozen=True)
class Term:
    id: str
    label: str
    kind: str  # "topic" or "capability"
    phrases: tuple[str, ...]  # normalised; matched without case
    group: str = ""
    exact: tuple[str, ...] = ()  # single words matched with case, for example "NOTES"
    # The topic name and the hand-made aliases. One hit of these is enough
    # evidence for the topic (see `anagram.local.understanding.chips.select_topics`).
    curated: tuple[str, ...] = ()


@dataclass(frozen=True)
class Vocabulary:
    version: str
    topics: dict[str, Term]
    capabilities: dict[str, Term]
    # normalised phrase -> term IDs, for each kind
    topic_index: dict[str, tuple[str, ...]]
    capability_index: dict[str, tuple[str, ...]]
    max_topic_words: int
    max_capability_words: int
    # normalised single word -> the exact forms that the text must have
    topic_exact: dict[str, frozenset[str]]
    # word -> inverse topic frequency, log(N / number of topics with the word)
    token_idf: dict[str, float] = field(default_factory=dict)

    def label(self, term_id: str) -> str:
        term = self.topics.get(term_id) or self.capabilities.get(term_id)
        return term.label if term else term_id

    def phrase_weight(self, phrase: str) -> float:
        """Weight of one topic phrase word, 0 to 1: the mean inverse topic
        frequency of its words, divided by the largest possible value. Words
        that many topics use ("data", "model", "analysis", "network") weigh
        less. The weights come from the vocabulary itself."""
        words = phrase.split()
        if not words or not self.token_idf:
            return 1.0
        top = math.log(max(len(self.topics), 2))
        idf = sum(self.token_idf.get(w, top) for w in words) / len(words)
        return round(min(1.0, idf / top), 4)


def _vocab_file(name: str) -> bytes:
    return resources.files("anagram.local.understanding").joinpath("vocab", name).read_bytes()


def _build_index(terms: dict[str, Term]) -> tuple[dict[str, tuple[str, ...]], int]:
    index: dict[str, set[str]] = {}
    for term in terms.values():
        for p in (*term.phrases, *(normalise(e) for e in term.exact)):
            if p:
                index.setdefault(p, set()).add(term.id)
    longest = max((len(p.split()) for p in index), default=1)
    return {p: tuple(sorted(ids)) for p, ids in index.items()}, longest


def _exact_forms(terms: dict[str, Term]) -> dict[str, frozenset[str]]:
    free = {p for t in terms.values() for p in t.phrases}
    forms: dict[str, set[str]] = {}
    for t in terms.values():
        for e in t.exact:
            if normalise(e) not in free:
                forms.setdefault(normalise(e), set()).add(e)
    return {p: frozenset(f) for p, f in forms.items()}


def _specific_word(keyword: str) -> bool:
    """A one-word OpenAlex keyword counts only if it looks like a name, an
    acronym, or a symbol (an upper-case letter or a digit), for example
    "Bacteroides" or "NLRP3". Plain words such as "maps" or "core" give false
    topics."""
    return any(c.isupper() or c.isdigit() for c in keyword)


_WORD = re.compile(r"^[A-Za-z0-9]+$")


def load_topics(raw: bytes | None = None, aliases: bytes | None = None) -> dict[str, Term]:
    doc = json.loads(gzip.decompress(raw if raw is not None else _vocab_file(TOPICS_FILE)))
    if doc.get("schema") != "anagram.vocab.openalex_topics.v1":
        raise ValueError("unknown topics snapshot schema")
    extra = json.loads(aliases if aliases is not None else _vocab_file(ALIASES_FILE))
    if extra.get("schema") != "anagram.vocab.topic_aliases.v1":
        raise ValueError("unknown topic aliases schema")
    out = {}
    for tid, name, keywords, field_name in doc["topics"]:
        phrases, exact = {normalise(name)}, set()
        for k in keywords:
            if len(normalise(k).split()) > 1:
                phrases.add(normalise(k))
            elif _WORD.match(k) and any(c.isupper() for c in k):
                exact.add(k)  # "NOTES" must not match "notes"
            elif _specific_word(k):
                phrases.add(normalise(k))
        aliases = {normalise(a) for a in extra["aliases"].get(tid, ())}
        phrases |= aliases
        curated = tuple(sorted(p for p in {normalise(name), *aliases} if p))
        out[tid] = Term(
            tid,
            name,
            "topic",
            tuple(sorted(p for p in phrases if p)),
            field_name,
            tuple(sorted(exact)),
            curated,
        )
    unknown = set(extra["aliases"]) - set(out)
    if unknown:
        raise ValueError(f"topic aliases name unknown topics: {sorted(unknown)}")
    return out


def load_capabilities(raw: bytes | None = None) -> dict[str, Term]:
    doc = json.loads(raw if raw is not None else _vocab_file(CAPABILITIES_FILE))
    if doc.get("schema") != "anagram.vocab.capabilities.v1":
        raise ValueError("unknown capabilities schema")
    out = {}
    for e in doc["entries"]:
        phrases = {normalise(e["label"])} | {normalise(p) for p in e["phrases"]}
        out[e["id"]] = Term(
            e["id"], e["label"], "capability", tuple(sorted(phrases)), e.get("group", "")
        )
    return out


def make_vocabulary(
    topics: dict[str, Term], capabilities: dict[str, Term], version: str = VOCAB_VERSION
) -> Vocabulary:
    t_index, t_max = _build_index(topics)
    c_index, c_max = _build_index(capabilities)
    return Vocabulary(
        version,
        topics,
        capabilities,
        t_index,
        c_index,
        t_max,
        c_max,
        _exact_forms(topics),
        _token_idf(topics),
    )


def _token_idf(topics: dict[str, Term]) -> dict[str, float]:
    """Inverse topic frequency of each word in the topic phrases."""
    df: dict[str, int] = {}
    for t in topics.values():
        for w in {w for p in (*t.phrases, *t.exact) for w in normalise(p).split()}:
            df[w] = df.get(w, 0) + 1
    n = max(len(topics), 2)
    return {w: math.log(n / c) for w, c in df.items()}


@cache
def default_vocabulary() -> Vocabulary:
    """The bundled vocabulary. Loaded once per process."""
    return make_vocabulary(load_topics(), load_capabilities())
