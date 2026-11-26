"""Enrichers: `Document` -> facts (spec/index.md section 4).

A fact is derived meaning of one item version: an entity, a claim, a need, an
offer, a topic, a summary (and `phrase`: a topic phrase hit of the keyword
enricher). Facts are never committed.

`ENRICHERS` is the registry (`anagram.enrichers` entry points plus the
built-in `chips`). An enricher with `external = True` is a disclosure
recipient and needs the user's opt-in (the same rule as converters). An
enricher reads only the owner's text (`Document.markdown`), never
`Document.quoted`.

`chips` is the keyword fallback: today's deterministic chip extraction
(`chips.py`), written as `topic`, `need`, `offer`, `phrase`, and `summary`
facts, so profile drafting keeps working with no model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from anagram.local.index.convert.document import Document
from anagram.local.index.registry import GROUP_ENRICHERS, Registry
from anagram.local.understanding.chips import ItemChips, extract_chips
from anagram.local.understanding.vocabulary import Vocabulary

FACT_KINDS = (
    "entity",
    "claim",
    "need",
    "offer",
    "topic",
    "summary",
    "phrase",
    # Obsidian notes (`connectors/obsidian.py`).
    "frontmatter",
    "frontmatter_error",
    "tag",
    "alias",
    "link",
    # Understanding: the item kind, a short title for people, and names
    # of people from the owner's text.
    "kind",
    "title",
    "person",
)
SUMMARY_CHARS = 160


class EnricherRefused(Exception):
    pass


@dataclass(frozen=True)
class Fact:
    kind: str
    value: str
    score: float = 0.0
    data: dict = field(default_factory=dict)
    # Where the fact came from: the anchor and parent of a block and the
    # fields of its `Span`. None: `fact_span` looks for the value in the blocks.
    span: dict | None = None


# Facts whose value is not text of the item, so no block can hold it.
NO_SPAN_KINDS = frozenset({"summary", "kind"})


def fact_span(doc: Document, fact: Fact) -> dict | None:
    """The span of a fact: the span that the enricher gave, else the span of
    the first block that holds the value (case and white space do not
    matter), else None."""
    if fact.span is not None:
        return fact.span
    if fact.kind in NO_SPAN_KINDS:
        return None
    return doc.span_of(fact.value)


@dataclass(frozen=True)
class ItemInfo:
    """What an enricher may know of an item beyond its document: no text, no
    content of other people."""

    kind: str = "file"  # item kind: "file", "git_commit", "zotero_item", ...
    name: str | None = None
    ref: str = ""  # the path in the source, for path words only
    media_type: str = ""
    source_kind: str = ""
    size: int | None = None
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class EnrichContext:
    vocab: Vocabulary
    item: ItemInfo | None = None


class Enricher(ABC):
    name: ClassVar[str] = ""
    version: ClassVar[str] = "1"
    external: ClassVar[bool] = False
    recipient: ClassVar[str | None] = None
    paid: ClassVar[bool] = False

    def available(self) -> bool:
        return True

    @abstractmethod
    def enrich(self, doc: Document, ctx: EnrichContext) -> list[Fact]: ...


def check_enricher(enricher: Enricher, allowed: bool) -> None:
    if enricher.external and not allowed:
        raise EnricherRefused(
            f"enricher {enricher.name!r} sends text to"
            f" {enricher.recipient or 'an outside service'}; the user must opt in"
        )


def summary_of(title: str | None, text: str) -> str:
    body: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith(("#", "<!--", "|")):
            body.append(s.lstrip("-* ").strip())
        if sum(len(b) for b in body) > SUMMARY_CHARS:
            break
    out = " ".join(body)
    if len(out) > SUMMARY_CHARS:
        out = out[: SUMMARY_CHARS - 3].rstrip() + "..."
    title = title or ""
    return f"{title}: {out}" if title and out and not out.startswith(title) else (title or out)


class ChipsEnricher(Enricher):
    """Keyword chips (deterministic, no model). The fallback enricher."""

    name = "chips"
    version = "1"

    def enrich(self, doc: Document, ctx: EnrichContext) -> list[Fact]:
        chips = extract_chips(doc.markdown, ctx.vocab, needs_offers=doc.prose)
        return chips_to_facts(chips) + [Fact("summary", summary_of(doc.title, doc.markdown))]


def chips_to_facts(chips: ItemChips) -> list[Fact]:
    out = []
    for kind, scores in (("topic", chips.topics), ("need", chips.needs), ("offer", chips.offers)):
        out += [Fact(kind, k, float(v)) for k, v in sorted(scores.items())]
    out += [Fact("phrase", k, float(v)) for k, v in sorted((chips.topic_phrases or {}).items())]
    return out


def facts_to_chips(facts: list[Fact]) -> ItemChips:
    chips = ItemChips()
    attr = {"topic": chips.topics, "need": chips.needs, "offer": chips.offers}
    for f in facts:
        if f.kind in attr:
            attr[f.kind][f.value] = int(f.score)
        elif f.kind == "phrase":
            chips.topic_phrases[f.value] = int(f.score)
    return chips


ENRICHERS: Registry[type[Enricher]] = Registry(GROUP_ENRICHERS)
ENRICHERS.register(ChipsEnricher.name, ChipsEnricher, builtin=True)

# kind_rules imports this module, so it comes after ENRICHERS.
from anagram.local.understanding.kind_rules import KindRulesEnricher  # noqa: E402

ENRICHERS.register(KindRulesEnricher.name, KindRulesEnricher, builtin=True)
