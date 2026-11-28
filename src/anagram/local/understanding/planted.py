"""Planted instructions: text in an item that gives orders to a model.

    guard = planted.Guard.of(owner_text)
    guard.clean        # the owner text with no strong span: the model input
    guard.tainted(s)   # True if the model output `s` copies a flagged span
    guard.names(kind)  # True if a flagged span names the kind `kind`

This is layer 2 of the defence against planted instructions. Layer 1 is
structural (`extractive.py`): the model writes no free text into a kept fact,
so it does not need to recognise an order. Detection is a second layer: it
recognises many English orders, and it is an arms race (in held-out tests it
flagged 1 of 10 orders as strong). A word check alone ("the output
words are in the item") does not stop a planted title, because the planted
words are in the item (injection success was 3 to 8 of 10). This module
gives three defences:

1. Detection. Each sentence gets signals: words that address a model, words
   that override rules, a verb that controls the answer with a field name
   ("title it", "classify as"), a field assignment ("kind: x", `"title":`),
   a role marker at the start of a line ("SYSTEM:", "### Instruction"),
   orders to the reader ("you must"), and a kind name in quotes. Two signal
   classes or one strong signal make a strong span; one signal makes a weak
   span. After a strong sentence, the rest of its line is strong too, and a
   short role header makes the next line strong.
2. Separation. A strong span does not go to the model, and it is not part of
   the text that a title candidate or a claim must come from.
3. Fail closed. An output that copies a flagged span is tainted: it shares
   a run of three words with the span, or it has a word of the span that is
   only in flagged spans. A copy of a strong span means that the model
   followed the order: `understand` keeps no model fact for the item (the
   rules kind and the rules title stay). A copy of a weak span drops that
   output only (a title, a claim, a name, the summary). A model kind that is
   not the rules kind and that a flagged span names is not kept.

A false positive costs little: a removed line is not read by the model, and
a weak span only stops an output that copies it. The rules do not know any
canary or test string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from anagram.local.understanding.kinds import KIND_IDS, KINDS

_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_SENTENCE = re.compile(r"(?<=[.!?;])\s+(?=\S)")

_ADDRESS = re.compile(
    r"\b(?:a\.?i\.?|ai|llms?|gpt|chatbot|bot|assistant|classifier|indexer|parser"
    r"|language model|the model|any model|automated|automatic|tools? that"
    r"|ai agents?|system prompt|whoever (?:reads|processes|opens|indexes|sorts)"
    r"|(?:reader|reading|processing|indexing) (?:of )?this (?:file|item|document|page|note))\b",
    re.IGNORECASE,
)
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|overrule|bypass)\b[^.!?\n]{0,40}?"
    r"(?:\b(?:rules|instructions|prompts|guidelines|directions|orders|system prompt)\b"
    r"|\b(?:everything|all|anything) (?:above|before|earlier|previous|prior)\b"
    r"|\b(?:above|previous|earlier|prior) (?:text|message|content|task)\b)",
    re.IGNORECASE,
)
_SOFT_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|instead|overrule)\b"
    r"|\bnew (?:task|instructions|rules|orders)\b"
    r"|\bthe (?:real|actual|true) (?:task|instruction|answer)\b",
    re.IGNORECASE,
)
_FIELD = (
    r"(?:kind|type|category|class|label|tag|title|heading|name|claims?|summary|summaries"
    r"|entit(?:y|ies)|people|person|json|output|answer|field)"
)
_CONTROL = re.compile(
    r"\b(?:answer|respond|reply|output|return|print|say|state|write|put|use|include|add|list"
    r"|report|set|give|make|mark|treat|call|name|title|label|tag|classify|categori[sz]e"
    r"|file|sort|summari[sz]e|describe)\b[^.!?\n]{0,60}?\b" + _FIELD + r"\b"
    r"|\b(?:classify|categori[sz]e|label|tag|mark|treat|file|sort|record|count|list)"
    r"\b[^.!?\n]{0,25}?\b(?:as|under|into)\b"
    r"|\b(?:title|name|call|label) (?:it|this|the (?:file|item|document|page|note))\b",
    re.IGNORECASE,
)
_ASSIGN = re.compile(
    r"[\"']?\b" + _FIELD + r"\b[\"']?\s*[:=]"
    r"|\bthe " + _FIELD + r" (?:of this (?:file|item|document|page|note) )?(?:here )?is\b",
    re.IGNORECASE,
)
_JSON_KEY = re.compile(r"[\"'](?:kind|title|claims|summary|entities)[\"']\s*:")
_ROLE = re.compile(
    r"^\s*(?:[#>*\-\s]*)(?:\[|<\|?|\()?\s*(?:system|assistant|user|developer|inst"
    r"|note to (?:the )?(?:model|ai|assistant))\s*(?:\]|\|?>|\))?\s*(?::|$|\])",
    re.IGNORECASE,
)
_YOU = re.compile(
    r"\byou(?:r)?\b[^.!?\n]{0,20}?\b(?:must|should|shall|have to|need to|are to|will now"
    r"|are required)\b|\bplease\b[^.!?\n]{0,30}?\b" + _FIELD + r"\b",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"[\"“”«»„‘’]\s*([^\"“”«»„‘’\n]{1,80}?)\s*[\"“”«»„‘’]")
_KIND_WORDS = frozenset(KIND_IDS) | {"administrative", "administration", "paperwork"}

STRONG = 2  # signal classes for a strong span
RUN = 3  # words in a shared run that taint an output
STRONG_TAINT = "strong"  # the output copies a strong span: keep no model fact
WEAK_TAINT = "weak"  # the output copies a weak span: drop that output only


def words(text: str) -> list[str]:
    return [w.lower() for w in _WORD.findall(text or "")]


def signals(sentence: str) -> set[str]:
    """The signal classes of one sentence (see the module text)."""
    got: set[str] = set()
    if _ADDRESS.search(sentence):
        got.add("address")
    if _OVERRIDE.search(sentence):
        got |= {"override", "override+"}  # an override of the rules counts twice
    elif _SOFT_OVERRIDE.search(sentence):
        got.add("override")
    if _CONTROL.search(sentence):
        got.add("control")
    if _ASSIGN.search(sentence):
        got.add("assign")
    if _JSON_KEY.search(sentence):
        got |= {"assign", "json"}
    if _ROLE.search(sentence):
        got |= {"role", "role+"}
    if _YOU.search(sentence):
        got.add("you")
    quoted = " ".join(m.group(1) for m in _QUOTED.finditer(sentence))
    if quoted and _KIND_WORDS & set(words(sentence)):
        got.add("quoted kind")
    return got


@dataclass(frozen=True)
class Span:
    start: int  # character offsets in the text
    end: int
    text: str
    strong: bool
    signals: frozenset[str] = frozenset()


def _sentences(line: str) -> list[tuple[int, int]]:
    out, at = [], 0
    for m in _SENTENCE.finditer(line):
        out.append((at, m.start()))
        at = m.end()
    out.append((at, len(line)))
    return [(a, b) for a, b in out if line[a:b].strip()]


def find(text: str) -> list[Span]:
    """The flagged spans of `text`, in order."""
    spans: list[Span] = []
    offset = 0
    carry = False  # a short role header makes the next line strong
    for line in (text or "").splitlines(keepends=True):
        body = line.rstrip("\n")
        strong_line = carry
        carry = False
        if not body.strip():
            offset += len(line)
            continue
        found: list[Span] = []
        for a, b in _sentences(body):
            sentence = body[a:b]
            got = signals(sentence)
            strong = strong_line or len(got) >= STRONG
            if got or strong:
                found.append(Span(offset + a, offset + b, sentence, strong, frozenset(got)))
            if strong:
                strong_line = True  # the rest of the line follows the order
            if "role" in got and len(words(sentence)) <= 4:
                carry = True
        # Weak sentences of one line that together have enough signals: the
        # order is cut into short sentences. The flagged part of the line is strong.
        union = set().union(*(s.signals for s in found)) if found else set()
        if len(found) >= 2 and len(union) >= STRONG:
            first, last = found[0].start, found[-1].end
            found = [Span(first, last, text[first:last], True, frozenset(union))]
        spans += found
        offset += len(line)
    return spans


def remove(text: str, spans: list[Span]) -> str:
    """`text` with the strong spans cut out (empty lines collapsed)."""
    out, at = [], 0
    for s in spans:
        if s.strong:
            out.append(text[at : s.start])
            at = s.end
    out.append(text[at:])
    joined = "".join(out)
    lines = [ln.rstrip() for ln in joined.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


@dataclass
class Guard:
    """The detection result for one item text."""

    text: str
    spans: list[Span]
    clean: str
    _span_words: list[list[str]] = field(default_factory=list, repr=False)
    _only: frozenset[str] = frozenset()

    @classmethod
    def of(cls, text: str) -> Guard:
        spans = find(text)
        clean = remove(text, spans)
        rest = text
        for s in sorted(spans, key=lambda s: -s.start):  # all flagged spans out
            rest = rest[: s.start] + " " + rest[s.end :]
        span_words = [words(s.text) for s in spans]
        flagged = {w for ws in span_words for w in ws}
        only = frozenset(flagged - set(words(rest)))
        return cls(text, spans, clean, span_words, only)

    @property
    def found(self) -> bool:
        return bool(self.spans)

    @property
    def strong(self) -> bool:
        return any(s.strong for s in self.spans)

    def tainted(self, output: str | None) -> str | None:
        """`STRONG_TAINT` or `WEAK_TAINT` if `output` copies a flagged span (a
        run of `RUN` words of the span, or a word of the span that is only in
        flagged spans), else None. A copy of a strong span wins."""
        if not output or not self.spans:
            return None
        got = words(output)
        have = set(got)
        runs = {tuple(got[i : i + RUN]) for i in range(len(got) - RUN + 1)}
        level = None
        for span, ws in zip(self.spans, self._span_words, strict=True):
            hit = bool(self._only & have & set(ws)) or any(
                tuple(ws[i : i + RUN]) in runs for i in range(len(ws) - RUN + 1)
            )
            if hit and span.strong:
                return STRONG_TAINT
            if hit:
                level = WEAK_TAINT
        return level

    def names(self, kind: str) -> bool:
        """True if a flagged span names the kind `kind` (its id or its label)."""
        if not self.spans:
            return False
        names = {kind.lower(), *words(KINDS.get(kind, ("", ""))[0])}
        if kind == "admin":
            names |= {"administrative", "administration", "paperwork"}
        return any(names & set(ws) for ws in self._span_words)
