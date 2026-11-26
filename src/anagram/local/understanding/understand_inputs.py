"""The model inputs of the `understand` stage and the defence of its answers.

    data = triage_input(doc, info, rules_kind)   # what the model reads
    user = render_item(data)                      # escaped JSON in a tag
    kept = defend(guard(doc), raw, candidates)    # layer 1 and layer 2

Each input holds only the owner text of `Document.markdown` with no strong
planted span (`planted.py`), never `Document.quoted`. The title is a choice
from candidates that the code made (`extractive.py`). `defend` keeps only
item sentences and names that are in the item; `obeys` finds an answer that
follows a planted instruction. `understand.py` has the rules of the stage.
"""

from __future__ import annotations

import json
import re

from anagram.local.index.convert.document import Document
from anagram.local.index.enrich import ItemInfo
from anagram.local.understanding import extractive, kind_rules, kinds, planted, titles
from anagram.local.understanding.prompts import VERIFY_KIND

TRIAGE_CHARS = 1200
EXTRACT_START = 2500
EXTRACT_END = 800
EXTRACT_CHARS = 6000
OUTLINE = 12
VERIFY_SENTENCES = 30  # the finding check reads at most this many sentences
DEFENDED = "defended"  # the mark of an extraction answer after `defend`


def outline(text: str) -> list[str]:
    return extractive.headings(text)[:OUTLINE]


def guard(doc: Document) -> planted.Guard:
    """The planted instructions of the owner text of `doc` (`planted.py`)."""
    return planted.Guard.of(titles.owner_text(doc.markdown))


def model_text(doc: Document, info: ItemInfo) -> tuple[str, str]:
    """(text, title) that a model may read: the owner text with no strong
    planted span, and the document title if it does not copy one."""
    g = guard(doc)
    title = titles.doc_title(doc, info) or ""
    if g.tainted(title) == planted.STRONG_TAINT:
        title = ""
    return g.clean, title


def title_candidates(doc: Document, info: ItemInfo) -> list[str]:
    """The titles that the model may choose from (`extractive.py`): made by
    code from the owner text with no strong span; none copies a flagged span."""
    g = guard(doc)
    return extractive.title_candidates(doc, info, g.clean, g)


def triage_input(doc: Document, info: ItemInfo, rules_kind: str) -> dict:
    text, _ = model_text(doc, info)
    return {
        "null_words": kind_rules.null_outcome(text),
        "outline": outline(text),
        "rules_guess": rules_kind,
        "text": text[:TRIAGE_CHARS],
        "titles": {str(n): t for n, t in enumerate(title_candidates(doc, info), start=1)},
    }


def chosen_title(answer: dict, triage: dict) -> str | None:
    """The candidate that the answer chose by its number, or None (0, a
    number out of range, or not a number: the rules title stays)."""
    n = answer.get("title")
    if isinstance(n, bool) or not isinstance(n, int):
        return None
    return (triage.get("titles") or {}).get(str(n))


def verify_input(doc: Document, info: ItemInfo) -> dict:
    """The input of the finding check: the title and the sentences of the
    owner text with no strong planted span, by number."""
    text, title = model_text(doc, info)
    sents = extractive.sentences(text[:EXTRACT_START])[:VERIFY_SENTENCES]
    return {"sentences": {str(n): x for n, x in enumerate(sents, start=1)}, "title": title}


def checked_kind(answer: dict, data: dict, fallback: str) -> tuple[str, str]:
    """(kind, role) from the answer of the finding check. The kind stays
    `finding` only if all agree: the role is "own_result", "result" is the
    number of a sentence of the input, "whose" is "own", and "in_paper" is
    true. Another role gives its kind (`VERIFY_KIND`); "whose" = "others"
    gives `reference`; else `fallback`."""
    role = str(answer.get("role") or "")
    n = answer.get("result")
    valid = not isinstance(n, bool) and isinstance(n, int) and str(n) in data["sentences"]
    if role != "own_result":
        return VERIFY_KIND.get(role, fallback), role
    if valid and answer.get("whose") == "own" and answer.get("in_paper") is True:
        return "finding", role
    if answer.get("whose") == "others":
        return kinds.REFERENCE, role
    return fallback, role


def not_finding(second: object, rules_kind: str) -> str:
    """The kind of an item that the finding check does not keep as a finding:
    the second kind of triage, else the rules kind, else `note`."""
    for k in (second, rules_kind):
        if k in kinds.KINDS and k not in ("finding", kinds.UNKNOWN):
            return str(k)
    return "note"


_RESULT_CUE = re.compile(
    r"\bwe (?:show|found|find|observe|measured)\b|\bresults?\b|\d+(?:\.\d+)?\s?(?:%|percent)"
    r"|\brmse\b|\bp\s?[<=]",
    re.IGNORECASE,
)


def extract_input(doc: Document, info: ItemInfo) -> dict:
    text, title = model_text(doc, info)
    start = text[:EXTRACT_START]
    end = text[-EXTRACT_END:] if len(text) > EXTRACT_START + EXTRACT_END else ""
    middle = text[len(start) : len(text) - len(end)]
    budget = EXTRACT_CHARS - len(start) - len(end)
    parts = []
    for para in re.split(r"\n\s*\n", middle):
        if budget <= 0:
            break
        if _RESULT_CUE.search(para):
            parts.append(para[:budget])
            budget -= len(parts[-1])
    return {
        "end": end,
        "outline": outline(text),
        "parts": parts,
        "start": start,
        "title": title,
    }


def escaped(value: object) -> str:
    """JSON with `<`, `>`, and `&` escaped: the text cannot close the tag."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_item(data: dict) -> str:
    return "<item>\n" + escaped(data) + "\n</item>"


def render_items(items: list[dict]) -> str:
    lines = [escaped({"item": d, "n": n}) for n, d in enumerate(items, start=1)]
    return "<items>\n" + "\n".join(lines) + "\n</items>"


_WORD = re.compile(r"[a-z0-9]+")
_SMALL = frozenset({"a", "an", "and", "at", "by", "for", "in", "is", "of", "on", "or", "the", "to"})


def words(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _SMALL]


def defend(g: planted.Guard, raw: dict, candidates: list[str]) -> dict:
    """The extraction answer with only the text that passes layer 1 and
    layer 2: claims and the summary as item sentences (`extractive`); names
    that are in text that layer 1 accepts (a kept claim, the summary, or a
    title candidate), so a name adds no new text; nothing that copies a
    flagged span. `obeyed` is True if a raw text field copied a strong span
    (the answer then keeps no model fact). The cache keeps this, not the raw
    answer."""
    source = g.clean  # an output must be in the text with no strong span
    sents = extractive.Sentences(source)
    raw_text = [str(c.get(k) or "") for c in raw.get("claims") or [] for k in ("text", "quote")]
    raw_text += [str(e.get("text") or "") for e in raw.get("entities") or []]
    raw_text += [str(p.get("name") or "") for p in raw.get("people") or []]
    raw_text.append(str(raw.get("summary") or ""))
    obeyed = any(g.tainted(t) == planted.STRONG_TAINT for t in raw_text if t.strip())
    claims: list[dict] = []
    for c in raw.get("claims") or []:
        text = None
        for name in ("text", "quote"):
            text = sents.find(str(c.get(name) or ""))
            if text:
                break
        if text and not g.tainted(text) and text not in {x["text"] for x in claims}:
            claims.append({"status": c.get("status"), "text": text})
    summary = sents.find(str(raw.get("summary") or ""))
    if summary and g.tainted(summary):
        summary = None
    accepted = "\n".join([*candidates, *(c["text"] for c in claims), summary or ""])
    entities: dict[str, dict] = {}
    for e in raw.get("entities") or []:
        name = " ".join(str(e.get("text") or "").lower().split())
        n = extractive.occurs(name, source)
        if name and n and extractive.occurs(name, accepted) and not g.tainted(name):
            entities.setdefault(name, {"count": n, "text": name, "type": e.get("type")})
    people: dict[str, dict] = {}
    for p in raw.get("people") or []:
        name = " ".join(str(p.get("name") or "").split())
        n = extractive.occurs(name, source)
        if name and n and extractive.occurs(name, accepted) and not g.tainted(name):
            people.setdefault(name, {"count": n, "name": name, "role": p.get("role")})
    return {
        "claims": claims,
        DEFENDED: True,
        "entities": list(entities.values()),
        "obeyed": obeyed,
        "people": list(people.values()),
        "summary": summary or "",
    }


def obeys(
    g: planted.Guard, answer: dict, title: str | None, extracted: dict | None, rules_kind: str
) -> bool:
    """True if the answers follow a planted instruction: a raw text field
    copied a strong span (`defend` marks it), the chosen title copies one, or
    the kind is new (not the rules kind) and a flagged span names it, or the
    polarity is "negative" and a flagged span names it."""
    kind = answer.get("kind")
    if kind != rules_kind and g.names(str(kind)):
        return True
    if answer.get("polarity") == kinds.NEGATIVE and g.names(kinds.NEGATIVE):
        return True
    if extracted and extracted.get("obeyed"):
        return True
    return bool(title) and g.tainted(title) == planted.STRONG_TAINT


def anchor(doc: Document, quote: str) -> str:
    """The anchor of the block that holds the quote ("" if none)."""
    q = quote.strip().lower()[:60]
    for b in doc.blocks:
        if q and q in b.text.lower():
            return f"{b.parent}/{b.anchor}" if b.parent else b.anchor
    return ""
