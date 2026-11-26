"""Pass 0 of understanding: the kind of an item from rules, with no model.

`KindRulesEnricher` runs in the `enrich` job next to `chips`. It writes:

- one `kind` fact (`data.by = "rules"`, a confidence from 0 to 1, and `stage`
  for a finding or a result);
- one `title` fact: a short clean phrase from the item (`titles.doc_title`);
- for a `labspace` item that carries `extra.type`: the author's kind with
  `data.by = "lab"` and the author's facts from `extra.facts`. Lab text does
  not go to a model of this member again.

Signals: the item kind, the source kind, the document kind, the media type,
words of the path, the text size, and cue phrases of the owner's text. The
rules read only `Document.markdown`, never `Document.quoted`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from anagram.local.index.enrich import EnrichContext, Enricher, Fact, ItemInfo
from anagram.local.index.store import loads
from anagram.local.understanding import titles
from anagram.local.understanding.kinds import FACT_KINDS_FROM_LAB, KINDS, SEED_KINDS

if TYPE_CHECKING:
    from anagram.local.index.convert.document import Document
    from anagram.local.index.local import LocalIndex

NAME = "kind_rules"
VERSION = "1"
# Confidence at or above this: the rules kind is final; no `understand` job.
SURE = 0.9

REFERENCE_ITEMS = frozenset({"zotero_item", "orcid_work"})
REFERENCE_SOURCES = frozenset({"zotero_file", "zotero_web", "orcid_works"})
CODE_ITEMS = frozenset({"git_commit", "github_commit"})
CODE_EXT = frozenset(
    {
        "py", "r", "jl", "js", "ts", "c", "h", "cpp", "rs", "go", "java", "m", "sh", "sql",
        "toml", "yaml", "yml", "ini", "cfg", "json", "ipynb", "do", "sas", "stan", "tex",
    }
)  # fmt: skip
NOISE_NAMES = frozenset({".ds_store", "thumbs.db", "desktop.ini"})
NOISE_EXT = frozenset({"lock", "tmp", "bak", "swp", "log", "pyc", "o"})

PATH_WORDS: dict[str, tuple[str, ...]] = {
    "plan": ("plan", "plans", "proposal", "grant", "aims", "roadmap", "priorities",
             "prereg", "preregistration", "budget-request"),
    "method": ("protocol", "protocols", "method", "methods", "procedure", "sop", "howto",
               "guide", "interview-guide", "codebook"),
    "note": ("notebook", "notes", "log", "journal", "meeting", "minutes", "ideas", "diary",
             "fieldnotes"),
    "draft": ("draft", "manuscript", "thesis", "chapter", "poster", "paper", "preprint",
              "talk", "slides", "deck", "decks"),
    "admin": ("budget", "invoice", "order", "orders", "schedule", "inventory", "booking",
              "form", "forms", "hr", "travel", "reimbursement", "timesheet", "teaching",
              "syllabus", "rota", "freezer"),
    "result": ("results", "figures", "figure", "fig", "output", "outputs", "benchmark"),
    "data": ("data", "raw", "dataset", "datasets"),
    "code": ("code", "src", "scripts", "lib"),
}  # fmt: skip

CUES: dict[str, tuple[str, ...]] = {
    "finding": (
        r"\bwe (?:show|found|find|demonstrate|conclude|report|identified|prove)\b",
        r"\b(?:our|these) results (?:show|suggest|indicate)\b",
        r"\bthis (?:shows|proves|confirms|establishes)\b",
        r"\bevidence (?:that|for)\b",
        r"\b(?:lemma|theorem|corollary)\b",
        r"\bwell resolved\b",
        r"\bwe attribute\b|\battributed to\b",
        r"\bkey finding\b|\bmain finding\b",
    ),
    "result": (
        r"\b\d+(?:\.\d+)?\s?(?:%|percent|nm|mm|mg|ml|kd|pkd|fold|a)\b",
        r"\brmse\b|\baccuracy\b|\bauc\b|\bp\s?[<=]\s?0?\.\d",
        r"\bn\s?=\s?\d+",
        r"\bmeasured\b|\bobserved\b|\bmean\b|\bmedian\b",
        r"\bresolution\b|\bhits?\b|\byield\b",
    ),
    "method": (
        r"\bprotocol\b|\bprocedure\b|\bstep \d\b",
        r"\bincubate\b|\bcentrifuge\b|\bwash\b|\bdilute\b",
        r"\bwe used\b|\bhow to\b|\binterview guide\b|\bcoding scheme\b",
    ),
    "plan": (
        r"\bwe will\b|\bwe plan\b|\bwe want to\b|\bnext steps?\b",
        r"\baim \d\b|\baims\b|\bmilestones?\b|\btimeline\b|\bdeliverables?\b",
        r"\bq[1-4]\b|\bproposal\b|\bpre-?registration\b|\bpriorities\b",
    ),
    "note": (
        r"(?m)^\s*-\s*\d{1,2}[-/]\d{1,2}\s*:",
        r"\bnotebook\b|\bmeeting\b|\bminutes\b|\btodo\b|\bidea\b|\blog\b",
    ),
    "draft": (
        r"(?m)^#+\s*(?:abstract|introduction|discussion|conclusions?|references)\s*$",
        r"\bmanuscript\b|\bchapter\b|\bposter\b|\bsubmission\b",
    ),
    "admin": (
        r"\binvoice\b|\border\b|\bbudget\b|\bbooking\b|\bfreezer\b|\binventory\b",
        r"\bschedule\b|\bwarranty\b|\breimburse|\btimesheet\b|\bdispenser\b",
        r"\broom [a-z]?\d+\b|\bbreeder\b|\bdelivery\b|\bship\b",
    ),
    "correspondence": (
        r"(?im)^\s*(?:hi|dear|hello)\b",
        r"(?im)^\s*(?:best|regards|thanks|cheers),?\s*$",
    ),
}
# A claim cue ("we show") says more about the role than a number or a word.
CUE_WEIGHT = {"finding": 2.5}
_CUES = {k: [re.compile(p, re.IGNORECASE) for p in ps] for k, ps in CUES.items()}
_HYPOTHESIS = re.compile(r"\bhypothes|\bwe (?:think|expect|suspect)\b|\bmay\b|\bmight\b", re.I)
_REPLICATED = re.compile(r"\breplicat|\brepeatable\b|\bagain\b|\breproduc", re.IGNORECASE)


# Words of a null or negative outcome. They do not change the
# rules kind, and they give no polarity: a model must read the item. An item
# with these words gets an `understand` job also when it is short, because a
# negative result is often one line ("no change in 12 runs").
_OUTCOME = (
    r"(?:effect|difference|change|shift|gain|signal|improvement|benefit|association"
    r"|correlation|link|rise|increase|decrease|drop|reduction|response|trend)s?"
)
NULL_OUTCOME = re.compile(
    r"\bno (?:(?:significant|measurable|clear|detectable|real|reliable|consistent"
    r"|meaningful|statistical|obvious|further)\s+)*" + _OUTCOME + r"\b"
    r"|\b(?:did|does|do|could|can|would)\s*(?:not|n't)\s+(?:change|differ|improve|affect"
    r"|alter|reduce|increase|raise|lower|replicate|reproduce|hold|survive|predict|beat"
    r"|outperform|show|be (?:replicated|reproduced))\b"
    r"|\b(?:failed|fails|fail) to (?:replicate|reproduce|change|differ|improve|beat|hold"
    r"|reach|show)\b"
    r"|\bnot (?:statistically\s+)?significant\b|\bnon-?significant\b"
    r"|\b(?:same as|no better than|no different from|indistinguishable from|equivalent to)\b"
    r"|\bwithin (?:the )?noise\b|\b(?:at|near) background\b"
    r"|\b(?:null|negative) (?:result|effect|finding|outcome)s?\b"
    r"|\b(?:went away|vanished|disappeared|fell to zero|stayed flat|was flat)\b"
    r"|\b(?:difference|change|effect|gain) (?:was|is|of) (?:zero|nil|0(?:\.0+)?)\b"
    r"|\bwithin [\d.]+ ?\w* of (?:the )?(?:baseline|control)\b"
    r"|\bin neither\b",
    re.IGNORECASE,
)


def null_outcome(text: str) -> bool:
    """True if `text` has words of a null or negative outcome."""
    return NULL_OUTCOME.search(text) is not None


@dataclass(frozen=True)
class Guess:
    kind: str
    confidence: float
    stage: str | None = None
    second: str | None = None


def path_words(info: ItemInfo | None) -> list[str]:
    if info is None:
        return []
    text = f"{info.ref or ''}/{info.name or ''}".lower()
    words = [w for w in re.split(r"[^a-z0-9]+", text) if w]
    parts = [p for p in re.split(r"[/\\]", text) if p]
    return words + parts


def _ext(info: ItemInfo | None) -> str:
    name = (info.name or info.ref or "") if info else ""
    suffix = PurePosixPath(name).suffix.lower()
    return suffix[1:] if suffix else ""


def stage_of(text: str) -> str:
    if _HYPOTHESIS.search(text):
        return "hypothesis"
    if _REPLICATED.search(text):
        return "replicated"
    return "observed"


def classify(
    doc: Document | None, info: ItemInfo | None = None, hints: Iterable[dict] = ()
) -> Guess:
    """The rules kind of one item, with a confidence from 0 to 1."""
    info = info or ItemInfo()
    dk = doc.kind if doc is not None else "binary"
    guess = _metadata_guess(doc, info, dk)
    if guess is not None:
        return guess
    if dk in ("table", "data"):
        return Guess("data", 0.9)
    if dk in ("binary", "file") or doc is None:
        return Guess("data" if (info.size or 0) > 0 else "noise", 0.6)
    text = titles.owner_text(doc.markdown)
    guess = _form_guess(doc, dk, text)
    if guess is not None:
        return guess
    return _text_guess(text, info, hints, dk)


def _metadata_guess(doc: Document | None, info: ItemInfo, dk: str) -> Guess | None:
    """A sure kind from the name, the item kind, the source kind, or the
    media type of an item. None if they do not decide."""
    ik, sk, mt = info.kind, info.source_kind, (info.media_type or "").lower()
    name = (info.name or "").lower()
    ext = _ext(info)
    if name in NOISE_NAMES or ext in NOISE_EXT or name.startswith(("~$", ".~lock")):
        return Guess("noise", 0.95)
    if ik in REFERENCE_ITEMS or sk in REFERENCE_SOURCES or dk == "bibliography":
        return Guess("reference", 0.95)
    if ik in CODE_ITEMS or dk in ("code", "code_repo") or (ext in CODE_EXT and ext != "tex"):
        return Guess("code", 0.95)
    if dk == "email" or mt == "message/rfc822" or sk == "gmail":
        return Guess("correspondence", 0.95)
    if doc is not None and doc.meta.get("third_party"):
        return Guess("reference", 0.9)  # a file that another person wrote
    return None


def _form_guess(doc: Document, dk: str, text: str) -> Guess | None:
    """A kind from the form of a document (an image, slides, or almost no
    text). None if the form does not decide."""
    if dk == "image":
        return Guess("result", 0.6, "observed", "data") if doc.title else Guess("data", 0.5)
    if dk == "slides" or titles.is_slides(doc.markdown):
        return Guess("draft", 0.9, None, "plan")
    if len(text) < 40:
        return Guess("unknown" if text else "noise", 0.5)
    return None


def _text_guess(text: str, info: ItemInfo, hints: Iterable[dict], dk: str) -> Guess:
    """A kind from scores of the path words, the cues in the text, and the
    hints."""
    scores: dict[str, float] = defaultdict(float)
    words = set(path_words(info))
    for kind, marks in PATH_WORDS.items():
        if words & set(marks):
            scores[kind] += 2.0
    if "readme" in words:
        scores["code"] += 1.5
    for kind, pats in _CUES.items():
        hits = sum(1.0 for p in pats if p.search(text))
        scores[kind] += min(3.0, hits) * CUE_WEIGHT.get(kind, 1.0)
    low = text.lower()
    for h in hints:
        hint = str(h.get("text") or "").lower().strip()
        if hint and h.get("kind") in KINDS and (hint in low or hint in " ".join(words)):
            scores[h["kind"]] += 3.0
    if dk == "canvas":
        scores["note"] += 1.0
    if not scores or max(scores.values()) <= 0:
        return Guess("note", 0.45)
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    kind, top = ranked[0]
    second = ranked[1][0] if len(ranked) > 1 and ranked[1][1] > 0 else None
    margin = top - (ranked[1][1] if len(ranked) > 1 else 0.0)
    confidence = round(min(0.85, 0.4 + 0.08 * top + 0.05 * margin), 2)
    return Guess(kind, confidence, stage_of(text) if kind in SEED_KINDS else None, second)


def lab_facts(info: ItemInfo) -> list[Fact] | None:
    """The author's kind and facts of a lab item, or None if it has none."""
    extra = info.extra or {}
    kind = extra.get("type")
    if info.source_kind != "labspace" or kind not in KINDS:
        return None
    out = [Fact("kind", kind, 1.0, {"by": "lab"})]
    for f in extra.get("facts") or []:
        if not isinstance(f, dict) or f.get("kind") not in FACT_KINDS_FROM_LAB:
            continue
        data = f.get("data") if isinstance(f.get("data"), dict) else {}
        try:
            score = float(f.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        out.append(Fact(f["kind"], str(f.get("value") or "")[:300], score, {**data, "by": "lab"}))
    return out


class KindRulesEnricher(Enricher):
    """The kind and the title of an item, with no model."""

    name = NAME
    version = VERSION

    def __init__(self, hints: Iterable[dict] = ()) -> None:
        self.hints = list(hints)

    def enrich(self, doc: Document, ctx: EnrichContext) -> list[Fact]:
        info = ctx.item or ItemInfo()
        lab = lab_facts(info)
        if lab is not None:
            title = titles.doc_title(doc, info)
            if title and not any(f.kind == "title" for f in lab):
                lab.append(Fact("title", title, 0.0, {"by": "lab"}))
            return lab
        guess = classify(doc, info, self.hints)
        data: dict = {"by": "rules"}
        if guess.stage:
            data["stage"] = guess.stage
        if guess.second:
            data["second"] = guess.second
        out = [Fact("kind", guess.kind, guess.confidence, data)]
        title = titles.doc_title(doc, info)
        if title:
            out.append(Fact("title", title, 0.0, {"by": "rules"}))
        return out


def item_info(index: LocalIndex, vid: int) -> ItemInfo:
    """What the rules know of one version beyond its document."""
    row = index.store.one(
        "SELECT i.kind, i.name, i.ref, v.media_type, v.digest, v.extra, s.kind AS skind"
        " FROM version v JOIN item i ON i.id = v.item_id JOIN source s ON s.id = v.source_id"
        " WHERE v.id = ?",
        (vid,),
    )
    if row is None:
        return ItemInfo()
    digest = loads(row["digest"]) or {}
    return ItemInfo(
        kind=row["kind"],
        name=row["name"],
        ref=row["ref"] or "",
        media_type=row["media_type"] or "",
        source_kind=row["skind"] or "",
        size=digest.get("size") if isinstance(digest, dict) else None,
        extra=loads(row["extra"]) or {},
    )
