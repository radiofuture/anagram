"""The run of `understand` jobs: model calls, the answer cache, and facts.

    runner = Runner(index, model, publish=publish, lab=lab, clock=clock)
    item = runner.prepare(job)      # None: the job ended (no text, no opt-in)
    runner.group([item, ...])        # triage, the finding check, extraction

`understand.run` claims the jobs and gives them to a `Runner` in groups.
Each answer is cached by a digest of the pass, the prompt version, the
taxonomy, the model, and the input text (`cache_key`). The cache keeps only
the defended answer. After each call that sent text: the disclosure rows
and, for a paid model, the event `budget.spend` (at most one in 10 s).
`understand.py` has the rules of the stage.
"""

from __future__ import annotations

import hashlib
import logging
import weakref
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from anagram.local.index import jobs, spaces
from anagram.local.index.convert.document import Document
from anagram.local.index.enrich import ItemInfo
from anagram.local.index.store import dumps, loads
from anagram.local.understanding import kind_rules, kinds, titles, understand_schema
from anagram.local.understanding.prompts import (
    EXTRACT_SCHEMA,
    EXTRACT_SYSTEM,
    PROMPT_VERSION,
    TRIAGE_BATCH_SCHEMA,
    TRIAGE_BATCH_SYSTEM,
    TRIAGE_SCHEMA,
    TRIAGE_SYSTEM,
    VERIFY_SCHEMA,
    VERIFY_SYSTEM,
)
from anagram.local.understanding.understand_inputs import (
    DEFENDED,
    anchor,
    checked_kind,
    chosen_title,
    defend,
    escaped,
    extract_input,
    guard,
    not_finding,
    obeys,
    render_item,
    render_items,
    title_candidates,
    triage_input,
    verify_input,
)
from anagram.models import profile
from anagram.models.base import (
    BudgetRefused,
    ModelError,
    TextModel,
    TextReply,
    TextRequest,
)
from anagram.models.ledger import usd_text

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

log = logging.getLogger("anagram.local.index")

ENRICHER = "understand"
TRIAGE_TOKENS = 96
VERIFY_TOKENS = 64
EXTRACT_TOKENS = 600
SPEND_EVENT_S = 10.0
WHAT_TRIAGE = "item text for classification"

Publish = Callable[[str, dict], None]
_last_spend: dict[str, float] = {}
_purged: weakref.WeakSet = weakref.WeakSet()  # the open stores that `purge_raw` read


def rules_guess(index: LocalIndex, vid: int) -> tuple[str, float]:
    row = index.store.one(
        "SELECT value, score FROM fact WHERE version_id = ? AND kind = 'kind'"
        " AND enricher = ? ORDER BY id LIMIT 1",
        (vid, kind_rules.NAME),
    )
    return (row[0], float(row[1])) if row else (kinds.UNKNOWN, 0.0)


def overridden(index: LocalIndex, vid: int) -> bool:
    understand_schema.ensure(index.store)
    return (
        index.store.one(
            "SELECT 1 FROM kind_override o JOIN version v ON v.item_id = o.item_id WHERE v.id = ?",
            (vid,),
        )
        is not None
    )


# ----------------------------------------------------------------- cache


def model_ident(model: TextModel) -> str:
    return f"{model.profile_id}|{model.model_id}"


def cache_key(pass_: str, model: TextModel, text: str) -> str:
    raw = f"{pass_}|{PROMPT_VERSION}|{kinds.TAXONOMY}|{model_ident(model)}|{text}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def purge_raw(index: LocalIndex) -> int:
    """Delete cached answers of an earlier prompt version that can hold free
    model text (a triage title as text, an extraction that is not defended).
    One time for each open store. Return the count."""
    store = index.store
    if store in _purged:
        return 0
    _purged.add(store)
    old = []
    for key, stage, output in store.q("SELECT key, pass, output FROM understand_cache"):
        data = loads(output) or {}
        if stage == "extract" and not data.get(DEFENDED):
            old.append(key)
        elif stage == "triage" and not isinstance(data.get("title"), int):
            old.append(key)
    for key in old:
        store.x("DELETE FROM understand_cache WHERE key = ?", (key,))
    return len(old)


def cache_get(index: LocalIndex, key: str) -> dict | None:
    row = index.store.one("SELECT output FROM understand_cache WHERE key = ?", (key,))
    return loads(row[0]) if row else None


def cache_put(
    index: LocalIndex, key: str, pass_: str, output: dict, model: TextModel, reply: TextReply | None
) -> None:
    index.store.x(
        "INSERT OR REPLACE INTO understand_cache (key, pass, output, model, input_tokens,"
        " output_tokens, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            key,
            pass_,
            dumps(output),
            model_ident(model),
            reply.input_tokens if reply else None,
            reply.output_tokens if reply else None,
            index.now(),
        ),
    )


# ------------------------------------------------------------------- run


@dataclass
class Item:
    job: jobs.Job
    vid: int
    sid: str
    doc: Document
    info: ItemInfo
    rules_kind: str
    triage: dict
    key: str = ""
    answer: dict | None = None


@dataclass
class RunReport:
    done: int = 0
    skipped: int = 0
    failed: int = 0
    retry: int = 0
    calls: int = 0
    cached: int = 0
    stopped: str | None = None  # "budget_reached" | "unreachable"
    items: list[str] = field(default_factory=list)  # item refs with new facts


class Stop(Exception):
    def __init__(self, state: str) -> None:
        super().__init__(state)
        self.state = state


class Runner:
    """The calls and the writes of one run of `understand` jobs."""

    def __init__(
        self,
        index: LocalIndex,
        model: TextModel,
        *,
        publish: Publish | None,
        lab: Callable[[str], Any] | None,
        clock: Callable[[], float],
    ) -> None:
        self.index = index
        self.model = model
        self.publish = publish
        self.lab = lab
        self.clock = clock
        self.report = RunReport()

    # ----------------------------------------------------------- checks

    def refusal(self, sid: str) -> str | None:
        """A reason if this model may not read this source, else None."""
        model = self.model
        if not model.external:
            return None
        who = model.recipient or "an outside service"
        prefs = self.index.source(sid)["prefs"]
        if model.recipient_id not in set(prefs.get("allow_external") or []):
            return f"this source does not allow {who}"
        space = spaces.space_of(self.index, sid)
        if space != spaces.PRIVATE:
            policy = self.lab(space.split(":", 1)[1]) if self.lab else None
            if policy is None or not policy.allows_recipient(model.recipient_id):
                return f"the lab does not allow {who}"
        return None

    def prepare(self, job: jobs.Job) -> Item | None:
        idx = self.index
        doc = idx.document(job.version_id)
        if doc is None:
            self.finish(job, jobs.SKIPPED, "this item has no text")
            return None
        if overridden(idx, job.version_id):
            self.finish(job, jobs.DONE)  # the person chose the kind
            return None
        reason = self.refusal(job.source_id)
        if reason is not None:
            self.finish(job, jobs.SKIPPED, reason)
            return None
        info = kind_rules.item_info(idx, job.version_id)
        rules_kind, _ = rules_guess(idx, job.version_id)
        item = Item(job, job.version_id, job.source_id, doc, info, rules_kind, {})
        item.triage = triage_input(doc, info, rules_kind)
        item.key = cache_key("triage", self.model, escaped(item.triage))
        return item

    # ------------------------------------------------------------- calls

    def call(self, request: TextRequest, sources: Iterable[str]) -> TextReply:
        model, idx = self.model, self.index
        try:
            reply = model.generate(request)
        except BudgetRefused:
            raise Stop("budget_reached") from None  # no text was sent
        except ModelError as exc:
            self.sent(sources)
            profile.note_call(idx, model.profile_id, exc)
            raise
        self.sent(sources)
        profile.note_call(idx, model.profile_id, None)
        profile.remember_mode(idx, model, self.clock)
        if reply.refusal:
            raise ModelError("refused")
        return reply

    def sent(self, sources: Iterable[str]) -> None:
        """After a call that sent text: the disclosure rows and the spend event."""
        self.report.calls += 1
        if self.model.external:
            for sid in dict.fromkeys(sources):
                self.index.log_disclosure(
                    self.model.recipient, self.model.recipient_id, WHAT_TRIAGE, sid
                )
        if self.model.paid:
            self.spend()

    def spend(self) -> None:
        if self.publish is None:
            return
        ledger = getattr(self.model, "ledger", None)
        if ledger is None:
            return
        now = self.clock()
        if now - _last_spend.get(str(ledger.path), -1e18) < SPEND_EVENT_S:
            return
        _last_spend[str(ledger.path)] = now
        snap = ledger.snapshot()
        self.publish(
            "budget.spend",
            {
                "budget_usd": usd_text(Decimal(ledger.limit_nano) / 10**9),
                "spent_usd": usd_text(Decimal(snap["reserved_nanousd"]) / 10**9),
            },
        )

    def triage(self, group: list[Item]) -> None:
        """Fill `item.answer` for each item: from the cache, from one call for
        the group (a cloud model), or from one call for each item."""
        todo = []
        for it in group:
            hit = cache_get(self.index, it.key)
            if hit is not None:
                it.answer = hit
                self.report.cached += 1
            else:
                todo.append(it)
        if len(todo) > 1:
            try:
                self.triage_batch(todo)
                return
            except ModelError as exc:
                if exc.code not in ("bad_output", "output_cut", "refused"):
                    raise
                log.info("understand: batch answer not usable; one call for each item")
        for it in todo:
            self.triage_one(it)

    def triage_one(self, it: Item) -> None:
        req = TextRequest(
            system=TRIAGE_SYSTEM,
            user=render_item(it.triage),
            schema=TRIAGE_SCHEMA,
            max_output_tokens=TRIAGE_TOKENS,
            purpose="understand.triage",
        )
        reply = self.call(req, [it.sid])
        it.answer = dict(reply.data or {})
        cache_put(self.index, it.key, "triage", it.answer, self.model, reply)

    def triage_batch(self, todo: list[Item]) -> None:
        req = TextRequest(
            system=TRIAGE_BATCH_SYSTEM,
            user=render_items([it.triage for it in todo]),
            schema=TRIAGE_BATCH_SCHEMA,
            max_output_tokens=TRIAGE_TOKENS * len(todo),
            purpose="understand.triage",
        )
        reply = self.call(req, [it.sid for it in todo])
        answers = {a.get("n"): a for a in (reply.data or {}).get("items") or []}
        if sorted(answers) != list(range(1, len(todo) + 1)):
            raise ModelError("bad_output")
        for n, it in enumerate(todo, start=1):
            it.answer = {k: v for k, v in answers[n].items() if k != "n"}
            cache_put(self.index, it.key, "triage", it.answer, self.model, None)

    def verify(self, it: Item, *, promote: bool = False) -> None:
        """The finding check: one call (or a cache hit) for an item that
        triage calls a finding. It changes `it.answer` if the check does not
        keep the finding. The answer has no text, so the cache keeps it.

        `promote`: the item is a negative `result` of triage.
        A model often calls a null outcome with a reading of the person a
        result. If the check agrees on all four answers, the kind becomes
        `finding` (second `result`); else the item stays a result."""
        data = verify_input(it.doc, it.info)
        key = cache_key("verify", self.model, escaped(data))
        hit = cache_get(self.index, key)
        if hit is not None:
            self.report.cached += 1
            answer = hit
        else:
            req = TextRequest(
                system=VERIFY_SYSTEM,
                user=render_item(data),
                schema=VERIFY_SCHEMA,
                max_output_tokens=VERIFY_TOKENS,
                purpose="understand.verify",
            )
            reply = self.call(req, [it.sid])
            got = reply.data or {}
            answer = {k: got.get(k) for k in ("in_paper", "result", "role", "whose")}
            cache_put(self.index, key, "verify", answer, self.model, reply)
        ans = dict(it.answer or {})
        kind, role = checked_kind(answer, data, not_finding(ans.get("second"), it.rules_kind))
        ans["check"] = role
        if promote:
            if kind == "finding":
                ans.update(kind="finding", second="result")
        elif kind != "finding":
            ans.update(kind=kind, second="finding", stage="")
        it.answer = ans

    def extract(self, it: Item) -> dict:
        data = extract_input(it.doc, it.info)
        key = cache_key("extract", self.model, escaped(data))
        hit = cache_get(self.index, key)
        if hit is not None:
            self.report.cached += 1
            return hit
        req = TextRequest(
            system=EXTRACT_SYSTEM,
            user=render_item(data),
            schema=EXTRACT_SCHEMA,
            max_output_tokens=EXTRACT_TOKENS,
            purpose="understand.extract",
        )
        reply = self.call(req, [it.sid])
        cands = title_candidates(it.doc, it.info)
        out = defend(guard(it.doc), dict(reply.data or {}), cands)
        cache_put(self.index, key, "extract", out, self.model, reply)
        return out

    # ------------------------------------------------------------ facts

    def facts(self, it: Item, extracted: dict | None) -> list[tuple]:
        """The facts to keep from the answers. Layer 1 (`extractive.py`): the
        title is a candidate chosen by number, a claim or the summary is an
        item sentence, a name is in the item. Layer 2 (`planted.py`): an
        answer that copies a strong span, or a new kind that a flagged span
        names, gives no model fact; an output that copies a weak span is
        dropped."""
        ans = it.answer or {}
        g = guard(it.doc)
        title = chosen_title(ans, it.triage)
        if extracted is not None and not extracted.get(DEFENDED):
            extracted = defend(g, extracted, title_candidates(it.doc, it.info))
        if g.found and obeys(g, ans, title, extracted, it.rules_kind):
            log.info("understand: the answer follows a planted instruction; rules kept")
            return []
        data: dict = {"by": "model"}
        kind = ans["kind"]
        if ans.get("stage") and kind in kinds.SEED_KINDS:
            data["stage"] = ans["stage"]
        polarity = kinds.polarity_of(kind, ans)  # a closed choice
        if polarity:
            data["polarity"] = polarity
        if ans.get("second") and ans["second"] != kind:
            data["second"] = ans["second"]
        if ans.get("check"):
            data["check"] = ans["check"]  # the role that the finding check gave
        confidence = min(1.0, max(0.0, float(ans.get("confidence") or 0.0)))
        out = [("kind", kind, confidence, data)]
        if title and not g.tainted(title):
            out.append(("title", title, 0.0, {"by": "model"}))
        if extracted:
            for c in extracted.get("claims") or []:
                text = str(c.get("text") or "")
                out.append(
                    ("claim", text, confidence, {"anchor": anchor(it.doc, text),
                                                 "quote": text, "status": c.get("status")}),
                )  # fmt: skip
            out += [
                ("entity", e["text"], float(e["count"]), {"type": e.get("type")})
                for e in extracted.get("entities") or []
            ]
            out += [
                ("person", p["name"], float(p["count"]), {"role": p.get("role")})
                for p in extracted.get("people") or []
            ]
            summary = str(extracted.get("summary") or "")
            if summary:
                out.append(("summary", titles.cut(summary, 160), 0.0, {"by": "model"}))
        return out

    def write(self, it: Item, rows: list[tuple]) -> None:
        idx = self.index
        with idx.store.transaction():
            idx.store.x(
                "DELETE FROM fact WHERE version_id = ? AND enricher = ?", (it.vid, ENRICHER)
            )
            idx.store.many(
                "INSERT INTO fact (version_id, kind, value, score, data, enricher,"
                " enricher_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(it.vid, k, v, s, dumps(d), ENRICHER, PROMPT_VERSION) for k, v, s, d in rows],
            )
        item_id = idx.store.one("SELECT item_id FROM version WHERE id = ?", (it.vid,))[0]
        ref = f"item:{item_id}"
        self.report.items.append(ref)
        if self.publish is not None:
            got = kinds.kind_of(idx, it.vid)
            self.publish(
                "item.kind",
                {
                    "by": got.by,
                    "confidence": got.confidence,
                    "kind": got.kind,
                    "ref": ref,
                    "title": got.title,
                },
            )

    # ------------------------------------------------------------- jobs

    def finish(self, job: jobs.Job, state: str, reason: str | None = None) -> None:
        jobs.finish(self.index.store, job, self.clock(), state, reason)
        if state == jobs.SKIPPED:
            self.report.skipped += 1
        else:
            self.report.done += 1

    def fail(self, job: jobs.Job, exc: ModelError) -> None:
        state = jobs.fail(self.index.store, job, f"model: {exc.code}", self.clock())
        if state == jobs.FAILED:
            self.report.failed += 1
        else:
            self.report.retry += 1

    def group(self, group: list[Item]) -> None:
        try:
            self.triage(group)
        except Stop:
            for it in group:
                jobs.release(self.index.store, it.job, self.clock())
            raise
        except ModelError as exc:
            for it in group:
                self.fail(it.job, exc)
            if exc.retryable or exc.code in ("unreachable", "no_key"):
                raise Stop("unreachable") from None
            return
        for it in group:
            try:
                if it.answer is None or it.answer.get("kind") not in kinds.KINDS:
                    raise ModelError("bad_output")
                if it.answer["kind"] == "finding":
                    self.verify(it)
                elif it.answer["kind"] == "result" and it.answer.get("polarity") == kinds.NEGATIVE:
                    self.verify(it, promote=True)
                extracted = self.extract(it) if it.answer["kind"] in kinds.EXTRACT_KINDS else None
                self.write(it, self.facts(it, extracted))
            except Stop:
                jobs.release(self.index.store, it.job, self.clock())
                raise
            except ModelError as exc:
                self.fail(it.job, exc)
                continue
            self.finish(it.job, jobs.DONE)
