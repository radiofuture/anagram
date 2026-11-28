"""Search, ask, and the timeline in the local UI (layer L2; the
part `UIService.ask`). The routes are in `shell/ui/routers/understanding.py`.

Rules:

- A scope is always inside `spaces.readable_spaces`
  (`UnderstandingUI.scope`).
- The model call of an answer or of a weekly summary runs on a worker
  thread and holds no lock. An answer arrives as `ask.sources`, `ask.delta`,
  `ask.done`, or `ask.error`, each with `thread` (the key of the event).
- The timeline makes no model call. A summary that is not in the cache is
  made on a worker; then `timeline.changed` tells the page to load again.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from datetime import date, timedelta
from typing import TYPE_CHECKING, Any

from anagram.local.api import (
    KINDS,
    PRIVATE_SCOPE,
    SEED_KINDS,
    answer_question,
    ask_history,
    check_question,
    clear_ask_history,
    digest,
    prepare_question,
    readable_spaces,
    record_answer,
    search_index,
)
from anagram.models import ModelError, profile
from anagram.shell.client import lab_context
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.models import FALLBACK, sentence
from anagram.shell.ui.understanding import MAX_QUERY, space_rows

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.ui")
MAX_HITS = 50
THREADS = 50  # answers of this session kept for `GET /api/ask/{thread}`
DELTA_S = 0.1  # at most 10 `ask.delta` events each second
MAX_TIMELINE = timedelta(days=731)


class AskUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self._threads: dict[str, dict] = {}
        self._ask_lock = threading.Lock()
        self._digests: set[str] = set()  # scopes with a summary worker
        self.delta_s = DELTA_S

    @staticmethod
    def _lab_allow(client: Any, scope: frozenset[str], model: Any) -> dict:
        """For each lab space of the scope, the recipient ids that the lab
        allows. A local model needs no entry."""
        out: dict[str, frozenset[str]] = {}
        labs = lab_context(client)
        if model is None or not model.external or labs is None:
            return out
        for s in scope:
            if not s.startswith("lab:"):
                continue
            try:
                lab = labs.lab_policy(s[4:])
            except Exception:  # noqa: S112 - a lab with no policy allows nothing
                continue
            if profile.may_read_lab(model, lab):
                out[s] = frozenset({model.recipient_id})
        return out

    def ask_setup(self) -> dict:
        """What the ask field needs: the model (or none), the readable
        spaces, and up to 3 titles of the person's newest findings and
        results, as examples."""
        with self.ui.session(index=True) as (client, idx):
            scope = readable_spaces(lab_context(client))
            cfg, _ = self.ui.models.load(client, idx)
            cfg, _ = self.ui.models.adopt_local(client, idx, cfg)
            state = self.ui.models.state(client, idx, cfg)
            pid = cfg.use.get("ask") or cfg.use.get("understand")
            chosen = cfg.profiles.get(pid) if pid else None
            rows = self.ui.understanding.rows(idx, PRIVATE_SCOPE)
            spaces_shown = space_rows(client, scope)
        seeds = [r for r in rows if r["kind"] in SEED_KINDS]
        seeds.sort(key=lambda r: (r["time"] or "", r["id"]), reverse=True)
        examples = list(dict.fromkeys(r["title"] for r in seeds if r["title"]))[:3]
        return {
            "examples": examples,
            "model": None if chosen is None else {"label": chosen.label},
            "spaces": spaces_shown,
            "state": state,
        }

    def search(
        self,
        q: object,
        space: object = None,
        kind: object = None,
        since: object = None,
        k: object = None,
    ) -> dict:
        """Scoped search (`retrieve.search`). Hits of other people's text
        come only from the private space, with `third_party`."""
        text = " ".join(str(q or "").split())
        if len(text) > MAX_QUERY:
            raise UIError(400, f"Type at most {MAX_QUERY} characters.")
        if kind not in (None, "") and kind not in KINDS:
            raise UIError(400, "Choose a kind from the list.")
        try:
            size = 10 if k in (None, "") else int(str(k))
        except ValueError:
            size = 0
        if not 1 <= size <= MAX_HITS:
            raise UIError(400, f"Ask for 1 to {MAX_HITS} results.")
        with self.ui.session(index=True) as (client, idx):
            scope = self.ui.understanding.scope(client, space)
            hits = search_index(
                idx,
                text,
                scope=scope,
                k=size,
                kinds=[str(kind)] if kind else (),
                since=str(since) if since else None,
            )
            mode = "hybrid" if idx.embedder is not None and idx.store.has_vec() else "text"
        return {"hits": [h.json() for h in hits], "mode": mode}

    def _emit(self, thread: str, type_: str, data: dict) -> None:
        # An answer's events use the thread id as their key.
        self.ui.publish(type_, {**data, "thread": thread}, key=thread)

    def start_ask(self, question: object, space: object = None, *, wait: bool = False) -> dict:
        """Start an answer on a worker thread and give its id. The answer
        arrives as `ask.sources`, `ask.delta`, `ask.done`, or `ask.error`,
        each with `thread` (the key of the event). `wait` runs it on this
        thread (for tests)."""
        try:
            text = check_question(question)
        except ValueError as exc:
            raise UIError(400, str(exc)) from None
        with self.ui.session(index=True) as (client, _):
            scope = self.ui.understanding.scope(client, space)
        thread = secrets.token_hex(8)
        with self._ask_lock:
            self._threads[thread] = {
                "answer": "",
                "grounded": None,
                "left_out": 0,
                "mode": None,
                "model": None,
                "question": text,
                "sources": [],
                "state": "working",
            }
            while len(self._threads) > THREADS:
                self._threads.pop(next(iter(self._threads)))
        if wait:
            self._run_ask(thread, text, scope)
        else:
            threading.Thread(
                target=self._run_ask, args=(thread, text, scope), name="ask", daemon=True
            ).start()
        return {"thread": thread}

    def _run_ask(self, thread: str, question: str, scope: frozenset[str]) -> None:
        record = self._threads.get(thread, {})
        try:
            with self.ui.session(index=True) as (client, idx):
                cfg, _ = self.ui.models.load(client, idx)
                model, reason = self.ui.models.ask_model(client, cfg)
                lab_allow = self._lab_allow(client, scope, model)
                prepared = prepare_question(
                    idx, question, scope=scope, model=model, lab_allow=lab_allow
                )
            pending, last, done = "", 0.0, None
            for event in answer_question(prepared, model):  # the model call holds no lock
                if event.type == "delta":
                    pending += event.data["text"]
                    record["answer"] = record.get("answer", "") + event.data["text"]
                    if time.monotonic() - last >= self.delta_s:
                        self._emit(thread, "ask.delta", {"text": pending})
                        pending, last = "", time.monotonic()
                    continue
                if pending:
                    self._emit(thread, "ask.delta", {"text": pending})
                    pending = ""
                if event.type == "sources":
                    record["sources"] = event.data["sources"]
                    record["left_out"] = event.data.get("left_out", 0)
                    self._emit(thread, "ask.sources", event.data)
                elif event.type == "error":
                    record.update(state="error")
                    code = event.data.get("code")
                    self._emit(thread, "ask.error", {**event.data, "message": sentence(code)})
                else:
                    done = {**event.data, "reason": reason if model is None else None}
                    record.update(
                        answer=done["text"],
                        grounded=done.get("grounded"),
                        mode=done["mode"],
                        model=done.get("model"),
                        state="done",
                    )
                    self._emit(thread, "ask.done", done)
            if done is not None:
                with self.ui.session(index=True) as (_, idx):
                    record_answer(idx, prepared, done, model)
        except UIError as exc:
            record.update(state="error")
            self._emit(thread, "ask.error", {"code": "failed", "message": exc.message})
        except Exception:  # the page must get an end; the log gets the class only
            log.exception("ask failed")
            record.update(state="error")
            self._emit(thread, "ask.error", {"code": "failed", "message": FALLBACK})

    def ask_thread(self, thread: str) -> dict:
        got = self._threads.get(thread)
        if got is None:
            raise UIError(404, "This answer is not on this computer now. Ask again.")
        return dict(got)

    def ask_history(self) -> list[dict]:
        with self.ui.session(index=True) as (client, idx):
            return ask_history(idx, scope=readable_spaces(lab_context(client)))

    def clear_ask_history(self) -> dict:
        with self.ui.session(index=True) as (_, idx):
            return {"cleared": clear_ask_history(idx)}

    # ------------------------------------------------------------- timeline

    def _range(self, since: object, until: object) -> tuple[str, str]:
        """ISO dates. The default is the last 12 weeks; at most 2 years."""
        start, end = digest.default_range(self.ui.models.today())
        try:
            first = date.fromisoformat(str(since)) if since not in (None, "") else None
            last = date.fromisoformat(str(until)) if until not in (None, "") else None
        except ValueError:
            raise UIError(400, "Type the dates as year-month-day.") from None
        if first is not None:
            start = first.isoformat()
        if last is not None:
            end = last.isoformat()
        if start >= end:
            raise UIError(400, "The start date must be before the end date.")
        if date.fromisoformat(end) - date.fromisoformat(start) > MAX_TIMELINE:
            raise UIError(400, "Ask for at most two years.")
        return start, end

    def timeline(self, space: object = None, since: object = None, until: object = None) -> list:
        """The weeks of the scope (`digest.timeline`), with no model call. A
        summary that is not in the cache is made on a worker; then the event
        `timeline.changed` tells the page to load again."""
        start, end = self._range(since, until)
        with self.ui.session(index=True) as (client, idx):
            readable = readable_spaces(lab_context(client))
            scope = self.ui.understanding.scope(client, space)
            digest.forget(idx, readable)
            cfg, _ = self.ui.models.load(client, idx)
            model, _ = self.ui.models.ask_model(client, cfg)
            lab_allow = self._lab_allow(client, scope, model)
            weeks = digest.timeline(
                idx,
                scope=scope,
                since=start,
                until=end,
                model=model,
                call=False,
                lab_allow=lab_allow,
            )
        if model is not None and digest.needs_summaries(weeks):
            self._start_digest(scope, start, end, model, lab_allow)
        return weeks

    def _start_digest(
        self, scope: frozenset[str], since: str, until: str, model: Any, lab_allow: dict
    ) -> None:
        key = " ".join(sorted(scope))
        with self._ask_lock:
            if key in self._digests:
                return
            self._digests.add(key)
        threading.Thread(
            target=self._run_digest,
            args=(key, scope, since, until, model, lab_allow),
            name="digest",
            daemon=True,
        ).start()

    def _run_digest(
        self,
        key: str,
        scope: frozenset[str],
        since: str,
        until: str,
        model: Any,
        lab_allow: dict,
    ) -> None:
        """Make the missing summaries. The model call holds no lock. One fault
        ends the run; the page keeps the weeks with no summary."""
        made = 0
        try:
            with self.ui.session(index=True) as (_, idx):
                todo = digest.jobs(
                    idx, scope=scope, since=since, until=until, model=model, lab_allow=lab_allow
                )
            for job in todo:
                try:
                    out = digest.summarize(model, job)
                except ModelError:
                    break
                with self.ui.session(index=True) as (_, idx):
                    digest.save(idx, job, out, model)
                made += 1
        except Exception:  # the log gets the class only
            log.exception("timeline summary failed")
        finally:
            with self._ask_lock:
                self._digests.discard(key)
        if made:
            self.ui.publish("timeline.changed", {"space": key})
