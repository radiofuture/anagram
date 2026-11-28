"""The tools of the agent gateway.

`TOOLS` maps a name to a `Tool`. Each tool has a scope of grant v2
(`access.TOOLS`): a read tool (`read.*`) reads the index; an act tool
(`act.*`) only puts a proposal in the act queue (`acts.py`). No tool sends,
shares, stamps, approves, or changes anything by itself.

Rules that each read tool keeps:

- Only spaces of `Context.scope` (the spaces that the person opened to this
  agent, readable on this device, and, for a lab, allowed by the lab for
  the class of the agent).
- Only items whose tier in the trust policy is `discoverable` or `shared`
  (`Context.open_items`). A `private` item never goes to an agent
  (net 05 step 2, interaction point I2).
- No text of other people: `retrieve.search(..., context=False)`, and
  `read_item` reads the table `chunk` only and refuses an item that another
  person wrote (`local/understanding/third_party.py`).
- No item of a source that the person closed to assistants
  (`prefs.assistant = false`).
- No source id, path, or key in a result. A space shows as "private" or the
  name of the lab.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from anagram.core.errors import ClientError
from anagram.gateway import access, acts
from anagram.local.api import (
    KIND_IDS,
    KINDS,
    PRIVATE,
    TRUST_DISCOVERABLE,
    Hit,
    LocalIndex,
    TrustPolicy,
    digest,
    humanize_title,
    kind_of,
    placeholders,
    search_index,
    source_state,
    tier_at_least,
)
from anagram.network.api import typed_draft

MAX_K = 20
MAX_HIT_TEXT = 600
MAX_PASSAGE = 1200
MAX_ITEM_TEXT = 4000
MAX_QUERY = 500


class ToolError(ValueError):
    """A bad input or a place that is not open. One sentence for the assistant."""


@dataclass
class Context:
    index: LocalIndex
    scope: frozenset[str]
    names: dict[str, str]  # space -> the word for the assistant
    skip: frozenset[str]  # source ids that the person closed to assistants
    today: date
    policy: TrustPolicy
    grant: access.Grant
    now: str = ""
    sources: list[str] = field(default_factory=list)  # the sources that the answer read

    def space_name(self, space: str) -> str:
        return self.names.get(space, "lab")

    def open_items(self, item_ids: set[int]) -> set[int]:
        """The items of `item_ids` that the trust policy lets an agent use:
        tier `discoverable` or wider. An item of another person is
        `private` (fail closed)."""
        if not item_ids:
            return set()
        ids = sorted(item_ids)
        rows = self.index.store.q(
            "SELECT i.id, i.source_id, i.key,"  # noqa: S608
            " (SELECT id FROM version WHERE item_id = i.id ORDER BY n DESC LIMIT 1) AS vid"
            f" FROM item i WHERE i.id IN ({placeholders(len(ids))})",
            ids,
        )
        out = set()
        for r in rows:
            third = r["vid"] is None or self.index.is_third_party(r["vid"])
            tier = self.policy.item_tier(r["source_id"], r["key"], third_party=third)
            if tier_at_least(tier, TRUST_DISCOVERABLE):
                out.add(r["id"])
        return out

    def read(self, source_id: str) -> None:
        if source_id not in self.sources:
            self.sources.append(source_id)


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    schema: dict
    what: str  # the `what` of the disclosure row
    run: Callable[[Context, dict], Any]
    scope: str  # the grant scope (`access.TOOLS`)

    @property
    def act(self) -> bool:
        return self.scope.startswith("act.")

    def json(self) -> dict:
        return {
            "annotations": {
                "destructiveHint": False,
                "idempotentHint": not self.act,
                "openWorldHint": False,
                "readOnlyHint": not self.act,
                "title": self.title,
            },
            "description": self.description,
            "inputSchema": self.schema,
            "name": self.name,
        }


# ------------------------------------------------------------------ inputs

SPACE = {
    "type": "string",
    "description": (
        'Where to look: "all" (the default), "private" (the person\'s own library),'
        " or the name of a lab."
    ),
}


def _text(args: dict, name: str, limit: int, required: bool = True) -> str | None:
    value = args.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"Give `{name}` as text.")
    text = " ".join(value.split())
    if len(text) > limit:
        raise ToolError(f"`{name}` has at most {limit} characters.")
    return text


def _day(args: dict, name: str) -> str | None:
    value = args.get(name)
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value)).isoformat()
    except ValueError:
        raise ToolError(f"Give `{name}` as a date, for example 2026-11-02.") from None


def _scope(ctx: Context, args: dict) -> frozenset[str]:
    value = args.get("space")
    if value in (None, "", "all"):
        return ctx.scope
    if not isinstance(value, str):
        raise ToolError("Give `space` as text.")
    want = value.strip().lower()
    for space in ctx.scope:
        name = ctx.space_name(space).lower()
        if want in (space.lower(), name) or (space.startswith("lab:") and want == space[4:]):
            return frozenset({space})
    raise ToolError('This place is not open to this assistant. Use "all" or "private".')


def _kinds(args: dict) -> tuple[str, ...]:
    value = args.get("kinds")
    if value in (None, []):
        return ()
    if not isinstance(value, list) or not all(v in KINDS for v in value):
        raise ToolError("Give `kinds` as a list of: " + ", ".join(KIND_IDS) + ".")
    return tuple(value)


def _hits(ctx: Context, query: str, k: int, **kw: Any) -> list[Hit]:
    got = search_index(ctx.index, query, k=min(2 * k, 100), context=False, **kw)
    got = [h for h in got if h.source_id not in ctx.skip and not h.third_party]
    keep = ctx.open_items({h.item_id for h in got})
    return [h for h in got if h.item_id in keep][:k]


# ------------------------------------------------------------------- tools


def search(ctx: Context, args: dict) -> dict:
    query = _text(args, "query", MAX_QUERY)
    k = args.get("k", 8)
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= MAX_K:
        raise ToolError(f"Give `k` as a number from 1 to {MAX_K}.")
    hits = _hits(
        ctx, query, k, scope=_scope(ctx, args), kinds=_kinds(args), since=_day(args, "since")
    )
    for h in hits:
        ctx.read(h.source_id)
    return {
        "hits": [
            {
                "kind": h.kind,
                "ref": h.item_ref,
                "space": ctx.space_name(h.space),
                "text": h.text[:MAX_HIT_TEXT],
                "time": h.time,
                "title": h.title,
            }
            for h in hits
        ]
    }


def ask(ctx: Context, args: dict) -> dict:
    question = _text(args, "question", MAX_QUERY)
    hits = _hits(ctx, question, 8, scope=_scope(ctx, args))
    for h in hits:
        ctx.read(h.source_id)
    return {
        "how": (
            "Answer the question from these passages only. Put the number of the passage"
            " after each statement, for example [2]. If they do not answer it, say so."
        ),
        "question": question,
        "sources": [
            {
                "anchor": h.anchor,
                "kind": h.kind,
                "n": n,
                "ref": h.item_ref,
                "space": ctx.space_name(h.space),
                "text": h.text[:MAX_PASSAGE],
                "time": h.time,
                "title": h.title,
            }
            for n, h in enumerate(hits, start=1)
        ],
    }


def _item_id(ref: object) -> int:
    head, _, tail = str(ref or "").partition(":")
    if head != "item" or not tail.isdigit() or len(tail) > 18:
        raise ToolError('Give `ref` as it came in a result, for example "item:12".')
    return int(tail)


def read_item(ctx: Context, args: dict) -> dict:
    iid = _item_id(args.get("ref"))
    anchor = args.get("anchor")
    if anchor is not None and not isinstance(anchor, str):
        raise ToolError("Give `anchor` as text.")
    space_list = sorted(ctx.scope)
    row = ctx.index.store.one(
        "SELECT i.id, i.source_id, i.name, i.time, coalesce(ss.space, ?) AS space,"  # noqa: S608
        " (SELECT id FROM version WHERE item_id = i.id ORDER BY n DESC LIMIT 1) AS vid"
        " FROM item i LEFT JOIN source_state ss ON ss.source_id = i.source_id"
        " WHERE i.id = ? AND i.present = 1 AND coalesce(ss.status, '') != ?"
        f" AND coalesce(ss.space, ?) IN ({','.join('?' * len(space_list))})",
        (PRIVATE, iid, source_state.REMOVING, PRIVATE, *space_list),
    )
    if row is None or row["vid"] is None or row["source_id"] in ctx.skip:
        raise ToolError("This item is not open to this assistant.")
    vid = row["vid"]
    if ctx.index.is_third_party(vid):  # another person wrote it: never to an assistant
        raise ToolError("This item is not open to this assistant.")
    if not ctx.open_items({iid}):  # the trust policy marks it private
        raise ToolError("This item is not open to this assistant.")
    ik = kind_of(ctx.index, vid)
    facts = ctx.index.store.q(
        "SELECT kind, value, data, enricher FROM fact WHERE version_id = ?"
        " AND kind IN ('claim', 'summary') ORDER BY score DESC, id",
        (vid,),
    )
    claims = [r["value"] for r in facts if r["kind"] == "claim"][:5]
    summaries = sorted(
        (r for r in facts if r["kind"] == "summary" and r["value"]),
        key=lambda r: 0 if r["enricher"] == "understand" else 1,
    )
    sql = "SELECT anchor, text FROM chunk WHERE version_id = ?"
    params: list = [vid]
    if anchor:
        sql += " AND anchor = ?"
        params.append(anchor)
    text, anchors = "", []
    for c in ctx.index.store.q(sql + " ORDER BY id", params):
        if len(text) >= MAX_ITEM_TEXT:
            break
        text += ("\n\n" if text else "") + c["text"]
        anchors.append(c["anchor"])
    if anchor and not anchors:
        raise ToolError("This item has no part with this anchor.")
    ctx.read(row["source_id"])
    return {
        "anchors": anchors,
        "claims": claims,
        "kind": ik.kind,
        "ref": f"item:{iid}",
        "space": ctx.space_name(row["space"]),
        "summary": summaries[0]["value"] if summaries else None,
        "text": text[:MAX_ITEM_TEXT],
        "time": row["time"],
        "title": ik.title or humanize_title(row["name"] or "") or None,
    }


def timeline(ctx: Context, args: dict) -> dict:
    since, until = digest.default_range(ctx.today)
    since = _day(args, "since") or since
    until = _day(args, "until") or until
    if since >= until:
        raise ToolError("`since` must be before `until`.")
    weeks = digest.timeline(
        ctx.index,
        scope=_scope(ctx, args),
        since=since,
        until=until,
        skip_sources=ctx.skip,
        keep=ctx.open_items,  # the trust policy: no private item, also not in the counts
    )
    refs = set()
    for w in weeks:
        for key in ("summary", "citations", "pending"):
            w.pop(key, None)
        w["space"] = "all" if w["space"] == "all" else ctx.space_name(w["space"])
        for name in ("findings", "results", "methods"):
            for r in w[name]:
                r["space"] = ctx.space_name(r["space"])
                refs.add(int(r["item_ref"][5:]))
    if refs:
        marks = ",".join("?" * len(refs))
        for r in ctx.index.store.q(
            f"SELECT DISTINCT source_id FROM item WHERE id IN ({marks})",  # noqa: S608
            sorted(refs),
        ):
            ctx.read(r[0])
    return {"weeks": weeks}


# --------------------------------------------------------------- act tools

LINES_DISCLOSURE = (
    "Nothing leaves this computer now. If you approve, these lines become the draft of"
    " your matching lines. You read and approve the lines on the Network matching screen"
    " before anything is sent."
)
# Fixed phrases that look like orders to a model and that honest lines do
# not contain. The text is compared in lower case, with each run of white
# space as one space. This is a lint, not a defence: the proposal shows a
# warning, and the person decides.
INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "system override",
    "ignore the above",
    "disregard the above",
    "disregard previous",
    "disregard all previous",
    "new instructions",
    "you must answer",
    "{{",
)
_SPACE = re.compile(r"\s+")


def _lines(args: dict, name: str) -> list[str]:
    value = args.get(name, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ToolError(f"Give `{name}` as a list of texts.")
    return value


def propose_lines(ctx: Context, args: dict) -> dict:
    """Queue lines for the draft of the matching lines. The person approves
    them in the local UI; then they are a draft that the person approves
    again on the Network matching screen. The lines are checked with the
    rules of an approval."""
    offers, wants = _lines(args, "offers"), _lines(args, "wants")
    try:
        typed_draft(offers, wants)
    except ClientError as exc:
        raise ToolError(str(exc)) from None
    payload = {"offers": offers, "wants": wants}
    text = _SPACE.sub(" ", " ".join(offers + wants).lower())
    try:
        act = acts.propose(
            ctx.index,
            ctx.grant,
            tool="act.lines_propose",
            kind=acts.LINES,
            payload=payload,
            disclosure=LINES_DISCLOSURE,
            now=ctx.now,
            flags=tuple(m for m in INJECTION_MARKERS if m in text),
        )
    except acts.ActError as exc:
        raise ToolError(str(exc)) from None
    return {
        "next": (
            "The person reads the proposal in Anagram and approves or declines it there."
            " Nothing changes until then. You cannot approve it."
        ),
        "proposal": act.id,
        "state": act.state,
    }


TOOLS: dict[str, Tool] = {}


def register(tool: Tool) -> None:
    if tool.name in TOOLS:
        raise ValueError(f"tool {tool.name} exists")
    TOOLS[tool.name] = tool


register(
    Tool(
        name="search",
        title="Search the library",
        description=(
            "Search the person's research library in Anagram (their own files and the"
            " lab spaces that they opened to you). Gives the best passages with a ref."
        ),
        schema={
            "additionalProperties": False,
            "properties": {
                "k": {"description": f"How many results, 1 to {MAX_K}.", "type": "integer"},
                "kinds": {
                    "description": "Only these kinds of item.",
                    "items": {"enum": list(KIND_IDS), "type": "string"},
                    "type": "array",
                },
                "query": {"description": "Words to look for.", "type": "string"},
                "since": {
                    "description": "Only items from this date (YYYY-MM-DD).",
                    "type": "string",
                },
                "space": SPACE,
            },
            "required": ["query"],
            "type": "object",
        },
        what="search results",
        run=search,
        scope="read.search",
    )
)
register(
    Tool(
        name="ask",
        title="Find passages for a question",
        description=(
            "Find the numbered passages of the person's library that can answer a question."
            " Anagram does not write the answer: you do, from these passages, with the numbers."
        ),
        schema={
            "additionalProperties": False,
            "properties": {
                "question": {"description": "The question.", "type": "string"},
                "space": SPACE,
            },
            "required": ["question"],
            "type": "object",
        },
        what="passages for an answer",
        run=ask,
        scope="read.ask",
    )
)
register(
    Tool(
        name="read_item",
        title="Read one item",
        description=(
            "Read one item of a result: its title, kind, summary, claims, and its text"
            f" (at most {MAX_ITEM_TEXT} characters, or the part at `anchor`)."
        ),
        schema={
            "additionalProperties": False,
            "properties": {
                "anchor": {"description": "The anchor of a passage.", "type": "string"},
                "ref": {
                    "description": 'The ref of a result, for example "item:12".',
                    "type": "string",
                },
            },
            "required": ["ref"],
            "type": "object",
        },
        what="the text of one item",
        run=read_item,
        scope="read.item",
    )
)
register(
    Tool(
        name="timeline",
        title="What was new, week by week",
        description=(
            "The findings, results, and methods of each week, newest week first. The"
            " default is the last 12 weeks."
        ),
        schema={
            "additionalProperties": False,
            "properties": {
                "since": {"description": "First day (YYYY-MM-DD).", "type": "string"},
                "space": SPACE,
                "until": {
                    "description": "The day after the last day (YYYY-MM-DD).",
                    "type": "string",
                },
            },
            "type": "object",
        },
        what="a timeline of titles and claims",
        run=timeline,
        scope="read.timeline",
    )
)
register(
    Tool(
        name="propose_lines",
        title="Propose lines for matching",
        description=(
            "Propose the person's lines for matching: what they offer and what they want,"
            " one short line each (at most 5 of each, 140 characters each). Anagram puts the"
            " proposal in a queue. The person approves or declines it in Anagram; you cannot."
            " Use the person's own words."
        ),
        schema={
            "additionalProperties": False,
            "properties": {
                "offers": {
                    "description": "What the person offers, one line each.",
                    "items": {"type": "string"},
                    "type": "array",
                },
                "wants": {
                    "description": "What the person wants, one line each.",
                    "items": {"type": "string"},
                    "type": "array",
                },
            },
            "type": "object",
        },
        what="a proposal for the matching lines",
        run=propose_lines,
        scope="act.lines_propose",
    )
)
