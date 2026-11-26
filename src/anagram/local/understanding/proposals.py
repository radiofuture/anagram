"""Proposed findings from the content of the items.

1. Seeds: current own items of kind `finding`, or of kind `result` with one
   claim or more, with a confidence of 0.6 or more, not stamped, and not a
   reference. The kind is the kind of `kinds.kinds_of` (the person, then the
   model, then the lab, then the rules), so with no model the rules kinds
   give the seeds.
2. Groups: seeds with a `related` or `builds_on` relation, or in the same
   project and at most 30 days apart, form one group.
3. Evidence: the `data` and `result` items with a `supports` relation to a
   seed. A method or code item is linked to the seed (the item screen shows
   it), but it is not evidence of the finding.
4. The claim is the claim fact with the highest score; else a drafter claim
   (with the same opt-in rule as `draft_findings`); else a sentence of the
   owner's text. The title is the title of the top seed: a short phrase,
   never a path.
5. No seed: `draft_findings_by_folder`.
6. State: table `proposal` (`new`, `later`, `dismissed`, `stamped`). A
   dismissed or stamped proposal does not come back. "Not a finding" also
   sets the kind `note` for the seeds (a correction by the person). Nothing
   here stamps a finding.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable, Iterable

from anagram.core.timefmt import iso_seconds
from anagram.local.index import spaces
from anagram.local.index.local import ItemView, LocalIndex
from anagram.local.understanding import kinds, links, understand_schema
from anagram.local.understanding.chips import select_topics
from anagram.local.understanding.drafter import Drafter, NullDrafter, check_drafter
from anagram.local.understanding.drafts import (
    FINDING_TOPIC_SCORE,
    GAP_DAYS,
    REFERENCE_KINDS,
    FindingDraft,
    _time,
    draft_findings_by_folder,
    item_titles,
    suggest_claim,
    texts_for_claim,
)

GROUP_DAYS = 30
MIN_CONFIDENCE = 0.6
STATES = ("new", "later", "dismissed", "stamped")
HIDDEN = frozenset({"dismissed", "stamped"})
Publish = Callable[[str, dict], None]


def _ids(index: LocalIndex, items: list[ItemView]) -> dict[str, int]:
    rows = index.store.q("SELECT id, source_id, key FROM item")
    by_key = {(r[1], r[2]): r[0] for r in rows}
    return {f"{i.source_id}\x00{i.key}": by_key[(i.source_id, i.key)] for i in items}


def _current_vid(index: LocalIndex, item_id: int) -> int:
    return index.store.one(
        "SELECT id FROM version WHERE item_id = ? ORDER BY n DESC LIMIT 1", (item_id,)
    )[0]


def _claims(index: LocalIndex, vids: Iterable[int]) -> dict[int, list[tuple[float, str]]]:
    out: dict[int, list[tuple[float, str]]] = defaultdict(list)
    vids = list(vids)
    for start in range(0, len(vids), 500):
        part = vids[start : start + 500]
        marks = ",".join("?" for _ in part)
        for r in index.store.q(
            "SELECT version_id, value, score FROM fact WHERE kind = 'claim'"  # noqa: S608
            f" AND version_id IN ({marks})",
            part,
        ):
            out[r[0]].append((float(r[2]), r[1]))
    return out


class _Union:
    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def join(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _count(n: int, one: str, many: str) -> str:
    return f"{'a' if n == 1 else n} {one if n == 1 else many}"


def _reason(seed_kinds: list[str], has_claim: bool, support: int) -> str:
    """Why the proposal matters, in one line: what the seeds are, a claim,
    and the files that support it."""
    f = seed_kinds.count("finding")
    r = len(seed_kinds) - f
    if f and r:
        what = f"{_count(f, 'finding', 'findings')} and {_count(r, 'result', 'results')}"
    elif f > 1 or r > 1:
        what = f"{f or r} related {'findings' if f else 'results'}"
    else:
        what = "a finding" if f else "a result"
    parts = [what[0].upper() + what[1:]]
    if has_claim:
        parts.append("with a claim")
    if support:
        noun = "file that supports it" if support == 1 else "files that support it"
        parts.append(f"and {support} {noun}" if has_claim else f"with {support} {noun}")
    return " ".join(parts)


def _now(index: LocalIndex) -> str:
    return iso_seconds(index.clock())


def _key(i: ItemView) -> str:
    return f"{i.source_id}\x00{i.key}"


class _Pool:
    """The own items in scope, with their item IDs, current versions, kinds,
    and claim facts."""

    def __init__(self, index: LocalIndex, items: list[ItemView]) -> None:
        self.items = items
        self.ids = _ids(index, items)
        self.vid_of = {k: _current_vid(index, iid) for k, iid in self.ids.items()}
        self.got = kinds.kinds_of(index, self.vid_of.values())
        self.claims = _claims(index, self.vid_of.values())
        self.by_ref = {self.ref(i): i for i in items}

    def kind(self, i: ItemView) -> kinds.ItemKind:
        return self.got[self.vid_of[_key(i)]]

    def claims_of(self, i: ItemView) -> list[tuple[float, str]]:
        return self.claims.get(self.vid_of[_key(i)], [])

    def ref(self, i: ItemView) -> str:
        return f"item:{self.ids[_key(i)]}"

    def seeds(self, stamped: set) -> list[ItemView]:
        """The items of kind `finding`, or `result` with a claim, with a
        confidence of `MIN_CONFIDENCE` or more, and not stamped."""
        out = []
        for it in self.items:
            k = self.kind(it)
            if (it.source_id, it.key) in stamped or k.confidence < MIN_CONFIDENCE:
                continue
            if k.kind == "finding" or (k.kind == "result" and self.claims_of(it)):
                out.append(it)
        return out


def propose_findings(
    index: LocalIndex,
    *,
    scope: frozenset[str] = spaces.PRIVATE_SCOPE,
    drafter: Drafter | None = None,
    allow_external: bool = False,
    select: Iterable[str] | None = None,
    gap_days: int = GAP_DAYS,
    publish: Publish | None = None,
) -> list[FindingDraft]:
    """The proposed findings in `scope` (see the module text). An external
    drafter reads text only of the proposals whose IDs are in `select`."""
    drafter = drafter or NullDrafter()
    check_drafter(drafter, allow_external)
    understand_schema.ensure(index.store)
    space: dict[str, str] = {}

    def in_scope(sid: str) -> bool:
        if sid not in space:
            space[sid] = spaces.space_of(index, sid)
        return space[sid] in scope

    pool = _Pool(
        index,
        [
            i
            for i in index.items(own_only=True)
            if i.kind not in REFERENCE_KINDS and in_scope(i.source_id)
        ],
    )
    seeds = pool.seeds(index.stamped())
    if not seeds:
        drafts = draft_findings_by_folder(
            index, drafter=drafter, allow_external=allow_external, select=select, gap_days=gap_days
        )
        drafts = [d for d in drafts if all(in_scope(i.source_id) for i in d.items)]
        return _with_state(index, drafts, publish)

    links.update(index)
    support = _support(index, pool, seeds)
    names = item_titles(index)
    chosen = set(select) if select is not None else set()
    out = [
        _proposal(index, pool, members, support, names, drafter, chosen)
        for members in _groups(index, pool, seeds)
    ]
    out.sort(key=lambda d: (-_time(d.end), d.id))
    return _with_state(index, out, publish)


def _groups(index: LocalIndex, pool: _Pool, seeds: list[ItemView]) -> list[list[ItemView]]:
    """The seeds in groups: a `related` or `builds_on` relation, or the same
    project at most `GROUP_DAYS` apart, puts two seeds in one group."""
    seed_refs = {pool.ref(i) for i in seeds}
    union = _Union()
    for s in seeds:
        union.find(pool.ids[_key(s)])
    for kind_, src, dst in index.relations():
        if kind_ in (links.RELATED, links.BUILDS_ON) and src in seed_refs and dst in seed_refs:
            union.join(int(src[5:]), int(dst[5:]))
    projects = index.projects()
    by_project: dict[str, list[ItemView]] = defaultdict(list)
    for s in seeds:
        p = projects.get((s.source_id, s.key))
        if p:
            by_project[p].append(s)
    for group in by_project.values():
        group.sort(key=lambda i: _time(i.time))
        for a, b in zip(group, group[1:], strict=False):
            if abs(_time(b.time) - _time(a.time)) <= GROUP_DAYS * 86400:
                union.join(pool.ids[_key(a)], pool.ids[_key(b)])
    groups: dict[int, list[ItemView]] = defaultdict(list)
    for s in seeds:
        groups[union.find(pool.ids[_key(s)])].append(s)
    return list(groups.values())


def _support(index: LocalIndex, pool: _Pool, seeds: list[ItemView]) -> dict[str, list[str]]:
    """For each seed ref, the refs of the evidence items (`data` or `result`)
    with a `supports` relation to it."""
    seed_refs = {pool.ref(i) for i in seeds}
    support: dict[str, list[str]] = defaultdict(list)
    for _, src, dst in index.relations(links.SUPPORTS):
        if dst in seed_refs and src in pool.by_ref and src not in seed_refs:
            if pool.kind(pool.by_ref[src]).kind in links.EVIDENCE_KINDS:
                support[dst].append(src)
    return support


def _proposal(
    index: LocalIndex,
    pool: _Pool,
    members: list[ItemView],
    support: dict[str, list[str]],
    names: dict,
    drafter: Drafter,
    chosen: set[str],
) -> FindingDraft:
    """The proposal of one group of seeds."""
    members.sort(  # a finding first: its title names the proposal
        key=lambda i: (
            pool.kind(i).kind != "finding",
            -pool.kind(i).confidence,
            -_time(i.time),
            i.key,
        ),
    )
    top = members[0]
    evidence = []
    for s in members:
        for ref in support.get(pool.ref(s), ()):
            if pool.by_ref[ref] not in evidence and pool.by_ref[ref] not in members:
                evidence.append(pool.by_ref[ref])
    part = members + evidence
    digest = hashlib.sha256("\n".join(sorted(i.root for i in part)).encode()).hexdigest()
    best = max((c for s in members for c in pool.claims_of(s)), default=None)
    if best is not None:
        claim, by = best[1], "model"
    else:
        may_read = not drafter.external or digest[:16] in chosen
        claim, by = _drafted_claim(index, members, drafter, may_read=may_read)
    chips, third = [], set()
    for it in part:
        m = index.meaning(it.source_id, it.key)
        if m is not None:
            chips.append(m.chips)
            if m.has_third_party:
                third.add(it.key)
    topic_ids = [t for t, _ in select_topics(chips, index.vocab, 3, FINDING_TOPIC_SCORE)]
    times = sorted((i.time for i in part if i.time), key=_time)
    return FindingDraft(
        id=digest[:16],
        title=names.get((top.source_id, top.key)) or "Untitled finding",
        claim_suggestion=claim,
        items=part,
        start=times[0] if times else None,
        end=times[-1] if times else None,
        topics=[index.vocab.label(t) for t in topic_ids],
        third_party=bool(third),
        drafted_by=by,
        third_party_keys=frozenset(third),
        reason=_reason([pool.kind(m).kind for m in members], best is not None, len(evidence)),
        where=pool.ref(top),
        polarity=pool.kind(top).polarity,
    )


def _drafted_claim(
    index: LocalIndex, members: list[ItemView], drafter: Drafter, *, may_read: bool
) -> tuple[str | None, str]:
    """A claim with no claim fact: from the drafter if it may read the text,
    else a sentence of the owner's text. Return `(claim, drafted_by)`."""
    texts, doc_titles = texts_for_claim(index, members)
    claim = drafter.claim(texts) if texts and may_read else None
    if claim is not None:
        return claim, drafter.name
    return suggest_claim(texts, skip=doc_titles), "deterministic"


# ----------------------------------------------------------------- state


def states(index: LocalIndex) -> dict[str, str]:
    understand_schema.ensure(index.store)
    return {r[0]: r[1] for r in index.store.q("SELECT id, state FROM proposal")}


def _with_state(
    index: LocalIndex, drafts: list[FindingDraft], publish: Publish | None
) -> list[FindingDraft]:
    """Record new proposals; leave out dismissed and stamped ones."""
    known = states(index)
    now = _now(index)
    out = []
    for d in drafts:
        state = known.get(d.id)
        if state is None:
            index.store.x(
                "INSERT OR IGNORE INTO proposal (id, state, reason, created_at, updated_at)"
                " VALUES (?, 'new', ?, ?, ?)",
                (d.id, d.reason, now, now),
            )
            state = "new"
            if publish is not None:
                publish("suggestion.new", {"id": d.id, "state": state, "title": d.title})
        if state in HIDDEN:
            continue
        d.state = state
        out.append(d)
    return out


def set_state(
    index: LocalIndex,
    draft_id: str,
    state: str,
    *,
    title: str | None = None,
    publish: Publish | None = None,
) -> None:
    """Change the state of one proposal (`later`, `dismissed`, `stamped`, `new`)."""
    if state not in STATES:
        raise ValueError("not a proposal state")
    understand_schema.ensure(index.store)
    now = _now(index)
    index.store.x(
        "INSERT INTO proposal (id, state, reason, created_at, updated_at) VALUES (?, ?, '', ?, ?)"
        " ON CONFLICT (id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
        (draft_id, state, now, now),
    )
    if publish is not None:
        publish("suggestion.changed", {"id": draft_id, "state": state, "title": title})


def dismiss(index: LocalIndex, draft: FindingDraft, *, publish: Publish | None = None) -> None:
    """ "Not a finding": the proposal goes away, and its seeds get the kind
    `note` from the person (only items that the model or rules call a finding
    or a result)."""
    set_state(index, draft.id, "dismissed", title=draft.title, publish=publish)
    ids = _ids(index, list(draft.items))
    for it in draft.items:
        iid = ids[f"{it.source_id}\x00{it.key}"]
        if kinds.kind_of(index, _current_vid(index, iid)).kind in kinds.SEED_KINDS:
            kinds.set_override(index, iid, "note", publish=publish)


def import_used(index: LocalIndex, draft_ids: Iterable[str]) -> int:
    """Copy the `used_drafts` list of the old UI state one time: each ID
    becomes a `stamped` proposal. Return the count."""
    n = 0
    for did in draft_ids:
        if states(index).get(did) != "stamped":
            set_state(index, did, "stamped")
            n += 1
    return n
