"""Draft findings.

A draft is a proposal. It is a separate object. Nothing here commits or
submits anything. The user acts through an explicit call:
`approve_finding(client, draft, claim=...)` commits a finding with the
evidence files and the claim that the user confirms. The suggested claim is
never used unless the caller passes it. (The matching lines have their own
draft: the profile lens, `local/understanding/profile/`.)

Quoted third-party text (for example in emails) is never used for chips or
claims. A draft that includes such evidence has `third_party = True`, so the UI
can warn before the user shares it through a ring.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath

from anagram.local.index.local import ItemView, LocalIndex
from anagram.local.ports import Committer
from anagram.local.understanding import kinds, titles
from anagram.local.understanding.chips import select_topics, split_units, unit_polarity
from anagram.local.understanding.drafter import Drafter, NullDrafter, check_drafter

# Topic scores are weighted (see `select_topics`). A topic in a finding draft
# needs this score.
FINDING_TOPIC_SCORE = 1.0
CLAIM_CHARS = 200
GAP_DAYS = 14
# Record kinds that are other people's or already public work. They inform
# topics but do not go into finding drafts.
REFERENCE_KINDS = frozenset({"zotero_item", "orcid_work"})


# -------------------------------------------------------------- findings


@dataclass
class FindingDraft:
    id: str
    title: str
    claim_suggestion: str | None
    items: list[ItemView]
    start: str | None
    end: str | None
    topics: list[str] = field(default_factory=list)  # topic labels
    third_party: bool = False
    drafted_by: str = "deterministic"
    # Keys of the items that hold other people's words (for example quoted
    # email). `approve_finding` gives these flags to the client vault, and the
    # vault's grant gate then asks for an acknowledgement before a share.
    third_party_keys: frozenset[str] = frozenset()
    # Why Anagram proposes it, for people ("A result with a claim and 3 files
    # that support it"), and the state of the proposal (`proposals.py`).
    reason: str = ""
    state: str = "new"
    # The group of the draft (a folder or a source). For code and tests only:
    # it can be a path, and a screen never shows it (`title` is for people).
    where: str = ""
    # The polarity of the top seed (`kinds.POLARITY`), or None.
    polarity: str | None = None

    @property
    def paths(self) -> list[str]:
        return [i.path for i in self.items if i.path]

    @property
    def committable(self) -> bool:
        """`Client.findings.commit_finding` takes files. Record items (for example Git
        commits) are already in the stream checkpoints."""
        return bool(self.paths)


def _time(s: str | None) -> float:
    """Seconds of an RFC 3339 UTC time. A cloud source can give fractions of
    a second ("2025-01-01T00:00:02.000Z")."""
    if not s:
        return 0.0
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC).timestamp()
    except ValueError:
        return 0.0


def _group_key(item: ItemView) -> tuple[str, str]:
    if item.path is None:
        return item.source_id, item.kind
    parent = PurePosixPath(item.ref).parent.as_posix()
    return item.source_id, parent


def _split_by_time(items: list[ItemView], gap_days: int) -> list[list[ItemView]]:
    items = sorted(items, key=lambda i: (_time(i.time), i.key))
    groups: list[list[ItemView]] = []
    for it in items:
        if groups and _time(it.time) - _time(groups[-1][-1].time) <= gap_days * 86400:
            groups[-1].append(it)
        else:
            groups.append([it])
    return groups


def suggest_claim(texts: Sequence[str], skip: Iterable[str] = ()) -> str | None:
    """A one-line claim from the owner's text only: the first sentence with a
    result, need, or offer cue; else the first sentence of prose. No internal
    reference, no HTML comment, and no unit in `skip` (the titles)."""
    first = None
    skipped = {s.strip().lower() for s in skip if s}
    for text in texts:
        for unit in split_units(titles.owner_text(text)):
            if unit.heading or len(unit.text) < 20 or unit.text.strip().lower() in skipped:
                continue
            first = first or unit.text
            if unit_polarity(unit) is not None or any(
                w in unit.text.lower() for w in ("we show", "we found", "resolved", "map at")
            ):
                return unit.text[:CLAIM_CHARS]
    return first[:CLAIM_CHARS] if first else None


def draft_findings(
    index: LocalIndex,
    *,
    drafter: Drafter | None = None,
    allow_external: bool = False,
    select: Iterable[str] | None = None,
    gap_days: int = GAP_DAYS,
) -> list[FindingDraft]:
    """Proposed findings from the content of the items (`proposals.py`): the
    items that a model or the rules call a finding or a result, grouped by
    links and projects. If no item is a finding, the drafts of
    `draft_findings_by_folder`. See `propose_findings` for `drafter`,
    `allow_external`, and `select`."""
    from anagram.local.understanding.proposals import propose_findings

    return propose_findings(
        index, drafter=drafter, allow_external=allow_external, select=select, gap_days=gap_days
    )


def texts_for_claim(index: LocalIndex, items: Iterable[ItemView]) -> tuple[list[str], list[str]]:
    """The owner's prose of the items for a claim (no slides: their lines are
    not sentences), and the titles of the items (a title is not a claim)."""
    texts, names = [], []
    for it in items:
        m = index.meaning(it.source_id, it.key)
        if m is None:
            continue
        names.append(m.extracted.title or "")
        if m.extracted.prose and m.extracted.text.strip() and m.extracted.kind != "slides":
            texts.append(m.extracted.text)
    return texts, names


def group_title(index: LocalIndex, items: Sequence[ItemView], titles_by_vid: dict) -> str:
    """A short title for people: the title of the newest item that has one;
    for a group of records with no file, the name of the source. Never a
    path (experience rule 9)."""
    if items and all(i.path is None for i in items):
        label = titles.humanize(index.source(items[0].source_id)["label"])
        if label:
            return label
    for it in sorted(items, key=lambda i: (_time(i.time), i.key), reverse=True):
        title = titles_by_vid.get((it.source_id, it.key))
        if title:
            return title
    for it in items:
        title = titles.humanize(it.name or it.ref)
        if title:
            return title
    return "Untitled files"


def draft_findings_by_folder(
    index: LocalIndex,
    *,
    drafter: Drafter | None = None,
    allow_external: bool = False,
    select: Iterable[str] | None = None,
    gap_days: int = GAP_DAYS,
) -> list[FindingDraft]:
    """Group related evidence (same folder or repository, close in time) and
    propose a finding for each group. The fallback of `propose_findings` when
    no item is a finding.

    An external drafter reads text only of the drafts whose IDs are in
    `select` (the drafts that the user picks for a model draft). With no
    `select`, an external drafter reads nothing. This matches the disclosure
    "[Provider] reads the files you select". A drafter that keeps text on the
    device (`external = False`) reads all groups."""
    drafter = drafter or NullDrafter()
    check_drafter(drafter, allow_external)
    chosen = set(select) if select is not None else set()
    groups: dict[tuple[str, str], list[ItemView]] = defaultdict(list)
    names = item_titles(index)
    refs = reference_items(index)
    for item in index.items(own_only=True):
        if item.kind in REFERENCE_KINDS or (item.source_id, item.key) in refs:
            continue
        groups[_group_key(item)].append(item)
    out = []
    for (sid, where), items in sorted(groups.items()):
        for part in _split_by_time(items, gap_days):
            chips, third_keys = [], set()
            for it in part:
                m = index.meaning(it.source_id, it.key)
                if m is None:
                    continue
                chips.append(m.chips)
                if m.has_third_party:
                    third_keys.add(it.key)
            texts, doc_titles = texts_for_claim(index, part)
            digest = hashlib.sha256("\n".join(sorted(i.root for i in part)).encode()).hexdigest()
            may_read = not drafter.external or digest[:16] in chosen
            claim = drafter.claim(texts) if texts and may_read else None
            by = drafter.name if claim else "deterministic"
            if claim is None:
                claim = suggest_claim(texts, skip=doc_titles)
            topic_ids = [t for t, _ in select_topics(chips, index.vocab, 3, FINDING_TOPIC_SCORE)]
            out.append(
                FindingDraft(
                    id=digest[:16],
                    title=group_title(index, part, names),
                    where=where if where not in (".", "") else index.source(sid)["label"],
                    claim_suggestion=claim,
                    items=part,
                    start=part[0].time,
                    end=part[-1].time,
                    topics=[index.vocab.label(t) for t in topic_ids],
                    third_party=bool(third_keys),
                    drafted_by=by,
                    third_party_keys=frozenset(third_keys),
                )
            )
    return out


def _current(index: LocalIndex) -> dict[int, tuple[str, str]]:
    out = {}
    for r in index.store.q(
        "SELECT i.source_id, i.key, (SELECT id FROM version WHERE item_id = i.id"
        " ORDER BY n DESC LIMIT 1) AS vid FROM item i WHERE i.present = 1"
    ):
        if r["vid"] is not None:
            out[r["vid"]] = (r["source_id"], r["key"])
    return out


def item_titles(index: LocalIndex) -> dict[tuple[str, str], str]:
    """(source id, key) -> the title of the current version (`kinds.kinds_of`)."""
    current = _current(index)
    got = kinds.kinds_of(index, current)
    return {current[vid]: k.title for vid, k in got.items() if k.title}


def reference_items(index: LocalIndex) -> set[tuple[str, str]]:
    """Items of the kind `reference` (work of other people, for example a
    Zotero export file in a folder). They inform topics but are no finding."""
    current = _current(index)
    got = kinds.kinds_of(index, current)
    return {current[vid] for vid, k in got.items() if k.kind == kinds.REFERENCE}


def approve_finding(
    client: Committer,
    draft: FindingDraft,
    *,
    claim: str | None,
    keys: Iterable[str] | None = None,
):
    """Commit a finding with the evidence files of the draft (or the subset in
    `keys`) and the claim that the user confirms. Return the proof bundle.

    Each evidence item with other people's words is flagged in the client
    vault (`third_party`), so a later grant or publish needs an explicit
    acknowledgement."""
    chosen = set(keys) if keys is not None else None
    items = [i for i in draft.items if i.path and (chosen is None or i.key in chosen)]
    if not items and claim is None:
        raise ValueError("nothing to commit: no files and no claim")
    return client.findings.commit_finding(
        [i.path for i in items],
        claim=claim,
        source="index",
        third_party=[i.key in draft.third_party_keys for i in items],
    )
