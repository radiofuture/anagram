"""Pass 3 of understanding: links between items, with no model.

- `related`: two items of the same space that share 2 entities or more
  (`data.score` is the Jaccard share of their entities). An entity that is in
  many items of the space (more than `COMMON_SHARE` of them, and more than
  `COMMON_MIN`) says nothing about one pair: it is the topic of the lab, and
  it does not count.
- `supports`: an item -> a `finding` or `result` item of the same space and
  the same place (project, else folder), at most `NEAR_DAYS` apart:
  - a `data` or `result` item (the evidence kinds; a result supports only a
    finding): when the place is small (`PLACE_MAX` items or fewer), or the two
    share an entity or a topic chip;
  - a `code` or `method` item (how the work was done): only when the two
    share an entity or a topic chip.

`update(index)` makes the two relation kinds again for all current items. It
reads facts only (no text), so it is fast and needs no model. Links never
cross a space.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from anagram.core.timefmt import seconds_or
from anagram.local.index import spaces
from anagram.local.understanding import kinds

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

RELATED = "related"
SUPPORTS = "supports"
BUILDS_ON = "builds_on"
KINDS = (RELATED, SUPPORTS)
MIN_SHARED = 2
SUPPORT_KINDS = frozenset({"data", "code", "method", "result"})
EVIDENCE_KINDS = frozenset({"data", "result"})  # what a proposed finding holds as evidence
# An entity in more items than this says nothing about one pair.
COMMON = 25
COMMON_MIN = 8
COMMON_SHARE = 0.2
PLACE_MAX = 12
NEAR_DAYS = 30


def _facts(index: LocalIndex, vids: list[int], kind: str, enricher: str | None = None):
    out: dict[int, set[str]] = defaultdict(set)
    for start in range(0, len(vids), 500):
        part = vids[start : start + 500]
        marks = ",".join("?" for _ in part)
        sql = f"SELECT version_id, value FROM fact WHERE kind = ? AND version_id IN ({marks})"  # noqa: S608
        args: list = [kind, *part]
        if enricher:
            sql += " AND enricher = ?"
            args.append(enricher)
        for vid, value in index.store.q(sql, args):
            out[vid].add(value)
    return out


def _near(a: float | None, b: float | None) -> bool:
    return a is None or b is None or abs(a - b) <= NEAR_DAYS * 86400


def _item_info(index: LocalIndex, items: list, got: dict) -> dict[int, tuple]:
    """For each item: (space, place, kind, version id). The place is the
    project, else the folder, else the source."""
    projects = index.projects()
    space: dict[str, str] = {}
    info = {}
    for r in items:
        sid = r["source_id"]
        if sid not in space:
            space[sid] = spaces.space_of(index, sid)
        where = projects.get((sid, r["key"])) or (
            f"folder:{sid}:{PurePosixPath(r['ref']).parent}" if r["ref"] else f"source:{sid}"
        )
        info[r["id"]] = (space[sid], where, got[r["vid"]].kind, r["vid"])
    return info


def _shared_entities(info: dict[int, tuple], entities: dict) -> dict[tuple[int, int], int]:
    """For each pair of items of one space: the count of entities that they
    share. An entity in many items of the space does not count."""
    in_space: dict[str, int] = defaultdict(int)
    for sp, _w, _k, _v in info.values():
        in_space[sp] += 1
    holders: dict[tuple[str, str], list[int]] = defaultdict(list)  # (space, entity) -> items
    for iid, (sp, _w, _k, vid) in info.items():
        for e in entities.get(vid, ()):
            holders[(sp, e)].append(iid)
    shared: dict[tuple[int, int], int] = defaultdict(int)
    for (sp, _e), ids in holders.items():
        if len(ids) > min(COMMON, max(COMMON_MIN, COMMON_SHARE * in_space[sp])):
            continue  # an entity in many items says nothing about one pair
        for a, b in combinations(sorted(ids), 2):
            shared[(a, b)] += 1
    return shared


def _related(info: dict[int, tuple], entities: dict, shared: dict) -> list[tuple]:
    related = []
    for (a, b), n in sorted(shared.items()):
        if n >= MIN_SHARED:
            union = entities[info[a][3]] | entities[info[b][3]]
            related.append((a, b, round(n / len(union), 3)))
    return related


def _can_support(k_src: str, k_dst: str) -> bool:
    if k_src not in SUPPORT_KINDS or k_dst not in kinds.SEED_KINDS:
        return False
    return k_src != "result" or k_dst == "finding"


def _supports(info: dict[int, tuple], when: dict, shared: dict, topics: dict) -> list[tuple]:
    places: dict[tuple[str, str], list[int]] = defaultdict(list)  # (space, project) -> items
    for iid, (sp, where, _k, _v) in info.items():
        places[(sp, where)].append(iid)
    supports = []
    for ids in places.values():
        small = len(ids) <= PLACE_MAX
        for src in ids:
            _, _, k_src, v_src = info[src]
            for dst in ids:
                _, _, k_dst, v_dst = info[dst]
                if dst == src or not _can_support(k_src, k_dst):
                    continue
                if not _near(when[src], when[dst]):
                    continue
                pair = (min(src, dst), max(src, dst))
                signal = bool(
                    shared.get(pair) or topics.get(v_src, set()) & topics.get(v_dst, set())
                )
                if signal or (small and k_src in EVIDENCE_KINDS):
                    supports.append((src, dst))
    return supports


def update(index: LocalIndex) -> dict[str, int]:
    """Make the `related` and `supports` relations again. Return the counts."""
    rows = index.store.q(
        "SELECT i.id, i.source_id, i.key, i.ref, i.time, (SELECT id FROM version"
        " WHERE item_id = i.id ORDER BY n DESC LIMIT 1) AS vid FROM item i WHERE i.present = 1"
    )
    items = [r for r in rows if r["vid"] is not None]
    vids = [r["vid"] for r in items]
    entities = _facts(index, vids, "entity")
    topics = _facts(index, vids, "topic", "chips")
    info = _item_info(index, items, kinds.kinds_of(index, vids))
    when = {r["id"]: seconds_or(r["time"]) for r in items}
    shared = _shared_entities(info, entities)
    related = _related(info, entities, shared)
    supports = _supports(info, when, shared, topics)
    now = index.now()
    with index.store.transaction():
        index.store.x("DELETE FROM relation WHERE kind IN (?, ?)", KINDS)
        for a, b, score in related:
            index.relate(RELATED, f"item:{a}", f"item:{b}", now, {"score": score})
        for a, b in supports:
            index.relate(SUPPORTS, f"item:{a}", f"item:{b}", now)
    return {RELATED: len(related), SUPPORTS: len(supports)}
