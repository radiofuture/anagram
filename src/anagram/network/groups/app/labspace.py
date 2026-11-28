"""The bridge between the lab space and the local index.

Two directions:

- In: `LabSpaceConnector` (kind `labspace`) gives the live items of one lab
  from the local lab cache (`labspace.sqlite`) to the index. The staged
  pipeline converts, chunks, and embeds them on this computer, so search and
  ask read lab material with no second index. Each lab has one source, and
  its `source_state.space` is `lab:<lab_id>`.
- Out: `publish_index_item` makes a lab item from an indexed item of the
  person, and `publish_pending` publishes each new version of a source whose
  space is a lab. The publish map in the lab cache makes both idempotent.

Rules:

- A `labspace` source has `own = False`. Its items go into no checkpoint, no
  finding draft, and no matching lines (the source guards read the flag). A lab item
  never goes back into the lab space (`publish_index_item` refuses a source
  with `own = False`), and a `gmail` source never goes into a lab space.
- The connector does not give an item that this device published from a
  source whose space is that lab: the original is in the index already.
- A source leaves a lab space: the items that the bridge published from it
  are removed from the lab space (`withdraw`). An item that the person put
  into the lab space by hand stays.
- The space hook (`space_hook(labs, idx)`) needs the lab context of the
  person (`Client.lab_context`) and the index. A caller that changes a space gives the hook to
  `source_state.set_space`. With no hook, `sync_index` (the task
  `lab.watch`, or `anagram lab sync`) does the same work later. All
  functions are safe to run again.
- The `Client` composition gives `LabSpaceConnector` to the index
  (`Client.index_sources`); the app does not import L3.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from anagram.core.crypto.chunked import hash_bytes
from anagram.core.errors import FormatError
from anagram.identity.api import validate_lab_id
from anagram.local.api import (
    FACT_KINDS_FROM_LAB,
    KINDS,
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    kind_of,
    lab_space,
    remove_source,
    source_state,
    space_of,
)
from anagram.network.groups.app.labcache import LabCache
from anagram.network.groups.app.labrecords import LabItemDraft
from anagram.network.groups.app.labroster import LabError

if TYPE_CHECKING:
    from anagram.local.api import (
        FACT_KINDS_FROM_LAB,
        KINDS,
        LocalIndex,
        kind_of,
        lab_space,
        source_state,
        space_of,
    )
    from anagram.network.groups.app.labcontext import AppLabs

log = logging.getLogger(__name__)

KIND = "labspace"
ITEM_KIND = "lab_item"
MEDIA_TYPE = "text/markdown"
NEVER_IN_LAB = frozenset({"gmail"})  # mail stays private
_FACT_KINDS = FACT_KINDS_FROM_LAB
_TITLE_MAX = 500
_FACT_MAX = 2000


def _lab_of(space: str) -> str | None:
    return space[4:] if space.startswith("lab:") else None


def _line(text: str | None, limit: int) -> str:
    """One line of text with no control characters (the lab item format
    refuses them), at most `limit` characters."""
    out = " ".join("".join(c if ord(c) >= 0x20 else " " for c in (text or "")).split())
    return out[:limit]


# ----------------------------------------------------------------- in


class LabSpaceConnector(Connector):
    """The items of one lab space, from the local lab cache."""

    kind: ClassVar[str] = KIND
    label: ClassVar[str] = "Lab space"
    own: ClassVar[bool] = False  # the items are the work of other people too

    def __init__(
        self,
        lab_id: str,
        *,
        cache: LabCache | None = None,
        home: Path | None = None,
        keystore: Any = None,
        store: Any = None,
    ) -> None:
        try:
            self.lab_id = validate_lab_id(lab_id)
        except FormatError as exc:
            raise ConnectorError("labspace: the config has no valid lab ID") from exc
        self._cache = cache
        self._home = Path(home) if home is not None else None
        self._keystore = keystore
        self._store = store

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> LabSpaceConnector:
        """The cache is `labspace.sqlite` next to the index, with the key from
        the keystore of the client (`ctx.credentials`, which `for_client`
        gives)."""
        creds = ctx.credentials
        if creds is None or getattr(creds, "store", None) is None:
            raise ConnectorError("labspace: the lab space needs the index of a client")
        return cls(
            cfg.get("lab_id", ""),
            home=Path(creds.store.path).parent,
            keystore=creds.keystore,
            store=creds.store,
        )

    def config(self) -> dict:
        return {"kind": KIND, "lab_id": self.lab_id}

    def describe(self) -> str:
        return self.label

    @contextlib.contextmanager
    def _open(self) -> Iterator[LabCache]:
        if self._cache is not None:
            yield self._cache
            return
        if self._home is None or self._keystore is None:
            raise ConnectorError("labspace: no lab cache")
        cache = LabCache(self._home, self._keystore, None)  # items only: no roster replay
        try:
            yield cache
        finally:
            cache.close()

    def _mine(self, cache: LabCache) -> set[str]:
        """Item IDs that this device published from a source in this lab
        space (the original is in the index)."""
        if self._store is None:
            return set()
        here = set(source_state.sources_in_space(self._store, lab_space(self.lab_id)))
        return {r["item_id"] for r in cache.published_rows(self.lab_id) if r["source_id"] in here}

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        with self._open() as cache:
            if cache.left(self.lab_id):
                return
            mine = self._mine(cache)
            rows = cache.items(self.lab_id)
        for value, text in rows:
            if value["item_id"] in mine:
                continue
            yield item_of(value, text)


def item_of(value: dict, text: str) -> EvidenceItem:
    """One evidence item for a live lab item. The fact score of the lab
    format is per mille; the index score is 0 to 1."""
    data = text.encode("utf-8")
    facts = [
        {
            "kind": f["kind"],
            "value": f["value"],
            "score": (f["score"] or 0) / 1000.0,
        }
        for f in value.get("facts") or []
    ]
    return EvidenceItem(
        key=value["item_id"],
        kind=ITEM_KIND,
        name=value["title"],
        media_type=MEDIA_TYPE,
        digest=hash_bytes(data),
        ref=f"lab:{value['lab_id']}/{value['item_id']}",
        time=value["published_at"],
        data=data,
        extra={
            "author": value["author"],
            "facts": facts,
            "item_kind": value["kind"],
            "lab_id": value["lab_id"],
            "type": value["type"],
        },
    )


def lab_sources(idx: LocalIndex) -> dict[str, str]:
    """lab_id -> source ID of each `labspace` source (no source that is
    being removed)."""
    out = {}
    for sid, src in idx.sources().items():
        if src["kind"] == KIND:
            out[src["config"].get("lab_id", "")] = sid
    return out


def ensure_lab_sources(labs: AppLabs, idx: LocalIndex) -> list[str]:
    """Add or drop `labspace` sources to match the labs of this person.

    A lab gets a source when it is readable now (`AppLabs.readable_labs`)
    and its lab space has at least one item (an empty lab space is not a
    source on the Sources screen).
    A source goes when the person left the lab or is not in its verified
    roster. A lab whose current key is not on this device yet keeps its
    source (a rotation does not make the index read everything again).
    Return the IDs of the `labspace` sources after the change."""
    readable = set(labs.readable_labs())
    cache = labs.roster.labcache
    members = {
        lab_id
        for lab_id in cache.labs()
        if (st := cache.state(lab_id)) is not None and labs.device.subject in st.members
    }
    have = lab_sources(idx)
    publish = source_state.publisher(idx.store, idx.clock)
    for lab_id, sid in sorted(have.items()):
        if lab_id not in members:
            remove_source(idx, sid, publish=publish)
            del have[lab_id]
    for lab_id in sorted(readable - set(have)):
        if not cache.items(lab_id):
            continue
        conn = LabSpaceConnector(lab_id, cache=cache, store=idx.store)
        have[lab_id] = idx.add_source(conn, label=cache.name(lab_id) or conn.label)
    for lab_id, sid in have.items():
        space = lab_space(lab_id)
        if space_of(idx, sid) != space:
            source_state.set_space(idx.store, sid, space, now=idx.clock(), publish=publish)
    return sorted(have.values())


# ---------------------------------------------------------------- out


def _check_publishable(idx: LocalIndex, sid: str) -> dict:
    try:
        src = idx.source(sid)
    except KeyError:
        raise LabError("This source is not on this computer.") from None
    if not idx.is_own(sid):
        raise LabError("This item is in the lab space already.")
    if src["kind"] in NEVER_IN_LAB:
        raise LabError("Mail stays in your private space.")
    return src


def _draft(idx: LocalIndex, src: dict, sid: str, key: str):
    """(LabItemDraft without item_id, version n) of the current version of an
    item, or None if the item is not converted yet."""
    row = idx.store.one(
        "SELECT v.id, v.n, i.name, i.time, i.present, v.media_type FROM version v"
        " JOIN item i ON i.id = v.item_id WHERE i.source_id = ? AND i.key = ?"
        " ORDER BY v.n DESC LIMIT 1",
        (sid, key),
    )
    if row is None or not row["present"]:
        raise LabError("This item is not in your index.")
    if idx.is_third_party(row["id"]):
        raise LabError("Another person wrote this item. It stays in your private space.")
    doc = idx.document(row["id"])
    if doc is None:
        return None
    k = kind_of(idx, row["id"])
    title = _line(k.title or doc.title or row["name"] or src["label"], _TITLE_MAX) or "Untitled"
    facts = []
    for f in idx.facts(sid, key):
        if f.kind not in _FACT_KINDS or (f.data or {}).get("by") == "lab":
            continue
        value = _line(f.value, _FACT_MAX)
        if value:
            score = max(0, min(1000, round(float(f.score or 0.0) * 1000)))
            facts.append({"kind": f.kind, "score": score, "value": value})
    draft = LabItemDraft(
        kind="source_item",
        title=title,
        text=doc.markdown,
        origin={
            "media_type": row["media_type"],
            "name": _line(row["name"], _TITLE_MAX) or None,
            "source_kind": src["kind"],
            "time": row["time"],
        },
        type=k.kind if k.kind in KINDS else None,
        facts=tuple(facts[:200]),
    )
    return draft, int(row["n"])


def publish_index_item(
    labs: AppLabs,
    idx: LocalIndex,
    lab_id: str,
    sid: str,
    key: str,
    attach: bool = False,
    *,
    auto: bool = False,
) -> str:
    """Put an indexed item of the person into the lab space, or a new
    revision of it when the version changed. Return the lab item ID. The
    text is the converted document; the kind and the facts go with it,
    so another member does not send the text to a model again."""
    src = _check_publishable(idx, sid)
    got = _draft(idx, src, sid, key)
    if got is None:
        raise LabError("This item is not ready yet. Try again when Anagram has read it.")
    draft, n = got
    if attach:
        row = idx.store.one("SELECT path FROM item WHERE source_id = ? AND key = ?", (sid, key))
        path = Path(row[0]) if row is not None and row[0] else None
        if path is None or not path.is_file():
            raise LabError("This item has no file on this computer to attach.")
        draft = replace(draft, files=(path,))
    cache = labs.roster.labcache
    old = cache.published(lab_id, sid, key)
    if old is not None:
        item_id, old_n = old
        live = cache.item(lab_id, item_id)
        if live is not None and not live[0]["deleted"]:
            has_files = bool(live[0].get("attachments"))
            if old_n == n and (not attach or has_files):
                return item_id
            draft = replace(draft, item_id=item_id)
    item_id = labs.space.lab_publish(lab_id, draft)
    cache.set_published(lab_id, sid, key, item_id, n, auto=auto)
    return item_id


def publish_pending(labs: AppLabs, idx: LocalIndex, lab_id: str, sid: str) -> int:
    """Publish each new version of a source whose space is this lab, and
    withdraw the items that are not in the source now. Return the number of
    items published. Idempotent. A source in another space, a lab source, or
    a mail source gives 0."""
    space = lab_space(lab_id)
    try:
        src = idx.source(sid)
    except KeyError:
        return 0
    if space_of(idx, sid) != space or not idx.is_own(sid) or src["kind"] in NEVER_IN_LAB:
        return 0
    cache = labs.roster.labcache
    done = {r["key"]: r for r in cache.published_rows(lab_id) if r["source_id"] == sid}
    count = 0
    present = set()
    for it in idx.items(sid):
        present.add(it.key)
        try:
            got = _draft(idx, src, sid, it.key)
        except LabError:
            continue
        if got is None:
            continue  # not converted yet; the next run takes it
        row = done.get(it.key)
        if row is not None and row["version_n"] == got[1]:
            continue  # published (or removed from the lab space by a PI or admin)
        # An item that the person put in by hand stays a hand item.
        auto = row["auto"] if row is not None else True
        publish_index_item(labs, idx, lab_id, sid, it.key, auto=auto)
        count += 1
    for k, row in done.items():
        if k not in present and row["auto"]:
            _withdraw_one(labs, lab_id, sid, k, row["item_id"])
    return count


def _withdraw_one(labs: AppLabs, lab_id: str, sid: str, key: str, item_id: str) -> None:
    live = labs.roster.labcache.item(lab_id, item_id)
    if live is not None and not live[0]["deleted"]:
        try:
            labs.space.lab_unpublish(lab_id, item_id)
        except LabError:
            return  # not in the lab now, or no key: the map row stays for a later run
    labs.roster.labcache.drop_published(lab_id, sid, key)


def withdraw(labs: AppLabs, lab_id: str, sid: str) -> int:
    """Remove from the lab space the items that the bridge published from
    one source. An item put in by hand stays. Return the number of rows."""
    rows = [
        r
        for r in labs.roster.labcache.published_rows(lab_id)
        if r["source_id"] == sid and r["auto"]
    ]
    for r in rows:
        _withdraw_one(labs, lab_id, sid, r["key"], r["item_id"])
    return len(rows)


def withdraw_stale(labs: AppLabs, idx: LocalIndex, lab_id: str) -> int:
    """`withdraw` for each source that is not in this lab space now (it
    moved, or it was removed)."""
    here = set(source_state.sources_in_space(idx.store, lab_space(lab_id)))
    gone = {
        r["source_id"]
        for r in labs.roster.labcache.published_rows(lab_id)
        if r["auto"] and r["source_id"] not in here
    }
    return sum(withdraw(labs, lab_id, sid) for sid in sorted(gone))


def sync_index(labs: AppLabs, idx: LocalIndex, *, scan: bool = True) -> dict:
    """The full reconcile after `lab_sync`: lab sources, withdraws, publishes,
    and a scan of the lab sources. Return {"sources", "published",
    "withdrawn"}."""
    sources = ensure_lab_sources(labs, idx)
    published = withdrawn = 0
    for lab_id in labs.readable_labs():
        withdrawn += withdraw_stale(labs, idx, lab_id)
        for sid in source_state.sources_in_space(idx.store, lab_space(lab_id)):
            if idx.is_own(sid):
                published += publish_pending(labs, idx, lab_id, sid)
    if scan and sources:
        idx.scan(sources)
    return {"published": published, "sources": sources, "withdrawn": withdrawn}


# --------------------------------------------------------- space hook


def space_hook(labs: AppLabs, idx: LocalIndex) -> source_state.SpaceHook:
    """The lab space hook for `source_state.set_space`: withdraw from the old
    lab space, publish into the new one, with this lab context and index. A fault
    raises, so the caller gets `SpaceHookError`; the next `sync_index` does
    the work again."""

    def hook(sid: str, old: str, new: str) -> None:
        try:
            if not idx.is_own(sid):
                return
        except KeyError:
            return
        old_lab, new_lab = _lab_of(old), _lab_of(new)
        if old_lab is not None:
            withdraw(labs, old_lab, sid)
        if new_lab is not None:
            publish_pending(labs, idx, new_lab, sid)

    return hook
