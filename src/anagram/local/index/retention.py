"""Byte retention after conversion, and removal of a source with its data.

Cloud bytes never go to a plain file: the sync engine stores the bytes of an
item in `version.blob`, inside SQLCipher.

- `after_convert(index, vid)`: for a source that can get the same bytes
  again (`refetchable = True`), a blob above `KEEP_BLOB_MAX` is deleted after
  a conversion. The digest, the evidence opening, and `version.extra.fetch`
  stay. A local file source keeps no blob in any case.
- `refetch(index, v)`: get the bytes again for a new conversion
  (`connector.fetch`), and compare the digest. A mismatch is a skipped item.
- `remove_source(index, sid)`: delete all rows of one source in short
  transactions. A version that a timestamped finding uses (`finding_ref`)
  keeps its `version` and `item` rows (the opening and the digest only; no
  bytes, no text, no meaning), because the proof of the finding needs the
  opening. Then the account of the source is revoked if no other source uses
  it.

Kept on purpose: the `disclosure` log (a record of what went to an outside
service) and the `source_event` log (at most 2 000 rows, no content).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from anagram.core.crypto.chunked import ContentDigest, hash_bytes
from anagram.local.index.convert import Skip
from anagram.local.index.store import IndexStore, loads, placeholders
from anagram.local.index.vec_store import SqliteVecStore
from anagram.local.sources import source_state as ss
from anagram.local.sources.http import SourceFault

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex

log = logging.getLogger("anagram.local.index")

KEEP_BLOB_MAX = 1 * 1024 * 1024
BATCH = 1000

GONE = Skip(
    "the source no longer has these exact bytes",
    "The item keeps its date proof. The next sync reads the new version.",
)
NOT_AGAIN = Skip(
    "Anagram cannot read these bytes again now",
    "The item keeps its date proof. Anagram tries again with the next version.",
)


def _refetchable(index: LocalIndex, sid: str):
    """The connector of a source if it can get the same bytes again."""
    try:
        conn = index.connector(sid)
    except Exception:  # a source that does not open keeps its bytes
        return None
    if getattr(conn, "refetchable", False) and callable(getattr(conn, "fetch", None)):
        return conn
    return None


def after_convert(index: LocalIndex, vid: int) -> bool:
    """Delete a large blob that the source can give again. Return True if
    the blob was deleted."""
    row = index.store.one(
        "SELECT source_id, length(blob) AS size, extra FROM version WHERE id = ?", (vid,)
    )
    if row is None or row["size"] is None or row["size"] <= KEEP_BLOB_MAX:
        return False
    conn = _refetchable(index, row["source_id"])
    if conn is None:
        return False
    # A source can keep some bytes: a Drive export is not byte-stable.
    can = getattr(conn, "can_refetch", None)
    if callable(can) and not can(loads(row["extra"]) or {}):
        return False
    index.store.x("UPDATE version SET blob = NULL WHERE id = ?", (vid,))
    return True


def refetch(index: LocalIndex, v) -> bytes | Skip:
    """The bytes of version row `v` (of `JobRunner.version`) from the
    source again, or a `Skip`. The bytes must have the digest of the
    version."""
    conn = _refetchable(index, v["sid"])
    if conn is None:
        return Skip("no bytes for this item", "Nothing to do.")
    extra = loads(v["extra"]) or {}
    try:
        data = conn.fetch(v["key"], extra)
    except SourceFault as exc:
        if exc.code == "not_found":
            return GONE
        return NOT_AGAIN
    digest = ContentDigest.from_json(loads(v["digest"]))
    if hash_bytes(data, digest.chunk_size).digest != digest.digest:
        return GONE
    return data


# ------------------------------------------------------------------ remove


def _chunks(ids: list, n: int = BATCH) -> Iterable[list]:
    for i in range(0, len(ids), n):
        yield ids[i : i + n]


def remove_source(
    index: LocalIndex,
    sid: str,
    *,
    delete_data: bool = True,
    publish: Callable[[str, dict], None] | None = None,
) -> dict:
    """Remove one source and delete what Anagram read from it. Return
    `{"removed_items", "kept_for_findings", "account_revoked"}`.

    The source is `removing` first, so a sync or a scan stops and does not
    start again. A removal that stops in the middle (a crash) can run again
    and continues."""
    if not delete_data:
        raise ValueError("a source is removed with its data")
    store = index.store
    publish = publish or ss.publisher(store, index.clock)
    index.source(sid)  # KeyError for an unknown source
    state = ss.get(store, sid, index.clock())
    account_id = state.account_id
    ss.set_status(store, sid, ss.REMOVING, now=index.clock(), publish=publish)
    index.connectors.pop(sid, None)

    kept_vids = {
        r[0]
        for r in store.q(
            "SELECT DISTINCT v.id FROM version v JOIN finding_ref f ON f.version_id = v.id"
            " WHERE v.source_id = ?",
            (sid,),
        )
    }
    kept_items = {
        r[0]
        for r in store.q(
            "SELECT DISTINCT item_id FROM version WHERE id IN"
            " (SELECT version_id FROM finding_ref) AND source_id = ?",
            (sid,),
        )
    }
    store.x("DELETE FROM job WHERE source_id = ?", (sid,))
    _remove_versions(store, sid, kept_vids)
    removed = _remove_items(index, sid, kept_items)
    _remove_source_rows(store, sid, keep_row=bool(kept_items))
    revoked = _revoke_unused_account(index, sid, account_id)
    out = {
        "account_revoked": revoked,
        "kept_for_findings": len(kept_items),
        "removed_items": removed,
    }
    publish(
        "source.removed",
        {
            "id": sid,
            "kept_for_findings": out["kept_for_findings"],
            "removed_items": out["removed_items"],
        },
    )
    return out


def _remove_versions(store: IndexStore, sid: str, kept_vids: set) -> None:
    """Delete the versions of a source and what was made from them. A kept
    version (a finding uses it) keeps its row with no bytes."""
    vids = [r[0] for r in store.q("SELECT id FROM version WHERE source_id = ?", (sid,))]
    for part in _chunks(vids):
        m = placeholders(len(part))
        with store.transaction():
            chunk_ids = store.q(f"SELECT id FROM chunk WHERE version_id IN ({m})", part)  # noqa: S608
            SqliteVecStore(store).delete(r[0] for r in chunk_ids)
            store.x(f"DELETE FROM chunk WHERE version_id IN ({m})", part)  # noqa: S608
            store.x(f"DELETE FROM context_chunk WHERE version_id IN ({m})", part)  # noqa: S608
            store.x(f"DELETE FROM fact WHERE version_id IN ({m})", part)  # noqa: S608
            store.x(f"DELETE FROM document WHERE version_id IN ({m})", part)  # noqa: S608
            store.x(f"DELETE FROM job WHERE version_id IN ({m})", part)  # noqa: S608
            refs = [f"version:{v}" for v in part]
            rm = placeholders(len(refs))
            store.x(
                f"DELETE FROM relation WHERE src IN ({rm}) OR dst IN ({rm})",  # noqa: S608
                refs + refs,
            )
            gone = [v for v in part if v not in kept_vids]
            if gone:
                store.x(f"DELETE FROM version WHERE id IN ({placeholders(len(gone))})", gone)  # noqa: S608
            keep = [v for v in part if v in kept_vids]
            if keep:  # the opening and the digest only
                store.x(
                    f"UPDATE version SET blob = NULL, extra = NULL"  # noqa: S608
                    f" WHERE id IN ({placeholders(len(keep))})",
                    keep,
                )


def _remove_items(index: LocalIndex, sid: str, kept_items: set) -> int:
    """Delete the items of a source. A kept item (a finding uses it) keeps its
    row with no path. Return the count of deleted items."""
    store = index.store
    items = [r[0] for r in store.q("SELECT id FROM item WHERE source_id = ?", (sid,))]
    has_override = (
        store.one("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kind_override'")
        is not None
    )
    removed = 0
    for part in _chunks(items):
        with store.transaction():
            refs = [f"item:{i}" for i in part]
            rm = placeholders(len(refs))
            store.x(
                f"DELETE FROM relation WHERE src IN ({rm}) OR dst IN ({rm})",  # noqa: S608
                refs + refs,
            )
            gone = [i for i in part if i not in kept_items]
            if gone:
                gm = placeholders(len(gone))
                if has_override:
                    store.x(f"DELETE FROM kind_override WHERE item_id IN ({gm})", gone)  # noqa: S608
                store.x(f"DELETE FROM item WHERE id IN ({gm})", gone)  # noqa: S608
                removed += len(gone)
            keep = [i for i in part if i in kept_items]
            if keep:
                store.x(
                    f"UPDATE item SET path = NULL, present = 0,"  # noqa: S608
                    f" removed_at = coalesce(removed_at, ?) WHERE id IN ({placeholders(len(keep))})",
                    [index.now(), *keep],
                )
    return removed


def _remove_source_rows(store: IndexStore, sid: str, *, keep_row: bool) -> None:
    """Delete the checkpoint, the status, and the source row. With `keep_row`,
    the source row stays with no config (kept items need it)."""
    with store.transaction():
        store.x("DELETE FROM checkpoint WHERE source_id = ?", (sid,))
        store.x("DELETE FROM status WHERE key LIKE ?", (f"%:{sid}",))
        if not keep_row:
            store.x("DELETE FROM source_state WHERE source_id = ?", (sid,))
            store.x("DELETE FROM source WHERE id = ?", (sid,))
        else:
            # The kept items need their source row (a foreign key). It stays
            # with no config and no name, in the state `removing`; no list
            # shows it, and no scan reads it.
            store.x(
                "UPDATE source SET config = ?, label = '', prefs = '{}', error = NULL WHERE id = ?",
                ('{"kind": "removed"}', sid),
            )


def _revoke_unused_account(index: LocalIndex, sid: str, account_id: str | None) -> bool:
    """Revoke the account of a removed source if no other source uses it.
    Return True if the account was revoked."""
    if account_id is None:
        return False
    others = index.store.one(
        "SELECT count(*) FROM source_state WHERE account_id = ? AND source_id != ? AND status != ?",
        (account_id, sid, ss.REMOVING),
    )[0]
    credentials = getattr(index, "credentials", None)
    if others or credentials is None:
        return False
    try:
        return bool(credentials.revoke(account_id))
    except Exception as exc:  # the local token is gone; the UI says where to remove access
        log.warning("revoke after a source removal failed: %s", type(exc).__name__)
        return False
