"""The scan of the local index: evidence for the items that a source gives.

    index.scan()                                   # each source, then the jobs
    index.scanner.scan_source(sid, report)         # one source, no jobs
    index.scanner.apply_item(sid, kind, item, prev, now, t, report)

`Scanner` is the part `LocalIndex.scanner`. A contract v1 source gives all
its items (`Connector.scan`); a contract v2 source gives changes with a
cursor (`SyncEngine`, which writes with `apply_item` and `apply_removed`).
Each new or changed item gets a version with a salted evidence record
(`anagram.evidence.v1`) and a `convert` job. The scan of one source writes in
one transaction. The structural relations (`version_of`, `duplicate_of`,
`same_project`) are written in the same transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from anagram.core.timefmt import format_time
from anagram.local.index import jobs
from anagram.local.index.store import dumps, loads
from anagram.local.sources import EvidenceItem, KnownItem, source_state
from anagram.local.sources.http import SourceFault
from anagram.local.sources.sync import is_sync_source
from anagram.proofs.records import evidence_fields, evidence_opening

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex


@dataclass
class ScanReport:
    new: list[tuple[str, str]] = field(default_factory=list)  # (source_id, key)
    changed: list[tuple[str, str]] = field(default_factory=list)
    unchanged: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (source_id, message)
    # Contract v2 sources that stopped at their time limit: scan them again soon.
    more: list[str] = field(default_factory=list)

    def changes(self) -> int:
        """The count of new, changed, and removed items."""
        return len(self.new) + len(self.changed) + len(self.removed)


class Scanner:
    """The scan part of one `LocalIndex`."""

    def __init__(self, index: LocalIndex) -> None:
        self.index = index
        self.store = index.store

    def item_rows(self, sid: str) -> dict[str, object]:
        return {r["key"]: r for r in self.store.q("SELECT * FROM item WHERE source_id = ?", (sid,))}

    def record_fault(self, sid: str, exc: Exception) -> None:
        """Record the fault of a contract v1 scan in the source state, so the
        person sees one fault model for all kinds. A v1 scan is tried again
        at each cycle; the next scan with no fault clears it."""
        if isinstance(exc, SourceFault):
            code, retry_at = exc.code, exc.retry_at
        elif isinstance(exc, FileNotFoundError | NotADirectoryError):
            code, retry_at = "not_found", None
        elif isinstance(exc, OSError):
            code, retry_at = "offline", None
        else:
            code, retry_at = "unknown", None
        clock = self.index.clock
        try:
            source_state.set_fault(
                self.store,
                sid,
                code,
                type(exc).__name__,
                now=clock(),
                retry_at=retry_at,
                publish=source_state.publisher(self.store, clock),
            )
        except source_state.SourceStateError:
            pass  # the source is being removed, or it is gone

    def scan_source(self, sid: str, report: ScanReport, full: bool = False) -> None:
        """Scan one source into `report`. With `full`, hash each file again."""
        index = self.index
        src = index.source(sid)
        state = source_state.read(self.store, sid)
        if state is not None and (state.paused or state.stored_status == source_state.REMOVING):
            return
        conn = index.connector(sid)
        if is_sync_source(conn):  # contract v2: changes with a cursor
            from anagram.local.sources.sync_engine import SyncEngine

            if SyncEngine(index).run(sid, report).more:
                report.more.append(sid)
            return
        t = self._scan_all(sid, src, conn, report, full)
        self.after_scan(sid)
        if state is not None and (
            state.error_code is not None or state.stored_status == source_state.FIRST_SYNC
        ):
            source_state.set_status(
                self.store,
                sid,
                source_state.LIVE,
                now=t,
                publish=source_state.publisher(self.store, index.clock),
            )

    def _scan_all(self, sid: str, src: dict, conn, report: ScanReport, full: bool) -> float:
        """A contract v1 scan: all items of the source in one transaction.
        Give the clock time of the scan."""
        old = self.item_rows(sid)
        known = {
            k: KnownItem(
                loads(v["digest"]), loads(v["digest"])["size"], _ns(v["mtime_ns"]), v["media_type"]
            )
            for k, v in old.items()
            if v["present"]
        }
        if full:  # no size and mtime shortcut
            known = {k: KnownItem(v.digest, -1, None, None) for k, v in known.items()}
        seen: set[str] = set()
        source_kind = src["config"]["kind"]
        now, t = self.index.now(), self.index.clock()
        new_items: list[int] = []
        # Read and hash outside the write transaction, so another process (the
        # UI or the helper) can use the store while a large source is hashed.
        scanned = list(conn.scan(known))
        before = report.changes()
        with self.store.transaction():
            for item in scanned:
                seen.add(item.key)
                item_id = self.apply_item(sid, source_kind, item, old.get(item.key), now, t, report)
                if item_id is not None:
                    new_items.append(item_id)
            for key, rec in old.items():
                if key not in seen and rec["present"]:
                    self.apply_removed(sid, rec["id"], key, now, report)
            if new_items:
                self.project_relations(sid, src["config"], new_items, now)
            self.mark_scanned(sid, now, report.changes() > before)
        return t

    def after_scan(self, sid: str) -> None:
        """The work of a source kind on the index after a scan or after its
        jobs (for example the link relations of a vault). A connector with a
        method `after_scan(index, sid)` gets the call."""
        hook = getattr(self.index.connector(sid), "after_scan", None)
        if callable(hook):
            hook(self.index, sid)

    def mark_scanned(self, sid: str, now: str, changed: bool) -> None:
        self.store.x(
            "UPDATE source SET last_scan_at = ?,"
            " last_change_at = CASE WHEN ? THEN ? ELSE last_change_at END WHERE id = ?",
            (now, changed, now, sid),
        )

    def apply_item(
        self,
        sid: str,
        source_kind: str,
        item: EvidenceItem,
        prev,
        now: str,
        t: float,
        report: ScanReport,
    ) -> int | None:
        """Write one item that a source gave: a new item, a new version, or
        nothing when the digest is that of the current version. `prev` is the
        `item` row with this key, or None. The caller holds the transaction.
        Return the item ID when a version was made, else None."""
        digest = dumps(item.digest.to_json())
        if prev is not None and prev["present"] and prev["digest"] == digest:
            if prev["mtime_ns"] != _ns_text(item.mtime_ns):
                self.store.x(
                    "UPDATE item SET mtime_ns = ? WHERE id = ?",
                    (_ns_text(item.mtime_ns), prev["id"]),
                )
            report.unchanged.append((sid, item.key))
            return None
        item_id, n = self._write_item(sid, item, prev, digest, now)
        vid = self._write_version(sid, source_kind, item, item_id, n, digest, now)
        self._structural_relations(item_id, vid, n, item.digest.digest.hex(), now)
        jobs.enqueue(self.store, jobs.CONVERT, vid, sid, t)
        (report.changed if prev is not None else report.new).append((sid, item.key))
        return item_id

    def _write_item(
        self, sid: str, item: EvidenceItem, prev, digest: str, now: str
    ) -> tuple[int, int]:
        """Insert or update the `item` row. Give (item ID, next version number)."""
        fields = (
            item.kind,
            item.name,
            item.media_type,
            item.ref,
            str(item.path) if item.path else None,
            _ns_text(item.mtime_ns),
            item.time or _mtime(item.mtime_ns),
            digest,
            now,
        )
        if prev is None:
            item_id = self.store.x(
                "INSERT INTO item (kind, name, media_type, ref, path, mtime_ns, time,"
                " digest, seen_at, present, source_id, key)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (*fields, sid, item.key),
            ).lastrowid
            return item_id, 1
        item_id = prev["id"]
        self.store.x(
            "UPDATE item SET kind = ?, name = ?, media_type = ?, ref = ?, path = ?,"
            " mtime_ns = ?, time = ?, digest = ?, seen_at = ?, present = 1,"
            " removed_at = NULL WHERE id = ?",
            (*fields, item_id),
        )
        n = self.store.one(
            "SELECT coalesce(max(n), 0) + 1 FROM version WHERE item_id = ?",
            (item_id,),
        )[0]
        return item_id, n

    def _write_version(
        self,
        sid: str,
        source_kind: str,
        item: EvidenceItem,
        item_id: int,
        n: int,
        digest: str,
        now: str,
    ) -> int:
        """Insert version `n` with its salted evidence opening. Give its ID."""
        opening = evidence_opening(
            evidence_fields(item.digest, item.media_type, item.name, source_kind)
        )
        return self.store.x(
            "INSERT INTO version (item_id, source_id, n, digest, digest_hex, media_type,"
            " root, opening, blob, extra, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?)",
            (
                item_id,
                sid,
                n,
                digest,
                item.digest.digest.hex(),
                item.media_type,
                opening.root().hex(),
                dumps(opening.to_json()),
                item.data,
                dumps(item.extra) if item.extra else None,
                now,
            ),
        ).lastrowid

    def apply_removed(self, sid: str, item_id: int, key: str, now: str, report: ScanReport) -> None:
        """Mark one item as removed from its source. Its records stay."""
        self.store.x(
            "UPDATE item SET present = 0, removed_at = ? WHERE id = ?",
            (now, item_id),
        )
        report.removed.append((sid, key))

    # ---------------------------------------------------------- relations

    def _structural_relations(
        self, item_id: int, vid: int, n: int, digest_hex: str, now: str
    ) -> None:
        relate = self.index.relate
        if n > 1:
            prev = self.store.one(
                "SELECT id FROM version WHERE item_id = ? AND n = ?", (item_id, n - 1)
            )
            if prev is not None:
                relate("version_of", f"version:{vid}", f"version:{prev[0]}", now)
        dup = self.store.one(
            "SELECT v.item_id FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE v.digest_hex = ? AND v.item_id != ? AND i.present = 1"
            " ORDER BY v.id LIMIT 1",
            (digest_hex, item_id),
        )
        if dup is not None:
            relate("duplicate_of", f"item:{item_id}", f"item:{dup[0]}", now)

    def project_relations(self, sid: str, cfg: dict, item_ids: list[int], now: str) -> None:
        """`same_project`: each item -> one project node. A Git repository is a
        project (for its commits and for the files in its folder); else the
        top folder under the source root."""
        kind = cfg.get("kind")
        if kind == "git":
            for iid in item_ids:
                self.index.relate("same_project", f"item:{iid}", f"project:git:{cfg['repo']}", now)
        elif kind == "folder":
            self._folder_projects(sid, Path(cfg["root"]), item_ids, now)
        else:
            for iid in item_ids:
                self._cloud_relations(sid, iid, now)

    def _cloud_relations(self, sid: str, iid: int, now: str) -> None:
        """A cloud source names the project in the item (`extra.project`, for
        example the top selected Drive folder) and can give more relations
        (`extra.relations`: [kind, node] pairs)."""
        relate = self.index.relate
        row = self.store.one(
            "SELECT extra FROM version WHERE item_id = ? ORDER BY n DESC LIMIT 1", (iid,)
        )
        extra = (loads(row["extra"]) if row is not None and row["extra"] else None) or {}
        if isinstance(extra.get("project"), str):
            relate("same_project", f"item:{iid}", f"project:{extra['project']}", now)
        for rel in extra.get("relations") or []:
            if not (
                isinstance(rel, list) and len(rel) == 2 and all(isinstance(x, str) for x in rel)
            ):
                continue
            dst = rel[1]
            if dst.startswith("key:"):
                # `key:<key>`: another item of the same source.
                other = self.store.one(
                    "SELECT id FROM item WHERE source_id = ? AND key = ?", (sid, dst[4:])
                )
                if other is None:
                    continue
                dst = f"item:{other['id']}"
            relate(rel[0], f"item:{iid}", dst, now)

    def _folder_projects(self, sid: str, root: Path, item_ids: list[int], now: str) -> None:
        conn = self.index.connector(sid)
        repos = conn.repositories() if hasattr(conn, "repositories") else []
        rel_repos = sorted(
            (r.relative_to(root).as_posix() for r in repos if r != root), key=len, reverse=True
        )
        marks = ",".join("?" for _ in item_ids)
        for iid, ref in self.store.q(
            f"SELECT id, ref FROM item WHERE id IN ({marks})",  # noqa: S608
            item_ids,
        ):
            parts = PurePosixPath(ref).parts
            project = next((f"git:{root / r}" for r in rel_repos if ref.startswith(r + "/")), None)
            if project is None and root in repos:
                project = f"git:{root}"
            if project is None:
                project = f"folder:{root / parts[0]}" if len(parts) > 1 else f"folder:{root}"
            self.index.relate("same_project", f"item:{iid}", f"project:{project}", now)


def _ns_text(mtime_ns: int | None) -> str | None:
    """Nanosecond times are above the JSON safe integer range: store text."""
    return None if mtime_ns is None else str(mtime_ns)


def _ns(text: str | None) -> int | None:
    return None if text is None else int(text)


def _mtime(mtime_ns: int | None) -> str | None:
    if mtime_ns is None:
        return None
    return format_time(datetime.fromtimestamp(mtime_ns // 1_000_000_000, UTC))
