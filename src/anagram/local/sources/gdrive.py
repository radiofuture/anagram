"""Google Drive source (`gdrive`, contract v2). Read-only.

Config (no secret):

    {"kind": "gdrive", "account": "<account id>",
     "include": {"folders": [...], "shared_drives": [...], "my_drive": false},
     "types": "documents", "max_mb": 50}

The person selects folders, shared drives, or all of My Drive. "Shared with
me" files that are in no selected folder are not read.

One `sync` call:

1. First call: take the changes token (`changes/startPageToken`) before the
   first read, so changes during the backfill are not lost. Read the folder
   map (`{folder id: parent}`) and the ID of the My Drive root.
2. Live step (each call, cheap): `changes.list` from the stored token. One
   call when nothing changed. A removed, trashed, or moved-out file gives a
   `Delete`. A folder that moves into or out of the selection gives a
   targeted listing of its tree.
3. Backfill, newest first (`orderBy=modifiedTime desc`), one page of 1 000
   files for each `Cursor`. 50 000 files are 50 list calls.
4. Reconcile, only after the changes token expired: a new token and a new
   backfill; at the end, each known key that the listing did not give is a
   `Delete`.

Content: a binary file is `files/{id}?alt=media`. A Google Doc is exported
as Markdown, a Sheet as `.xlsx`, Slides as `.pptx`. The export limit is
10 MB. A file that is too large, that the owner does not permit to download,
or whose export fails is a skipped item (counted in the progress note).

An access token goes only to `www.googleapis.com` (`CredentialStore`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from anagram.core.crypto.chunked import hash_bytes
from anagram.local.index.media import DOCX, OCTET, PPTX, XLSX, sniff_bytes
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
)
from anagram.local.sources.google import GoogleApi
from anagram.local.sources.http import RateLimiter, SourceFault
from anagram.local.sources.sync import (
    BATCH_MAX,
    Cursor,
    Delete,
    Note,
    SyncContext,
    Upsert,
    copy_cursor_state,
)
from anagram.local.understanding import third_party

log = logging.getLogger("anagram.local.index")

DRIVE = "https://www.googleapis.com/drive/v3"
FOLDER = "application/vnd.google-apps.folder"
GDOC = "application/vnd.google-apps.document"
GSHEET = "application/vnd.google-apps.spreadsheet"
GSLIDES = "application/vnd.google-apps.presentation"
# Google type -> (export type, file name suffix). Google Docs export to
# Markdown since 2024 (verify with a live check); the fallback is plain text.
EXPORTS = {
    GDOC: ("text/markdown", ".md"),
    GSHEET: (XLSX, ".xlsx"),
    GSLIDES: (PPTX, ".pptx"),
}
EXPORT_FALLBACK = {GDOC: ("text/plain", ".txt")}
SUFFIXES = dict([*EXPORTS.values(), *EXPORT_FALLBACK.values()])
EXPORT_MAX = 10 * 1024 * 1024
DOCUMENT_TYPES = frozenset(
    {
        GDOC,
        GSHEET,
        GSLIDES,
        "application/pdf",
        DOCX,
        PPTX,
        XLSX,
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
        "application/rtf",
        "text/markdown",
        "text/x-markdown",
        "text/plain",
        "text/csv",
        "text/tab-separated-values",
        "application/x-ipynb+json",
    }
)
TYPES = ("documents", "all")
PAGE = 1000
BATCH_BYTES = 64 * 1024 * 1024  # bytes of upserts between two cursors
FILE_FIELDS = (
    "id,name,mimeType,modifiedTime,size,parents,driveId,trashed,webViewLink,"
    "owners(emailAddress),lastModifyingUser(emailAddress),capabilities(canDownload)"
)
MY_DRIVE = "my_drive"
MAX_DEPTH = 100
RATE_PER_S = 10.0  # requests each second for one person (verify the project quota)


def _rfc3339_ns(value: str | None) -> int | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(dt.timestamp() * 1_000_000_000)


def check_include(include: object) -> dict:
    """A clean `include` value. Each ID is a short text."""
    if not isinstance(include, Mapping):
        raise ConnectorError("include must be an object")
    out = {"folders": [], "my_drive": bool(include.get("my_drive", False)), "shared_drives": []}
    for key in ("folders", "shared_drives"):
        values = include.get(key) or []
        if not isinstance(values, list) or not all(
            isinstance(v, str) and 0 < len(v) <= 200 for v in values
        ):
            raise ConnectorError(f"include.{key} must be a list of IDs")
        out[key] = sorted(set(values))
    if not (out["folders"] or out["shared_drives"] or out["my_drive"]):
        raise ConnectorError("select one folder or drive")
    return out


class GoogleDriveConnector(Connector):
    kind = "gdrive"
    label = "Google Drive"
    auth: ClassVar[str] = "oauth"
    provider: ClassVar[str] = "google"
    refetchable: ClassVar[bool] = True
    rate: ClassVar[float] = RATE_PER_S

    def __init__(
        self,
        account: str,
        include: dict,
        *,
        types: str = "documents",
        max_mb: int = 50,
        ctx: SourceContext | None = None,
    ) -> None:
        if types not in TYPES:
            raise ConnectorError(f"unknown types value: {types}")
        if not isinstance(max_mb, int) or not 1 <= max_mb <= 50:
            raise ConnectorError("max_mb must be 1 to 50")
        self.account = account
        self.include = check_include(include)
        self.types = types
        self.max_mb = max_mb
        self._ctx = ctx
        self._api: GoogleApi | None = None

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> GoogleDriveConnector:
        return cls(
            cfg["account"],
            cfg.get("include") or {},
            types=cfg.get("types", "documents"),
            max_mb=cfg.get("max_mb", 50),
            ctx=ctx,
        )

    def config(self) -> dict:
        return {
            "account": self.account,
            "include": self.include,
            "kind": self.kind,
            "max_mb": self.max_mb,
            "types": self.types,
        }

    def describe(self) -> str:
        return "Google Drive"

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise ConnectorError("use sync")

    @property
    def api(self) -> GoogleApi:
        if self._api is None:
            self._api = GoogleApi.open(self._ctx, self.account, RateLimiter(self.rate, self.rate))
        return self._api

    # ----------------------------------------------------------- selection

    def _selected(self, f: dict, folders: dict, root: str | None) -> str | None:
        """The top selected folder or drive of a file (the project node), or
        None if the file is not in the selection."""
        drive = f.get("driveId")
        if drive and drive in self.include["shared_drives"]:
            return drive
        chosen = set(self.include["folders"])
        parents = f.get("parents") or []
        top = None
        seen = 0
        node = parents[0] if parents else None
        while node is not None and seen < MAX_DEPTH:
            if node in chosen:
                top = node  # keep the highest selected folder
            if self.include["my_drive"] and root is not None and node == root and not drive:
                return top or MY_DRIVE
            node = folders.get(node)
            seen += 1
        return top

    def _wanted_type(self, mime: str) -> bool:
        if mime == FOLDER:
            return False
        if self.types == "all":
            return not mime.startswith("application/vnd.google-apps.") or mime in EXPORTS
        return mime in DOCUMENT_TYPES

    # ---------------------------------------------------------------- sync

    def sync(self, ctx: SyncContext) -> Iterator:
        state = dict(ctx.state) if ctx.state.get("v") == 1 else {}
        if ctx.state.get("reset"):
            # The selection changed: read it again and delete what left it.
            state = {}
            yield from self._reconcile_start(state)
        elif not state:
            state = self._start({"v": 1})
            yield Note(phase="first_sync")
            yield Cursor(dict(state))
        # The live step first: it is one call when nothing changed.
        try:
            yield from self._live(ctx, state)
        except SourceFault as exc:
            if exc.code == "cursor_expired":
                yield from self._reconcile_start(state)
            else:
                raise
        if not state["backfill"]["done"]:
            yield from self._backfill(ctx, state)

    def _start(self, state: dict) -> dict:
        token = self.api.json(f"{DRIVE}/changes/startPageToken", {"supportsAllDrives": "true"})
        state["start_token"] = token["startPageToken"]
        state["page_token"] = token["startPageToken"]
        state["backfill"] = {"done": False, "n": 0, "page": None}
        state.update(self._folder_map())
        return state

    def _folder_map(self) -> dict:
        folders: dict[str, str | None] = {}
        page = None
        while True:
            params = {
                "corpora": "allDrives",
                "fields": "nextPageToken,files(id,parents,driveId)",
                "includeItemsFromAllDrives": "true",
                "pageSize": PAGE,
                "q": f"mimeType='{FOLDER}' and trashed=false",
                "supportsAllDrives": "true",
            }
            if page:
                params["pageToken"] = page
            body = self.api.json(f"{DRIVE}/files", params)
            for f in body.get("files") or []:
                parents = f.get("parents") or []
                folders[f["id"]] = parents[0] if parents else None
            page = body.get("nextPageToken")
            if not page:
                break
        root = None
        if self.include["my_drive"]:
            root = self.api.json(f"{DRIVE}/files/root", {"fields": "id"})["id"]
        return {"folders": folders, "root": root, "folders_at": time.time()}

    def _reconcile_start(self, state: dict) -> Iterator:
        """The changes token expired: a new token, a new folder map, and a
        new backfill. The keys that the backfill does not give are deleted
        at its end."""
        new = self._start({"v": 1})
        new["backfill"]["reconcile"] = True
        new["seen"] = []
        state.clear()
        state.update(new)
        yield Note(phase="reconcile")
        yield Cursor(dict(state))

    def _list_params(self, page: str | None) -> dict:
        params = {
            "corpora": "allDrives",
            "fields": f"nextPageToken,files({FILE_FIELDS})",
            "includeItemsFromAllDrives": "true",
            "orderBy": "modifiedTime desc",
            "pageSize": PAGE,
            "q": f"trashed=false and mimeType!='{FOLDER}'",
            "supportsAllDrives": "true",
        }
        if page:
            params["pageToken"] = page
        return params

    def _backfill(self, ctx: SyncContext, state: dict) -> Iterator:
        """One list page of 1 000 files at a time. Inside a page, a `Cursor`
        comes after each 200 upserts or 64 MB of bytes (`offset` is the
        position in the page), so a batch stays small."""
        bf = state["backfill"]
        reconcile = bool(bf.get("reconcile"))
        phase = "reconcile" if reconcile else "first_sync"
        while not bf["done"]:
            body = self.api.json(f"{DRIVE}/files", self._list_params(bf.get("page")))
            files = body.get("files") or []
            n, size, oldest = 0, 0, None
            for i in range(int(bf.get("offset", 0)), len(files)):
                f = files[i]
                project = self._selected(f, state["folders"], state.get("root"))
                if project is None:
                    continue
                if reconcile:
                    state["seen"].append(f["id"])
                change, skip = self._upsert(ctx, f, project)
                bf["skipped"] = bf.get("skipped", 0) + skip
                bf["n"] += 1
                oldest = f.get("modifiedTime") or oldest
                if change is None:
                    continue
                yield change
                n += 1
                size += len(change.item.data or b"")
                if n >= BATCH_MAX or size >= BATCH_BYTES:
                    bf["offset"] = i + 1
                    yield Note(phase=phase, done=bf["n"], at=oldest, skipped=bf["skipped"])
                    yield Cursor(copy_cursor_state(state, ("backfill", "folders")))
                    n, size = 0, 0
            bf["page"] = body.get("nextPageToken")
            bf["offset"] = 0
            if not bf["page"]:
                bf["done"] = True
                if reconcile:
                    seen = set(state.pop("seen", []))
                    for key in list(ctx.known_keys("")):
                        if key not in seen:
                            yield Delete(key)
                    bf.pop("reconcile", None)
            yield Note(phase=phase, done=bf["n"], at=oldest, skipped=bf.get("skipped", 0))
            yield Cursor(copy_cursor_state(state, ("backfill", "folders")))
            if ctx.stop() or time.monotonic() > ctx.deadline:
                return
        yield Note(phase="live")

    def _live(self, ctx: SyncContext, state: dict) -> Iterator:
        token = state["page_token"]
        while True:
            try:
                body = self.api.json(
                    f"{DRIVE}/changes",
                    {
                        "fields": f"nextPageToken,newStartPageToken,changes(fileId,removed,file({FILE_FIELDS}))",
                        "includeItemsFromAllDrives": "true",
                        "includeRemoved": "true",
                        "pageSize": PAGE,
                        "pageToken": token,
                        "supportsAllDrives": "true",
                    },
                )
            except SourceFault as exc:
                if exc.status in (400, 404, 410) and exc.code in ("not_found", "unknown"):
                    raise SourceFault("cursor_expired", "the changes token expired") from None
                raise
            changes = body.get("changes") or []
            n, size = 0, 0
            for i in range(int(state.get("page_offset", 0)), len(changes)):
                for change in self._change(ctx, state, changes[i]):
                    yield change
                    if isinstance(change, Upsert):
                        n += 1
                        size += len(change.item.data or b"")
                if n >= BATCH_MAX or size >= BATCH_BYTES:
                    # A cursor inside the page: the next call starts after
                    # this change, so a batch stays small.
                    state["page_offset"] = i + 1
                    yield Cursor(copy_cursor_state(state, ("backfill", "folders")))
                    n, size = 0, 0
            nxt = body.get("nextPageToken")
            token = nxt or body.get("newStartPageToken") or token
            state["page_token"] = token
            state["page_offset"] = 0
            yield Cursor(copy_cursor_state(state, ("backfill", "folders")))
            if not nxt:
                return

    def _change(self, ctx: SyncContext, state: dict, ch: dict) -> Iterator:
        fid = ch.get("fileId")
        f = ch.get("file") or {}
        folders = state["folders"]
        if f.get("mimeType") == FOLDER or fid in folders:
            yield from self._folder_change(ctx, state, fid, f, bool(ch.get("removed")))
            return
        if ch.get("removed") or f.get("trashed"):
            yield Delete(fid)
            return
        project = self._selected(f, folders, state.get("root"))
        if project is None:
            yield Delete(fid)  # moved out of the selection; unknown keys change nothing
            return
        change, skip = self._upsert(ctx, f, project)
        if skip:
            state["backfill"]["skipped"] = state["backfill"].get("skipped", 0) + skip
        if change is not None:
            yield change

    def _folder_change(self, ctx, state, fid, f, removed) -> Iterator:
        folders = state["folders"]
        root = state.get("root")
        probe = {"driveId": f.get("driveId"), "parents": [fid]}
        before = self._selected(probe, folders, root)
        if removed or f.get("trashed"):
            folders.pop(fid, None)
        else:
            parents = f.get("parents") or []
            folders[fid] = parents[0] if parents else None
        after = None if (removed or f.get("trashed")) else self._selected(probe, folders, root)
        if before == after:
            return
        # The folder moved into or out of the selection: read its tree.
        for child in self._tree(fid, depth=0):
            if child.get("mimeType") == FOLDER:
                continue
            if after is None or child.get("trashed"):
                yield Delete(child["id"])
            else:
                change, _ = self._upsert(ctx, child, after)
                if change is not None:
                    yield change

    def _tree(self, folder: str, depth: int) -> Iterator[dict]:
        if depth > MAX_DEPTH:
            return
        page = None
        while True:
            params = {
                "corpora": "allDrives",
                "fields": f"nextPageToken,files({FILE_FIELDS})",
                "includeItemsFromAllDrives": "true",
                "pageSize": PAGE,
                # Also trashed files: the children of a trashed folder are trashed.
                "q": f"'{folder}' in parents",
                "supportsAllDrives": "true",
            }
            if page:
                params["pageToken"] = page
            body = self.api.json(f"{DRIVE}/files", params)
            for f in body.get("files") or []:
                yield f
                if f.get("mimeType") == FOLDER:
                    yield from self._tree(f["id"], depth + 1)
            page = body.get("nextPageToken")
            if not page:
                return

    # ------------------------------------------------------------- content

    def _upsert(self, ctx: SyncContext, f: dict, project: str) -> tuple[Upsert | None, int]:
        """`(change, skipped)`: an `Upsert`, or None for a file that did not
        change or that is left out (`skipped` = 1 for a file that a limit or
        the owner left out)."""
        mime = f.get("mimeType") or OCTET
        if not self._wanted_type(mime):
            return None, 0
        mtime = _rfc3339_ns(f.get("modifiedTime"))
        size = int(f["size"]) if f.get("size") is not None else None
        known = ctx.known(f["id"])
        if known is not None and known.mtime_ns == mtime and (size is None or known.size == size):
            return None, 0
        if size is not None and size > self.max_mb * 1024 * 1024:
            return None, 1
        if (f.get("capabilities") or {}).get("canDownload") is False:
            return None, 1
        try:
            data, media_type, export_type = self._content(f["id"], mime, f.get("name") or "")
        except SourceFault as exc:
            if exc.code in ("permission_lost", "not_found", "too_large") or exc.status == 403:
                return None, 1  # a fault of one item, not of the source
            raise
        name = f.get("name") or f["id"]
        suffix = SUFFIXES.get(export_type) if export_type else None
        if suffix and not name.endswith(suffix):
            name += suffix
        owners = [o.get("emailAddress") for o in f.get("owners") or [] if o.get("emailAddress")]
        me = getattr(self.api, "email", None)
        extra = {
            "fetch": {"export": export_type, "id": f["id"]},
            "owners": owners,
            "parents": list(f.get("parents") or []),
            "project": f"gdrive:{project}",
            "url": f.get("webViewLink"),
        }
        # A file with owners that do not include the member is the text of
        # another person. With no known address of the member, the file is
        # third-party (fail closed). A file in a shared drive has no owner:
        # it is lab work and stays own text (threat model section 16).
        if owners and not (me and me.lower() in (o.lower() for o in owners)):
            extra[third_party.MARK] = True
            name = third_party.shared_file_name(f.get("modifiedTime"), Path(name).suffix)
        item = EvidenceItem(
            key=f["id"],
            kind="gdrive_file",
            name=name,
            media_type=media_type,
            digest=hash_bytes(data),
            ref=f"gdrive:{f['id']}",
            mtime_ns=mtime,
            time=f.get("modifiedTime"),
            data=data,
            extra=extra,
        )
        return Upsert(item), 0

    def _content(self, fid: str, mime: str, name: str) -> tuple[bytes, str, str | None]:
        """`(bytes, media type, export type or None)`."""
        export = EXPORTS.get(mime)
        if export is None:
            data = self.api.get(
                f"{DRIVE}/files/{fid}", {"alt": "media", "supportsAllDrives": "true"}
            ).body
            return data, (sniff_bytes(data, name) if data else mime), None
        targets = [export[0]] + ([EXPORT_FALLBACK[mime][0]] if mime in EXPORT_FALLBACK else [])
        for i, target in enumerate(targets):
            try:
                data = self.api.get(f"{DRIVE}/files/{fid}/export", {"mimeType": target}).body
            except SourceFault as exc:
                if exc.status == 400 and i + 1 < len(targets):
                    continue  # the export type is refused: try the fallback
                raise
            if len(data) > EXPORT_MAX:
                raise SourceFault("too_large", "the export is larger than the limit")
            return data, target, target
        raise SourceFault("unknown", "no export type was accepted")

    def can_refetch(self, extra: dict) -> bool:
        """An export is not byte-stable, so its bytes stay in the store."""
        return not (extra.get("fetch") or {}).get("export")

    def fetch(self, key: str, extra: dict) -> bytes:
        fetch = extra.get("fetch") or {}
        if fetch.get("export"):
            return self.api.get(f"{DRIVE}/files/{key}/export", {"mimeType": fetch["export"]}).body
        return self.api.get(
            f"{DRIVE}/files/{key}", {"alt": "media", "supportsAllDrives": "true"}
        ).body

    # ------------------------------------------------------- setup screen

    @classmethod
    def choices(cls, ctx: SourceContext, account, parent: str | None) -> dict:
        """Folders for the folder tree. With no parent: My Drive and the
        shared drives. With a parent: its folders."""
        api = GoogleApi.open(ctx, account.id, RateLimiter(cls.rate, cls.rate))
        items = []
        if parent is None:
            items.append(
                {"has_children": True, "id": MY_DRIVE, "name": "My Drive", "type": "my_drive"}
            )
            page = None
            while True:
                params = {"fields": "nextPageToken,drives(id,name)", "pageSize": 100}
                if page:
                    params["pageToken"] = page
                body = api.json(f"{DRIVE}/drives", params)
                for d in body.get("drives") or []:
                    items.append(
                        {
                            "has_children": True,
                            "id": d["id"],
                            "name": d.get("name") or "",
                            "type": "shared_drive",
                        }
                    )
                page = body.get("nextPageToken")
                if not page:
                    break
            return {"items": items}
        folder = "root" if parent == MY_DRIVE else parent
        page = None
        while True:
            params = {
                "corpora": "allDrives",
                "fields": "nextPageToken,files(id,name)",
                "includeItemsFromAllDrives": "true",
                "orderBy": "name",
                "pageSize": PAGE,
                "q": f"'{folder}' in parents and mimeType='{FOLDER}' and trashed=false",
                "supportsAllDrives": "true",
            }
            if page:
                params["pageToken"] = page
            body = api.json(f"{DRIVE}/files", params)
            for f in body.get("files") or []:
                items.append(
                    {
                        "has_children": True,
                        "id": f["id"],
                        "name": f.get("name") or "",
                        "type": "folder",
                    }
                )
            page = body.get("nextPageToken")
            if not page:
                break
        return {"items": items}

    @classmethod
    def preview(cls, ctx: SourceContext, cfg: dict) -> dict:
        """Drive gives no cheap count for a folder tree."""
        return {"estimate": None, "of": None}
