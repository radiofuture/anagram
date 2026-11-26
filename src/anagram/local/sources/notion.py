"""Notion source (`notion`, contract v2). Read-only.

Config (no secret): `{"kind": "notion", "account": "<account id>", "max_depth": 6}`.

The person selects pages in the Notion consent screen. The integration sees
only these pages and their child pages. "Choose pages" starts the sign-in
again, and the source then reads the selection again (cursor `reset`).

API version `2022-06-28` (the version that the code was tested with). One `sync` call:

1. Backfill: `POST /search` for pages, newest edit first, 100 for each call.
   Each page: `GET /blocks/{id}/children` (recursive to `max_depth`; a child
   page is its own item and is not followed). `blocks_to_markdown` writes the
   text. A `Cursor` after each search page.
2. Live: the same search. It stops at the first page edited before
   `edited_after` minus 2 minutes (Notion rounds the time to the minute). A
   page with the same `last_edited_time` as the known item is not read again.
   `edited_after` is the newest `last_edited_time` that the search gave (the
   time of Notion, not of this computer).
3. Deletes: Notion gives no delete events. Once each 24 hours the source lists
   all IDs and deletes each known key that is not there. A page with
   `archived` or `in_trash` is a `Delete` at once.

Each page is one record item (`notion_page`). Files and images keep their
name in the Markdown; the source does not download them (their URLs expire).
"""

from __future__ import annotations

import base64
import dataclasses
import itertools
import json
import time
import urllib.parse
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    record_item,
)
from anagram.local.sources.http import HttpResponse, RateLimiter, SourceFault
from anagram.local.sources.oauth import NOTION
from anagram.local.sources.sync import Cursor, Delete, Note, SyncContext, Upsert, copy_cursor_state

API = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"
RATE_PER_S = 3.0  # the documented average limit of an integration
PAGE = 100
SLACK = timedelta(minutes=2)
IDS_EVERY_S = 24 * 3600.0
MAX_DEPTH = 6
KIND = "notion_page"
_now = time.time  # tests replace this


def _time_ns(value: str | None) -> int | None:
    if not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(t.timestamp()) * 1_000_000_000 + t.microsecond * 1000


# ------------------------------------------------------------------ markdown


def rich_text(parts: list | None) -> str:
    """Notion rich text -> Markdown (bold, italic, code, strike, link)."""
    out = []
    for p in parts or []:
        text = str(p.get("plain_text", ""))
        if not text:
            continue
        a = p.get("annotations") or {}
        if a.get("code"):
            text = f"`{text}`"
        if a.get("bold"):
            text = f"**{text}**"
        if a.get("italic"):
            text = f"*{text}*"
        if a.get("strikethrough"):
            text = f"~~{text}~~"
        href = p.get("href")
        if isinstance(href, str) and href.startswith(("http://", "https://")):
            text = f"[{text}]({href})"
        out.append(text)
    return "".join(out)


def _file_name(value: dict) -> str:
    """The name of a file block. The URL expires, so it is not kept."""
    caption = rich_text(value.get("caption"))
    if caption:
        return caption
    if value.get("name"):
        return str(value["name"])
    url = (value.get(value.get("type", "")) or {}).get("url", "")
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    return urllib.parse.unquote(name) or "file"


def _link_line(t: str, v: dict, text: str, pad: str, n: int) -> list[str]:
    url = v.get("url", "")
    return [f"<{url}>" if url else ""]


def _table_row_line(t: str, v: dict, text: str, pad: str, n: int) -> list[str]:
    cells = [rich_text(c) for c in v.get("cells") or []]
    return ["| " + " | ".join(cells) + " |"]


def _code_lines(t: str, v: dict, text: str, pad: str, n: int) -> list[str]:
    return [f"```{v.get('language', '')}".rstrip(), rich_text(v.get("rich_text")), "```"]


def _file_line(t: str, v: dict, text: str, pad: str, n: int) -> list[str]:
    return [f"[{t}: {_file_name(v)}]"]


def _heading_line(t: str, v: dict, text: str, pad: str, n: int) -> list[str]:
    return ["#" * int(t[-1]) + " " + text]


# The Markdown lines of one block, by block type: f(type, value, text, pad, n),
# where `n` is the number of a numbered list item. Another type gives its text.
_BLOCK_LINES = {
    "paragraph": lambda t, v, text, pad, n: [pad + text if text else ""],
    "heading_1": _heading_line,
    "heading_2": _heading_line,
    "heading_3": _heading_line,
    "bulleted_list_item": lambda t, v, text, pad, n: [f"{pad}- {text}"],
    "numbered_list_item": lambda t, v, text, pad, n: [f"{pad}{n}. {text}"],
    "to_do": lambda t, v, text, pad, n: [f"{pad}- [{'x' if v.get('checked') else ' '}] {text}"],
    "toggle": lambda t, v, text, pad, n: [f"{pad}- {text}"],
    "quote": lambda t, v, text, pad, n: ["> " + text],
    "callout": lambda t, v, text, pad, n: ["> " + text],
    "code": _code_lines,
    "equation": lambda t, v, text, pad, n: [f"$${v.get('expression', '')}$$"],
    "divider": lambda t, v, text, pad, n: ["---"],
    **dict.fromkeys(("image", "file", "pdf", "video", "audio"), _file_line),
    **dict.fromkeys(("bookmark", "embed", "link_preview"), _link_line),
    "child_page": lambda t, v, text, pad, n: [f"[page: {v.get('title', '')}]"],
    "child_database": lambda t, v, text, pad, n: [f"[database: {v.get('title', '')}]"],
    "table_row": _table_row_line,
}

_NESTED_LISTS = ("bulleted_list_item", "numbered_list_item", "to_do", "toggle")


def _children_markdown(t: str, kids: list[dict], depth: int) -> list[str]:
    """The Markdown lines of the children of a block of type `t`. A table
    gets a separator row after its first row; a list item indents them."""
    if t == "table":
        rows = blocks_to_markdown(kids, depth + 1).splitlines()
        if rows:
            cols = rows[0].count("|") - 1
            rows.insert(1, "|" + " --- |" * cols)
        return rows
    return [blocks_to_markdown(kids, depth + 1 if t in _NESTED_LISTS else depth)]


def blocks_to_markdown(blocks: list[dict], depth: int = 0) -> str:
    """Blocks (each with its `children` list) -> Markdown."""
    lines: list[str] = []
    pad = "  " * depth
    n = 0
    for b in blocks:
        t = b.get("type", "")
        v = b.get(t) or {}
        text = rich_text(v.get("rich_text"))
        kids = b.get("children") or []
        n = n + 1 if t == "numbered_list_item" else 0
        line = _BLOCK_LINES.get(t)
        if line is not None:
            lines.extend(line(t, v, text, pad, n))
        elif text:
            lines.append(pad + text)
        if kids:
            lines.extend(_children_markdown(t, kids, depth))
        if depth == 0 and t not in ("bulleted_list_item", "numbered_list_item", "to_do"):
            lines.append("")
    return "\n".join(lines).strip("\n") + ("\n" if depth == 0 else "")


def page_title(page: dict) -> str:
    for prop in (page.get("properties") or {}).values():
        if isinstance(prop, dict) and prop.get("type") == "title":
            return rich_text(prop.get("title")).strip()
    return ""


def page_properties(page: dict) -> dict:
    """The simple values of the properties: text, select, date, people
    names, URL, number, checkbox, status."""
    out = {}
    for name, prop in sorted((page.get("properties") or {}).items()):
        if not isinstance(prop, dict):
            continue
        t, v = prop.get("type"), prop.get(prop.get("type", ""))
        if t in ("title", "rich_text"):
            value = rich_text(v)
        elif t in ("select", "status"):
            value = (v or {}).get("name")
        elif t == "multi_select":
            value = [x.get("name") for x in v or []]
        elif t == "date":
            value = {"end": (v or {}).get("end"), "start": (v or {}).get("start")} if v else None
        elif t == "people":
            value = [x.get("name") for x in v or [] if x.get("name")]
        elif t in ("url", "number", "checkbox", "email", "phone_number"):
            value = v
        else:
            continue
        if value not in (None, "", []):
            out[name] = value
    return out


# ------------------------------------------------------------------- source


class NotionApi:
    def __init__(self, creds, account_id: str, limiter: RateLimiter | None) -> None:
        self.creds, self.account_id, self.limiter = creds, account_id, limiter
        acct = creds.account(account_id)
        if acct is None:
            raise SourceFault("auth_expired", "the account is not there")
        self.workspace = acct.label

    @classmethod
    def open(cls, ctx, account_id: str, limiter: RateLimiter | None = None) -> NotionApi:
        creds = getattr(ctx, "credentials", None) if ctx is not None else None
        if creds is None:
            raise SourceFault("auth_expired", "no credential store")
        return cls(creds, account_id, limiter)

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        headers = {"Notion-Version": NOTION_VERSION, "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        resp = self.creds.request(
            self.account_id, method, API + path, headers, data, limiter=self.limiter
        )
        out = resp.json()
        if not isinstance(out, dict):
            raise SourceFault("unknown", "the answer is not a JSON object")
        return out

    def search(self, cursor: str | None, page_size: int = PAGE) -> dict:
        body = {
            "filter": {"property": "object", "value": "page"},
            "page_size": page_size,
            "sort": {"direction": "descending", "timestamp": "last_edited_time"},
        }
        if cursor:
            body["start_cursor"] = cursor
        return self.call("POST", "/search", body)

    def children(self, block_id: str, depth: int, max_depth: int) -> list[dict]:
        out: list[dict] = []
        cursor = None
        while True:
            q = {"page_size": PAGE, **({"start_cursor": cursor} if cursor else {})}
            body = self.call("GET", f"/blocks/{block_id}/children?{urllib.parse.urlencode(q)}")
            for b in body.get("results") or []:
                t = b.get("type")
                if b.get("has_children") and t not in ("child_page", "child_database"):
                    if depth + 1 < max_depth:
                        b = {**b, "children": self.children(b["id"], depth + 1, max_depth)}
                out.append(b)
            cursor = body.get("next_cursor")
            if not body.get("has_more") or not cursor:
                return out


class NotionConnector(Connector):
    kind = "notion"
    label = "Notion"
    auth: ClassVar[str] = "oauth"
    provider: ClassVar[str] = "notion"
    refetchable: ClassVar[bool] = False  # a record keeps its bytes
    rate: ClassVar[float] = RATE_PER_S

    def __init__(
        self, account: str, *, max_depth: int = MAX_DEPTH, ctx: SourceContext | None = None
    ) -> None:
        if not isinstance(account, str) or not account:
            raise ConnectorError("account is needed")
        if not isinstance(max_depth, int) or not 1 <= max_depth <= 20:
            raise ConnectorError("max_depth must be 1 to 20")
        self.account = account
        self.max_depth = max_depth
        self._ctx = ctx
        self._api: NotionApi | None = None

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> NotionConnector:
        return cls(cfg["account"], max_depth=cfg.get("max_depth", MAX_DEPTH), ctx=ctx)

    def config(self) -> dict:
        return {"account": self.account, "kind": self.kind, "max_depth": self.max_depth}

    def describe(self) -> str:
        return "Notion"

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise ConnectorError("use sync")

    @property
    def api(self) -> NotionApi:
        if self._api is None:
            self._api = NotionApi.open(self._ctx, self.account, RateLimiter(self.rate, self.rate))
        return self._api

    # ---------------------------------------------------------------- sync

    def sync(self, ctx: SyncContext) -> Iterator:
        state = dict(ctx.state) if ctx.state.get("v") == 1 else {}
        if ctx.state.get("reset") or not state:
            reconcile = bool(ctx.state.get("reset")) or ctx.state.get("v") is not None
            state = {
                "backfill": {"cursor": None, "done": False, "n": 0},
                "edited_after": None,
                "ids_at": _now(),
                "v": 1,
            }
            if reconcile:
                state["backfill"]["reconcile"] = True
                state["seen"] = []
            yield Note(phase="reconcile" if reconcile else "first_sync")
            yield Cursor(copy_cursor_state(state))
        if not state["backfill"]["done"]:
            yield from self._backfill(ctx, state)
            return
        yield from self._live(ctx, state)
        if _now() - float(state.get("ids_at") or 0) >= IDS_EVERY_S:
            yield from self._ids(ctx, state)

    def _backfill(self, ctx: SyncContext, state: dict) -> Iterator:
        bf = state["backfill"]
        reconcile = bool(bf.get("reconcile"))
        phase = "reconcile" if reconcile else "first_sync"
        while True:
            body = self.api.search(bf.get("cursor"))
            for page in body.get("results") or []:
                state["edited_after"] = (
                    max(state.get("edited_after") or "", page.get("last_edited_time") or "") or None
                )
                if page.get("archived") or page.get("in_trash"):
                    continue
                if reconcile:
                    state["seen"].append(page["id"])
                change = self._page(ctx, page)
                if change is not None:
                    yield change
                    bf["n"] += 1
                    bf["oldest"] = page.get("last_edited_time")
            bf["cursor"] = body.get("next_cursor") if body.get("has_more") else None
            if not bf["cursor"]:
                bf["done"] = True
                if reconcile:
                    seen = set(state.pop("seen", []))
                    for key in list(ctx.known_keys("")):
                        if key not in seen:
                            yield Delete(key)
                    bf.pop("reconcile", None)
                yield Note(phase=phase, done=bf["n"], at=bf.get("oldest"))
                yield Cursor(copy_cursor_state(state))
                yield Note(phase="live")
                return
            yield Note(phase=phase, done=bf["n"], at=bf.get("oldest"))
            yield Cursor(copy_cursor_state(state))
            if ctx.stop() or time.monotonic() > ctx.deadline:
                return

    def _live(self, ctx: SyncContext, state: dict) -> Iterator:
        after = state.get("edited_after")
        stop_at = None
        if after:
            stop_at = (datetime.fromisoformat(after.replace("Z", "+00:00")) - SLACK).isoformat()
        newest = after or ""
        cursor = None
        while True:
            body = self.api.search(cursor)
            for page in body.get("results") or []:
                edited = page.get("last_edited_time") or ""
                if stop_at is not None and _iso(edited) < stop_at:
                    state["edited_after"] = newest or None
                    yield Cursor(copy_cursor_state(state))
                    return
                newest = max(newest, edited)
                if page.get("archived") or page.get("in_trash"):
                    if ctx.known(page["id"]) is not None:
                        yield Delete(page["id"])
                    continue
                change = self._page(ctx, page)
                if change is not None:
                    yield change
            cursor = body.get("next_cursor") if body.get("has_more") else None
            if not cursor:
                break
        state["edited_after"] = newest or None
        yield Cursor(copy_cursor_state(state))

    def _ids(self, ctx: SyncContext, state: dict) -> Iterator:
        """The daily delete: all IDs, then each known key that is not there.
        An ID that is not known is read (a page that came back)."""
        ids: set[str] = set()
        cursor = None
        while True:
            body = self.api.search(cursor)
            for page in body.get("results") or []:
                if page.get("archived") or page.get("in_trash"):
                    continue
                ids.add(page["id"])
                if ctx.known(page["id"]) is None:
                    change = self._page(ctx, page)
                    if change is not None:
                        yield change
            cursor = body.get("next_cursor") if body.get("has_more") else None
            if not cursor:
                break
        for key in list(ctx.known_keys("")):
            if key not in ids:
                yield Delete(key)
        state["ids_at"] = _now()
        yield Cursor(copy_cursor_state(state))

    def _page(self, ctx: SyncContext, page: dict) -> Upsert | Delete | None:
        pid = page["id"]
        edited = page.get("last_edited_time")
        known = ctx.known(pid)
        ns = _time_ns(edited)
        if known is not None and ns is not None and known.mtime_ns == ns:
            return None
        try:
            blocks = self.api.children(pid, 0, self.max_depth)
        except SourceFault as exc:
            if exc.code in ("not_found", "permission_lost"):
                # The page left the selection since the search.
                return Delete(pid) if known is not None else None
            raise
        return Upsert(self.item(page, blocks))

    def item(self, page: dict, blocks: list[dict]) -> EvidenceItem:
        title = page_title(page) or "Untitled"
        text = f"# {title}\n\n" + blocks_to_markdown(blocks)
        rec = {
            "id": page["id"],
            "last_edited_time": page.get("last_edited_time"),
            "parent": page.get("parent") or {},
            "properties": page_properties(page),
            "url": page.get("url"),
        }
        item = record_item(
            key=page["id"],
            kind=KIND,
            name=title,
            ref=f"notion:{page['id']}",
            record=rec,
            text=text,
            title=title,
            prose=True,
            time=page.get("last_edited_time"),
            extra=_relations(page),
        )
        return dataclasses.replace(item, mtime_ns=_time_ns(page.get("last_edited_time")))

    def fetch(self, key: str, extra: dict) -> bytes:
        raise SourceFault("not_found", "a Notion record keeps its bytes")

    # ------------------------------------------------------- setup screen

    @classmethod
    def choices(cls, ctx: SourceContext, account, parent: str | None) -> dict:
        api = NotionApi.open(ctx, account.id, RateLimiter(cls.rate, cls.rate))
        body = api.search(None)
        pages = [
            {"id": p["id"], "title": page_title(p) or "Untitled"}
            for p in body.get("results") or []
            if not p.get("archived") and not p.get("in_trash")
        ]
        return {"pages": pages, "workspace": api.workspace}

    @classmethod
    def preview(cls, ctx: SourceContext, cfg: dict) -> dict:
        return {"estimate": None, "of": None}


def _relations(page: dict) -> dict:
    parent = page.get("parent") or {}
    if parent.get("type") == "page_id" and parent.get("page_id"):
        return {"relations": [["child_of", f"key:{parent['page_id']}"]]}
    if parent.get("type") == "database_id" and parent.get("database_id"):
        return {"project": f"notion:{parent['database_id']}"}
    return {}


def _iso(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


# --------------------------------------------------------------------- fake


def _err(status: int, code: str, message: str = "", headers: dict | None = None) -> HttpResponse:
    body = {"code": code, "message": message or code, "object": "error", "status": status}
    return HttpResponse(
        status, {"content-type": "application/json", **(headers or {})}, json.dumps(body).encode()
    )


def _ok(body: dict) -> HttpResponse:
    return HttpResponse(200, {"content-type": "application/json"}, json.dumps(body).encode())


NOTION_EPOCH = 1_767_225_600  # 2026-01-01 UTC; the fake Notion clock starts here


@dataclass
class FakeNotion:
    """A deterministic model of Notion for tests (an `HttpTransport`):
    OAuth (authorize, token with HTTP Basic, revoke), `POST /v1/search`, and
    `GET /v1/blocks/{id}/children`. Script it with `add_page`, `edit_page`,
    `archive`, `unshare`, and `fail_next`."""

    client_id: str = "fake-notion-client"
    client_secret: str = "fake-notion-secret"  # noqa: S105 - a test value, not a secret
    bot_id: str = "b0b0b0b0-0000-4000-8000-000000000001"
    workspace: str = "Lab workspace"
    calls: list[tuple[str, str]] = field(default_factory=list)
    pages: dict[str, dict] = field(default_factory=dict)
    blocks: dict[str, list[dict]] = field(default_factory=dict)  # parent id -> children
    revoked: list[str] = field(default_factory=list)
    _codes: set[str] = field(default_factory=set)
    _tokens: set[str] = field(default_factory=set)
    _fail: list[HttpResponse] = field(default_factory=list)
    _n: itertools.count = field(default_factory=lambda: itertools.count(1))
    _minute: int = 0

    # ----------------------------------------------------------- scripting

    def _id(self) -> str:
        return str(uuid.UUID(int=next(self._n)))

    def _tick(self) -> str:
        self._minute += 1
        t = NOTION_EPOCH + 60 * self._minute  # Notion rounds edit times to the minute
        return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:00.000Z")

    def add_page(
        self,
        title: str,
        blocks: list[dict] | None = None,
        *,
        parent: str | None = None,
        database: str | None = None,
        properties: dict | None = None,
    ) -> str:
        pid = self._id()
        if parent:
            par = {"page_id": parent, "type": "page_id"}
            self.blocks.setdefault(parent, []).append(
                {
                    "child_page": {"title": title},
                    "has_children": True,
                    "id": pid,
                    "type": "child_page",
                }
            )
        elif database:
            par = {"database_id": database, "type": "database_id"}
        else:
            par = {"type": "workspace", "workspace": True}
        now = self._tick()
        self.pages[pid] = {
            "archived": False,
            "created_time": now,
            "id": pid,
            "in_trash": False,
            "last_edited_time": now,
            "object": "page",
            "parent": par,
            "properties": {
                "title": {
                    "id": "title",
                    "title": [{"plain_text": title, "type": "text"}],
                    "type": "title",
                },
                **(properties or {}),
            },
            "url": f"https://www.notion.so/{pid.replace('-', '')}",
            "shared": parent is None,  # a child page is seen through its parent
        }
        self._set_blocks(pid, blocks or [])
        return pid

    def _set_blocks(self, parent: str, blocks: list[dict]) -> None:
        keep = [b for b in self.blocks.get(parent, []) if b.get("type") == "child_page"]
        out = []
        for b in blocks:
            b = dict(b)
            kids = b.pop("children", None)
            b.setdefault("id", self._id())
            b["has_children"] = bool(kids)
            if kids:
                self._set_blocks(b["id"], kids)
            out.append(b)
        self.blocks[parent] = out + keep

    def edit_page(
        self, pid: str, blocks: list[dict] | None = None, title: str | None = None
    ) -> None:
        p = self.pages[pid]
        if blocks is not None:
            self._set_blocks(pid, blocks)
        if title is not None:
            p["properties"]["title"]["title"] = [{"plain_text": title, "type": "text"}]
        p["last_edited_time"] = self._tick()

    def archive(self, pid: str) -> None:
        self.pages[pid]["archived"] = True
        self.pages[pid]["in_trash"] = True
        self.pages[pid]["last_edited_time"] = self._tick()

    def unshare(self, pid: str) -> None:
        """The person removed the page from the selection (no edit time)."""
        self.pages[pid]["shared"] = False

    def fail_next(self, status: int, headers: dict | None = None, times: int = 1) -> None:
        self._fail.extend(
            [_err(status, "rate_limited" if status == 429 else "fault", headers=headers)] * times
        )

    def authorize(self, url: str, *, deny: bool = False) -> str:
        parts = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.hostname != "api.notion.com" or q.get("client_id") != self.client_id:
            raise ValueError("FakeNotion: not an authorize URL of this client")
        if deny:
            args = {"error": "access_denied", "state": q["state"]}
        else:
            code = f"fake-notion-code-{next(self._n)}"
            self._codes.add(code)
            args = {"code": code, "state": q["state"]}
        return q["redirect_uri"] + "?" + urllib.parse.urlencode(args)

    # -------------------------------------------------------------- transport

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        self.calls.append((method, url))
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "api.notion.com":
            raise AssertionError("FakeNotion: not the Notion API")
        h = {k.lower(): v for k, v in headers.items()}
        if parts.path in ("/v1/oauth/token", "/v1/oauth/revoke"):
            return self._oauth(parts.path, h, body)
        if h.get("notion-version") != NOTION_VERSION:
            return _err(400, "missing_version")
        if self._fail:
            return self._fail.pop(0)
        if h.get("authorization", "").removeprefix("Bearer ") not in self._tokens:
            return _err(401, "unauthorized", "API token is invalid.")
        if parts.path == "/v1/search" and method == "POST":
            return self._search(json.loads(body or b"{}"))
        if parts.path.startswith("/v1/blocks/") and parts.path.endswith("/children"):
            q = dict(urllib.parse.parse_qsl(parts.query))
            return self._children(parts.path.split("/")[3], q)
        return _err(404, "object_not_found")

    def _oauth(self, path: str, h: dict[str, str], body: bytes | None) -> HttpResponse:
        """The token and revoke endpoints (client Basic auth)."""
        basic = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        if h.get("authorization") != f"Basic {basic}":
            return _err(401, "unauthorized")
        form = json.loads(body or b"{}")
        if path.endswith("/revoke"):
            self._tokens.discard(form.get("token"))
            self.revoked.append(form.get("token", ""))
            return _ok({})
        if form.get("grant_type") != "authorization_code" or form.get("code") not in self._codes:
            return HttpResponse(
                400, {"content-type": "application/json"}, b'{"error": "invalid_grant"}'
            )
        self._codes.discard(form["code"])
        token = f"ntn_fake{next(self._n):08d}"
        self._tokens.add(token)
        return _ok(
            {
                "access_token": token,
                "bot_id": self.bot_id,
                "owner": {"type": "user"},
                "token_type": "bearer",
                "workspace_id": "w0000000-0000-4000-8000-000000000001",
                "workspace_name": self.workspace,
            }
        )

    def grant(self) -> str:
        """An access token as a complete sign-in gives it."""
        token = f"ntn_fake{next(self._n):08d}"
        self._tokens.add(token)
        return token

    def revoke_all(self) -> None:
        self._tokens.clear()

    def _visible(self, pid: str) -> bool:
        p = self.pages.get(pid)
        while p is not None:
            if p["shared"]:
                return True
            p = self.pages.get(p["parent"].get("page_id", ""))
        return False

    def _search(self, body: dict) -> HttpResponse:
        if body.get("sort", {}).get("direction") != "descending":
            return _err(400, "validation_error", "this fake gives only descending sort")
        pages = [p for p in self.pages.values() if self._visible(p["id"])]
        pages.sort(key=lambda p: (p["last_edited_time"], p["id"]), reverse=True)
        start = int(body.get("start_cursor") or 0)
        size = min(int(body.get("page_size", 100)), 100)
        part = pages[start : start + size]
        more = start + size < len(pages)
        results = [{k: v for k, v in p.items() if k != "shared"} for p in part]
        return _ok(
            {
                "has_more": more,
                "next_cursor": str(start + size) if more else None,
                "object": "list",
                "page_or_database": {},
                "results": results,
                "type": "page_or_database",
            }
        )

    def _children(self, bid: str, q: dict) -> HttpResponse:
        if bid in self.pages and not self._visible(bid):
            return _err(404, "object_not_found", "Could not find block.")
        if bid not in self.blocks:
            return _err(404, "object_not_found", "Could not find block.")
        items = self.blocks[bid]
        start = int(q.get("start_cursor") or 0)
        size = min(int(q.get("page_size", 100)), 100)
        part = items[start : start + size]
        more = start + size < len(items)
        return _ok(
            {
                "block": {},
                "has_more": more,
                "next_cursor": str(start + size) if more else None,
                "object": "list",
                "results": [{"object": "block", **b} for b in part],
                "type": "block",
            }
        )


def para(text: str, **annotations) -> dict:
    """A paragraph block for tests."""
    return {
        "paragraph": {
            "rich_text": [{"annotations": annotations, "plain_text": text, "type": "text"}]
        },
        "type": "paragraph",
    }


def block(kind: str, text: str = "", children: list[dict] | None = None, **value) -> dict:
    """A block of `kind` for tests."""
    v = {"rich_text": [{"plain_text": text, "type": "text"}] if text else [], **value}
    out = {kind: v, "type": kind}
    if children:
        out["children"] = children
    return out


__all__ = ["NOTION", "FakeNotion", "NotionConnector", "blocks_to_markdown"]
