"""Gmail source (`gmail`, contract v2). Read-only, private space only.

Config (no secret):

    {"kind": "gmail", "account": "<account id>",
     "filter": {"mode": "mine", "labels": [], "senders": [], "exclude_senders": [],
                "exclude_categories": ["promotions", "social", "updates", "forums"],
                "skip_bulk": true, "after": "2024-11-16", "max_mb": 25, "attachments": true},
     "max_items": 20000}

Defaults: only threads in which the member wrote, the
last 2 years, at most 20 000 items. Generic IMAP is not in the release.

The filter is structured, so the same filter is a Gmail query for the first
sync (`GmailFilter.query`) and a local test for live changes
(`GmailFilter.matches`).

One `sync` call:

1. First call: `profile` gives the `historyId` before the first read (changes
   during the backfill are not lost), the address, and the message count.
2. Live step: `history.list` from the stored `historyId`. One call when
   nothing changed. A new message is read and tested. In mode `mine`, a new
   message of the member in an unknown thread brings the whole thread, and a
   received message in a known thread is included. A deleted message, or a
   message that goes to the trash or spam, is a `Delete`.
3. Backfill, newest first: `threads.list` (mode `mine`) or `messages.list`,
   500 for each page. Stops at `max_items`.
4. Reconcile, only when the history is too old (HTTP 404): the IDs of the
   query again, unknown messages are read, known keys that are gone are
   deleted.

Each message is one item (key `<thread id>/<message id>`, media type
`message/rfc822`). An attachment of an allowed type (at most 20 MB) is its
own item (key `<thread id>/<message id>/a<n>`).

Own or received (`local/understanding/third_party.py`): a message with the label SENT is the
member's own (`extra["own"] = True`); the `.eml` converter keeps
its quoted text apart. Each other message is received (fail closed): the
message and its attachments get `extra["third_party"] = True` and a neutral
name with the date only, because the subject and the file names are text of
the sender. All their text goes to context chunks.
"""

from __future__ import annotations

import base64
import email
import email.policy
import email.utils
import re
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import ClassVar

from anagram.core.crypto.chunked import hash_bytes
from anagram.core.timefmt import iso_seconds
from anagram.local.index.media import DOCX, PPTX, XLSX, sniff_bytes
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

GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
MODES = ("mine", "labels", "all")
CATEGORIES = ("promotions", "social", "updates", "forums")
NO_REPLY = (
    "noreply@",
    "no-reply@",
    "donotreply@",
    "notifications@",
    "mailer-daemon@",
    "calendar-notification@google.com",
)
ALWAYS_OUT = frozenset({"SPAM", "TRASH", "DRAFT", "CHAT"})
OWN_LABELS = frozenset({"SENT"})  # a message the member sent; each other one is received
ATTACHMENT_TYPES = frozenset(
    {
        "application/pdf",
        DOCX,
        PPTX,
        XLSX,
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "text/markdown",
        "text/plain",
        "text/csv",
        "application/x-ipynb+json",
    }
)
ATTACHMENT_MAX = 20 * 1024 * 1024
PAGE = 500
MAX_ITEMS = 20_000
BATCH_BYTES = 64 * 1024 * 1024
# Quota units of a call (Gmail API usage limits; verify with a live check).
UNITS = {
    "profile": 1,
    "threads.list": 10,
    "threads.get": 10,
    "messages.list": 5,
    "messages.get": 5,
    "history": 2,
    "labels": 1,
    "sendAs": 1,
}
UNITS_PER_S = 100.0  # below the documented limit of 250 units each second for one person
_SENDER = re.compile(r"^[A-Za-z0-9._%+@-]{1,254}$")
_LABEL = re.compile(r"^[^\s\"{}()][^\"{}()]{0,224}$")


def default_after(today: date | None = None) -> str:
    today = today or datetime.now(UTC).date()
    try:
        return today.replace(year=today.year - 2).isoformat()
    except ValueError:  # 29 February
        return today.replace(year=today.year - 2, day=28).isoformat()


@dataclass(frozen=True)
class GmailFilter:
    mode: str = "mine"
    labels: tuple[str, ...] = ()  # label names (mode `labels`)
    senders: tuple[str, ...] = ()
    exclude_senders: tuple[str, ...] = ()
    exclude_categories: tuple[str, ...] = CATEGORIES
    skip_bulk: bool = True
    after: str = field(default_factory=default_after)
    max_mb: int = 25
    attachments: bool = True
    owner: str = ""  # the address of the member; not in the config

    @classmethod
    def from_config(cls, cfg: Mapping, owner: str = "") -> GmailFilter:
        if not isinstance(cfg, Mapping):
            raise ConnectorError("filter must be an object")
        mode = cfg.get("mode", "mine")
        if mode not in MODES:
            raise ConnectorError(f"unknown mode: {mode}")

        def texts(key: str, rule: re.Pattern) -> tuple[str, ...]:
            values = cfg.get(key) or []
            if not isinstance(values, list) or not all(
                isinstance(v, str) and rule.match(v) for v in values
            ):
                raise ConnectorError(f"filter.{key} is not valid")
            return tuple(sorted({v.strip().lower() if rule is _SENDER else v for v in values}))

        cats = cfg.get("exclude_categories", list(CATEGORIES))
        if not isinstance(cats, list) or not set(cats) <= set(CATEGORIES):
            raise ConnectorError("filter.exclude_categories is not valid")
        after = cfg.get("after") or default_after()
        try:
            date.fromisoformat(after)
        except (TypeError, ValueError):
            raise ConnectorError("filter.after must be a date (YYYY-MM-DD)") from None
        max_mb = cfg.get("max_mb", 25)
        if not isinstance(max_mb, int) or not 1 <= max_mb <= 25:
            raise ConnectorError("filter.max_mb must be 1 to 25")
        labels = texts("labels", _LABEL)
        if mode == "labels" and not labels:
            raise ConnectorError("choose one label")
        return cls(
            mode=mode,
            labels=labels,
            senders=texts("senders", _SENDER),
            exclude_senders=texts("exclude_senders", _SENDER),
            exclude_categories=tuple(c for c in CATEGORIES if c in cats),
            skip_bulk=bool(cfg.get("skip_bulk", True)),
            after=after,
            max_mb=max_mb,
            attachments=bool(cfg.get("attachments", True)),
            owner=owner.lower(),
        )

    def config(self) -> dict:
        return {
            "after": self.after,
            "attachments": self.attachments,
            "exclude_categories": list(self.exclude_categories),
            "exclude_senders": list(self.exclude_senders),
            "labels": list(self.labels),
            "max_mb": self.max_mb,
            "mode": self.mode,
            "senders": list(self.senders),
            "skip_bulk": self.skip_bulk,
        }

    def query(self) -> str:
        """The Gmail search query, for example
        `from:me after:2024/11/16 -in:chats -category:promotions smaller:25M`."""
        terms = []
        if self.mode == "mine":
            terms.append("from:me")
        elif self.mode == "labels":
            terms.append("{" + " ".join(f"label:{_label_term(n)}" for n in self.labels) + "}")
        if self.senders:
            terms.append("from:(" + " OR ".join(self.senders) + ")")
        terms.extend(f"-from:{s}" for s in self.exclude_senders)
        terms.append(f"after:{self.after.replace('-', '/')}")
        terms.extend(("-in:chats", "-in:spam", "-in:trash", "-in:drafts"))
        terms.extend(f"-category:{c}" for c in self.exclude_categories)
        terms.append(f"smaller:{self.max_mb}M")
        return " ".join(terms)

    def matches(
        self,
        label_ids: set[str],
        headers: Mapping[str, str],
        size: int,
        *,
        label_names: Mapping[str, str] | None = None,
        internal_ms: int | None = None,
    ) -> bool:
        """The local test of a message (live changes). `headers` has
        lower-case names. Mode `mine` is a thread rule; the connector applies
        it."""
        return (
            self._labels_match(label_ids, label_names)
            and size <= self.max_mb * 1024 * 1024
            and (internal_ms is None or internal_ms >= self._after_ms())
            and self._sender_ok(headers)
            and not (self.skip_bulk and is_bulk(headers))
        )

    def _after_ms(self) -> float:
        return datetime.fromisoformat(self.after).replace(tzinfo=UTC).timestamp() * 1000

    def _labels_match(self, label_ids: set[str], label_names: Mapping[str, str] | None) -> bool:
        """False for an excluded label or category, or (mode `labels`) for no
        selected label."""
        if label_ids & ALWAYS_OUT:
            return False
        if any(f"CATEGORY_{c.upper()}" in label_ids for c in self.exclude_categories):
            return False
        if self.mode == "labels":
            names = {(label_names or {}).get(i, i) for i in label_ids}
            return bool(names & set(self.labels))
        return True

    def _sender_ok(self, headers: Mapping[str, str]) -> bool:
        """False for a no-reply sender, a sender out of `senders`, or an
        excluded sender."""
        sender = email.utils.parseaddr(headers.get("from", ""))[1].lower()
        if any(sender.startswith(p) or sender == p for p in NO_REPLY):
            return False
        if self.senders and not any(_sender_match(sender, s) for s in self.senders):
            return False
        return not any(_sender_match(sender, s) for s in self.exclude_senders)


def _label_term(name: str) -> str:
    """A label name in a Gmail query: spaces become `-` (verify)."""
    return re.sub(r"\s+", "-", name.strip()).lower()


def _sender_match(sender: str, pattern: str) -> bool:
    """An address, or a domain (`example.org` or `@example.org`)."""
    if "@" in pattern and not pattern.startswith("@"):
        return sender == pattern
    domain = pattern.lstrip("@")
    return sender.endswith("@" + domain) or sender.endswith("." + domain)


def is_bulk(headers: Mapping[str, str]) -> bool:
    """A list, a newsletter, or an automatic message."""
    if headers.get("list-unsubscribe") or headers.get("list-id"):
        return True
    if headers.get("precedence", "").strip().lower() in ("bulk", "list", "junk"):
        return True
    auto = headers.get("auto-submitted", "").strip().lower()
    return bool(auto) and auto != "no"


def _headers(raw: bytes) -> dict[str, str]:
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    msg = email.message_from_bytes(head + b"\r\n\r\n", policy=email.policy.compat32)
    return {k.lower(): str(v) for k, v in msg.items()}


def _rfc3339(ms: int | None) -> str | None:
    if ms is None:
        return None
    return iso_seconds(ms / 1000)


class GmailConnector(Connector):
    kind = "gmail"
    label = "Gmail"
    auth: ClassVar[str] = "oauth"
    provider: ClassVar[str] = "google"
    refetchable: ClassVar[bool] = True
    rate: ClassVar[float] = UNITS_PER_S

    def __init__(
        self,
        account: str,
        filter: dict | None = None,  # the name of the config key
        *,
        max_items: int = MAX_ITEMS,
        ctx: SourceContext | None = None,
    ) -> None:
        if not isinstance(max_items, int) or not 1 <= max_items <= 1_000_000:
            raise ConnectorError("max_items must be 1 to 1 000 000")
        self.account = account
        self.filter = GmailFilter.from_config(filter or {})
        self.max_items = max_items
        self._ctx = ctx
        self._api: GoogleApi | None = None

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> GmailConnector:
        return cls(
            cfg["account"], cfg.get("filter"), max_items=cfg.get("max_items", MAX_ITEMS), ctx=ctx
        )

    def config(self) -> dict:
        return {
            "account": self.account,
            "filter": self.filter.config(),
            "kind": self.kind,
            "max_items": self.max_items,
        }

    def describe(self) -> str:
        return "Gmail"

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise ConnectorError("use sync")

    @property
    def api(self) -> GoogleApi:
        if self._api is None:
            self._api = GoogleApi.open(self._ctx, self.account, RateLimiter(self.rate, self.rate))
        return self._api

    def _get(self, path: str, params: dict | None, units: str) -> dict:
        return self.api.json(f"{GMAIL}/{path}", params, cost=UNITS[units])

    # ---------------------------------------------------------------- sync

    def sync(self, ctx: SyncContext) -> Iterator:
        state = dict(ctx.state) if ctx.state.get("v") == 1 else {}
        if ctx.state.get("reset"):
            state = {}
            yield from self._reconcile_start(state)
        elif not state:
            state.update(self._start())
            yield Note(phase="first_sync", total=state.pop("_total", None))
            yield Cursor(copy_cursor_state(state))
        flt = self._filter(state)
        try:
            yield from self._live(ctx, state, flt)
        except SourceFault as exc:
            if exc.code != "cursor_expired":
                raise
            yield from self._reconcile_start(state)
        if not state["backfill"]["done"]:
            yield from self._backfill(ctx, state, flt)

    def _filter(self, state: dict) -> GmailFilter:
        cfg = self.filter.config()
        return GmailFilter.from_config(cfg, state.get("email", ""))

    def _start(self) -> dict:
        profile = self._get("profile", None, "profile")
        labels = self._get("labels", None, "labels").get("labels") or []
        aliases = []
        try:
            send_as = self._get("settings/sendAs", None, "sendAs").get("sendAs") or []
            aliases = sorted({a["sendAsEmail"].lower() for a in send_as if a.get("sendAsEmail")})
        except SourceFault as exc:
            if exc.code not in ("permission_lost", "not_found"):
                raise
        return {
            "_total": profile.get("messagesTotal"),
            "aliases": aliases,
            "backfill": {"done": False, "n": 0, "offset": 0, "page": None},
            "email": str(profile.get("emailAddress", "")).lower(),
            "history_id": str(profile["historyId"]),
            "labels": {lb["id"]: lb.get("name", lb["id"]) for lb in labels if lb.get("id")},
            "v": 1,
        }

    def _reconcile_start(self, state: dict) -> Iterator:
        new = self._start()
        new.pop("_total", None)
        new["backfill"]["reconcile"] = True
        new["seen"] = []
        state.clear()
        state.update(new)
        yield Note(phase="reconcile")
        yield Cursor(copy_cursor_state(state))

    # ------------------------------------------------------------ backfill

    def _backfill(self, ctx: SyncContext, state: dict, flt: GmailFilter) -> Iterator:
        bf = state["backfill"]
        reconcile = bool(bf.get("reconcile"))
        phase = "reconcile" if reconcile else "first_sync"
        threads = flt.mode == "mine"
        while not bf["done"]:
            body, entries = self._list_page(flt, bf.get("page"), threads=threads)
            n, size = 0, 0
            for i in range(int(bf.get("offset", 0)), len(entries)):
                if bf["n"] >= self.max_items:
                    break
                for mid, tid in self._entry_messages(entries[i], threads=threads):
                    key = f"{tid}/{mid}"
                    taken = ctx.known(key) is not None
                    for change in self._message(ctx, state, flt, mid, tid):
                        yield change
                        if isinstance(change, Upsert):
                            n += 1
                            size += len(change.item.data or b"")
                            if change.item.key == key:
                                taken = True
                                bf["oldest"] = change.item.time or bf.get("oldest")
                    if taken:
                        bf["n"] += 1  # a message in the index (new or known)
                        if reconcile:
                            state["seen"].append(key)
                if n >= BATCH_MAX or size >= BATCH_BYTES:
                    bf["offset"] = i + 1
                    yield Note(phase=phase, done=bf["n"], at=bf.get("oldest"))
                    yield Cursor(copy_cursor_state(state))
                    n, size = 0, 0
            bf["page"] = body.get("nextPageToken")
            bf["offset"] = 0
            if not bf["page"] or bf["n"] >= self.max_items:
                bf["done"] = True
                if reconcile:
                    yield from _end_reconcile(ctx, state, flt)
            yield Note(phase=phase, done=bf["n"], at=bf.get("oldest"))
            yield Cursor(copy_cursor_state(state))
            if ctx.stop() or time.monotonic() > ctx.deadline:
                return
        yield Note(phase="live")

    def _list_page(self, flt: GmailFilter, page: str | None, *, threads: bool) -> tuple:
        """One page of the backfill list: `(body, entries)`. The entries are
        threads (mode `mine`) or messages."""
        params = {"maxResults": PAGE, "q": flt.query()}
        if page:
            params["pageToken"] = page
        if threads:
            body = self._get("threads", params, "threads.list")
            return body, body.get("threads") or []
        body = self._get("messages", params, "messages.list")
        return body, body.get("messages") or []

    def _entry_messages(self, entry: dict, *, threads: bool) -> list[tuple[str, str]]:
        """The `(message id, thread id)` pairs of one list entry."""
        if threads:
            return self._thread_messages(entry["id"])
        return [(entry["id"], entry.get("threadId") or entry["id"])]

    def _thread_messages(self, tid: str) -> list[tuple[str, str]]:
        body = self._get(f"threads/{tid}", {"format": "minimal"}, "threads.get")
        return [(m["id"], m.get("threadId") or tid) for m in body.get("messages") or []]

    # ------------------------------------------------------------- content

    def _message(self, ctx, state, flt: GmailFilter, mid: str, tid: str) -> Iterator:
        """The items of one message (the message and its attachments).
        Messages do not change, so a known key is not read again."""
        key = f"{tid}/{mid}"
        if ctx.known(key) is not None:
            return
        try:
            msg = self._get(f"messages/{mid}", {"format": "raw"}, "messages.get")
        except SourceFault as exc:
            if exc.code == "not_found":
                return  # deleted since the listing
            raise
        raw = base64.urlsafe_b64decode(msg.get("raw", "") + "=" * (-len(msg.get("raw", "")) % 4))
        labels = set(msg.get("labelIds") or [])
        headers = _headers(raw)
        ms = int(msg["internalDate"]) if msg.get("internalDate") else None
        if not flt.matches(
            labels, headers, len(raw), label_names=state.get("labels"), internal_ms=ms
        ):
            return
        yield from self._items(key, tid, mid, raw, labels, headers, ms, flt)

    def _items(self, key, tid, mid, raw, labels, headers, ms, flt) -> Iterator:
        own = bool(labels & OWN_LABELS)  # no label: received (fail closed)
        extra = {
            "fetch": {"id": mid},
            "labels": sorted(labels),
            "relations": [["same_thread", f"thread:gmail:{tid}"]],
            "thread": tid,
        }
        if own:
            subject = headers.get("subject", "").strip()
            name = (subject[:200] or "(no subject)") + ".eml"
            extra["own"] = True
        else:
            name = third_party.mail_name(ms)
            extra[third_party.MARK] = True
        item = EvidenceItem(
            key=key,
            kind="email",
            name=name,
            media_type="message/rfc822",
            digest=hash_bytes(raw),
            ref=f"gmail:{mid}",
            mtime_ns=ms * 1_000_000 if ms is not None else None,
            time=_rfc3339(ms),
            data=raw,
            extra=extra,
        )
        yield Upsert(item)
        if not flt.attachments:
            return
        for n, (name, data) in enumerate(attachments(raw), start=1):
            mt = sniff_bytes(data, name)
            if mt not in ATTACHMENT_TYPES or len(data) > ATTACHMENT_MAX:
                continue
            a_extra = {
                "fetch": {"attachment": n, "id": mid},
                "relations": [
                    ["attached_to", f"key:{key}"],  # the message item
                    ["same_thread", f"thread:gmail:{tid}"],
                ],
                "thread": tid,
            }
            if not own:  # an attachment of a received mail: the sender's text
                a_extra[third_party.MARK] = True
                name = third_party.attachment_name(n, name, ms)
            yield Upsert(
                EvidenceItem(
                    key=f"{key}/a{n}",
                    kind="email_attachment",
                    name=name,
                    media_type=mt,
                    digest=hash_bytes(data),
                    ref=f"gmail:{mid}/a{n}",
                    mtime_ns=item.mtime_ns,
                    time=item.time,
                    data=data,
                    extra=a_extra,
                )
            )

    def fetch(self, key: str, extra: dict) -> bytes:
        fetch = extra.get("fetch") or {}
        msg = self._get(f"messages/{fetch['id']}", {"format": "raw"}, "messages.get")
        raw = base64.urlsafe_b64decode(msg.get("raw", "") + "=" * (-len(msg.get("raw", "")) % 4))
        n = fetch.get("attachment")
        if not n:
            return raw
        found = attachments(raw)
        if not 1 <= n <= len(found):
            raise SourceFault("not_found", "the attachment is not there")
        return found[n - 1][1]

    # ---------------------------------------------------------------- live

    def _live(self, ctx: SyncContext, state: dict, flt: GmailFilter) -> Iterator:
        start = state["history_id"]
        page = state.get("history_page")
        while True:
            params = {
                "historyTypes": ["messageAdded", "messageDeleted", "labelAdded", "labelRemoved"],
                "maxResults": PAGE,
                "startHistoryId": start,
            }
            if page:
                params["pageToken"] = page
            try:
                body = self._get("history", params, "history")
            except SourceFault as exc:
                if exc.code == "not_found":
                    raise SourceFault("cursor_expired", "the history is too old") from None
                raise
            for h in body.get("history") or []:
                yield from self._history(ctx, state, flt, h)
            page = body.get("nextPageToken")
            if page:
                state["history_page"] = page
                yield Cursor(copy_cursor_state(state))
                continue
            state.pop("history_page", None)
            state["history_id"] = str(body.get("historyId") or start)
            yield Cursor(copy_cursor_state(state))
            return

    def _history(self, ctx, state, flt: GmailFilter, h: dict) -> Iterator:
        for e in h.get("messagesDeleted") or []:
            m = e.get("message") or {}
            yield from _delete_message(f"{m.get('threadId') or m.get('id')}/{m.get('id')}")
        for e in h.get("labelsAdded") or []:
            m = e.get("message") or {}
            if set(e.get("labelIds") or []) & {"TRASH", "SPAM"}:
                yield from _delete_message(f"{m.get('threadId') or m.get('id')}/{m.get('id')}")
        added = [e.get("message") or {} for e in h.get("messagesAdded") or []]
        added += [
            e.get("message") or {}
            for e in h.get("labelsRemoved") or []
            if set(e.get("labelIds") or []) & {"TRASH", "SPAM"}
        ]
        for m in added:
            mid, tid = m.get("id"), m.get("threadId") or m.get("id")
            if not mid or ctx.known(f"{tid}/{mid}") is not None:
                continue
            if set(m.get("labelIds") or []) & ALWAYS_OUT:
                continue
            if flt.mode != "mine":
                yield from self._message(ctx, state, flt, mid, tid)
                continue
            yield from self._mine_rule(ctx, state, flt, mid, tid, m)

    def _mine_rule(self, ctx, state, flt, mid, tid, m) -> Iterator:
        """Mode `mine`: a message of the member brings its thread; a received
        message counts only in a thread that is known."""
        thread_known = next(iter(ctx.known_keys(f"{tid}/")), None) is not None
        own = "SENT" in set(m.get("labelIds") or [])
        if thread_known:
            yield from self._message(ctx, state, flt, mid, tid)
        elif own:
            for other, t in self._thread_messages(tid):
                yield from self._message(ctx, state, flt, other, t)

    # ------------------------------------------------------- setup screen

    @classmethod
    def choices(cls, ctx: SourceContext, account, parent: str | None) -> dict:
        api = GoogleApi.open(ctx, account.id, RateLimiter(cls.rate, cls.rate))
        profile = api.json(f"{GMAIL}/profile", None, cost=UNITS["profile"])
        labels = api.json(f"{GMAIL}/labels", None, cost=UNITS["labels"]).get("labels") or []
        out = []
        for lb in labels:
            if lb.get("type") != "user":
                continue
            detail = api.json(f"{GMAIL}/labels/{lb['id']}", None, cost=UNITS["labels"])
            out.append(
                {"count": detail.get("messagesTotal"), "id": lb["id"], "name": lb.get("name", "")}
            )
            if len(out) >= 100:
                break
        return {
            "email": profile.get("emailAddress"),
            "labels": sorted(out, key=lambda x: x["name"].lower()),
            "total": profile.get("messagesTotal"),
        }

    @classmethod
    def preview(cls, ctx: SourceContext, cfg: dict) -> dict:
        """`resultSizeEstimate` of the query and `messagesTotal`."""
        api = GoogleApi.open(ctx, cfg["account"], RateLimiter(cls.rate, cls.rate))
        flt = GmailFilter.from_config(cfg.get("filter") or {})
        profile = api.json(f"{GMAIL}/profile", None, cost=UNITS["profile"])
        what = "threads" if flt.mode == "mine" else "messages"
        body = api.json(
            f"{GMAIL}/{what}", {"maxResults": 1, "q": flt.query()}, cost=UNITS[f"{what}.list"]
        )
        estimate = body.get("resultSizeEstimate")
        if isinstance(estimate, int):
            estimate = min(estimate, int(cfg.get("max_items", MAX_ITEMS)))
        return {"estimate": estimate, "of": profile.get("messagesTotal")}


def _delete_message(key: str) -> Iterator[Delete]:
    """A message and its attachments (`<key>/a<n>`)."""
    yield Delete(key)
    yield Delete(key + "/", prefix=True)


def _end_reconcile(ctx: SyncContext, state: dict, flt: GmailFilter) -> Iterator[Delete]:
    """At the end of a reconcile backfill: delete each known message that the
    backfill did not see, and each attachment if the filter has none."""
    seen = set(state.pop("seen", []))
    for key in list(ctx.known_keys("")):
        parts = key.split("/")
        if len(parts) == 2 and key not in seen:
            yield from _delete_message(key)
        elif len(parts) == 3 and not flt.attachments:
            yield Delete(key)
    state["backfill"].pop("reconcile", None)


def attachments(raw: bytes) -> list[tuple[str, bytes]]:
    """`(file name, bytes)` of each attachment that is not inline, in the
    order of the MIME tree."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        name = part.get_filename()
        if disposition != "attachment" or not name:
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:  # noqa: S112 - a broken part is left out
            continue
        out.append((name[:200], data))
    return out
