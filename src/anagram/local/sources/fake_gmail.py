"""`FakeGmail`: the Gmail part of `FakeGoogle`, for tests.

It models the profile, labels, sendAs, threads, messages, and history of one
Gmail account in memory. No test calls Google.
"""

from __future__ import annotations

import base64
import email.message
import email.utils
import re
import time
from datetime import UTC, datetime

from anagram.local.sources.google import google_error, json_response
from anagram.local.sources.http import HttpResponse

SYSTEM_LABELS = (
    "INBOX",
    "SENT",
    "DRAFT",
    "SPAM",
    "TRASH",
    "UNREAD",
    "STARRED",
    "IMPORTANT",
    "CATEGORY_PERSONAL",
    "CATEGORY_PROMOTIONS",
    "CATEGORY_SOCIAL",
    "CATEGORY_UPDATES",
    "CATEGORY_FORUMS",
)
_TERM = re.compile(r"\{[^}]*\}|-?[a-z]+:\([^)]*\)|\S+")


class FakeGmail:
    """The Gmail part of `FakeGoogle`: profile, labels, sendAs,
    threads, messages (`format=raw`, `format=minimal`), and history. The
    search understands the terms that `GmailFilter.query` writes."""

    def __init__(self, email: str = "member@example.org") -> None:
        self.email = email
        self.aliases: list[str] = []
        self.messages: dict[str, dict] = {}
        self.labels: dict[str, str] = {}  # user label id -> name
        self.history: list[dict] = []
        self.history_id = 1000
        self._floor = 0  # a start below this is too old (HTTP 404)
        self._n = 0
        self._version = 0
        self._cache: dict[tuple, list[str]] = {}
        # Messages are 1 minute apart, from 400 days ago (inside 2 years).
        self.epoch_ms = (int(time.time()) - 400 * 86_400) * 1000

    # ---------------------------------------------------------- scripting

    def add_label(self, name: str) -> str:
        lid = f"Label_{len(self.labels) + 1}"
        self.labels[lid] = name
        return lid

    def add_message(
        self,
        subject: str = "Hello",
        body: str = "Text.",
        *,
        sender: str | None = None,
        to: str | None = None,
        thread: str | None = None,
        labels: tuple[str, ...] = ("INBOX",),
        sent: bool = False,
        at_ms: int | None = None,
        headers: dict[str, str] | None = None,
        attachments: tuple[tuple[str, str, bytes], ...] = (),
    ) -> tuple[str, str]:
        """A new message: `(message id, thread id)`. `sent=True` is a
        message of the member (label SENT). `attachments`: (name, media
        type, bytes)."""
        self._n += 1
        mid = f"{0x18F0000000000000 + self._n:016x}"
        tid = thread or mid
        frm = self.email if sent else (sender or "colleague@example.net")
        at = at_ms if at_ms is not None else self.epoch_ms + self._n * 60_000
        date = email.utils.formatdate(at / 1000, usegmt=True)
        if attachments:
            msg = email.message.EmailMessage()
            msg["From"] = frm
            msg["To"] = to or (self.email if not sent else "colleague@example.net")
            msg["Subject"] = subject
            msg["Date"] = date
            msg["Message-ID"] = f"<{mid}@fake.example>"
            for k, v in (headers or {}).items():
                msg[k] = v
            msg.set_content(body)
            for name, mt, data in attachments:
                main, sub = mt.split("/", 1)
                msg.add_attachment(data, maintype=main, subtype=sub, filename=name)
            raw = msg.as_bytes()
        else:
            extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
            raw = (
                f"From: {frm}\r\nTo: {to or self.email}\r\nSubject: {subject}\r\n"
                f"Date: {date}\r\nMessage-ID: <{mid}@fake.example>\r\n{extra}"
                f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
            ).encode()
        names = set(labels) | ({"SENT"} if sent else set())
        if sent:
            names.discard("INBOX")
        self.messages[mid] = {
            "id": mid,
            "labels": names,
            "raw": raw,
            "sender": frm.lower(),
            "threadId": tid,
            "time": at,
        }
        self._record("messagesAdded", mid)
        return mid, tid

    def delete_message(self, mid: str) -> None:
        """A delete for ever (not the trash)."""
        self._record("messagesDeleted", mid)
        del self.messages[mid]

    def label(self, mid: str, add: tuple[str, ...] = (), remove: tuple[str, ...] = ()) -> None:
        m = self.messages[mid]
        if add:
            m["labels"] |= set(add)
            self._record("labelsAdded", mid, list(add))
        if remove:
            m["labels"] -= set(remove)
            self._record("labelsRemoved", mid, list(remove))

    def expire_history(self) -> None:
        """Each history ID of before this call is too old."""
        self.history_id += 1
        self._floor = self.history_id

    def _short(self, mid: str) -> dict:
        m = self.messages[mid]
        return {"id": mid, "labelIds": sorted(m["labels"]), "threadId": m["threadId"]}

    def _record(self, what: str, mid: str, label_ids: list[str] | None = None) -> None:
        self.history_id += 1
        self._version += 1
        self._cache.clear()
        entry = {"message": self._short(mid)}
        if label_ids is not None:
            entry["labelIds"] = label_ids
        self.history.append(
            {"id": str(self.history_id), "messages": [entry["message"]], what: [entry]}
        )

    # ---------------------------------------------------------- search

    def _match(self, m: dict, terms: list[str]) -> bool:
        for t in terms:
            neg = t.startswith("-")
            t = t.lstrip("-")
            if t.startswith("{"):
                ok = any(self._match(m, [x]) for x in t[1:-1].split())
            elif t == "from:me":
                ok = "SENT" in m["labels"]
            elif t.startswith("from:("):
                ok = any(_fake_sender(m["sender"], x) for x in t[6:-1].split(" OR "))
            elif t.startswith("from:"):
                ok = _fake_sender(m["sender"], t[5:])
            elif t.startswith("label:"):
                want = t[6:]
                names = {self.labels.get(i, i) for i in m["labels"]}
                ok = any(re.sub(r"\s+", "-", n).lower() == want for n in names)
            elif t.startswith("after:"):
                day = datetime.strptime(t[6:], "%Y/%m/%d").replace(tzinfo=UTC)
                ok = m["time"] >= day.timestamp() * 1000
            elif t.startswith("in:"):
                ok = {"chats": "CHAT", "spam": "SPAM", "trash": "TRASH", "drafts": "DRAFT"}.get(
                    t[3:], t[3:].upper()
                ) in m["labels"]
            elif t.startswith("category:"):
                ok = f"CATEGORY_{t[9:].upper()}" in m["labels"]
            elif t.startswith("smaller:"):
                ok = len(m["raw"]) < int(t[8:].rstrip("M")) * 1024 * 1024
            else:
                raise ValueError(f"FakeGmail: search term not known: {t}")
            if ok == neg:
                return False
        return True

    def _search(self, what: str, q: str) -> list[str]:
        """Message or thread IDs, newest first."""
        key = (what, q)
        if key in self._cache:
            return self._cache[key]
        terms = _TERM.findall(q)
        hits = [
            m
            for m in self.messages.values()
            if not m["labels"] & {"SPAM", "TRASH"} or "-in:trash" not in terms
            if self._match(m, terms)
        ]
        hits.sort(key=lambda m: (m["time"], m["id"]), reverse=True)
        if what == "messages":
            out = [m["id"] for m in hits]
        else:
            seen: dict[str, None] = {}
            for m in hits:
                seen.setdefault(m["threadId"], None)
            out = list(seen)
        self._cache[key] = out
        return out

    # ---------------------------------------------------------- routes

    def route(self, path: str, q: dict, many: dict) -> HttpResponse:
        """The answer to a Gmail API path below `users/me/`."""
        if path == "profile":
            return self._profile()
        if path == "settings/sendAs":
            return self._send_as()
        if path == "labels":
            return self._label_list()
        if path in ("threads", "messages"):
            return self._ids(path, q)
        if path == "history":
            return self._history(q, many)
        for prefix, handler in (
            ("labels/", self._label),
            ("threads/", self._thread),
            ("messages/", self._message),
        ):
            if path.startswith(prefix):
                return handler(path[len(prefix) :], q)
        return google_error(404, "notFound")

    def _profile(self) -> HttpResponse:
        return json_response(
            200,
            {
                "emailAddress": self.email,
                "historyId": str(self.history_id),
                "messagesTotal": len(self.messages),
                "threadsTotal": len({m["threadId"] for m in self.messages.values()}),
            },
        )

    def _send_as(self) -> HttpResponse:
        items = [{"isPrimary": True, "sendAsEmail": self.email}]
        items += [{"isPrimary": False, "sendAsEmail": a} for a in self.aliases]
        return json_response(200, {"sendAs": items})

    def _label_list(self) -> HttpResponse:
        items = [{"id": i, "name": i, "type": "system"} for i in SYSTEM_LABELS]
        items += [{"id": i, "name": n, "type": "user"} for i, n in self.labels.items()]
        return json_response(200, {"labels": items})

    def _label(self, lid: str, q: dict) -> HttpResponse:
        if lid not in self.labels:
            return google_error(404, "notFound", "Requested entity was not found.")
        count = sum(1 for m in self.messages.values() if lid in m["labels"])
        body = {"id": lid, "messagesTotal": count, "name": self.labels[lid], "type": "user"}
        return json_response(200, body)

    def _ids(self, path: str, q: dict) -> HttpResponse:
        """`threads` or `messages`: one page of the IDs that the search finds."""
        ids = self._search(path, q.get("q", ""))
        start = int(q.get("pageToken") or 0)
        size = min(int(q.get("maxResults", 100)), 500)
        part = ids[start : start + size]
        body = {"resultSizeEstimate": len(ids)}
        if part:
            if path == "threads":
                body["threads"] = [{"historyId": str(self.history_id), "id": t} for t in part]
            else:
                body["messages"] = [
                    {"id": i, "threadId": self.messages[i]["threadId"]} for i in part
                ]
        if start + size < len(ids):
            body["nextPageToken"] = str(start + size)
        return json_response(200, body)

    def _thread(self, tid: str, q: dict) -> HttpResponse:
        msgs = sorted(
            (m for m in self.messages.values() if m["threadId"] == tid),
            key=lambda m: m["time"],
        )
        if not msgs:
            return google_error(404, "notFound", "Requested entity was not found.")
        return json_response(
            200,
            {
                "historyId": str(self.history_id),
                "id": tid,
                "messages": [
                    {**self._short(m["id"]), "internalDate": str(m["time"])} for m in msgs
                ],
            },
        )

    def _message(self, mid: str, q: dict) -> HttpResponse:
        m = self.messages.get(mid)
        if m is None:
            return google_error(404, "notFound", "Requested entity was not found.")
        out = {
            **self._short(m["id"]),
            "historyId": str(self.history_id),
            "internalDate": str(m["time"]),
            "sizeEstimate": len(m["raw"]),
        }
        if q.get("format") == "raw":
            out["raw"] = base64.urlsafe_b64encode(m["raw"]).decode()
        return json_response(200, out)

    def _history(self, q: dict, many: dict) -> HttpResponse:
        try:
            start = int(q.get("startHistoryId", ""))
        except ValueError:
            return google_error(400, "invalidArgument", "Invalid startHistoryId.")
        if start < self._floor:
            return google_error(404, "notFound", "Requested entity was not found.")
        # `messageAdded` (a type) names the `messagesAdded` field.
        types = {
            t.replace("message", "messages", 1).replace("label", "labels", 1)
            for t in many.get("historyTypes") or []
        }
        rows = [
            h
            for h in self.history
            if int(h["id"]) > start and (not types or types & set(h) - {"id", "messages"})
        ]
        at = int(q.get("pageToken") or 0)
        size = min(int(q.get("maxResults", 100)), 500)
        body = {"historyId": str(self.history_id)}
        if rows[at : at + size]:
            body["history"] = rows[at : at + size]
        if at + size < len(rows):
            body["nextPageToken"] = str(at + size)
        return json_response(200, body)


def _fake_sender(sender: str, pattern: str) -> bool:
    if "@" in pattern and not pattern.startswith("@"):
        return sender == pattern
    domain = pattern.lstrip("@")
    return sender.endswith("@" + domain) or sender.endswith("." + domain)
