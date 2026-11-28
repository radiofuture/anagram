"""The agent grants of the person (grant v2; open-agents plan section 2.1,
primitive `agent-grant`).

The record is the meta key `agent_grants` of the encrypted index store:

    {"version": 2,
     "grants": [{"id", "name", "recipient_class": "cloud" | "local",
                 "spaces": [space, ...], "tools": [scope, ...],
                 "daily_chars", "expires": "YYYY-MM-DD" | null,
                 "added_at", "last_used", "revoked_at", "http": <sha256 hex> | null}]}

- Off by default: with no grant, no tool gives text.
- One grant for each agent. The id is in the command that the agent starts
  (`anagram mcp --assistant <id>`). On stdio it is a name for a grant, not a
  secret: a program of this user on this computer can read the index key
  too. On loopback HTTP the agent also needs the bearer key of the grant;
  the record keeps only its SHA-256 (`http`).
- `recipient_class` is the person's statement (the node cannot see which
  model runs behind a client). The default is `cloud`, the safe class. A
  lab space for a cloud agent needs the lab to allow cloud agents too.
- `tools` are scopes (`read.search`, ..., `act.lines_propose`). A tool that
  is not in the grant is refused. In v1 an outside agent prepares drafts
  only: a negotiation scope is refused when the person adds
  or changes a grant.
- `expires` is the first day (UTC) with no access. None: no expiry.
- A revoke sets `revoked_at` and keeps the row, so the log view keeps the
  name. A revoked grant gives no more text at the next call.
- The daily limit counts the characters that one grant got today (UTC), in
  the meta key `agent_usage`.
- Migration: a v1 record (meta key `mcp`, one entry for each assistant)
  becomes grants with the same ids, the four read tools, class `cloud`, and
  no expiry, at the first read. Then the key `mcp` is deleted.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, replace
from datetime import date
from typing import Any

from anagram.local.api import source_state

META = "agent_grants"
USAGE = "agent_usage"
V1_META = "mcp"
V1_USAGE = "mcp_usage"
VERSION = 2
DAILY_CHARS = 200_000
MAX_DAILY_CHARS = 2_000_000
MAX_ACTIVE = 10
MAX_ROWS = 50  # active and revoked; the oldest revoked rows go first
MAX_NAME = 60

CLOUD = "cloud"
LOCAL = "local"
CLASSES = (CLOUD, LOCAL)
RECIPIENT = {
    CLOUD: "{name} and the company that runs it",
    LOCAL: "{name} on this computer",
}
ADAPTER = "agent"  # the adapter of a disclosure row is "agent:<grant id>"

READ_TOOLS = ("read.search", "read.ask", "read.item", "read.timeline")
ACT_TOOLS = ("act.lines_propose",)
TOOLS = READ_TOOLS + ACT_TOOLS
# Negotiation scopes of the open-agents plan (4.2). Not in v1 (decision C22,
# net 06 step 1): only the person's node negotiates, with the local model.
NEGOTIATION = ("act.ask", "act.table_reply", "act.intro_propose", "act.room_card")

ACTIVE = "active"
EXPIRED = "expired"
REVOKED = "revoked"


class AccessError(ValueError):
    """A bad change of the record. The message is one sentence for people."""


@dataclass(frozen=True)
class Grant:
    id: str
    name: str
    spaces: tuple[str, ...]
    added_at: str
    recipient_class: str = CLOUD
    tools: tuple[str, ...] = READ_TOOLS
    daily_chars: int = DAILY_CHARS
    expires: str | None = None
    last_used: str | None = None
    revoked_at: str | None = None
    http: str | None = None

    @property
    def recipient(self) -> str:
        return RECIPIENT[self.recipient_class].format(name=self.name)

    @property
    def adapter(self) -> str:
        return f"{ADAPTER}:{self.id}"

    def state(self, today: date) -> str:
        if self.revoked_at is not None:
            return REVOKED
        if self.expires is not None and today.isoformat() >= self.expires:
            return EXPIRED
        return ACTIVE

    def json(self) -> dict:
        return {
            "added_at": self.added_at,
            "daily_chars": self.daily_chars,
            "expires": self.expires,
            "http": self.http,
            "id": self.id,
            "last_used": self.last_used,
            "name": self.name,
            "recipient_class": self.recipient_class,
            "revoked_at": self.revoked_at,
            "spaces": list(self.spaces),
            "tools": list(self.tools),
        }

    def view(self, today: date) -> dict:
        """The grant for the local UI: no key hash."""
        out = self.json()
        out["http"] = self.http is not None
        out["recipient"] = self.recipient
        out["state"] = self.state(today)
        return out


# ------------------------------------------------------------------ record


def _grant(row: dict) -> Grant:
    return Grant(
        id=str(row["id"]),
        name=str(row["name"]),
        spaces=tuple(row.get("spaces") or ()),
        added_at=str(row.get("added_at") or ""),
        recipient_class=row.get("recipient_class")
        if row.get("recipient_class") in CLASSES
        else CLOUD,  # fmt: skip
        tools=tuple(t for t in row.get("tools") or () if t in TOOLS),
        daily_chars=int(row.get("daily_chars") or DAILY_CHARS),
        expires=row.get("expires"),
        last_used=row.get("last_used"),
        revoked_at=row.get("revoked_at"),
        http=row.get("http"),
    )


def _from_v1(old: dict) -> dict:
    limit = int(old.get("daily_chars") or DAILY_CHARS)
    rows = []
    for a in old.get("assistants") or []:
        if not isinstance(a, dict) or not a.get("id") or not a.get("name"):
            continue
        rows.append(
            Grant(
                id=str(a["id"]),
                name=str(a["name"]),
                spaces=tuple(a.get("spaces") or ()),
                added_at=str(a.get("added_at") or ""),
                daily_chars=limit,
                last_used=a.get("last_used"),
            ).json()
        )
    return {"grants": rows, "version": VERSION}


def _doc(index: Any) -> dict:
    doc = index.store.get_meta(META)
    if isinstance(doc, dict) and doc.get("version") == VERSION:
        doc.setdefault("grants", [])
        return doc
    old = index.store.get_meta(V1_META)
    doc = _from_v1(old if isinstance(old, dict) else {})
    if old is not None:  # migrate once (grant v2 replaces the meta key `mcp`)
        with index.store.transaction():
            index.store.set_meta(META, doc)
            usage = index.store.get_meta(V1_USAGE)
            if isinstance(usage, dict):
                index.store.set_meta(USAGE, usage)
            index.store.x("DELETE FROM meta WHERE key IN (?, ?)", (V1_META, V1_USAGE))
    return doc


def _save(index: Any, doc: dict) -> None:
    rows = doc["grants"]
    revoked = [r for r in rows if r.get("revoked_at")]
    while len(rows) > MAX_ROWS and revoked:
        rows.remove(revoked.pop(0))
    index.store.set_meta(META, doc)


def grants(index: Any) -> list[Grant]:
    """Each grant, also the revoked ones, in the order of adding."""
    return [_grant(r) for r in _doc(index)["grants"]]


def find(index: Any, grant_id: str) -> Grant | None:
    return next((g for g in grants(index) if g.id == grant_id), None)


def find_by_key(index: Any, key: str) -> Grant | None:
    """The grant whose loopback HTTP key is `key` (constant-time compare)."""
    if not isinstance(key, str) or not key:
        return None
    digest = hashlib.sha256(key.encode()).hexdigest()
    found = None
    for g in grants(index):
        if g.http is not None and hmac.compare_digest(g.http, digest):
            found = g
    return found


# ------------------------------------------------------------------ inputs


def _name(name: object) -> str:
    text = " ".join(str(name or "").split())
    if not text:
        raise AccessError("Type the name of the assistant.")
    if len(text) > MAX_NAME:
        raise AccessError(f"Type at most {MAX_NAME} characters.")
    return text


def _spaces(spaces: object) -> tuple[str, ...]:
    if not isinstance(spaces, list) or not spaces:
        raise AccessError("Choose one place or more.")
    out = []
    for s in spaces:
        try:
            out.append(source_state.check_space(s))
        except source_state.SourceStateError:
            raise AccessError("Choose a place from the list.") from None
    return tuple(sorted(set(out)))


def _class(value: object) -> str:
    if value not in CLASSES:
        raise AccessError("Say if the assistant runs on this computer only.")
    return str(value)


def _tools(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not value:
        raise AccessError("Choose one tool or more.")
    for t in value:
        if t in NEGOTIATION:
            raise AccessError(
                "In this version only Anagram on this computer talks to other agents."
                " An assistant can prepare drafts for you."
            )
        if t not in TOOLS:
            raise AccessError("Choose a tool from the list.")
    return tuple(t for t in TOOLS if t in value)  # the order of TOOLS


def _expires(value: object, today: date) -> str | None:
    if value in (None, ""):
        return None
    try:
        day = date.fromisoformat(str(value))
    except ValueError:
        raise AccessError("Give the end date as a date, for example 2027-02-17.") from None
    if day <= today:
        raise AccessError("Choose an end date after today.")
    return day.isoformat()


def _daily(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= MAX_DAILY_CHARS:
        raise AccessError(f"Choose a daily limit from 1 to {MAX_DAILY_CHARS:,} characters.")
    return value


def _active(doc: dict, today: date) -> list[Grant]:
    return [g for g in map(_grant, doc["grants"]) if g.state(today) == ACTIVE]


# ----------------------------------------------------------------- changes


def add(  # noqa: PLR0913 (one keyword for each field that the person sets)
    index: Any,
    name: object,
    spaces: object,
    now: str,
    *,
    recipient_class: object = CLOUD,
    tools: object = READ_TOOLS,
    expires: object = None,
    daily_chars: object = DAILY_CHARS,
) -> Grant:
    today = date.fromisoformat(now[:10])
    text = _name(name)
    checked_spaces = _spaces(spaces)
    checked_class = _class(recipient_class)
    checked_tools = _tools(tools)
    checked_daily = _daily(daily_chars)
    checked_expires = _expires(expires, today)
    with index.store.transaction():
        doc = _doc(index)
        active = _active(doc, today)
        if len(active) >= MAX_ACTIVE:
            raise AccessError(f"Anagram permits at most {MAX_ACTIVE} assistants.")
        if any(g.name.lower() == text.lower() for g in active):
            raise AccessError("An assistant has this name. Give this one a new name.")
        taken = {r["id"] for r in doc["grants"]}
        gid = secrets.token_hex(8)
        while gid in taken:
            gid = secrets.token_hex(8)
        got = Grant(
            id=gid,
            name=text,
            spaces=checked_spaces,
            added_at=now,
            recipient_class=checked_class,
            tools=checked_tools,
            daily_chars=checked_daily,
            expires=checked_expires,
        )
        doc["grants"].append(got.json())
        _save(index, doc)
    return got


_UNSET = object()


def change(  # noqa: PLR0913
    index: Any,
    grant_id: str,
    spaces: object = _UNSET,
    *,
    today: date | None = None,
    recipient_class: object = _UNSET,
    tools: object = _UNSET,
    expires: object = _UNSET,
    daily_chars: object = _UNSET,
) -> Grant:
    """Change a grant that is not revoked. An expired grant can get a new end
    date. A field that is not given stays."""
    today = today or date.today()
    with index.store.transaction():
        doc = _doc(index)
        for n, row in enumerate(doc["grants"]):
            g = _grant(row)
            if g.id != grant_id or g.revoked_at is not None:
                continue
            if spaces is not _UNSET:
                g = replace(g, spaces=_spaces(spaces))
            if recipient_class is not _UNSET:
                g = replace(g, recipient_class=_class(recipient_class))
            if tools is not _UNSET:
                g = replace(g, tools=_tools(tools))
            if expires is not _UNSET:
                g = replace(g, expires=_expires(expires, today))
            if daily_chars is not _UNSET:
                g = replace(g, daily_chars=_daily(daily_chars))
            doc["grants"][n] = g.json()
            _save(index, doc)
            return g
    raise KeyError(grant_id)


def revoke(index: Any, grant_id: str, now: str) -> Grant:
    """End a grant at once. The row stays (the log keeps the name); the HTTP
    key stops working."""
    with index.store.transaction():
        doc = _doc(index)
        for n, row in enumerate(doc["grants"]):
            g = _grant(row)
            if g.id == grant_id and g.revoked_at is None:
                g = replace(g, revoked_at=now, http=None)
                doc["grants"][n] = g.json()
                _save(index, doc)
                usage = index.store.get_meta(USAGE) or {}
                if isinstance(usage, dict) and usage.pop(grant_id, None) is not None:
                    index.store.set_meta(USAGE, usage)
                return g
    raise KeyError(grant_id)


def new_http_key(index: Any, grant_id: str) -> str:
    """A new bearer key for loopback HTTP. The record keeps its SHA-256 only;
    the caller shows the key one time. An older key stops working."""
    key = secrets.token_urlsafe(32)
    with index.store.transaction():
        doc = _doc(index)
        for row in doc["grants"]:
            if row["id"] == grant_id and not row.get("revoked_at"):
                row["http"] = hashlib.sha256(key.encode()).hexdigest()
                _save(index, doc)
                return key
    raise KeyError(grant_id)


# ------------------------------------------------------------------- usage


def used_today(index: Any, grant_id: str, today: str) -> int:
    usage = index.store.get_meta(USAGE) or {}
    row = usage.get(grant_id) if isinstance(usage, dict) else None
    if not isinstance(row, dict) or row.get("day") != today:
        return 0
    return int(row.get("chars") or 0)


def try_note_use(index: Any, grant_id: str, chars: int, limit: int, today: str, now: str) -> bool:
    """Atomically check the daily limit and record `chars` if within `limit`."""
    with index.store.transaction():
        before = used_today(index, grant_id, today)
        if before + int(chars) > limit:
            return False
        usage = index.store.get_meta(USAGE) or {}
        if not isinstance(usage, dict):
            usage = {}
        usage[grant_id] = {"chars": before + int(chars), "day": today}
        index.store.set_meta(USAGE, usage)
        doc = _doc(index)
        for row in doc["grants"]:
            if row["id"] == grant_id:
                row["last_used"] = now
        index.store.set_meta(META, doc)
        return True


def note_use(index: Any, grant_id: str, chars: int, today: str, now: str) -> None:
    """Add `chars` to the count of today, and set `last_used`."""
    with index.store.transaction():
        usage = index.store.get_meta(USAGE) or {}
        if not isinstance(usage, dict):
            usage = {}
        before = used_today(index, grant_id, today)
        usage[grant_id] = {"chars": before + int(chars), "day": today}
        index.store.set_meta(USAGE, usage)
        doc = _doc(index)
        for row in doc["grants"]:
            if row["id"] == grant_id:
                row["last_used"] = now
        index.store.set_meta(META, doc)
