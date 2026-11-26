"""The labs of the local UI (layer L3).

`LabUI` gives the screens of the lab: members, invites, roles, the lab space,
and the settings. The routes are in `shell/ui/routers/labs.py`. Rules:

- A response holds no path, no device key, no record ID, and no key bytes.
  A person is `{"id", "name"}` (and `"you"` for the person at this computer).
  The `id` lets the screen act on a person; the screen does not show it.
- Each action publishes its live event on the bus, so that a
  second page of the same person gets the change at once. The task
  `lab.watch` (`shell/ui/labwatch.py`) publishes the changes of other members.
- An error is one sentence with one next step (`LabError` text).
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from anagram.admission.api import (
    DEFAULT_INVITE_DAYS,
    lab_invite_id,
    parse_lab_invite_link,
)
from anagram.core.errors import FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import parse_time
from anagram.local.api import kind_label
from anagram.models.profile import PROVIDERS
from anagram.network.api import (
    ADMIN,
    MAX_ITEM_TITLE,
    MEMBER,
    PI,
    LabError,
    LabItemDraft,
    publish_index_item,
    sync_lab_index,
)
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.source_kinds import KINDS

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

ROLE_ACTIONS = (
    "invite",
    "invite_admin",
    "revoke_invite",
    "add",
    "remove",
    "role",
    "transfer",
    "settings",
    "rename",
    "tombstone",
    "publish",
)
MAX_NOTE = 200_000  # characters of a note that a person types


def _iso(at: str | None) -> str | None:
    if not at:
        return None
    try:
        return parse_time(at).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (FormatError, ValueError, TypeError):
        return None


class LabUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self.publish = ui.publish

    # ------------------------------------------------------------ people

    def _names(self, fresh: bool = False) -> dict[str, str]:
        return self.ui.people.names(fresh)

    @staticmethod
    def _person(pid: str | None, names: dict[str, str], me: str) -> dict | None:
        if not pid:
            return None
        return {"id": pid, "name": names.get(pid) or "A member", "you": pid == me}

    # -------------------------------------------------------------- labs

    def mine(self) -> list[dict]:
        """The labs of this person: the verified cache, completed from the
        node list (a lab that this device has not seen yet)."""
        with self.ui.session() as c:
            rows = {r["lab_id"]: r for r in c.labs.lab_list()}
            try:
                listed = [x for x in (c.account.whoami().get("labs") or []) if isinstance(x, str)]
            except NodeHTTPError:
                listed = []
            fetched = False
            for lab_id in listed:
                if lab_id in rows or c.lab_roster.labcache.left(lab_id):
                    continue
                try:
                    c.lab_roster.lab_state(lab_id)
                    fetched = True
                except LabError:
                    continue
            if fetched:
                rows = {r["lab_id"]: r for r in c.labs.lab_list()}
        return [
            {
                "i_lead": r["role"] == PI,  # read by the old welcome code
                "id": r["lab_id"],
                "members": r["members"],
                "name": r["name"],
                "role": r["role"],
                "rotation_due": r["rotation_due"],
            }
            for r in sorted(rows.values(), key=lambda r: r["name"].lower())
        ]

    def create(self, name: Any) -> dict:
        if not isinstance(name, str) or not name.strip():
            raise UIError(400, "Give the lab a name.")
        # Two labs of one person with one name cannot be told apart on screen.
        if any(lab["name"].strip().lower() == name.strip().lower() for lab in self.mine()):
            raise UIError(
                409, "You already have a lab with this name. Give the new lab another name."
            )
        with self.ui.session() as c:
            lab_id = c.labs.lab_create(name)["lab_id"]
        self.publish("lab.members", {"change": "joined", "lab": lab_id})
        return self.view(lab_id)

    def view(self, lab_id: str) -> dict:
        """The lab with its members, open invites, and actions of my role."""
        names = self._names()
        with self.ui.session() as c:
            try:
                state = c.lab_roster.lab_state(lab_id)
            except LabError as exc:
                raise UIError(404, "You are not in this lab.") from exc
            me = c.device.subject
            role = state.members.get(me)
            due = c.lab_keys.rotation_due(state)
            epoch = c.lab_roster.labcache.epoch(state.lab_id)
            now = c.device.now()
        if any(pid not in names for pid in state.members):
            names = self._names(fresh=True)
        can = {a: state.can(me, a) for a in ROLE_ACTIONS}
        can["invite_admin"] = state.can(me, "invite", ADMIN)
        can["leave"] = role in (ADMIN, MEMBER)
        members = []
        order = {PI: 0, ADMIN: 1, MEMBER: 2}
        for pid, r in sorted(
            state.members.items(), key=lambda kv: (order[kv[1]], names.get(kv[0], "").lower())
        ):
            members.append(
                {
                    "can_remove": pid != me and state.can(me, "remove", r),
                    "joined_at": _iso(state.times.get(pid)),
                    # Who vouched; a PI or admin sees it.
                    "invited_by": self._person(state.invited_by[pid], names, me)
                    if can["invite"] and pid in state.invited_by and pid != me
                    else None,
                    "person": self._person(pid, names, me),
                    "role": r,
                    "you": pid == me,
                }
            )
        invites = []
        if can["invite"]:
            for iid in reversed(state.open_invites(now)):
                inv = state.invites[iid]
                auth = inv["auth"]
                invites.append(
                    {
                        "by": self._person(auth["created_by"], names, me),
                        "expires_at": _iso(auth["expires_at"]),
                        "id": iid,
                        "max_uses": auth["max_uses"],
                        "role": auth["role"],
                        "uses": inv["uses"],
                    }
                )
        return {
            "can": can,
            "id": state.lab_id,
            "invites": invites,
            "key": {"epoch": epoch, "rotation_due": due},
            "members": members,
            "name": state.name,
            "role": role,
        }

    def rename(self, lab_id: str, name: Any) -> dict:
        if not isinstance(name, str) or not name.strip():
            raise UIError(400, "Give the lab a name.")
        with self.ui.session() as c:
            c.labs.lab_rename(lab_id, name)
        self.publish("lab.members", {"change": "renamed", "lab": lab_id})
        return self.view(lab_id)

    # ----------------------------------------------------------- invites

    def invite(self, lab_id: str, body: dict) -> dict:
        role = body.get("role") or MEMBER
        uses = body.get("max_uses", 1)
        days = body.get("expires_days", DEFAULT_INVITE_DAYS)
        with self.ui.session() as c:
            out = c.admission.lab_invite(lab_id, role=role, max_uses=uses, expires_days=days)
        self.publish("lab.invites", {"lab": lab_id})
        return {"expires_at": _iso(out["expires_at"]), "id": out["invite_id"], "url": out["url"]}

    def revoke(self, lab_id: str, invite_id: str) -> dict:
        with self.ui.session() as c:
            state = c.lab_roster.lab_state(lab_id)
            if invite_id not in state.invites:
                raise UIError(404, "This invite link is closed already.")
            c.admission.lab_revoke_invite(lab_id, invite_id)
        self.publish("lab.invites", {"lab": lab_id})
        return self.view(lab_id)

    def _link(self, url: str | None) -> str:
        if url:
            return url
        pending = self.ui.state.get("pending_invite") or {}
        if pending.get("kind") == "lab" and pending.get("url"):
            return pending["url"]
        raise UIError(404, "There is no lab invite to open. Open the invite link again.")

    def preview(self, url: str | None = None) -> dict:
        """What the person sees before the join: the lab, the role, who
        invited, the end date, and the node. No key and no ID."""
        link = self._link(url)
        try:
            auth = parse_lab_invite_link(link)["auth"]
        except FormatError as exc:
            raise UIError(400, "This is not a lab invite link. Copy the full link.") from exc
        out = {
            "by": None,
            "expires_at": _iso(auth["expires_at"]),
            "host": urllib.parse.urlsplit(auth["node_url"]).hostname,
            "lab": auth["lab_name"],
            "member": False,
            "open": parse_time(auth["expires_at"]).timestamp() > self.ui.clock(),
            "role": auth["role"],
        }
        if not self.ui.joined():
            return out
        names = self._names()
        out["by"] = names.get(auth["created_by"])
        with self.ui.session() as c:
            if auth["node_key"] != c.device.identity_config().get("node_key"):
                raise UIError(400, "This invite link is for another node.")
            out["member"] = any(r["lab_id"] == auth["lab_id"] for r in c.labs.lab_list())
            out["id"] = auth["lab_id"] if out["member"] else None
            iid = lab_invite_id(auth)
            try:
                info = c.device.http.call("GET", f"/labs/invites/{iid}", auth=True)
                out["open"] = bool(info.get("open")) and out["open"]
            except NodeHTTPError:
                out["open"] = False
        return out

    def join(self, url: str | None = None) -> dict:
        """Join a lab with a link (no `url`: the pending lab invite)."""
        if not self.ui.joined():
            return {"signin": True}
        link = self._link(url)
        pending = self.ui.state.get("pending_invite") or {}
        with self.ui.session(index=True) as (c, idx):
            got = c.admission.lab_join(link)
            try:
                c.labs.lab_sync(got["lab_id"])
                sync_lab_index(c.lab_context, idx, scan=False)
            except (LabError, NodeHTTPError):
                pass  # the task `lab.watch` does it again
        if pending.get("url") == link:
            self.ui.state.update(pending_invite=None)
        self.publish("lab.members", {"change": "joined", "lab": got["lab_id"]})
        return {"id": got["lab_id"], "name": got["name"], "role": got["role"]}

    # ----------------------------------------------------------- members

    def add(self, lab_id: str, body: dict) -> dict:
        who, role = body.get("person"), body.get("role") or MEMBER
        if not isinstance(who, str) or not who:
            raise UIError(400, "Choose a person from the search results.")
        with self.ui.session() as c:
            c.labs.lab_add(lab_id, who, role)
        self.publish("lab.members", {"change": "added", "lab": lab_id})
        return self.view(lab_id)

    def remove(self, lab_id: str, pid: str) -> dict:
        with self.ui.session() as c:
            c.labs.lab_remove(lab_id, pid)
        self.publish("lab.members", {"change": "removed", "lab": lab_id})
        self.publish("lab.key", {"lab": lab_id, "rotation_due": False})
        return self.view(lab_id)

    def change(self, lab_id: str, pid: str, body: dict) -> dict:
        with self.ui.session() as c:
            if body.get("transfer") is True:
                c.labs.lab_transfer(lab_id, pid)
                change = "transfer"
            elif body.get("role") in (ADMIN, MEMBER):
                c.labs.lab_set_role(lab_id, pid, body["role"])
                change = "role"
            else:
                raise UIError(400, "Choose the role admin or member.")
        self.publish("lab.members", {"change": change, "lab": lab_id})
        return self.view(lab_id)

    def leave(self, lab_id: str) -> dict:
        with self.ui.session(index=True) as (c, idx):
            name = c.lab_roster.lab_state(lab_id).name
            c.labs.lab_leave(lab_id)
            try:
                sync_lab_index(c.lab_context, idx, scan=False)
            except (LabError, NodeHTTPError):
                pass
        self.publish("lab.removed", {"lab": lab_id, "name": name})
        return {"left": True}

    # ---------------------------------------------------------- settings

    def settings(self, lab_id: str) -> dict:
        names = self._names()
        with self.ui.session() as c:
            got = c.lab_space.lab_settings(lab_id)
            state = c.lab_roster.labcache.state(lab_id)
            me = c.device.subject
        can_edit = bool(state and state.can(me, "settings"))
        sections = got["sections"]
        recipients = [
            {
                "external": True,
                "id": f"model:{p.get('id')}",
                "name": p.get("label") or p.get("model"),
            }
            for p in (sections.get("models") or {}).get("profiles") or []
            if isinstance(p, dict) and p.get("id")
        ]
        return {
            "can_edit": can_edit,
            "editors": [
                self._person(pid, names, me)["name"]
                for pid, r in sorted((state.members if state else {}).items())
                if r in (PI, ADMIN)
            ],
            "providers": list(PROVIDERS),
            "recipients": recipients,
            "settings": sections,
            "source_kinds": [
                {"kind": k, "label": kind_label(k)}
                for k, info in KINDS.items()
                if "lab" in info.spaces
            ],
            "updated_at": _iso(got["updated_at"]),
            "updated_by": self._person(got["updated_by"], names, me),
        }

    def set_settings(self, lab_id: str, body: dict) -> dict:
        if not isinstance(body, dict) or not body:
            raise UIError(400, "Choose a setting to change.")
        with self.ui.session() as c:
            got = c.lab_space.lab_set_settings(lab_id, body)
        self.publish("lab.settings", {"lab": lab_id, "rev": got["rev"]})
        return self.settings(lab_id)

    # --------------------------------------------------------- lab space

    def _row(self, value: dict, names: dict[str, str], me: str) -> dict:
        return {
            "attachments": len(value.get("attachments") or []),
            "author": self._person(value["author"], names, me),
            "id": value["item_id"],
            "kind": value["kind"],
            "published_at": _iso(value["published_at"]),
            "title": value["title"],
            "type": value.get("type"),
            "updated_at": _iso(value.get("updated_at")),
            "yours": value["author"] == me,
        }

    def space(self, lab_id: str, after: int = 0, limit: int = 100) -> dict:
        names = self._names()
        with self.ui.session() as c:
            values = c.lab_space.lab_items(lab_id)
            c.lab_roster.member_cache(c.lab_roster.check_lab_id(lab_id))
            me = c.device.subject
        values.sort(key=lambda v: (v["published_at"], v["item_id"]), reverse=True)
        limit = max(1, min(int(limit), 200))
        after = max(0, int(after))
        page = values[after : after + limit]
        nxt = after + len(page) if after + len(page) < len(values) else None
        return {"items": [self._row(v, names, me) for v in page], "next": nxt}

    def item(self, lab_id: str, item_id: str) -> dict:
        names = self._names()
        with self.ui.session() as c:
            got = c.lab_space.lab_item(lab_id, item_id)
            state = c.lab_roster.labcache.state(c.lab_roster.check_lab_id(lab_id))
            me = c.device.subject
        value = got["item"]
        out = {
            "attachments": [
                {"media_type": a.get("media_type"), "n": n, "name": a["name"], "size": a["size"]}
                for n, a in enumerate(value.get("attachments") or [])
            ],
            "can_remove": value["author"] == me or bool(state and state.can(me, "tombstone")),
            "item": self._row(value, names, me),
            "text": got["text"],
        }
        finding = value.get("finding")
        if isinstance(finding, dict):
            out["finding"] = {"claim": finding.get("claim")}
        return out

    def put(self, lab_id: str, body: dict) -> dict:
        """Put an item into the lab space: an indexed item of mine
        (`{"item": "item:<n>"}` or `{"source", "key"}`), a finding
        (`{"finding": root}`), or a note (`{"note": {"title", "text"}}`)."""
        names = self._names()
        attach = body.get("attach") is True
        with self.ui.session(index=True) as (c, idx):
            if isinstance(body.get("note"), dict):
                note = body["note"]
                title, text = note.get("title"), note.get("text")
                if not isinstance(title, str) or not title.strip():
                    raise UIError(400, "Give the note a title.")
                if not isinstance(text, str) or len(text) > MAX_NOTE:
                    raise UIError(400, "A note has at most 200,000 characters.")
                item_id = c.lab_space.lab_publish(
                    lab_id,
                    LabItemDraft(kind="note", title=title.strip(), text=text, origin={}),
                )
            elif isinstance(body.get("finding"), str):
                item_id = self._put_finding(c, lab_id, body["finding"])
            else:
                sid, key = self._source_key(idx, body)
                item_id = publish_index_item(
                    c.lab_context, idx, c.lab_roster.check_lab_id(lab_id), sid, key, attach
                )
            value = c.lab_space.lab_item(lab_id, item_id)["item"]
            me = c.device.subject
        self.publish("lab.space", {"change": "published", "item": item_id, "lab": lab_id})
        return self._row(value, names, me)

    @staticmethod
    def _source_key(idx: Any, body: dict) -> tuple[str, str]:
        ref = body.get("item")
        if isinstance(ref, str) and ref.startswith("item:") and ref[5:].isdigit():
            row = idx.store.one("SELECT source_id, key FROM item WHERE id = ?", (int(ref[5:]),))
            if row is None:
                raise UIError(404, "This item is not in your library.")
            return row[0], row[1]
        sid, key = body.get("source"), body.get("key")
        if not isinstance(sid, str) or not isinstance(key, str):
            raise UIError(400, "Choose an item from your library.")
        return sid, key

    @staticmethod
    def _put_finding(c: Any, lab_id: str, root: str) -> str:
        try:
            row = c.vault.find(root)
        except (KeyError, ValueError) as exc:
            raise UIError(404, "This finding is not on this computer.") from exc
        claim = (c.findings.opening(row.root).finding.fields.get("claim") or "").strip()
        title = claim.splitlines()[0][:MAX_ITEM_TITLE] if claim else "Finding"
        return c.lab_space.lab_publish(
            lab_id,
            LabItemDraft(
                kind="finding",
                title=title,
                text=claim,
                origin={},
                finding_root=row.root,
            ),
        )

    def file(self, lab_id: str, item_id: str, n: int) -> tuple[str, str, bytes]:
        """One attachment of a lab item: (name, media type, bytes)."""
        with self.ui.session() as c:
            return c.lab_space.lab_file(lab_id, item_id, n)

    def unpublish(self, lab_id: str, item_id: str) -> dict:
        with self.ui.session() as c:
            c.lab_space.lab_unpublish(lab_id, item_id)
        self.publish("lab.space", {"change": "removed", "item": item_id, "lab": lab_id})
        return {"removed": True}
