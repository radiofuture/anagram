"""Sharing in the local UI (layer L3):
share targets, sharing with people and labs, reader invites, the history,
"Shared with me", the reading model, and the task `shares.sync`. The routes
are in `shell/ui/routers/sharing.py`.

Received work stays encrypted on disk: the views read through
`open_received`, and an original file is decrypted in memory. A file that can
hold a script (HTML, SVG, and each type that is not PDF, an image, or text)
is sent as an attachment, never inline.

Live events go to `UIService.publish` . The task
`shares.sync` calls `Client.share_sync.sync_shares` every 60 s while a page is
open or a reader invite waits, else every 15 minutes. Its first run moves old
plaintext folders of `received/` into the encrypted store
(`migrate_received`).

The rings and the inbox are the sharing of the first screens (`/api/rings`,
`/api/inbox`, `/api/findings/{root}/share`); "Open and check" of the inbox
reads through the encrypted store too (`open_inbox`).
"""

from __future__ import annotations

import logging
import re
import threading
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi.responses import Response, StreamingResponse

from anagram.core.canonical import canonical_json
from anagram.core.errors import ClientError
from anagram.core.timefmt import epoch_text
from anagram.identity.api import is_subject
from anagram.network.api import COMMUNITY, PUBLIC, ThirdPartyWarning
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.people import typed_orcid

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.ui.sharing")

GRANT_ID = re.compile(r"^[0-9a-f]{32}$")
FIGURE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_TARGETS = 50
FAST_S = 60.0  # a page is open, or a reader invite waits for its claim
SLOW_S = 900.0
# Shown inline in the browser: PDF, images that cannot hold a script, plain
# text. Each other type (HTML and SVG too) is an attachment.
INLINE = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp"}
RECEIVED_DIR = "received"
# Default rings, inner to outer. "My lab" gets the lab when the person picks one.
DEFAULT_RINGS = (
    ("My lab", []),
    ("Collaborators", []),
    ("Community", [COMMUNITY]),
    ("Public", [PUBLIC]),
)


def disposition(kind: str, name: str) -> str:
    ascii_name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:120] or "file"
    return f"{kind}; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name)}"


def _ack(body: dict) -> bool:
    return body.get("ack_third_party") is True


class SharingUI:
    """It uses `ui.session()` for a request and `ui.open_client()` for the task."""

    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self.publish = ui.publish
        self.open_invites = False
        self._migrated = False
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- labels

    def label(self, subject: str | None) -> str:
        """A name for a person. Never a raw ID on the screen."""
        if not subject:
            return "A member"
        name = self.ui.people.label(subject)
        return "A member" if name == subject else name

    def _lab_names(self, c) -> dict[str, str]:
        try:
            return {lab["lab_id"]: lab["name"] for lab in c.labs.lab_list()}
        except Exception:  # a lab cache fault leaves the plain word
            return {}

    def _history_view(self, rows: list[dict], labs: dict[str, str]) -> list[dict]:
        out = []
        for h in rows:
            person = dict(h["person"])
            if person["kind"] == "lab":
                lab_id = h["target"].removeprefix("lab:")
                person["label"] = f"Everyone in {labs.get(lab_id, 'your lab')}"
            elif person["kind"] == "member":
                person["label"] = self.label(person["subject"])
            out.append({**h, "person": person})
        return out

    def _finding_id(self, c, ref: str) -> str:
        return c.vault.find(ref).finding_id

    # --------------------------------------------------------------- targets

    def targets(self, q: str) -> list[dict]:
        q = (q or "").strip()
        if len(q) > 254:
            raise UIError(400, "Type less text.")
        out = []
        typed = typed_orcid(q.lower())
        if typed:
            out.append({"detail": "ORCID iD", "id": f"orcid:{typed}", "kind": "invite_orcid",
                        "label": typed})  # fmt: skip
        elif "@" in q and " " not in q and not q.startswith("@"):
            email = q.lower()
            out.append({"detail": "Email address", "id": f"email:{email}",
                        "kind": "invite_email", "label": email})  # fmt: skip
        for p in self.ui.people.search(q):
            if is_subject(p["id"]):
                out.append({**p, "kind": "person"})
        with self.ui.session() as c:
            labs = c.labs.lab_list()
        for lab in labs:
            if q.lower() in lab["name"].lower():
                out.append({"detail": "Your lab", "id": f"lab:{lab['lab_id']}", "kind": "lab",
                            "label": f"Everyone in {lab['name']}"})  # fmt: skip
        return out

    # ------------------------------------------------------- share and stop

    def _third_party(self, root: str, exc: ThirdPartyWarning) -> UIError:
        with self.ui.session() as c:
            items = c.grants.third_party_items(root)
        return UIError(409, str(exc), {"third_party": items})

    def share(self, root: str, body: dict) -> dict:
        targets = body.get("targets")
        if (
            not isinstance(targets, list)
            or not 0 < len(targets) <= MAX_TARGETS
            or not all(isinstance(t, str) for t in targets)
        ):
            raise UIError(400, "Choose at least one person or lab.")
        with_included = body.get("with_included", True) is not False
        ack = _ack(body)
        invited, delivered = [], []
        try:
            with self.ui.session() as c:
                fid = self._finding_id(c, root)
                people, contacts = [], []
                for t in targets:
                    if t.startswith(("email:", "orcid:")):
                        found = c.shares.resolve_target(t.split(":", 1)[1])
                        if found["kind"] == "person":
                            people.append(found["target"])
                        else:
                            contacts.append(found["label"])
                    elif t.startswith("lab:") or is_subject(t):
                        people.append(t)
                    else:
                        raise UIError(400, "Choose a person or a lab from the list.")
                out = {"shared": [], "waiting": []}
                if people:
                    out = c.shares.share(
                        root, people, with_included=with_included, warnings_ack=ack
                    )
                for contact in contacts:
                    got = c.invites.invite_reader(
                        root, contact, with_included=with_included, warnings_ack=ack
                    )
                    invited.append({**got, "label": contact})
                labs = self._lab_names(c)
        except ThirdPartyWarning as exc:
            raise self._third_party(root, exc) from exc
        shared = []
        for s in out["shared"]:
            if s["target"].startswith("lab:"):
                name = labs.get(s["target"].removeprefix("lab:"), "your lab")
                shared.append({"label": f"Everyone in {name}", "people": s["people"],
                               "target": s["target"]})  # fmt: skip
            else:
                delivered.append(s["target"])
                shared.append({"label": self.label(s["target"]), "people": 1,
                               "target": s["target"]})  # fmt: skip
        for subject in delivered:
            self.publish("share.delivered", {"finding_id": fid, "subject": subject})
        if invited:
            self.open_invites = True
        self.publish("finding.changed")
        return {
            "finding": self.ui.library.finding(root),
            "invited": invited,
            "shared": shared,
            "waiting": [self.label(s) for s in out["waiting"]],
        }

    def audience(self, root: str) -> dict:
        with self.ui.session() as c:
            row = c.vault.find(root)
            rows = c.read_records.history(finding_id=row.finding_id)
            versions = [
                {"created_at": r.created_at, "root": r.root, "version": r.version}
                for r in sorted(c.vault.list(), key=lambda r: r.version)
                if r.finding_id == row.finding_id
            ]
            labs = self._lab_names(c)
        return {"audience": self._history_view(rows, labs), "versions": versions[::-1]}

    def stop(self, root: str, body: dict) -> dict:
        target = body.get("target")
        if not isinstance(target, str) or not target:
            raise UIError(400, "Choose whom to stop sharing with.")
        with self.ui.session() as c:
            out = c.shares.stop_sharing(root, target)
        self.publish("share.stopped", {"finding_id": out["finding_id"], "target": target})
        self.publish("finding.changed")
        return {"finding": self.ui.library.finding(root), "stopped": target}

    def rekey(self, root: str, body: dict) -> dict:
        try:
            with self.ui.session() as c:
                out = c.shares.rekey_now(root, warnings_ack=_ack(body))
        except ThirdPartyWarning as exc:
            raise self._third_party(root, exc) from exc
        self.publish("finding.changed")
        return {"finding": self.ui.library.finding(out["root"])}

    def follow(self, root: str) -> dict:
        """After a commit: the new version goes to the people and labs that
        have the finding (`sharing.follow_versions`). A version with a file of
        another person is not sent with no acknowledgement."""
        try:
            with self.ui.session() as c:
                fid = self._finding_id(c, root)
                out = c.shares.share_new_version(root)
        except ThirdPartyWarning:
            return {"held": True, "labs": 0, "people": 0, "waiting": 0}
        except UIError as exc:
            log.info("a new version did not go to the audience: %s", exc.status)
            return {"held": True, "labs": 0, "people": 0, "waiting": 0}
        people = [s["target"] for s in out["shared"] if not s["target"].startswith("lab:")]
        for subject in people:
            self.publish("share.delivered", {"finding_id": fid, "subject": subject})
        return {
            "held": False,
            "labs": len(out["shared"]) - len(people),
            "people": len(people),
            "waiting": len(out["waiting"]),
        }

    # --------------------------------------------------------------- history

    def history(self, finding: str | None, person: str | None) -> list[dict]:
        with self.ui.session() as c:
            fid = self._finding_id(c, finding) if finding else None
            rows = c.read_records.history(finding_id=fid, person=person or None)
            labs = self._lab_names(c)
        return self._history_view(rows, labs)

    def record(self, finding_id: str, subject: str) -> tuple[str, str]:
        if not is_subject(subject):
            raise UIError(404, "No record for this person.")
        with self.ui.session() as c:
            fid = self._finding_id(c, finding_id)
            doc = c.read_records.share_record(fid, subject)

        safe = re.sub(r"[^A-Za-z0-9-]", "", fid)[:16] or "finding"
        return f"anagram-share-record-{safe}.json", canonical_json(doc).decode() + "\n"

    def preview(self, root: str) -> dict:
        with self.ui.session() as c:
            model = c.shares.preview(root)
        model["owner"]["label"] = "You"
        return model

    # --------------------------------------------------------- shared with me

    def _grant(self, grant_id: str) -> str:
        if not GRANT_ID.match(grant_id or ""):
            raise UIError(404, "Unknown shared finding.")
        return grant_id

    def shared(self) -> list[dict]:
        with self.ui.session() as c:
            rows = c.received.shared_with_me()
        return [{**r, "sender": self.label(r["sender"])} for r in rows]

    def open(self, grant_id: str) -> dict:
        gid = self._grant(grant_id)
        with self.ui.session() as c:
            model = c.received.read_shared(gid)
        model["owner"]["label"] = self.label(model["owner"]["subject"])
        return model

    def file(self, grant_id: str, slot: int) -> Response:
        gid = self._grant(grant_id)
        try:
            with self.ui.session() as c:
                item = c.received.received_item(gid, slot)
                pieces = c.received.received_file(gid, slot)
        except UIError as exc:
            if exc.status != 400:
                raise
            raise UIError(404, "No such file. Open the finding first.") from exc
        media = item["media_type"]
        if media in INLINE:
            kind, served = "inline", media
        elif media.startswith("text/") and media not in ("text/html", "text/xml"):
            kind, served = "inline", "text/plain; charset=utf-8"
        else:
            kind, served = "attachment", "application/octet-stream"
        return StreamingResponse(
            pieces,
            media_type=served,
            headers={"Content-Disposition": disposition(kind, item["name"])},
        )

    def figure(self, grant_id: str, slot: int, figure_id: str) -> Response:
        gid = self._grant(grant_id)
        if not FIGURE_ID.match(figure_id):
            raise UIError(404, "No such figure.")
        try:
            with self.ui.session() as c:
                media, data = c.received.received_figure(gid, slot, figure_id)
        except UIError as exc:
            if exc.status != 400:
                raise
            raise UIError(404, "No such figure. Open the finding first.") from exc
        headers = {}
        if media not in INLINE:  # an SVG figure draws in <img>; it never opens as a page
            headers["Content-Disposition"] = disposition("attachment", figure_id)
        return Response(data, media_type=media, headers=headers)

    def proof(self, grant_id: str) -> tuple[str, str]:
        gid = self._grant(grant_id)
        with self.ui.session() as c:
            text = c.received.received_proof(gid)
        return f"anagram-proof-{gid[:12]}.json", text

    def save(self, grant_id: str, body: dict) -> dict:
        gid = self._grant(grant_id)
        folder = body.get("folder")
        if not isinstance(folder, str) or not folder.strip():
            raise UIError(400, "Choose a folder.")
        target = Path(folder).expanduser()
        if not target.is_absolute():
            raise UIError(400, "Choose a folder.")
        with self.ui.session() as c:
            paths = c.received.save_received(gid, target)
        return {"files": [Path(p).name for p in paths]}

    def open_inbox(self, grant_id: str) -> dict:
        """The old "Open and check" of the sharing screen, through the
        encrypted received store. The view keeps its old keys; the files come
        from `/api/shared/<id>/files/<slot>`, and `reader` is the full page."""
        model = self.open(grant_id)
        view = {
            "claim": model["claim"],
            "details": {"receipt": None, "root": model["root"]},
            "files": [{"name": it["name"], "slot": it["slot"]} for it in model["items"]],
            "folder": None,
            "granted_at": model["granted_at"],
            "owner": model["owner"]["label"],
            "proven_by": model["proven_by"],
            "reader": f"/reader/#{grant_id}",
            "verified": model["verified"],
            "version": model["version"],
        }
        opened = dict(self.ui.state.get("opened") or {})
        opened[grant_id] = view
        self.ui.state.update(opened=opened)
        self.publish("resource.stale", {"paths": ["/api/inbox", "/api/shared"]})
        return view

    def inbox(self) -> list[dict]:
        opened = self.ui.state.get("opened") or {}
        with self.ui.session() as c:
            items = c.grants.inbox()
        return [
            {
                "files": g["blobs"],
                "for_this_device": g["for_this_device"],
                "id": g["grant_id"],
                "opened": opened.get(g["grant_id"]),
                "received_at": epoch_text(g["received_at"]),
                "sender": self.ui.people.label(g["sender"]),
            }
            for g in sorted(items, key=lambda g: g["received_at"], reverse=True)
        ]

    def received_file(self, grant_id: str, name: str) -> Path:
        """A file of a finding that an older version opened into `received/`."""
        if (
            not GRANT_ID.fullmatch(grant_id)
            or not name
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or name.startswith(".")
            or Path(name).name != name
        ):
            raise UIError(404, "This file is not in the finding.")
        base = self.ui.home / RECEIVED_DIR / grant_id
        p = base / name
        if p.is_symlink() or not p.is_file():
            raise UIError(404, "Open the finding first, then open the file.")
        if p.resolve().parent != base.resolve():
            raise UIError(404, "This file is not in the finding.")
        return p

    # ----------------------------------------------------------------- rings

    def _member_view(self, m: str) -> dict:
        if m == COMMUNITY:
            return {"id": m, "kind": "community", "label": "Everyone in this community"}
        if m == PUBLIC:
            return {"id": m, "kind": "public", "label": "Everyone (public)"}
        if m.startswith("lab:"):
            name = self.ui.people.lab_name(m.removeprefix("lab:"))
            return {"id": m, "kind": "lab", "label": f"Everyone in {name or 'the lab'}"}
        return {"id": m, "kind": "person", "label": self.ui.people.label(m)}

    def rings(self) -> list[dict]:
        with self.ui.session() as c:
            rings = c.grants.ring_list()
        return [
            {"members": [self._member_view(m) for m in r["members"]], "name": r["name"]}
            for r in rings
        ]

    def _ring_changed(self) -> list[dict]:
        out = self.rings()
        self.publish("ring.changed")
        return out

    def ring_add(self, ring: str, member: str) -> list[dict]:
        with self.ui.session() as c:
            c.grants.ring_add(ring, [member])
        return self._ring_changed()

    def ring_remove(self, ring: str, member: str) -> list[dict]:
        with self.ui.session() as c:
            c.grants.ring_remove(ring, [member])
        return self._ring_changed()

    def ring_create(self, name: str) -> list[dict]:
        with self.ui.session() as c:
            c.grants.ring_create(name.strip())
        return self._ring_changed()

    def share_ring(self, root: str, ring: str, ack: bool) -> dict:
        """Share a finding with a ring (`POST /api/findings/{root}/share`)."""
        try:
            with self.ui.session() as c:
                out = c.grants.grant(root, ring=ring, warnings_ack=ack)
        except ThirdPartyWarning as exc:
            raise self._third_party(root, exc) from exc
        view = {
            "finding": self.ui.library.finding(root),
            "public": bool(out["public"]),
            "shared": len(out["granted"]),
            "waiting": [self.ui.people.label(s) for s in out["skipped"]],
        }
        self.publish("finding.changed")
        return view

    def revoke_ring(self, root: str, ring: str, ack: bool) -> dict:
        try:
            with self.ui.session() as c:
                out = c.grants.revoke(root, ring=ring, warnings_ack=ack)
        except ThirdPartyWarning as exc:
            raise self._third_party(root, exc) from exc
        view = {"finding": self.ui.library.finding(out["root"]), "shared": len(out["granted"])}
        self.publish("finding.changed")
        return view

    # --------------------------------------------------------- reader claims

    def reader_claims(self) -> list[dict]:
        """Claims of reader invites that wait for the owner."""
        with self.ui.open_client() as c:
            rows = c.invites.reader_claims()
        return [
            {
                "contact": (r["contact"] or {}).get("value"),
                "email": r["email"],
                "id": r["invite_id"],
                "name": r["name"] or self.label(r["subject"]),
            }
            for r in rows
        ]

    def answer_claim(self, invite_id: str, give: bool) -> dict:
        with self._lock, self.ui.open_client() as c:
            try:
                out = c.invites.confirm_reader_claim(invite_id, give)
            except ClientError as exc:
                raise UIError(404, "This question has an answer already.") from exc
        self.publish("share.confirm", {"invite_id": invite_id})
        self.publish("resource.stale", {"paths": ["/api/history"]})
        return {"given": out["given"]}

    # ------------------------------------------------------------------ task

    def interval(self, bus) -> float:
        return FAST_S if (bus.subscribers() > 0 or self.open_invites) else SLOW_S

    def sync(self) -> None:
        """One run of the task `shares.sync`."""
        with self._lock, self.ui.open_client() as c:
            if not self._migrated:
                moved = c.received.migrate_received()
                self._migrated = True
                if moved["moved"]:
                    self.publish("resource.stale", {"paths": ["/api/shared", "/api/inbox"]})
            c.share_sync.sync_shares(publish=self._publish_named)
            self.open_invites = c.invites.has_open_invites()

    def _publish_named(self, kind: str, data: dict) -> None:
        """The sender of `shared.received` and the reader of `share.read`
        are names on the page (Home says "<name> shared a finding with
        you"), as in `GET /api/shared` and `GET /api/history`."""
        if kind == "shared.received" and data.get("sender"):
            data = {**data, "sender": self.label(data["sender"])}
        if kind == "share.read" and data.get("subject"):
            data = {**data, "reader": self.label(data["subject"])}
        self.publish(kind, data)
