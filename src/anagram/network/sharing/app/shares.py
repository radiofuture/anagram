"""The send side of shares (`Shares`, `Client.shares`,
layer L3). See spec/vault.md sections 12 to 14.

- shares to people and sets, the audience, new versions (`share`,
  `share_new_version`); a share with my own lab puts the finding into the
  lab space (`lab_publish`, no grant);
- stop sharing and "make a new version now" (`stop_sharing`, `rekey_now`);
- the reading copy (`upload_reading_copy`) and "See what they see"
  (`preview`).

The other parts of sharing on this computer: the share tables
(`tables`), reader invites (`invites`), the owner's read records and history
(`records`), the received store (`received`), and the task `shares.sync`
(`sync`).
"""

from __future__ import annotations

import logging
import urllib.parse

from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import format_time
from anagram.identity.api import Device, Directory, is_subject, validate_lab_id, validate_orcid
from anagram.local.api import Findings
from anagram.network.formats.sharing import reading_blob_id
from anagram.network.groups.app.labrecords import LabItemDraft, LabSpace
from anagram.network.groups.app.labroster import LabRoster
from anagram.network.ports import FindingVault
from anagram.network.sharing.app import readcopy
from anagram.network.sharing.app.grants import Grants
from anagram.network.sharing.app.invites import stop_invite_share
from anagram.network.sharing.app.received import TITLE_MAX, reading_model
from anagram.network.sharing.app.tables import INVITE_TARGET, LAB_TARGET, ShareStore
from anagram.proofs.records import LINK_INCLUDES, finding_links

log = logging.getLogger("anagram.client")

SET_DEPTH = 3  # `includes` links followed when a set is shared
LAB_ORIGIN = {"media_type": "text/plain", "name": "finding", "source_kind": "anagram", "time": None}


class Shares:
    """Shares of the findings of this person, on this computer (layer L3)."""

    def __init__(
        self,
        device: Device,
        directory: Directory,
        findings: Findings,
        roster: LabRoster,
        space: LabSpace,
        grants: Grants,
        store: ShareStore,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.store = store
        self.directory = directory
        self.findings = findings
        self.roster = roster
        self.space = space
        self.grants = grants

    # ------------------------------------------------------------ sharing

    def resolve_target(self, text: str) -> dict:
        """What a typed share target is. Order: a pid or a lab ID; an ORCID iD
        (`resolve_person`); an email address (`GET /resolve/email`).
        -> {"kind": "person"|"lab"|"unknown_email"|"unknown_orcid", "target", "label"}.
        An unknown address or iD is not an error: it is a person to invite to
        the node (there is no guest reader)."""
        v = text.strip()
        if is_subject(v):
            return {"kind": "person", "label": v, "target": v}
        if v.startswith(("lab:", "lab-")):
            try:
                lab = validate_lab_id(v.removeprefix("lab:"))
            except FormatError as exc:
                raise ClientError("not a lab ID") from exc
            return {"kind": "lab", "label": lab, "target": "lab:" + lab}
        if "@" in v:
            return self._resolve_email(v.lower())
        try:
            orcid = validate_orcid(v.removeprefix("orcid:"))
        except FormatError as exc:
            raise ClientError("not a person ID, lab ID, ORCID iD, or email address") from exc
        try:
            return {
                "kind": "person",
                "label": orcid,
                "target": self.directory.resolve_person(orcid),
            }
        except LogMisbehaved:
            raise
        except ClientError:
            return {"kind": "unknown_orcid", "label": orcid, "target": None}

    def _resolve_email(self, email: str) -> dict:
        if len(email) > 254 or any(c.isspace() for c in email) or email.startswith("@"):
            raise ClientError("not an email address")
        try:
            found = self.device.http.call(
                "GET", f"/resolve/email/{urllib.parse.quote(email, safe='@')}", auth=True
            )
        except NodeHTTPError as exc:
            if exc.status == 404:
                return {"kind": "unknown_email", "label": email, "target": None}
            raise
        if not is_subject(found.get("subject")):
            raise LogMisbehaved("node gave a bad person ID")
        return {"kind": "person", "label": email, "target": found["subject"]}

    def set_roots(self, ref: str) -> list[str]:
        """The finding, then each finding that it includes (`includes` links,
        depth 3, no cycles) that is in this vault. Roots, in walk order."""
        level = [self.vault.find(ref).root]
        out: list[str] = []
        seen: set[str] = set()
        for _ in range(SET_DEPTH + 1):
            nxt = []
            for root in level:
                if root in seen:
                    continue
                seen.add(root)
                out.append(root)
                for link in finding_links(self.findings.opening(root).finding.fields):
                    t = link.target.hex()
                    if link.type == LINK_INCLUDES and t not in seen and self.vault.get(t):
                        nxt.append(t)
            level = nxt
        return out

    def share(
        self,
        ref: str,
        targets: list[str],
        *,
        with_included: bool = True,
        warnings_ack: bool = False,
    ) -> dict:
        """Share one finding (and the findings that it includes) with people,
        or with the lab space of a lab of the sharer. A person target is a pid
        (`resolve_target` gives it); a lab target is `lab:<lab_id>`. A person
        with no active device key waits: the grant comes at a later
        `sync_shares`. A lab gets no grant: the finding goes into the lab
        space (`lab_publish`), where each member reads it.
        -> {"shared": [{"target", "people"}], "waiting": [pid], "findings": [root]}."""
        roots = self.set_roots(ref) if with_included else [self.vault.find(ref).root]
        people: list[str] = []
        labs: list[str] = []
        for t in targets:
            if t.startswith(LAB_TARGET):
                lab_id = self._own_lab(t)
                if lab_id not in labs:
                    labs.append(lab_id)
                continue
            if not is_subject(t):
                raise ClientError("a share target is a person ID; use resolve_target first")
            if t != self.device.subject and t not in people:
                people.append(t)
        for root in roots:  # the third-party check of all roots before any send
            self.grants.third_party_gate(root, warnings_ack)
        at = format_time(self.device.now())
        shared, waiting = [], set()
        for lab_id in labs:
            shared.append({"people": self._share_to_lab(lab_id, roots, at),
                           "target": LAB_TARGET + lab_id})  # fmt: skip
        for person in people:
            delivered, waits = self._share_to_person(person, roots, at)
            if waits:
                waiting.add(person)
            if delivered:
                shared.append({"people": 1, "target": person})
        return {"findings": roots, "shared": shared, "waiting": sorted(waiting)}

    def _share_to_person(self, person: str, roots: list[str], at: str) -> tuple[int, bool]:
        """Give each root to one person (a grant), or note that the share
        waits for a device key. -> (roots delivered, True if one waits)."""
        vault = self.vault
        parent = roots[0]
        delivered, waits = 0, False
        for root in roots:
            row = vault.get(root)
            new = self.store.put_share(
                row.finding_id, person, parent if root != parent else None, at
            )
            if any(g["recipient"] == person for g in vault.grants_sent(root)):
                delivered += 1
                continue
            self.upload_reading_copy(root)
            out = self.grants.grant(root, recipients=[person], warnings_ack=True)
            kind, detail = "waiting", {}
            if out["granted"]:
                delivered += 1
                kind, detail = "shared", {"grant_id": out["granted"][0]["grant_id"]}
            elif not new:
                continue
            else:
                waits = True
            self.store.add_share_event(
                finding_id=row.finding_id,
                root=root,
                person=person,
                target=person,
                kind=kind,
                at=at,
                detail=detail,
            )
        return delivered, waits

    # ------------------------------------------- owner: the lab space

    def _own_lab(self, target: str) -> str:
        """The lab ID of a `lab:<id>` target, if this person is in that lab
        and can publish to its space (verified roster). Else ClientError,
        before any send."""
        try:
            state = self.roster.lab_state(target.removeprefix(LAB_TARGET))
        except ClientError as exc:  # LabError: not a lab, or not my lab
            raise ClientError("You can share only with a lab that you are in.") from exc
        if not state.can(self.device.subject, "publish"):
            raise ClientError("Your role in this lab does not permit this.")
        return state.lab_id

    def _lab_draft(self, root: str, item_id: str | None) -> LabItemDraft:
        claim = (self.findings.opening(root).finding.fields.get("claim") or "").strip()
        first = claim.splitlines()[0] if claim else ""
        title = "".join(" " if ord(c) < 0x20 else c for c in first)[:TITLE_MAX].strip()
        return LabItemDraft(
            kind="finding",
            title=title or f"Finding {root[:12]}",
            text=claim,
            origin=dict(LAB_ORIGIN),
            type="finding",
            finding_root=root,
            item_id=item_id,
        )

    def _lab_item_record(self, lab_id: str, finding_id: str) -> dict | None:
        return self.store.lab_items.load(f"{lab_id}/{finding_id}")

    def _share_to_lab(self, lab_id: str, roots: list[str], at: str) -> int:
        """Put each finding version into the lab space: one lab item for each
        finding, and a new revision of that item for a new version. The item
        has the claim and the public proof bundle (no evidence file). Return
        the number of other members of the lab."""
        target = LAB_TARGET + lab_id
        parent = roots[0]
        for root in roots:
            row = self.vault.get(root)
            new = self.store.put_share(
                row.finding_id, target, parent if root != parent else None, at
            )
            rec = self._lab_item_record(lab_id, row.finding_id)
            if rec and rec["root"] == root and not new:
                continue  # this version is in the lab space
            item_id = None
            if rec:
                try:
                    item_id = self.space.lab_publish(lab_id, self._lab_draft(root, rec["item_id"]))
                except ClientError:  # the item was removed (a PI or an admin)
                    item_id = None
            if item_id is None:
                item_id = self.space.lab_publish(lab_id, self._lab_draft(root, None))
            self.store.lab_items.dump(
                f"{lab_id}/{row.finding_id}", {"item_id": item_id, "root": root}
            )
            self.store.add_share_event(
                finding_id=row.finding_id,
                root=root,
                target=target,
                kind="shared",
                at=at,
                detail={"item_id": item_id, "version": row.version},
            )
        state = self.roster.labcache.state(lab_id)
        return len([m for m in state.members if m != self.device.subject]) if state else 0

    def _stop_lab(self, ref: str, target: str) -> dict:
        """Stop sharing a finding with my lab: remove its lab item (a
        tombstone; the node deletes the text). Members who read it before
        keep what they saw."""
        lab_id = target.removeprefix(LAB_TARGET)
        row = self.vault.find(ref)
        if not any(
            sh["target"] == target and sh["state"] == "active"
            for sh in self.store.shares_of(row.finding_id)
        ):
            raise ClientError("This finding is not shared with this lab.")
        rec = self._lab_item_record(lab_id, row.finding_id)
        removed = []
        if rec:
            try:
                self.space.lab_unpublish(lab_id, rec["item_id"])
                removed.append(rec["item_id"])
            except ClientError as exc:  # gone already, or I left the lab
                log.info("lab item of a stopped share: %s", type(exc).__name__)
            self.store.lab_items.delete(f"{lab_id}/{row.finding_id}")
        at = format_time(self.device.now())
        self.store.stop_share(row.finding_id, target, at)
        self.store.add_share_event(finding_id=row.finding_id, root=row.root, target=target,
                        kind="stopped", at=at, detail={"removed": removed})  # fmt: skip
        return {"finding_id": row.finding_id, "target": target, "withdrawn": []}

    def lab_shares(self, finding_id: str) -> list[str]:
        """The labs that have this finding in their space (active shares)."""
        return [
            sh["target"].removeprefix(LAB_TARGET)
            for sh in self.store.shares_of(finding_id)
            if sh["target"].startswith(LAB_TARGET) and sh["state"] == "active"
        ]

    def audience(self, finding_id: str) -> set[str]:
        """The people who keep this finding: each person who got a version (a
        grant) or has an active share, less each person whose share is stopped."""
        roots = {r.root for r in self.vault.list() if r.finding_id == finding_id}
        people = {
            g["recipient"]
            for g in self.vault.grants_sent()
            if g["root"] in roots and is_subject(g["recipient"])
        }
        stopped = set()
        for sh in self.store.shares_of(finding_id):
            if is_subject(sh["target"]):
                (people if sh["state"] == "active" else stopped).add(sh["target"])
        people -= stopped
        people.discard(self.device.subject)
        return people

    def follow_versions(self) -> bool:
        """Client config `sharing.follow_versions` (default true)."""
        return bool(self.device.config.get("sharing", {}).get("follow_versions", True))

    def share_new_version(self, root: str, *, warnings_ack: bool = False) -> dict:
        """Give a new version to the audience of its finding, if
        `sharing.follow_versions` is on. The commit path calls it."""
        row = self.vault.find(root)
        people = sorted(self.audience(row.finding_id))
        labs = [LAB_TARGET + lab_id for lab_id in self.lab_shares(row.finding_id)]
        if not (people or labs) or not self.follow_versions():
            return {"findings": [row.root], "shared": [], "waiting": []}
        out = self.share(row.root, labs + people, with_included=False, warnings_ack=warnings_ack)
        at = format_time(self.device.now())
        for person in people:
            self.store.add_share_event(
                finding_id=row.finding_id,
                root=row.root,
                person=person,
                target=person,
                kind="new_version",
                at=at,
                detail={"version": row.version},
            )
        return out

    def retry_waiting(self) -> list[dict]:
        """Grants for people who had no device key at the share (a part of
        the task `shares.sync`). Return `{"finding_id", "subject"}` for each
        person who got a grant now."""
        out = []
        for sh in self.store.shares_of():
            person = sh["target"]
            if sh["state"] != "active" or not is_subject(person):
                continue
            roots = sorted({
                e["root"] for e in self.store.share_events(finding_id=sh["finding_id"])
                if e["kind"] == "waiting" and e["target"] == person and e["root"]
            })  # fmt: skip
            for root in roots:
                if self.vault.get(root) is None or any(
                    g["recipient"] == person for g in self.vault.grants_sent(root)
                ):
                    continue
                got = self.share(root, [person], with_included=False, warnings_ack=True)
                if got["shared"]:
                    out.append({"finding_id": sh["finding_id"], "subject": person})
        return out

    # --------------------------------------------------- owner: stop, rekey

    def _withdraw(self, grant_id: str) -> bool:
        """Delete a grant on the node and forget it here (so that
        `sync_grants` does not post it again). True if the node had it."""
        try:
            self.device.http.call("DELETE", f"/grants/{grant_id}", None, auth=True)
            gone = True
        except NodeHTTPError as exc:
            if exc.status != 404:
                raise
            gone = False
        self.vault.forget_grant_sent(grant_id)
        return gone

    def stop_sharing(self, ref: str, target: str) -> dict:
        """Stop sharing a finding (all its versions) with a person. Their
        grants are withdrawn, so the node refuses them from now on, and later
        versions do not go to them. What they opened or saved before stays
        with them. -> {"finding_id", "target", "withdrawn": [grant_id]}.
        A target `invite:<id>` is an invited person who has not joined."""
        if target.startswith(INVITE_TARGET):
            return stop_invite_share(self.device, self.store, self.vault, ref, target)
        if target.startswith(LAB_TARGET):
            return self._stop_lab(ref, target)
        if not is_subject(target):
            raise ClientError("a share target is a person ID")
        vault = self.vault
        row = vault.find(ref)
        roots = {r.root for r in vault.list() if r.finding_id == row.finding_id}
        withdrawn = []
        for g in vault.grants_sent():
            if g["root"] in roots and g["recipient"] == target:
                self._withdraw(g["grant_id"])
                withdrawn.append(g["grant_id"])
        at = format_time(self.device.now())
        if self.store.has_share(row.finding_id, target):
            self.store.stop_share(row.finding_id, target, at)
        else:  # a person who got the finding by a ring grant: an explicit stop
            self.store.add_stopped_share(row.finding_id, target, at)
        self.store.add_share_event(
            finding_id=row.finding_id,
            root=row.root,
            person=target,
            target=target,
            kind="stopped",
            at=at,
            detail={"withdrawn": sorted(withdrawn)},
        )
        return {"finding_id": row.finding_id, "target": target, "withdrawn": sorted(withdrawn)}

    def rekey_now(self, ref: str, *, warnings_ack: bool = False) -> dict:
        """ "Make a new version now": a new version with a new content key for
        the people who keep access (`audience`), then withdraw all grants of the
        older versions and delete their blobs on the node. The files must be on
        this computer. A blob that a public release lists stays.
        -> {"root", "shared", "withdrawn", "deleted_blobs", "kept_blobs"}."""
        row = self.vault.find(ref)
        people = sorted(self.audience(row.finding_id))
        old_roots = {r.root for r in self.vault.list() if r.finding_id == row.finding_id}
        labs = [LAB_TARGET + lab_id for lab_id in self.lab_shares(row.finding_id)]
        new_root = self.grants.revoke(row.root, warnings_ack=warnings_ack)["root"]
        out = self.share(new_root, labs + people, with_included=False, warnings_ack=warnings_ack)
        withdrawn = []
        for g in self.vault.grants_sent():
            if g["root"] in old_roots and is_subject(g["recipient"]):
                self._withdraw(g["grant_id"])
                withdrawn.append(g["grant_id"])
        deleted, kept = self._delete_blobs(old_roots)
        self.store.add_share_event(
            finding_id=row.finding_id,
            root=new_root,
            target="all",
            kind="new_version",
            at=format_time(self.device.now()),
            detail={"rekey": True, "withdrawn": len(withdrawn)},
        )
        return {
            "deleted_blobs": sorted(deleted),
            "kept_blobs": sorted(kept),
            "root": new_root,
            "shared": out["shared"],
            "withdrawn": sorted(withdrawn),
        }

    def _delete_blobs(self, roots: set[str]) -> tuple[list[str], list[str]]:
        """Delete the evidence blobs and the reading copies of these versions
        on the node. -> (deleted, kept: a public release lists them)."""
        vault = self.vault
        deleted, kept = [], []
        for root in sorted(roots):
            ids = [(s, m["blob_id"]) for s, m in vault.evidence_meta(root).items()]
            reading = self.store.reading_copy.get(root)
            ids += [(None, reading)] if reading else []
            for slot, blob_id in ids:
                if not blob_id:
                    continue
                try:
                    self.device.http.call("DELETE", f"/blobs/{blob_id}", None, auth=True)
                except NodeHTTPError as exc:
                    if exc.status == 409:  # a public release lists it
                        kept.append(blob_id)
                        continue
                    if exc.status != 404:
                        raise
                deleted.append(blob_id)
                if slot is None:
                    self.store.reading_copy.delete(root)
                else:
                    vault.clear_blob(root, slot)
        return deleted, kept

    # ------------------------------------------------- owner: reading copy

    def upload_reading_copy(self, ref: str) -> str | None:
        """Make the reading copy of one finding version from the local files,
        encrypt it with the reading key, and upload it (one time for each
        version). Return the blob ID, or None if no copy can be made (no local
        file, or the copy is too large). It never stops a share."""
        root = self.vault.find(ref).root
        got = self.store.reading_copy.get(root)
        if got:
            return got
        doc = self.findings.opening(root)
        paths = {s: m.get("path") for s, m in self.vault.evidence_meta(root).items()}
        files = readcopy.read_files(doc, paths)
        if not files:
            return None
        try:
            copy = readcopy.build(doc, files)
        except FormatError as exc:
            log.info("no reading copy for %s: %s", root[:12], exc)
            return None
        key = self.grants.content_key(root)
        blob = readcopy.seal(copy, key, bytes.fromhex(root))
        blob_id = reading_blob_id(key, bytes.fromhex(root))
        self.device.http.call("PUT", f"/blobs/{blob_id}", blob, auth=True)
        self.store.reading_copy.set(root, blob_id)
        return blob_id

    def preview(self, ref: str) -> dict:
        """ "See what they see": the reading model of my own finding version,
        made from the files on this computer (no node call)."""
        row = self.vault.find(ref)
        doc = self.findings.opening(row.root)
        paths = {s: m.get("path") for s, m in self.vault.evidence_meta(row.root).items()}
        copy = readcopy.build(doc, readcopy.read_files(doc, paths))
        report = {"claim": doc.finding.fields.get("claim"), "granted_at": None,
                  "not_after": None, "root": row.root, "verified": False}  # fmt: skip
        payload = {"owner": self.device.subject, "version": row.version}
        return {**reading_model(None, payload, doc, copy, report), "preview": True}
