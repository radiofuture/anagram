"""Reader invites: share a finding with
a person who is not a member yet (`ReaderInvites`, `Client.invites`, layer
L3). See spec/vault.md and spec/identity.md.

The owner makes an invite for an email address or an ORCID iD; the node
mails the link. The share waits on this computer as the target
`invite:<invite_id>`. When the person joins and claims the invite, the owner
confirms the claimer and the grant goes (`sync_reader_invites`).

The local record of an invite (`reader-invite/<id>` in the vault kv) holds
the roots and the state, not the contact. The contact and the link are
sealed (`share-label`).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import format_time
from anagram.identity.api import Device, is_subject, validate_orcid
from anagram.network.ports import FindingVault
from anagram.network.sharing.app.grants import Grants
from anagram.network.sharing.app.tables import INVITE_TARGET, ShareStore

if TYPE_CHECKING:
    from anagram.network.sharing.app.shares import Shares

_INVITE_ID = re.compile(r"^[0-9a-f]{64}$")


def _contact(contact) -> tuple[str, str]:
    """(kind, value) of a typed email address or ORCID iD, or of
    `{"kind", "value"}`. The node checks the value again."""
    if isinstance(contact, dict):
        kind, value = contact.get("kind"), str(contact.get("value", ""))
    else:
        value = str(contact).strip()
        kind = "email" if "@" in value else "orcid"
    value = value.strip()
    if kind == "email":
        email = value.lower()
        if (
            "@" not in email
            or len(email) > 254
            or any(c.isspace() for c in email)
            or email.startswith("@")
        ):
            raise ClientError("not an email address")
        return "email", email
    if kind == "orcid":
        try:
            return "orcid", validate_orcid(value.removeprefix("orcid:"))
        except FormatError as exc:
            raise ClientError("not an email address or ORCID iD") from exc
    raise ClientError("a contact is an email address or an ORCID iD")


# ------------------------------------------------------- local records


def invite_label(device: Device, iid: str) -> dict | None:
    """The sealed contact and link of an invite that this computer made."""
    raw = device.unseal("share-label", INVITE_TARGET + iid)
    return json.loads(raw) if raw else None


def revoke_invite(device: Device, store: ShareStore, iid: str) -> dict:
    """End an invite on the node and mark the local record revoked."""
    try:
        device.http.call("DELETE", f"/reader-invites/{iid}", None, auth=True)
    except NodeHTTPError as exc:
        if exc.status != 404:
            raise
    rec = store.invites.load(iid)
    if rec is not None:
        rec["state"] = "revoked"
        store.invites.dump(iid, rec)
    return {"invite_id": iid, "state": "revoked"}


def stop_invite_share(
    device: Device, store: ShareStore, vault: FindingVault, ref: str, target: str
) -> dict:
    """Stop sharing one finding with an invited person who has not joined.
    The node invite ends when no finding is left on it."""
    iid = target.removeprefix(INVITE_TARGET)
    row = vault.find(ref)
    rec = store.invites.load(iid) or {"roots": [], "state": "open"}
    at = format_time(device.now())
    store.stop_share(row.finding_id, target, at)
    mine = {r.root for r in vault.list() if r.finding_id == row.finding_id}
    rec["roots"] = [r for r in rec["roots"] if r not in mine]
    if not rec["roots"] and rec.get("state") == "open":
        revoke_invite(device, store, iid)
        rec = store.invites.load(iid) or rec
    store.invites.dump(iid, rec)
    store.add_share_event(finding_id=row.finding_id, root=row.root, target=target,
                    kind="stopped", at=at, detail={})  # fmt: skip
    return {"finding_id": row.finding_id, "target": target, "withdrawn": []}


class ReaderInvites:
    """The owner side of reader invites on this computer (layer L3)."""

    def __init__(
        self,
        device: Device,
        grants: Grants,
        shares: Shares,
        store: ShareStore,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.store = store
        self.grants = grants
        self.shares = shares

    def _open_invite_for(self, kind: str, value: str) -> tuple[str, dict] | None:
        """The local open reader invite for this contact, if this computer
        made one: (invite_id, label)."""
        for iid, rec in self.store.invites.loaded_items():
            if rec.get("state") != "open":
                continue
            label = invite_label(self.device, iid)
            if label and label["contact"] == {"kind": kind, "value": value}:
                return iid, label
        return None

    def invite_reader(
        self,
        ref: str,
        contact: str | dict,
        *,
        expires_days: int = 30,
        with_included: bool = True,
        warnings_ack: bool = False,
    ) -> dict:
        """Share a finding with a person who is not a member yet.
        `contact` is an email address or an ORCID iD (text, or
        `{"kind", "value"}`). The node makes a reader invite and, for an
        email address, mails the link. The share waits on this computer: the
        grant goes at a later `sync_reader_invites`, after the person joined
        with that contact. -> {"invite_id", "link", "mailed", "expires_at"}."""
        kind, value = _contact(contact)
        vault = self.vault
        roots = self.shares.set_roots(ref) if with_included else [vault.find(ref).root]
        for root in roots:  # the third-party check of all roots before any send
            self.grants.third_party_gate(root, warnings_ack)
        for root in roots:  # the later grant is fast
            self.grants.upload(root)
            self.shares.upload_reading_copy(root)
        found = self._open_invite_for(kind, value)
        if found is not None:
            iid, label = found
            out = {"expires_at": label["expires_at"], "invite_id": iid, "link": label["link"],
                   "mailed": False}  # fmt: skip
        else:
            out = self._new_invite(kind, value, expires_days)
            iid = out["invite_id"]
        rec = self.store.invites.load(iid) or {"roots": [], "state": "open"}
        at = format_time(self.device.now())
        target = INVITE_TARGET + iid
        parent = roots[0]
        for root in roots:
            row = vault.get(root)
            new = self.store.put_share(
                row.finding_id, target, parent if root != parent else None, at
            )
            if root not in rec["roots"]:
                rec["roots"].append(root)
            if new:
                self.store.add_share_event(
                    finding_id=row.finding_id,
                    root=root,
                    target=target,
                    kind="invite_sent",
                    at=at,
                    detail={"mailed": out["mailed"]},
                )
        self.store.invites.dump(iid, rec)
        return out

    def _new_invite(self, kind: str, value: str, expires_days: int) -> dict:
        """Make an invite on the node and seal its contact and link here."""
        body = {"contact": {"kind": kind, "value": value}, "expires_days": expires_days}
        http = self.device.http
        got = http.call("POST", "/reader-invites", body, auth=True)
        if got.get("invite_url") is None:  # an open invite that this computer has no link for
            http.call("DELETE", f"/reader-invites/{got['invite_id']}", None, auth=True)
            got = http.call("POST", "/reader-invites", body, auth=True)
        iid = got["invite_id"]
        if not isinstance(iid, str) or not _INVITE_ID.match(iid):
            raise LogMisbehaved("node gave a bad invite ID")
        out = {
            "expires_at": got["expires_at"],
            "invite_id": iid,
            "link": got["invite_url"],
            "mailed": bool(got["mailed"]),
        }
        label = {
            "contact": {"kind": kind, "value": value},
            "expires_at": out["expires_at"],
            "link": out["link"],
        }
        self.device.seal("share-label", INVITE_TARGET + iid, json.dumps(label).encode())
        return out

    def reader_invites(self) -> list[dict]:
        """The reader invites of this person on the node, with the contact
        from this computer (None if another computer made the invite)."""
        got = self.device.http.call("GET", "/reader-invites", None, auth=True)
        out = []
        for inv in got.get("invites", []):
            label = invite_label(self.device, inv["invite_id"])
            out.append({**inv, "contact": label["contact"] if label else None})
        return out

    def has_open_invites(self) -> bool:
        """True while this computer waits for a reader invite to be claimed."""
        return any(
            rec.get("state") in ("open", "claimed") for _, rec in self.store.invites.loaded_items()
        )

    def sync_reader_invites(self) -> list[dict]:
        """One owner tick for reader invites (`sync_shares` calls
        it). A claimed invite becomes a share with the person (a
        grant for each root, with the key lookup and its log proofs). An
        invite that ended unclaimed stops its shares. No node call if this
        computer has no open or waiting invite.
        -> [{"kind": "shared" | "invite_expired", "invite_id", "subject",
        "findings": [finding_id]}]."""
        mine = dict(self.store.invites.loaded_items())
        mine = {i: r for i, r in mine.items() if r.get("state") in ("open", "claimed")}
        if not mine:
            return []
        on_node = {
            i["invite_id"]: i
            for i in self.device.http.call("GET", "/reader-invites", None, auth=True).get(
                "invites", []
            )
        }
        changed = []
        for iid, rec in sorted(mine.items()):
            inv = on_node.get(iid)
            if inv is None or inv["state"] in ("expired", "revoked"):
                findings = self._end_invite(iid, rec, "invite_expired")
                changed.append({"findings": findings, "invite_id": iid, "kind": "invite_expired",
                                "subject": None})  # fmt: skip
                continue
            if inv["state"] != "claimed":
                continue
            subject = inv.get("subject")
            if not is_subject(subject):
                raise LogMisbehaved("node gave a bad person ID")
            if rec.get("confirmed") != subject:
                if self._note_claimer(iid, rec, inv):
                    changed.append({"findings": [], "invite_id": iid, "kind": "confirm",
                                    "subject": subject})  # fmt: skip
                continue
            findings = self._deliver(iid, rec, subject)
            if findings:
                changed.append({"findings": findings, "invite_id": iid, "kind": "shared",
                                "subject": subject})  # fmt: skip
        return changed

    def _note_claimer(self, iid: str, rec: dict, inv: dict) -> bool:
        """Only the node checks the claim. A node that breaks
        the rules can name a person that it controls, so the owner confirms
        the claimer before the content key goes. Keep a new claimer; return
        True if the claimer is new."""
        subject = inv["subject"]
        if rec.get("claimer") == subject:
            return False
        rec["claimer"] = subject
        email = inv.get("claimer_email")
        rec["claimer_email"] = email if isinstance(email, str) else None
        self.store.invites.dump(iid, rec)
        return True

    def _deliver(self, iid: str, rec: dict, subject: str) -> list[str]:
        """The shares of a confirmed claim go to the person. Return the
        finding IDs that the person got now."""
        vault = self.vault
        target = INVITE_TARGET + iid
        done, findings = True, []
        for root in rec["roots"]:
            row = vault.get(root)
            if row is None:
                continue
            if not self.store.any_active(row.finding_id, target, subject):
                continue  # the owner stopped this share before the claim
            parent = rec["roots"][0]
            self.store.put_share(row.finding_id, subject, parent if root != parent else None,
                             format_time(self.device.now()))  # fmt: skip
            self.store.move_invite_share(row.finding_id, target, subject)
            out = self.shares.share(root, [subject], with_included=False, warnings_ack=True)
            if out["waiting"]:
                done = False  # the person has no device key yet: try again
            elif row.finding_id not in findings:
                findings.append(row.finding_id)
        rec["state"] = "done" if done else "claimed"
        rec["subject"] = subject
        self.store.invites.dump(iid, rec)
        return findings

    def reader_claims(self) -> list[dict]:
        """The reader invites that a person claimed and that wait for the
        owner. -> [{"invite_id", "subject", "name", "email",
        "contact", "findings"}]. The name comes from the signed identity
        record of the person; the email address from the node."""
        out = []
        for iid, rec in self.store.invites.loaded_items():
            claimer = rec.get("claimer")
            if rec.get("state") not in ("open", "claimed") or not claimer:
                continue
            if rec.get("confirmed") == claimer:
                continue
            try:
                record = self.device.http.call("GET", f"/identity/{claimer}", None, auth=True)
            except NodeHTTPError:
                record = {}
            label = invite_label(self.device, iid)
            titles = []
            for root in rec["roots"]:
                row = self.vault.get(root)
                if row is not None:
                    titles.append(row.finding_id)
            out.append(
                {
                    "contact": label["contact"] if label else None,
                    "email": rec.get("claimer_email"),
                    "findings": titles,
                    "invite_id": iid,
                    "name": record.get("display_name"),
                    "subject": claimer,
                }
            )
        return sorted(out, key=lambda x: x["invite_id"])

    def confirm_reader_claim(self, iid: str, give: bool) -> dict:
        """The answer of the owner to a claim. Yes: the grant
        goes now (or at the next sync). No: the shares of the invite stop;
        the person stays a member and gets nothing from this invite."""
        rec = self.store.invites.load(iid)
        if rec is None or not rec.get("claimer") or rec.get("state") not in ("open", "claimed"):
            raise ClientError("no claim of this invite waits for an answer")
        if give:
            rec["confirmed"] = rec["claimer"]
            self.store.invites.dump(iid, rec)
            changed = self.sync_reader_invites()
            return {"changed": changed, "given": True, "invite_id": iid}
        findings = self._end_invite(iid, rec, "stopped")
        return {"findings": findings, "given": False, "invite_id": iid}

    def _end_invite(self, iid: str, rec: dict, kind: str) -> list[str]:
        vault = self.vault
        target = INVITE_TARGET + iid
        at = format_time(self.device.now())
        findings = []
        for root in rec["roots"]:
            row = vault.get(root)
            if row is None or row.finding_id in findings:
                continue
            findings.append(row.finding_id)
            if self.store.stop_share(row.finding_id, target, at, only_active=True):
                self.store.add_share_event(finding_id=row.finding_id, root=root, target=target,
                                kind=kind, at=at, detail={})  # fmt: skip
        rec["state"] = "ended"
        self.store.invites.dump(iid, rec)
        return findings
