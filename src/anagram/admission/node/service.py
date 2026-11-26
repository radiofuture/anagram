"""Admission on the node (layer L4; spec/admission.md): `AdmissionService`.

Entry is by invite only. The invite is the proof of a person:
the inviter vouches for the person, and the node records who invited whom
(`invited_by`, `invite_chain`). The three ways in are three forms of one
model (`anagram.admission.model`): a node invite, a lab invite, and a reader
invite. The policy of the node (`NodePolicy`) decides; a lab narrows it with
its own rule (the person who made the invite can still invite).

`AdmissionService` is the registration gate of L1 (`RegistrationGate`): the
identity service makes a member only from an `Admission` that it gives. It
holds no state of its own besides its tables (`AdmissionStore`), so two instances on one node agree.

Patterns from Wish (not its code): secrets are stored only as hashes; an
invite claim is idempotent for the same account and refused for another.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from anagram.admission import formats
from anagram.admission.model import (
    GROUP,
    NODE,
    READER,
    USED,
    Claim,
    Endorsement,
    NodePolicy,
    Vouch,
    endorser_may,
    group_endorsement,
)
from anagram.admission.node.reader import ReaderInvites
from anagram.admission.node.store import AdmissionStore
from anagram.core.errors import Conflict, Forbidden, FormatError, Gone, NodeError, NotFound
from anagram.identity.api import (
    Admission,
    check_device_nonce,
    is_subject,
    mask_email,
    stated_email,
)
from anagram.network.api import (
    LabState,
    invite_recipient,
    make_join_entry,
)

USED_TEXT = "This invite link was used. Ask the person who sent it for a new link."
EXPIRED_TEXT = "This invite link has expired. Ask the person who sent it for a new link."
CLOSED_TEXT = "This invite link is no longer valid. Ask for a new link."


def via_of(ref: str | None) -> str | None:
    """The kind of endorsement of a vouch reference (`members.invite`)."""
    if not ref:
        return None
    if ref.startswith("lab:"):
        return GROUP
    return READER if ref.startswith("reader:") else NODE


def group_creation(identity, policy: NodePolicy) -> Callable[[str], bool]:
    """`may_create(subject)` for `LabService`: the create rule of the node
    policy, from the member row (role and vouch)."""

    def may_create(subject: str) -> bool:
        row = identity.member_ref(subject)
        if row is None:
            return False
        role, ref = row
        return policy.may_create_group(role == "organizer", Vouch(via_of(ref), None))

    return may_create


class AdmissionService:
    def __init__(
        self,
        identity,
        store: AdmissionStore,
        labs=None,
        policy: NodePolicy | None = None,
        readers: ReaderInvites | None = None,
    ) -> None:
        """`labs`: the `LabService` (for lab invites). `readers`: the reader
        invites; with None, a reader invite is unknown."""
        self.identity = identity
        self.labs = labs
        self.policy = policy or NodePolicy()
        self.readers = readers
        self._db = store.db
        self._lock = store.lock

    def _one(self, sql: str, *args):
        return self._db.execute(sql, args).fetchone()

    def _claim_now(self, claimer: str | None = None) -> Claim:
        """A claim now, in whole seconds (the stored expiry times are whole
        seconds)."""
        return Claim(at=datetime.fromtimestamp(self.identity.now(), UTC), claimer=claimer)

    # ---------------------------------------------------------- node invites

    def create_invite(
        self, created_by: str | None, expires_days: float = 7, organizer: bool = False
    ) -> dict:
        """created_by None means the node operator (local CLI on the node).
        Only the operator can make an organizer invite: the person who claims it
        becomes an organizer (also if they are a member already)."""
        idt = self.identity
        if created_by is not None:
            idt.require_organizer(created_by)
            if organizer:
                raise Forbidden("only the node operator can make an organizer invite")
        if not 0 < expires_days <= 90:
            raise NodeError("expiry must be 1 second to 90 days")
        token = secrets.token_bytes(32)
        expires = idt.now_dt() + timedelta(seconds=int(expires_days * 86400))
        doc = formats.make_invite(
            node_url=idt.cfg.public_url,
            node_key=idt.cfg.node_key,
            community=idt.cfg.community,
            token=token,
            expires_at=expires,
            assertion_key=idt.key,
        )
        self._db.execute(
            "INSERT INTO invites (id, created_by, created_at, expires_at, role)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                formats.invite_id(token.hex()),
                created_by,
                idt.now(),
                int(expires.timestamp()),
                "organizer" if organizer else "member",
            ),
        )
        return {"invite": doc, "invite_url": formats.invite_url(doc)}

    def _node_invite(self, iid: str) -> tuple[Endorsement, str | None, str | None]:
        """(endorsement, claimed_by, receipt) of a node invite row."""
        row = self._one(
            "SELECT expires_at, claimed_by, receipt, role, created_by FROM invites WHERE id = ?",
            iid,
        )
        if row is None:
            raise NotFound("unknown invite")
        expires_at, claimed_by, receipt, role, created_by = row
        e = Endorsement(
            kind=READER if role == "reader" else NODE,
            ref=iid,
            endorser=created_by,
            role=role,
            max_uses=1,
            uses=0 if claimed_by is None else 1,
            expires_at=datetime.fromtimestamp(expires_at, UTC),
        )
        return e, claimed_by, receipt

    def admit(self, subject: str, ticket: str) -> Admission:
        """`RegistrationGate`: check the node invite token `ticket` for
        `subject`, claim it, and give the `Admission` that L1 applied.
        `claim_invite` does the same and gives the signed receipt."""
        return self._claim(subject, ticket)[0]

    def claim_invite(self, subject: str, token: str) -> dict:
        """Claim a node invite: the person becomes a member. Return the signed
        receipt. Safe to run again for the same person."""
        return self._claim(subject, token)[1]

    def _claim(self, subject: str, token: str) -> tuple[Admission, dict]:
        try:
            iid = formats.invite_id(token)
        except (ValueError, TypeError) as exc:
            raise NotFound("unknown invite") from exc
        idt = self.identity
        with self._lock:
            e, claimed_by, receipt = self._node_invite(iid)
            ref = iid
            if e.kind == READER:  # the contact proof; no lab (members.invite)
                if self.readers is None or not self.readers.check_claim(iid, subject):
                    raise NotFound("unknown invite")
                ref = f"reader:{iid}"
            admission = Admission(subject, ref, "organizer" if e.role == "organizer" else "member")
            if claimed_by is not None and claimed_by == subject:
                return admission, json.loads(receipt)  # idempotent: the same receipt
            why = self.policy.decide(e, self._claim_now(subject))
            if why == USED:
                raise Conflict("invite is already used")
            if why is not None:
                raise Gone("invite has expired")
            receipt_doc = formats.make_receipt(
                invite=iid,
                subject=subject,
                community=idt.cfg.community,
                node_key=idt.cfg.node_key,
                claimed_at=idt.now_dt(),
                key=idt.key,
            )
            self._db.execute(
                "UPDATE invites SET claimed_by = ?, receipt = ? WHERE id = ?",
                (subject, json.dumps(receipt_doc), iid),
            )
            idt.add_member(admission)
            return admission, receipt_doc

    def open_invites(self) -> int:
        """The number of node invites that a person can still claim."""
        return int(
            self._one(
                "SELECT COUNT(*) FROM invites WHERE claimed_by IS NULL AND expires_at >= ?",
                self.identity.now(),
            )[0]
        )

    # ------------------------------------------------------ invite sign-in

    def invite_signin(
        self,
        invite: str,
        device_key: str,
        nonce: str,
        pid: str | None = None,
        email: str | None = None,
    ) -> dict:
        """Sign in with an invite and no third party. `invite` is the
        token of a node invite (hex) or `lab:<invite id>` of a lab invite. The
        answer has an assertion with method `invite` and no ORCID commitment,
        and a session. A node invite is claimed in the same lock, so one
        invite makes one account. A reader invite keeps its contact proof: the
        answer is `{"needs": "email_code", ...}` (the node sent a code to the
        invite address) or `{"needs": "orcid"}`."""
        idt = self.identity
        check_device_nonce(device_key, nonce)
        if pid is not None and not is_subject(pid):
            raise NodeError("pid must be pid:<32 hex>")
        email = stated_email(email)
        if not isinstance(invite, str) or not invite:
            raise NotFound("unknown invite")
        if invite.startswith("lab:"):
            return self._lab_invite_signin(
                invite.removeprefix("lab:"), device_key, nonce, pid, email
            )
        try:
            iid = formats.invite_id(invite)
        except (ValueError, TypeError) as exc:
            raise NotFound("unknown invite") from exc
        with self._lock:
            e, _, _ = self._node_invite(iid)
            if e.kind == READER:
                return self._reader_signin(iid, device_key, nonce, pid)
            if idt.vouch.rejoin_ok(pid, iid, device_key):
                return idt.vouch.sign_in(pid, device_key, nonce, self.claim_invite(pid, invite))
            why = self.policy.decide(e, self._claim_now())
            if why == USED:
                raise Conflict(USED_TEXT)
            if why is not None:
                raise Gone(EXPIRED_TEXT)
            subject = idt.vouch.new_account(pid, email, iid)
            receipt = self.claim_invite(subject, invite)
            return idt.vouch.sign_in(subject, device_key, nonce, receipt)

    def invite_preview(self, invite: str) -> dict:
        """What the join screen asks for, before the sign-in:
        `{"contact": "email" | "orcid" | None, "email_hint"}`. Only
        a holder of the link can ask. An unknown invite is `404`."""
        none = {"contact": None, "email_hint": None}
        if not isinstance(invite, str) or invite.startswith("lab:"):
            return none
        try:
            iid = formats.invite_id(invite)
        except (ValueError, TypeError) as exc:
            raise NotFound("unknown invite") from exc
        e, _, _ = self._node_invite(iid)
        got = self.readers.contact(iid) if e.kind == READER and self.readers else None
        if got is None:
            return none
        kind, contact, _ = got
        return {"contact": kind, "email_hint": mask_email(contact) if kind == "email" else None}

    def _lab_invite_signin(
        self, iid: str, device_key: str, nonce: str, pid: str | None, email: str | None
    ) -> dict:
        """A lab invite: the node checks that it is open. The person becomes a
        node member only with the lab join request (`join`)."""
        idt = self.identity
        with self._lock:
            if idt.vouch.rejoin_ok(pid, "lab:" + iid, device_key):
                return idt.vouch.sign_in(pid, device_key, nonce, None)
        try:
            info = self.lab_invite_info(iid) if self.labs is not None else None
        except NodeError:
            info = None
        if info is None:
            raise NotFound("unknown invite")
        if not info["open"]:
            raise Gone(CLOSED_TEXT)
        with self._lock:
            subject = idt.vouch.new_account(pid, email, "lab:" + iid)
            return idt.vouch.sign_in(subject, device_key, nonce, None)

    def _reader_signin(self, iid: str, device_key: str, nonce: str, pid: str | None) -> dict:
        """A reader invite names a contact. The contact proof stays: a code
        to the address, or the ORCID step."""
        row = self.readers.contact(iid) if self.readers is not None else None
        if row is None or row[2] != "open":
            raise NotFound("unknown invite")
        kind, contact, _ = row
        if kind != "email":
            return {"needs": "orcid"}
        start = self.identity.email_signin.start(contact, device_key, nonce, "join", pid)
        return {**start, "email_hint": mask_email(contact), "needs": "email_code"}

    # -------------------------------------------------------- vouches

    def invited_by(self, subject: str) -> dict | None:
        """Who vouched for the person: `{"via": "node" | "lab" |
        "reader", "by": <pid> | None}`. `by` None: the node operator."""
        row = self.identity.member_ref(subject)
        if row is None or not row[1]:
            return None
        ref = row[1]
        if ref.startswith("lab:"):
            try:
                by = self.labs.invite_auth(ref.removeprefix("lab:"))[1]["created_by"]
            except (AttributeError, NodeError):
                by = None
            return Vouch("lab", by).view()
        inv = self._one("SELECT created_by FROM invites WHERE id = ?", ref.removeprefix("reader:"))
        return Vouch(via_of(ref), inv[0] if inv else None).view()

    def invite_chain(self) -> list[dict]:
        """Who invited whom, for the organizer page. Names come from the
        identity records; no address and no ORCID iD."""

        def name(subject: str | None) -> str | None:
            if subject is None:
                return None
            rec = self.identity.identity_record(subject) or {}
            return rec.get("display_name") or "A member"

        out = []
        for subject, joined_at in self.identity.members_by_join():
            by = self.invited_by(subject) or {"by": None, "via": NODE}
            out.append(
                {
                    "by": by["by"],
                    "by_name": name(by["by"]),
                    "joined_at": joined_at,
                    "name": name(subject),
                    "subject": subject,
                    "via": by["via"],
                }
            )
        return out

    def may_create_group(self, subject: str) -> bool:
        return group_creation(self.identity, self.policy)(subject)

    # ---------------------------------------------------------- lab invites

    def _lab_refusal(self, state: LabState, invite_id: str) -> str | None:
        """None if a person can use the lab invite now, else the reason. The
        lab narrows the node policy: the person who made the invite must
        still be able to invite."""
        inv = state.invites.get(invite_id)
        if inv is None or state.closed:
            return "revoked"
        claim = self._claim_now()
        rule = endorser_may(state.creator_may_invite(inv["auth"]))
        return self.policy.decide(group_endorsement(inv), claim, narrow=(rule,))

    def put_lab_invite(
        self, subject: str, lab_id: str, auth: dict, package: dict | None, entry: dict
    ) -> dict:
        """A PI or admin records an invite: the public authorisation, the
        `invite` roster entry, and the key package of the
        invite. The node never gets the seed."""
        labs = self.labs
        with labs.lock:
            state = labs.member_state(subject, lab_id)
            if not isinstance(entry, dict) or entry.get("actor") != subject:
                raise Forbidden("you can send only your own roster entries")
            if entry.get("op") != "invite":
                raise NodeError("this route takes an invite entry")
            try:
                formats.verify_lab_invite(auth)
                iid = formats.lab_invite_id(auth)
            except (FormatError, TypeError) as exc:
                raise NodeError(f"invite refused: {exc}") from exc
            if entry.get("invite") != iid:
                raise NodeError("the entry names another invite")
            labs.check_invite_package(state, subject, iid, package)
            new = labs.apply(state, entry, {iid: auth})
            labs.add_invite(lab_id, iid, auth)
            if package is not None:
                labs.put_package(lab_id, package)
            labs.commit(lab_id, new, entry, dict(state.members))
            return {"head": new.head, "invite_id": iid, "seq": new.seq}

    def lab_invite_info(self, invite_id: str, subject: str | None = None) -> dict:
        """The preview of an invite for any session: the authorisation and
        whether it is open. The newest key package of the invite goes only to
        a member who joined with this invite (the joiner opens it after the
        join). A person who was removed from the lab gets no package and sees
        the invite as closed (the clients refuse the join too)."""
        labs = self.labs
        with labs.lock:
            lab_id, auth = labs.invite_auth(invite_id)
            state = labs.state(lab_id)
            inv = state.invites.get(invite_id) or {}
            if subject in state.removed:
                return {"auth": auth, "open": False, "package": None}
            is_open = self._lab_refusal(state, invite_id) is None
            if subject not in state.members or subject not in inv.get("joined", ()):
                return {"auth": auth, "open": is_open, "package": None}
            package = labs.newest_package(lab_id, invite_recipient(invite_id))
            return {"auth": auth, "open": is_open, "package": package}

    def join_lab(self, subject: str, lab_id: str, request: dict) -> dict:
        """Join with a lab invite. In one lock:
        check the request; make the person a node member if they are not one
        (at most `max_uses` node members for each invite); if the device of
        the request is not active yet, answer `{"status": "bind_device"}`
        (the client binds the device and sends the request again); else
        append the `join` entry. Safe to run again."""
        labs, idt = self.labs, self.identity
        with labs.lock:
            try:
                formats.validate_join_request(request)
            except FormatError as exc:
                raise NodeError(f"join request refused: {exc}") from exc
            if request["subject"] != subject:
                raise Forbidden("the join request is for another person")
            state = labs.state(lab_id)
            if request["lab_id"] != lab_id:
                raise NotFound("unknown lab")
            if subject in state.members:
                return _joined(state, subject)
            if subject in state.removed or request["device"] in state.barred:
                raise Gone(
                    "You were removed from this lab. Ask a PI or admin of the lab to add you."
                )
            iid = request["invite"]
            inv = state.invites.get(iid)
            if inv is None:
                raise NotFound("unknown invite")
            why = self._lab_refusal(state, iid)
            if why == USED:
                raise Conflict(USED_TEXT)
            if why is not None:
                raise Gone(CLOSED_TEXT)
            try:
                formats.verify_join_request(request, inv["auth"])
            except FormatError as exc:
                raise NodeError(f"join request refused: {exc}") from exc
            idt.add_member(Admission(subject, "lab:" + iid, limit=inv["auth"]["max_uses"]))
            if request["device"] not in idt.active_devices(subject):
                return {"status": "bind_device"}
            entry = make_join_entry(
                state=state, request=request, role=inv["auth"]["role"], at=idt.now_dt()
            )
            new = labs.apply(state, entry)
            labs.commit(lab_id, new, entry, dict(state.members))
            return _joined(new, subject)


def _joined(state: LabState, subject: str) -> dict:
    return {
        "head": state.head,
        "lab_id": state.lab_id,
        "role": state.members[subject],
        "seq": state.seq,
        "status": "joined",
    }
