"""Reader invites.

A member shares a finding with a person who is not a member yet. The member
gives an email address or an ORCID iD. The node makes a node invite with
that contact (an `invites` row with role `reader`, and a `reader_invites`
row). The person installs Anagram and joins with the normal join path.

Rules:

- The link alone gives nothing. `AdmissionService.claim_invite` calls
  `check_claim` for a reader invite: the session subject must have proved
  the invite contact (an email sign-in with that address, or an ORCID
  sign-in with that iD; the policy `invite_only` refuses a claim with no
  contact proof). Else the answer is the same 404 as for an unknown invite,
  and no member is made.
- The person joins with no lab. `members.invite` is `reader:<invite_id>`, so
  the lab create rule of the default node (`organizer_invite`) refuses them.
- No enumeration: the owner gets the same answer for each contact (a member,
  a person with an account, a new address). The owner learns the pid only
  after the claim.
- For an email contact the node sends one fixed message. It has no text of
  the owner except the display name, and no finding title. For an ORCID
  contact the node has no address: the owner sends the link.
- Limits: 20 open invites and 50 new invites each day for each owner; one
  open invite for each (owner, contact).

The table is in `identity.sqlite` (the invite rows are there too). It is
part of layer L4 (`anagram.admission`).
"""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Header

from anagram.admission.formats import invite_id, invite_url, make_invite
from anagram.admission.model import READER, Claim, Endorsement, NodePolicy
from anagram.admission.node.store import AdmissionStore
from anagram.core.errors import Forbidden, FormatError, NodeError, NotFound, RateLimited
from anagram.identity.api import validate_orcid

OPEN_MAX = 20
DAY_MAX = 50
EXPIRES_DAYS_DEFAULT = 30
EXPIRES_DAYS_MAX = 30
NAME_MAX = 80
STATES = ("open", "claimed", "revoked", "expired")

MAIL_SUBJECT = "A finding is shared with you in {community}"
MAIL_TEXT = (
    "{name} shared a finding with you in {community}.\n\n"
    "Install Anagram and join with this address:\n{link}\n\n"
    "The link works only for this address.\n"
)


def normalize_contact(contact: object) -> tuple[str, str]:
    """(kind, value) of `{"kind": "email" | "orcid", "value": str}`."""
    if not isinstance(contact, dict) or set(contact) != {"kind", "value"}:
        raise NodeError("contact must be {kind, value}")
    kind, value = contact["kind"], contact["value"]
    if kind == "email":
        email = str(value).strip().lower()
        if "@" not in email or len(email) > 254 or any(c.isspace() for c in email):
            raise NodeError("bad email address")
        if email.startswith("@") or email.endswith("@"):
            raise NodeError("bad email address")
        return "email", email
    if kind == "orcid":
        try:
            return "orcid", validate_orcid(str(value).strip().removeprefix("orcid:"))
        except FormatError as exc:
            raise NodeError("bad ORCID iD") from exc
    raise NodeError("contact kind must be email or orcid")


def _one_line(text: object) -> str:
    clean = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")).strip()
    return clean[:NAME_MAX] or "A member"


class ReaderInvites:
    """Reader invites of one node. `AdmissionService` uses `check_claim` and
    `contact` for a reader invite."""

    def __init__(self, identity, store: AdmissionStore, policy: NodePolicy | None = None) -> None:
        self.identity = identity
        self.policy = policy or NodePolicy()
        self._db = store.db
        self._lock = store.lock

    # ------------------------------------------------------------ helpers

    def _expire(self) -> None:
        self._db.execute(
            "UPDATE reader_invites SET state = 'expired' WHERE state = 'open' AND expires_at < ?",
            (self.identity.now(),),
        )

    def _owner_name(self, owner: str) -> str:
        record = self.identity.identity_record(owner) or {}
        return _one_line(record.get("display_name"))

    # -------------------------------------------------------------- owner

    def create(self, owner: str, contact: object, expires_days: object = None) -> dict:
        """Make a reader invite. The answer has the same keys for each
        contact. If the owner has an open invite for this contact, the
        answer names it and has no link (the owner's client keeps the link;
        a client that lost it revokes the old invite and asks again)."""
        self.identity.require_member(owner)
        kind, value = normalize_contact(contact)
        days = EXPIRES_DAYS_DEFAULT if expires_days is None else expires_days
        if (
            not isinstance(days, int | float)
            or isinstance(days, bool)
            or not 1 <= days <= EXPIRES_DAYS_MAX
        ):
            raise NodeError(f"expires_days must be 1 to {EXPIRES_DAYS_MAX}")
        idt = self.identity
        with self._lock:
            self._expire()
            now = idt.now()
            row = self._db.execute(
                "SELECT invite_id, expires_at FROM reader_invites"
                " WHERE owner = ? AND contact_kind = ? AND contact = ? AND state = 'open'",
                (owner, kind, value),
            ).fetchone()
            if row is not None:
                return {
                    "expires_at": row[1],
                    "invite_id": row[0],
                    "invite_url": None,
                    "mailed": False,
                }
            (open_n,) = self._db.execute(
                "SELECT COUNT(*) FROM reader_invites WHERE owner = ? AND state = 'open'", (owner,)
            ).fetchone()
            if open_n >= OPEN_MAX:
                raise RateLimited("You have too many open invites. Wait until people join.")
            (day_n,) = self._db.execute(
                "SELECT COUNT(*) FROM reader_invites WHERE owner = ? AND created_at > ?",
                (owner, now - 86400),
            ).fetchone()
            if day_n >= DAY_MAX:
                raise RateLimited("You made too many invites today. Try again tomorrow.")
            token = secrets.token_bytes(32)
            expires = idt.now_dt() + timedelta(seconds=int(days * 86400))
            doc = make_invite(
                node_url=idt.cfg.public_url,
                node_key=idt.cfg.node_key,
                community=idt.cfg.community,
                token=token,
                expires_at=expires,
                assertion_key=idt.key,
            )
            iid = invite_id(token.hex())
            self._db.execute(
                "INSERT INTO invites (id, created_by, created_at, expires_at, role)"
                " VALUES (?, ?, ?, ?, 'reader')",
                (iid, owner, now, int(expires.timestamp())),
            )
            self._db.execute(
                "INSERT INTO reader_invites (invite_id, owner, contact_kind, contact, state,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, 'open', ?, ?)",
                (iid, owner, kind, value, now, int(expires.timestamp())),
            )
        link = invite_url(doc)
        mailed = False
        if kind == "email":
            community = idt.cfg.community
            idt.email_signin.mailer.send(
                value,
                MAIL_SUBJECT.format(community=community),
                MAIL_TEXT.format(name=self._owner_name(owner), community=community, link=link),
            )
            self._db.execute(
                "UPDATE reader_invites SET mailed_at = ? WHERE invite_id = ?", (idt.now(), iid)
            )
            mailed = True
        return {
            "expires_at": int(expires.timestamp()),
            "invite_id": iid,
            "invite_url": link,
            "mailed": mailed,
        }

    def list(self, owner: str, state: str | None = None) -> dict:
        """The owner's own invites. `subject` only for a claimed invite."""
        self.identity.require_member(owner)
        if state is not None and state not in STATES:
            raise NodeError("unknown state")
        with self._lock:
            self._expire()
            sql = "SELECT invite_id, state, subject, expires_at FROM reader_invites WHERE owner = ?"
            args: tuple = (owner,)
            if state is not None:
                sql += " AND state = ?"
                args += (state,)
            rows = self._db.execute(sql + " ORDER BY created_at, invite_id", args).fetchall()
        return {
            "invites": [
                {
                    # The address of the claimer, for the
                    # confirmation of the owner. Only the owner sees it.
                    "claimer_email": self.identity.email_of(subject) if st == "claimed" else None,
                    "expires_at": exp,
                    "invite_id": iid,
                    "state": st,
                    "subject": subject if st == "claimed" else None,
                }
                for iid, st, subject, exp in rows
            ]
        }

    def revoke(self, owner: str, iid: str) -> dict:
        """The owner ends an invite. A later claim fails. A claimed invite
        stays claimed (the person is a member)."""
        self.identity.require_member(owner)
        with self._lock:
            self._expire()
            row = self._db.execute(
                "SELECT state FROM reader_invites WHERE invite_id = ? AND owner = ?", (iid, owner)
            ).fetchone()
            if row is None:
                raise NotFound("unknown invite")
            if row[0] == "claimed":
                raise Forbidden("the person has joined; stop sharing with them instead")
            self._db.execute(
                "UPDATE reader_invites SET state = 'revoked' WHERE invite_id = ?", (iid,)
            )
        return {"state": "revoked"}

    def mine(self, subject: str) -> dict:
        """The claimed reader invites of a person, with the owner pid: the app
        shows "<owner> shared a finding with you" until the grant comes."""
        self.identity.require_member(subject)
        with self._lock:  # one connection for all identity threads (as `list`)
            rows = self._db.execute(
                "SELECT invite_id, owner FROM reader_invites"
                " WHERE subject = ? AND state = 'claimed' ORDER BY created_at, invite_id",
                (subject,),
            ).fetchall()
        return {"invites": [{"invite_id": i, "owner": o} for i, o in rows]}

    # ------------------------------------------------------------- claim

    def contact(self, iid: str) -> tuple[str, str, str] | None:
        """(contact kind, contact, state) of a reader invite, or None."""
        row = self._db.execute(
            "SELECT contact_kind, contact, state FROM reader_invites WHERE invite_id = ?", (iid,)
        ).fetchone()
        return (row[0], row[1], row[2]) if row else None

    def check_claim(self, iid: str, subject: str) -> bool:
        """Called by `claim_invite` with the identity lock held. True (and the
        invite becomes `claimed`) only if the invite is open, not expired, and
        `subject` proved its contact. A claim again by the same person is
        True. Each refusal looks the same to the caller."""
        self._expire()
        row = self._db.execute(
            "SELECT contact_kind, contact, state, subject, expires_at FROM reader_invites"
            " WHERE invite_id = ?",
            (iid,),
        ).fetchone()
        if row is None:
            return False
        kind, contact, state, claimed_by, expires_at = row
        if state == "claimed":
            return claimed_by == subject
        if state != "open":
            return False
        endorsement = Endorsement(
            kind=READER,
            ref=iid,
            endorser=None,
            role="member",
            max_uses=1,
            uses=0,
            expires_at=datetime.fromtimestamp(expires_at, UTC),
            contact=(kind, contact),
        )
        proved = self.identity.proved_contact(subject, kind, contact)
        at = datetime.fromtimestamp(self.identity.now(), UTC)
        claim = Claim(at=at, claimer=subject, proved_contact=proved)
        if self.policy.decide(endorsement, claim) is not None:
            return False
        self._db.execute(
            "UPDATE reader_invites SET state = 'claimed', subject = ? WHERE invite_id = ?",
            (subject, iid),
        )
        return True


def reader_invites_router(invites: ReaderInvites, subject_of) -> APIRouter:
    router = APIRouter()

    @router.post("/reader-invites")
    def create(
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        if not isinstance(body, dict):
            raise NodeError("body must be an object")
        return invites.create(
            subject_of(authorization), body.get("contact"), body.get("expires_days")
        )

    @router.get("/reader-invites")
    def list_(state: str | None = None, authorization: str | None = Header(default=None)) -> dict:
        return invites.list(subject_of(authorization), state)

    @router.get("/reader-invites/mine")
    def mine(authorization: str | None = Header(default=None)) -> dict:
        return invites.mine(subject_of(authorization))

    @router.delete("/reader-invites/{iid}")
    def revoke(iid: str, authorization: str | None = Header(default=None)) -> dict:
        return invites.revoke(subject_of(authorization), iid)

    return router
