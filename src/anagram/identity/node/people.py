"""People lookup on the node (layer L1): the "findable" switch, and the
lookup of a pid by ORCID iD or by email address for a signed-in member, with
a rate limit and an audit table. Every refusal looks the same (404)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from anagram.core.errors import FormatError, NodeError, NotFound, RateLimited
from anagram.identity.formats.documents import validate_orcid
from anagram.identity.node.challenges import secret_hash
from anagram.identity.node.schema import ACCOUNT_TABLES, one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService

RESOLVES_PER_HOUR = 30


class PeopleLookup:
    """The findable flags of the accounts and the table `resolve_audit`."""

    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity

    def set_findable(self, subject: str, on: bool) -> dict:
        """The person decides if members can find their pid by ORCID iD and by
        the email addresses that they signed in with (one switch for both)."""
        self.identity.require_member(subject)
        if not isinstance(on, bool):
            raise NodeError("findable must be true or false")
        flag = 1 if on else 0
        n = 0
        for table in ACCOUNT_TABLES:
            n += self.identity.db.execute(
                f"UPDATE {table} SET findable = ? WHERE subject = ?",  # noqa: S608
                (flag, subject),
            ).rowcount
        if n == 0:
            raise NodeError("only a person with an email address or ORCID iD can be findable")
        return {"findable": on, "findable_by_orcid": on}

    def _limit(self, viewer: str) -> None:
        """Shared rate limit and audit of ORCID and email lookups. Raise
        RateLimited after RESOLVES_PER_HOUR lookups in one hour."""
        (recent,) = one(
            self.identity.db,
            "SELECT COUNT(*) FROM resolve_audit WHERE viewer = ? AND at > ?",
            viewer,
            self.identity.now() - 3600,
        )
        if recent >= RESOLVES_PER_HOUR:
            raise RateLimited("too many lookups; wait one hour")

    def _audit(self, viewer: str, query: str, answered: bool) -> None:
        self.identity.db.execute(
            "INSERT INTO resolve_audit (viewer, orcid, at, answered) VALUES (?, ?, ?, ?)",
            (viewer, query, self.identity.now(), 1 if answered else 0),
        )

    def resolve_email(self, viewer: str, email: str) -> dict:
        """Email address -> pid, for a signed-in member. Only for a member
        who turned on "findable". The same rate limit as `resolve_orcid` (one
        count for both); each query goes into the audit table as a hash of the
        address."""
        idt = self.identity
        idt.require_member(viewer)
        email = str(email).strip().lower()
        if "@" not in email or len(email) > 254 or any(c.isspace() for c in email):
            raise NotFound("no findable member with this email address")
        with idt.lock:
            self._limit(viewer)
            row = one(idt.db, "SELECT subject, findable FROM email_accounts WHERE email = ?", email)
            if row is None:  # a stated address, after a proved one
                row = one(
                    idt.db, "SELECT subject, findable FROM invite_accounts WHERE email = ?", email
                )
            ok = bool(row and row[1] and idt.is_member(row[0]))
            self._audit(viewer, "email-sha256:" + secret_hash("email", email), ok)
        if not ok:
            raise NotFound("no findable member with this email address")
        return {"subject": row[0]}

    def resolve_orcid(self, viewer: str, orcid: str) -> dict:
        """ORCID iD -> pid, for a signed-in member. Only for a member who turned
        on "findable by ORCID". Rate limit for each viewer; each query goes into
        the audit table."""
        idt = self.identity
        idt.require_member(viewer)
        try:
            orcid = validate_orcid(orcid)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        with idt.lock:
            self._limit(viewer)
            acct = idt.orcid_account(orcid)
            ok = bool(acct and acct["findable"] and idt.is_member(acct["subject"]))
            self._audit(viewer, orcid, ok)
        if not ok:
            raise NotFound("no findable member with this ORCID iD")
        return {"orcid": orcid, "subject": acct["subject"]}

    def audit(self, viewer: str | None = None) -> list[dict]:
        """The lookups in the audit table (of one viewer, or of all)."""
        sql = "SELECT viewer, orcid, at, answered FROM resolve_audit"
        rows = (
            self.identity.db.execute(sql + " WHERE viewer = ? ORDER BY id", (viewer,))
            if viewer
            else self.identity.db.execute(sql + " ORDER BY id")
        )
        return [{"answered": bool(a), "at": t, "orcid": o, "viewer": v} for v, o, t, a in rows]
