"""Sign-in by vouch on the node (layer L1): an invite vouches for a new
person, with no proof of a third party. The registration gate (L4,
`AdmissionService`) checks the invite and then calls this part."""

from __future__ import annotations

from typing import TYPE_CHECKING

from anagram.identity.formats.documents import verify_invite_rejoin
from anagram.identity.node.checks import validate_email
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService


def stated_email(email: str | None) -> str | None:
    """The address that a person stated (not proved), in lower case, or None."""
    if email is None or (isinstance(email, str) and not email.strip()):
        return None
    return validate_email(email, message="Type an email address, for example name@lab.org.")


class VouchSignIn:
    """The invite accounts (table `invite_accounts`) and their sign-in."""

    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity

    def rejoin_ok(
        self,
        pid: str | None,
        invite_ref: str,
        device_key: str,
        *,
        invite: str = "",
        nonce: str = "",
        device_signature: str | None = None,
    ) -> bool:
        """Pre-binding retry only: the same device retries a join before seq 0
        is bound. Already-bound devices MUST use `DeviceSignIn`."""
        if pid is None or not device_signature:
            return False
        row = one(
            self.identity.db,
            "SELECT invite, device_key FROM invite_accounts WHERE subject = ?",
            pid,
        )
        if row is None or row[0] != invite_ref or row[1] != device_key:
            return False
        state = self.identity.key_state(pid)
        if state.history:
            return False
        return verify_invite_rejoin(invite, pid, device_key, nonce, device_signature)

    def new_account(
        self,
        pid: str | None,
        email: str | None,
        invite_ref: str,
        *,
        device_key: str | None = None,
        admit_email: bool = True,
    ) -> str:
        """A new account with no proof of a third party: an invite vouches for
        the person. `email` is the address that the person stated. When
        `admit_email` is False, the address is kept pending until admission."""
        idt = self.identity
        subject = idt.new_subject(pid)
        claimed_email: str | None = None
        pending_email: str | None = None
        if email is not None:
            if admit_email:
                if not one(idt.db, "SELECT 1 FROM invite_accounts WHERE email = ?", email):
                    claimed_email = email  # the first person who stated an address keeps it
            else:
                pending_email = email
        idt.db.execute(
            "INSERT INTO invite_accounts"
            " (subject, email, created_at, invite, device_key, pending_email)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (subject, claimed_email, idt.now(), invite_ref, device_key, pending_email),
        )
        return subject

    def claim_pending_email(self, subject: str) -> None:
        """Promote a pending stated email on admission (uniqueness claimed only
        once admitted as a member)."""
        idt = self.identity
        row = one(
            idt.db,
            "SELECT email, pending_email FROM invite_accounts WHERE subject = ?",
            subject,
        )
        if row is None or row[0] is not None or row[1] is None:
            return
        pending = row[1]
        if one(idt.db, "SELECT 1 FROM invite_accounts WHERE email = ?", pending):
            idt.db.execute(
                "UPDATE invite_accounts SET pending_email = NULL WHERE subject = ?",
                (subject,),
            )
            return
        idt.db.execute(
            "UPDATE invite_accounts SET email = ?, pending_email = NULL WHERE subject = ?",
            (pending, subject),
        )

    def sign_in(self, subject: str, device: str, nonce: str, receipt: dict | None) -> dict:
        """The answer of a sign-in by vouch: an assertion with method `invite`
        and no ORCID commitment, and a session."""
        return {
            "assertion": self.identity.assertion(subject, None, "invite", device, nonce),
            "profile": {"name": None, "orcid": None, "orcid_salt": None},
            "receipt": receipt,
            "session": self.identity.new_session(subject, "invite", device),
        }
