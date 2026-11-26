"""Sign-in by vouch on the node (layer L1): an invite vouches for a new
person, with no proof of a third party. The registration gate (L4,
`AdmissionService`) checks the invite and then calls this part."""

from __future__ import annotations

from typing import TYPE_CHECKING

from anagram.core.errors import NodeError
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService


def stated_email(email: str | None) -> str | None:
    """The address that a person stated (not proved), in lower case, or None."""
    if email is None or (isinstance(email, str) and not email.strip()):
        return None
    email = str(email).strip().lower()
    if (
        "@" not in email
        or len(email) > 254
        or any(c.isspace() for c in email)
        or email.startswith("@")
        or email.endswith("@")
    ):
        raise NodeError("Type an email address, for example name@lab.org.")
    return email


class VouchSignIn:
    """The invite accounts (table `invite_accounts`) and their sign-in."""

    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity

    def rejoin_ok(self, pid: str | None, invite_ref: str, device_key: str) -> bool:
        """The same person runs the join again with the same invite (for
        example after a stop before the device was bound, or after another
        device approved this one). True only for the account that this invite
        made, and only for an active device of it, or when it has no device
        yet. A new device of a person with devices needs the approval of an
        active device in any case (key-binding rules)."""
        if pid is None:
            return False
        row = one(self.identity.db, "SELECT invite FROM invite_accounts WHERE subject = ?", pid)
        if row is None or row[0] != invite_ref:
            return False
        state = self.identity.key_state(pid)
        return device_key in state.devices or not state.history

    def new_account(self, pid: str | None, email: str | None, invite_ref: str) -> str:
        """A new account with no proof of a third party: an invite vouches for
        the person. `email` is the address that the person stated."""
        idt = self.identity
        subject = idt.new_subject(pid)
        if email is not None and one(
            idt.db, "SELECT 1 FROM invite_accounts WHERE email = ?", email
        ):
            email = None  # the first person who stated an address keeps it
        idt.db.execute(
            "INSERT INTO invite_accounts (subject, email, created_at, invite) VALUES (?, ?, ?, ?)",
            (subject, email, idt.now(), invite_ref),
        )
        return subject

    def sign_in(self, subject: str, device: str, nonce: str, receipt: dict | None) -> dict:
        """The answer of a sign-in by vouch: an assertion with method `invite`
        and no ORCID commitment, and a session."""
        return {
            "assertion": self.identity.assertion(subject, None, "invite", device, nonce),
            "profile": {"name": None, "orcid": None, "orcid_salt": None},
            "receipt": receipt,
            "session": self.identity.new_session(subject, "invite", device),
        }
