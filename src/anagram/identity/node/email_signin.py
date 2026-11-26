"""Sign-in with an email code on the node (layer L1): the node sends an
8-digit code to the address; the code proves the address."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from anagram.core.errors import Forbidden, NodeError, RateLimited
from anagram.identity.formats.documents import is_subject
from anagram.identity.node.challenges import Challenges
from anagram.identity.node.checks import NOT_A_MEMBER, check_device_nonce, sign_in_purpose
from anagram.identity.node.mailer import Mailer
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService

EMAIL_CODE_TTL = 600
EMAIL_STARTS_PER_HOUR = 5
PURPOSE = "email_signin"


def mask_email(email: str) -> str:
    """`a…@example.org`: enough for the person to know the address, and no
    more for a person who holds only the link."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}…@{domain}"


class EmailSignIn:
    """The email code challenge and the email accounts that it makes."""

    def __init__(self, identity: IdentityService, challenges: Challenges, mailer: Mailer) -> None:
        self.identity = identity
        self.challenges = challenges
        self.mailer = mailer

    def start(
        self,
        email: str,
        device_key: str,
        nonce: str,
        purpose: str | None = None,
        pid: str | None = None,
    ) -> dict:
        purpose = sign_in_purpose(purpose)
        check_device_nonce(device_key, nonce)
        if pid is not None and not is_subject(pid):
            raise NodeError("pid must be pid:<32 hex>")
        email = str(email).strip().lower()
        if "@" not in email or len(email) > 254 or any(c.isspace() for c in email):
            raise NodeError("bad email address")
        if self.challenges.recent(PURPOSE, email, 3600) >= EMAIL_STARTS_PER_HOUR:
            raise RateLimited("too many codes for this address; wait one hour")
        code = f"{secrets.randbelow(10**8):08d}"
        data = {"device_key": device_key, "nonce": nonce, "pid": pid, "purpose": purpose}
        cid = self.challenges.new(PURPOSE, email, data, EMAIL_CODE_TTL, secret=code)
        self.mailer.send(
            email,
            f"Your {self.identity.cfg.community} sign-in code",
            f"Your Anagram sign-in code is {code}. It expires in 10 minutes.\n"
            "If you did not ask for this code, ignore this message.\n",
        )
        return {"challenge_id": cid}

    def verify(self, challenge_id: str, code: str) -> dict:
        idt = self.identity
        with idt.lock:
            email, data = self.challenges.use(challenge_id, PURPOSE, code)
            self.challenges.mark_used(challenge_id)
            row = one(idt.db, "SELECT subject FROM email_accounts WHERE email = ?", email)
            if data.get("purpose") == "login":
                if row is None:  # no account is made for a login
                    raise Forbidden(NOT_A_MEMBER)
                idt.check_login(row[0], data["device_key"])
            if row is None:
                subject = idt.new_subject(data.get("pid"))
                idt.db.execute(
                    "INSERT INTO email_accounts (email, subject) VALUES (?, ?)", (email, subject)
                )
            else:
                subject = row[0]
            return {
                "assertion": idt.assertion(
                    subject, None, "email", data["device_key"], data["nonce"]
                ),
                "profile": {"name": None, "orcid": None, "orcid_salt": None},
                "session": idt.new_session(subject, "email", data["device_key"]),
            }
