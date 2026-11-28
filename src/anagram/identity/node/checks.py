"""Input checks that the sign-in methods of the node share (layer L1): the
purpose, the device key and nonce, and the person ID and ORCID salt that a
new person made."""

from __future__ import annotations

import re
import secrets

from anagram.core.crypto.hashing import SALT_LEN
from anagram.core.errors import NodeError
from anagram.identity.formats.documents import is_subject, new_pid

# Sign-in purposes. "join": any person (an invite claim comes next). "login":
# only a member, with a device that is active or not bound yet.
# "link": a member links an ORCID iD to the account (no assertion).
PURPOSES = ("join", "login", "link")
NOT_A_MEMBER = "you are not a member of this community; join with an invite link"
_EMAIL_LOCAL = re.compile(r"\A[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*\Z")
_EMAIL_LABEL = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def validate_email(value: object, *, message: str = "bad email address") -> str:
    """Validate and normalize a single RFC 5322 addr-spec email address."""
    if not isinstance(value, str):
        raise NodeError(message)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise NodeError(message)
    email = value.strip().lower()
    if not email or len(email) > 254 or email.count("@") != 1:
        raise NodeError(message)
    local, domain = email.split("@")
    if not 1 <= len(local) <= 64 or not _EMAIL_LOCAL.match(local):
        raise NodeError(message)
    labels = domain.split(".")
    if len(labels) < 2 or not all(_EMAIL_LABEL.match(lbl) for lbl in labels):
        raise NodeError(message)
    return email


def sign_in_purpose(purpose: str | None) -> str:
    purpose = purpose or "join"
    if purpose not in PURPOSES:
        raise NodeError("purpose must be join or login")
    return purpose


def check_device_nonce(device_key: str, nonce: str) -> None:
    try:
        if len(bytes.fromhex(device_key)) != 32 or len(bytes.fromhex(nonce)) != 16:
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise NodeError("device_key must be 32 bytes hex, nonce 16 bytes hex") from exc
    if device_key != device_key.lower() or nonce != nonce.lower():
        raise NodeError("hex must be lowercase")


def person_pid(pid: str | None) -> str:
    """The person ID that the client made, or a new one."""
    return pid if pid is not None and is_subject(pid) else new_pid()


def person_salt(salt: str | None) -> bytes:
    """The ORCID salt that the client made, or a new one."""
    try:
        raw = bytes.fromhex(salt) if isinstance(salt, str) else b""
    except ValueError:
        raw = b""
    return raw if len(raw) == SALT_LEN else secrets.token_bytes(SALT_LEN)
