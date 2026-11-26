"""Input checks that the sign-in methods of the node share (layer L1): the
purpose, the device key and nonce, and the person ID and ORCID salt that a
new person made."""

from __future__ import annotations

import secrets

from anagram.core.crypto.hashing import SALT_LEN
from anagram.core.errors import NodeError
from anagram.identity.formats.documents import is_subject, new_pid

# Sign-in purposes. "join": any person (an invite claim comes next). "login":
# only a member, with a device that is active or not bound yet.
# "link": a member links an ORCID iD to the account (no assertion).
PURPOSES = ("join", "login", "link")
NOT_A_MEMBER = "you are not a member of this community; join with an invite link"


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
