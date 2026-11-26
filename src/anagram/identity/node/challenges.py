"""One-time sign-in challenges of the node (layer L1): the email code, the
passkey challenges, and the device sign-in challenge.

Patterns from Wish (not its code): a secret is stored only as a hash; each
challenge has a purpose, an expiry, an attempt limit, and a single use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable

from anagram.core.errors import Unauthorized
from anagram.core.shared_db import SharedDB
from anagram.identity.node.schema import one

MAX_ATTEMPTS = 5


def secret_hash(*parts: str) -> str:
    """The stored hash of a secret (a token or a code) and its context."""
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


class Challenges:
    """The `challenges` table of `identity.sqlite`."""

    def __init__(self, db: SharedDB, now: Callable[[], int]) -> None:
        self._db = db
        self._now = now

    def new(
        self, purpose: str, destination: str, data: dict, ttl: int, secret: str | None = None
    ) -> str:
        """Store a new challenge and return its ID. `secret` (optional) is the
        code that the person must give back; only its hash is stored."""
        cid = secrets.token_urlsafe(16)
        hashed = secret_hash(purpose, cid, secret) if secret is not None else ""
        now = self._now()
        self._db.execute(
            "INSERT INTO challenges (id, purpose, destination, secret_hash, data, created_at,"
            " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cid, purpose, destination, hashed, json.dumps(data), now, now + ttl),
        )
        return cid

    def recent(self, purpose: str, destination: str, seconds: int) -> int:
        """The number of challenges for `destination` in the last `seconds`."""
        (n,) = one(
            self._db,
            "SELECT COUNT(*) FROM challenges WHERE purpose = ? AND destination = ?"
            " AND created_at > ?",
            purpose,
            destination,
            self._now() - seconds,
        )
        return n

    def use(self, cid: str, purpose: str, secret: str | None) -> tuple[str, dict]:
        """Check purpose, expiry, attempts, single use. Return (destination, data)."""
        row = one(
            self._db,
            "SELECT purpose, destination, secret_hash, data, expires_at, attempts, used"
            " FROM challenges WHERE id = ?",
            cid,
        )
        if row is None or row[0] != purpose:
            raise Unauthorized("unknown challenge")
        _, dest, hashed, data, expires, attempts, used = row
        if used or expires < self._now() or attempts >= MAX_ATTEMPTS:
            raise Unauthorized("challenge is used, expired, or locked")
        self._db.execute("UPDATE challenges SET attempts = attempts + 1 WHERE id = ?", (cid,))
        if secret is not None and not hmac.compare_digest(
            hashed, secret_hash(purpose, cid, str(secret))
        ):
            raise Unauthorized("wrong code")
        return dest, json.loads(data)

    def mark_used(self, cid: str) -> None:
        self._db.execute("UPDATE challenges SET used = 1 WHERE id = ?", (cid,))
