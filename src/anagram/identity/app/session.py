"""The session of this device on the node: the keystore entry `node-session`.

The value is the JSON document that the node gave at sign-in (it holds the
session token). It is not a file in the data directory: with a keychain
keystore, a copy of the disk does not show the token.
"""

from __future__ import annotations

import json

from anagram.identity.app.keystore import Keystore

SESSION_KEY = "node-session"


def read_session(ks: Keystore) -> dict | None:
    """The session document in this keystore, or None."""
    raw = ks.get(SESSION_KEY)
    if raw is None:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def session_token(ks: Keystore) -> str | None:
    doc = read_session(ks)
    token = doc.get("token") if doc else None
    return token if isinstance(token, str) else None


def write_session(ks: Keystore, doc: dict) -> None:
    """Store the session document. No copy of an old session stays."""
    ks.put(SESSION_KEY, json.dumps(doc, sort_keys=True).encode("utf-8"), overwrite=True)


def clear_session(ks: Keystore) -> None:
    ks.delete(SESSION_KEY)


__all__ = ["SESSION_KEY", "clear_session", "read_session", "session_token", "write_session"]
