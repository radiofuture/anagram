"""The trust policy in the encrypted index store (SQLCipher meta keys).

- `trust_policy`: the current signed document.
- `trust_policy_history`: the documents before it, newest first, at most
  `KEEP` (for the undo of net 05 step 4).

A save needs a document that `verify_policy` accepts, with the same owner
and a higher `rev` than the current one (no rollback). With no saved
document, `current` gives the default policy (decision N5).
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from anagram.core.errors import FormatError
from anagram.local.trust.policy import TrustPolicy, verify_policy

META = "trust_policy"
HISTORY = "trust_policy_history"
KEEP = 50


class TrustStore:
    def __init__(self, store: Any, owner: str, owner_devices: Collection[bytes]) -> None:
        """`store` is the `IndexStore`; `owner_devices` are the device keys
        of `owner` that may sign the policy."""
        self._store = store
        self._owner = owner
        self._devices = frozenset(owner_devices)

    def document(self) -> dict | None:
        """The current signed document, checked again at each read."""
        doc = self._store.get_meta(META)
        if doc is None:
            return None
        verify_policy(doc, self._devices)
        if doc["owner"] != self._owner:
            raise FormatError("trust policy: the saved policy is of another person")
        return doc

    def current(self) -> TrustPolicy:
        doc = self.document()
        return TrustPolicy.default(self._owner) if doc is None else TrustPolicy.from_doc(doc)

    def save(self, doc: dict) -> TrustPolicy:
        verify_policy(doc, self._devices)
        if doc["owner"] != self._owner:
            raise FormatError("trust policy: the owner is not the person of this device")
        with self._store.transaction():
            old = self.document()
            if old is not None and doc["rev"] <= old["rev"]:
                raise FormatError("trust policy: rev must be higher than the current rev")
            if old is not None:
                history = self._store.get_meta(HISTORY) or []
                self._store.set_meta(HISTORY, [old, *history][:KEEP])
            self._store.set_meta(META, doc)
        return TrustPolicy.from_doc(doc)

    def history(self) -> list[dict]:
        return list(self._store.get_meta(HISTORY) or [])
