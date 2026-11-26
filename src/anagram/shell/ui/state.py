"""Small UI state: `<home>/ui.sealed`.

It holds UI choices only: the invite link (for the first join), sources that
wait for the join to finish, the confirmation that the recovery kit is saved,
the institution display name, profile edits, the block list, settings, and
the port of the app. No key, salt, or file content goes here. Writes are
atomic.

With a keystore, the file is sealed with the keystore entry `ui-state-key`
(the invite link and the block list are not readable on a copy of the disk).
An old plain `ui.json` is read one time, sealed, and erased. With no keystore
(tests of this class only) the file is the plain `ui.json`.

Other tracks read and write the state through this class only.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from anagram.core.crypto import aead
from anagram.identity.api import Keystore, KeystoreError, erase_file

UI_FILE = "ui.json"  # the plain file of an older home
SEALED_FILE = "ui.sealed"
STATE_KEY = "ui-state-key"
SCHEMA = "anagram.ui_state.v1"
AAD = b"anagram.ui_state.v1"


class UIState:
    def __init__(
        self, home: Path, keystore: Keystore | Callable[[], Keystore] | None = None
    ) -> None:
        # `keystore`: a keystore, or a function that gives it at the first use
        # (the keychain is then not read before the state is necessary).
        self.home = Path(home)
        self.plain_path = self.home / UI_FILE
        self.path = self.home / SEALED_FILE if keystore is not None else self.plain_path
        self._keystore = keystore
        self._key: bytes | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------- sealing

    def _state_key(self) -> bytes:
        if self._key is None:
            ks = self._keystore() if callable(self._keystore) else self._keystore
            self._key = ks.get_or_create(STATE_KEY, aead.new_key)
        return self._key

    def _read_plain(self) -> dict | None:
        try:
            return json.loads(self.plain_path.read_text())
        except FileNotFoundError:
            return None

    def _read_sealed(self) -> dict | None:
        try:
            doc = json.loads(self.path.read_text(encoding="ascii"))
        except FileNotFoundError:
            return None
        except ValueError as exc:
            raise KeystoreError("the UI state file is malformed") from exc
        try:
            if doc.get("schema") != SCHEMA:
                raise ValueError("schema")
            plain = aead.open_sealed(
                self._state_key(), bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ct"]), AAD
            )
            return json.loads(plain)
        except (AttributeError, InvalidTag, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, KeystoreError):
                raise  # the keystore did not open (for example a locked keychain)
            # Never replace a file that does not open.
            raise KeystoreError(
                "the UI state file does not open with the key of this home"
            ) from exc

    def _write(self, data: dict) -> None:
        text = json.dumps(data, indent=2, sort_keys=True)
        if self._keystore is not None:
            nonce, ct = aead.seal(self._state_key(), text.encode(), AAD)
            text = json.dumps({"ct": ct.hex(), "nonce": nonce.hex(), "schema": SCHEMA})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ui-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ---------------------------------------------------------------- API

    def load(self) -> dict:
        with self._lock:
            if self._keystore is None:
                return self._read_plain() or {}
            data = self._read_sealed()
            if self.plain_path.exists():
                # An older home: seal the plain state, then erase the file.
                if data is None:
                    data = self._read_plain() or {}
                    self._write(data)
                erase_file(self.plain_path)
            return data or {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.load().get(key, default)

    def update(self, **values: Any) -> dict:
        with self._lock:
            data = self.load()
            data.update(values)
            self._write(data)
            return data
