"""A keystore whose key files are sealed with a master key.

File `<directory>/<name>.skey`, mode 0600, one line of JSON:
`{"ct": hex, "nonce": hex, "schema": "anagram.sealed_key.v1"}`. The associated
data binds the keystore ID and the name. A file that is moved to another name
or to another keystore does not open. A file that does not open is an error;
it is never replaced by a new key.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidTag

from anagram.core.crypto import aead
from anagram.identity.app.keystore import DirectoryKeystore, KeystoreError

SCHEMA = "anagram.sealed_key.v1"
SUFFIX = ".skey"


class SealedKeystore(DirectoryKeystore):
    suffix = SUFFIX

    def __init__(self, directory: str | Path, master: bytes, keystore_id: str) -> None:
        if len(master) != aead.KEY_LEN:
            raise KeystoreError("the master key must be 32 bytes")
        super().__init__(directory)
        self._master = master
        self.keystore_id = keystore_id

    def _aad(self, name: str) -> bytes:
        return SCHEMA.encode() + b"\x00" + self.keystore_id.encode() + b"\x00" + name.encode()

    def _encode(self, name: str, secret: bytes) -> str:
        nonce, ct = aead.seal(self._master, secret, self._aad(name))
        return json.dumps({"ct": ct.hex(), "nonce": nonce.hex(), "schema": SCHEMA}, sort_keys=True)

    def _decode(self, name: str, text: str, path: Path) -> bytes:
        try:
            doc = json.loads(text)
            if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
                raise ValueError("schema")
            nonce, ct = bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ct"])
            return aead.open_sealed(self._master, nonce, ct, self._aad(name))
        except (ValueError, KeyError, TypeError, InvalidTag):
            raise KeystoreError(f"sealed key file {path.name} does not open") from None
