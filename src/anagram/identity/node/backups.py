"""Encrypted key backups on the node (layer L1). The node stores only the
ciphertext; anyone with the backup ID can get it (spec/identity.md)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from anagram.core.errors import Conflict, Forbidden, FormatError, NodeError, NotFound
from anagram.identity.formats.backup import validate_backup
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService


class KeyBackups:
    """The table `backups`."""

    def __init__(self, identity: IdentityService) -> None:
        self.identity = identity

    def put(self, subject: str, doc: dict) -> dict:
        self.identity.require_member(subject)
        try:
            validate_backup(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if doc["subject"] != subject:
            raise Forbidden("backup is for another subject")
        db = self.identity.db
        row = one(db, "SELECT subject FROM backups WHERE backup_id = ?", doc["backup_id"])
        if row is not None and row[0] != subject:
            raise Conflict("backup ID is in use")
        db.execute(
            "INSERT OR REPLACE INTO backups (backup_id, subject, doc) VALUES (?, ?, ?)",
            (doc["backup_id"], subject, json.dumps(doc)),
        )
        return {"backup_id": doc["backup_id"]}

    def delete(self, subject: str, backup_id: str) -> dict:
        self.identity.require_member(subject)
        db = self.identity.db
        row = one(db, "SELECT subject FROM backups WHERE backup_id = ?", backup_id)
        if row is None or row[0] != subject:
            raise NotFound("no backup with this ID")
        db.execute("DELETE FROM backups WHERE backup_id = ?", (backup_id,))
        return {"deleted": backup_id}

    def get(self, backup_id: str) -> dict:
        row = one(self.identity.db, "SELECT doc FROM backups WHERE backup_id = ?", backup_id)
        if row is None:
            raise NotFound("no backup with this ID")
        return json.loads(row[0])
