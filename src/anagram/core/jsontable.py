"""A persistent map of text keys to JSON values in one sqlite table.

A service that keeps a small `dict` of state (for example the person-key
bindings of a node's credential issuer) can take a `JsonTable` instead, so
the state survives a restart. Values go through JSON: a tuple comes back as
a list.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, MutableMapping
from typing import Any

from anagram.core.shared_db import SharedDB

_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class JsonTable(MutableMapping[str, Any]):
    def __init__(self, db: SharedDB, table: str) -> None:
        if not _NAME.match(table):
            raise ValueError(f"bad table name: {table!r}")
        self.db = db
        self.table = table
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} (k TEXT PRIMARY KEY, v TEXT NOT NULL)")

    def __getitem__(self, key: str) -> Any:
        row = self.db.execute(f"SELECT v FROM {self.table} WHERE k = ?", (key,)).fetchone()  # noqa: S608
        if row is None:
            raise KeyError(key)
        return json.loads(row[0])

    def __setitem__(self, key: str, value: Any) -> None:
        self.db.execute(
            f"INSERT OR REPLACE INTO {self.table} (k, v) VALUES (?, ?)",  # noqa: S608
            (key, json.dumps(value, sort_keys=True)),
        )

    def __delitem__(self, key: str) -> None:
        if self.db.execute(f"DELETE FROM {self.table} WHERE k = ?", (key,)).rowcount == 0:  # noqa: S608
            raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter([r[0] for r in self.db.execute(f"SELECT k FROM {self.table} ORDER BY k")])  # noqa: S608

    def __len__(self) -> int:
        return int(self.db.execute(f"SELECT COUNT(*) FROM {self.table}").fetchone()[0])  # noqa: S608
