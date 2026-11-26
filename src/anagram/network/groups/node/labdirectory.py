"""The lab directory on the node: `LabDirectory`.

The tables `labs` and `lab_members` in labs.sqlite are a cache of the
verified rosters: the names and the members of each lab, for counts,
`labs_of`, and the matching operator. A row in the cache gives no access.
`LabService` (`labs`) writes it from the verified roster.
"""

from __future__ import annotations

from pathlib import Path

from anagram.core.shared_db import SharedDB

_DIRECTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS labs (
    lab_id TEXT PRIMARY KEY, name TEXT NOT NULL, pi TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS lab_members (
    lab_id TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY (lab_id, subject));
"""


class LabDirectory:
    """The names and members of the labs on this node (tables `labs` and
    `lab_members` in labs.sqlite). A cache of the verified rosters; the
    labs from before the roster keep their rows."""

    def __init__(self, db_path: str | Path) -> None:
        self._db = SharedDB(db_path)
        self._db.executescript(_DIRECTORY_SCHEMA)

    def put(self, lab_id: str, name: str, pi: str, members: list[str], now: int) -> None:
        """Write the cache of one lab (only `LabService`, from the roster)."""
        with self._db.lock:
            row = self._db.execute(
                "SELECT created_at FROM labs WHERE lab_id = ?", (lab_id,)
            ).fetchone()
            self._db.execute(
                "INSERT OR REPLACE INTO labs (lab_id, name, pi, created_at) VALUES (?, ?, ?, ?)",
                (lab_id, name, pi, row[0] if row else now),
            )
            self._db.execute("DELETE FROM lab_members WHERE lab_id = ?", (lab_id,))
            self._db.executemany(
                "INSERT INTO lab_members (lab_id, subject) VALUES (?, ?)",
                [(lab_id, s) for s in sorted(set(members))],
            )

    def labs_of(self, subject: str) -> list[str]:
        return [
            r[0]
            for r in self._db.execute(
                "SELECT lab_id FROM lab_members WHERE subject = ? ORDER BY lab_id", (subject,)
            )
        ]

    def name(self, lab_id: str) -> str | None:
        row = self._db.execute("SELECT name FROM labs WHERE lab_id = ?", (lab_id,)).fetchone()
        return row[0] if row else None

    def pi(self, lab_id: str) -> str | None:
        row = self._db.execute("SELECT pi FROM labs WHERE lab_id = ?", (lab_id,)).fetchone()
        return row[0] if row else None

    def counts(self) -> list[dict]:
        """Each lab name and its count of members, for the organizer page."""
        return [
            {"members": int(n), "name": name}
            for name, n in self._db.execute(
                "SELECT l.name, COUNT(m.subject) FROM labs l LEFT JOIN lab_members m"
                " ON l.lab_id = m.lab_id GROUP BY l.lab_id ORDER BY l.name"
            )
        ]
