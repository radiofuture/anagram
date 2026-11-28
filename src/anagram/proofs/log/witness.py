"""Local witness in the style of C2SP tlog-witness and tlog-cosignature.

The witness keeps the last checkpoint it cosigned for each log. It cosigns a
new checkpoint only if:

- a pinned log key signed it,
- its size is not smaller than the stored size,
- at the same size, its root equals the stored root,
- at a larger size, a consistency proof from the stored checkpoint is valid.

Otherwise it refuses. So a log cannot show two different histories (a fork) to
clients that check for this witness's cosignature.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from anagram.core.crypto import merkle
from anagram.core.shared_db import SharedDB
from anagram.proofs.log.checkpoint import open_checkpoint
from anagram.proofs.log.note import NoteSigner, NoteVerifier


class WitnessRefused(Exception):
    pass


class ForkDetected(WitnessRefused):
    pass


class WitnessConflict(WitnessRefused):
    """The caller's old size is not the witness's stored size. Retry with it."""

    def __init__(self, known_size: int) -> None:
        super().__init__(f"witness knows size {known_size}")
        self.known_size = known_size


class Witness:
    def __init__(
        self,
        signer: NoteSigner,
        db_path: str | Path,
        trusted_logs: list[NoteVerifier],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.signer = signer
        self.trusted_logs = list(trusted_logs)
        self.clock = clock
        self._db = SharedDB(db_path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS state (origin TEXT PRIMARY KEY, size INTEGER NOT NULL,"
            " root BLOB NOT NULL)"
        )

    @property
    def verifier(self) -> NoteVerifier:
        return self.signer.verifier

    def known(self, origin: str) -> tuple[int, bytes] | None:
        row = self._db.execute(
            "SELECT size, root FROM state WHERE origin = ?", (origin,)
        ).fetchone()
        return None if row is None else (int(row[0]), bytes(row[1]))

    def cosign(self, note_text: str, old_size: int, proof: list[bytes]) -> str:
        """Check and cosign a checkpoint. Return the cosignature line."""
        vc = open_checkpoint(note_text, self.trusted_logs)
        cp = vc.checkpoint
        with self._db.lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                state = self.known(cp.origin)
                known_size, known_root = state if state else (0, merkle.EMPTY_ROOT)
                if old_size != known_size:
                    raise WitnessConflict(known_size)
                if cp.size < known_size:
                    raise WitnessRefused("checkpoint is older than the last cosigned checkpoint")
                if cp.size == known_size:
                    if cp.root != known_root:
                        raise ForkDetected("same size, different root")
                elif not merkle.verify_consistency(known_size, cp.size, proof, known_root, cp.root):
                    raise ForkDetected("consistency proof failed")
                self._db.execute(
                    "INSERT OR REPLACE INTO state (origin, size, root) VALUES (?, ?, ?)",
                    (cp.origin, cp.size, cp.root),
                )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return self.signer.cosign(cp.text(), int(self.clock()))
