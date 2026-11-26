"""C2SP tlog-checkpoint (https://c2sp.org/tlog-checkpoint).

Body:

    <origin>\\n
    <tree size, decimal>\\n
    <root hash, base64>\\n
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from anagram.proofs.log.note import (
    Note,
    NoteError,
    NoteSigner,
    NoteVerifier,
    parse_note,
    verify_cosignature,
    verify_note_signature,
)

_SIZE = re.compile(r"^(0|[1-9][0-9]*)$")


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: tuple[str, ...] = ()

    def text(self) -> str:
        lines = [self.origin, str(self.size), base64.b64encode(self.root).decode()]
        lines += list(self.extensions)
        return "\n".join(lines) + "\n"

    def digest(self) -> bytes:
        """SHA-256 of the checkpoint text. Anchors timestamp this value."""
        return hashlib.sha256(self.text().encode("utf-8")).digest()

    @classmethod
    def parse_text(cls, text: str) -> Checkpoint:
        lines = text.split("\n")
        if len(lines) < 4 or lines[-1] != "" or not _SIZE.match(lines[1]):
            raise NoteError("malformed checkpoint")
        try:
            root = base64.b64decode(lines[2], validate=True)
        except binascii.Error as exc:
            raise NoteError("malformed checkpoint root") from exc
        if len(root) != 32 or not lines[0]:
            raise NoteError("malformed checkpoint")
        return cls(lines[0], int(lines[1]), root, tuple(lines[3:-1]))


def sign_checkpoint(cp: Checkpoint, signer: NoteSigner) -> str:
    text = cp.text()
    return text + "\n" + signer.signature_line(text)


@dataclass(frozen=True)
class VerifiedCheckpoint:
    checkpoint: Checkpoint
    note: Note
    log_key: NoteVerifier
    cosignatures: tuple[tuple[NoteVerifier, int], ...]


def open_checkpoint(
    note_text: str,
    log_keys: list[NoteVerifier],
    witness_keys: list[NoteVerifier] | tuple = (),
) -> VerifiedCheckpoint:
    """Parse a checkpoint note. Require a valid signature from one pinned log key
    whose name equals the origin. Collect valid cosignatures from pinned witnesses."""
    note = parse_note(note_text)
    cp = Checkpoint.parse_text(note.text)
    for key in log_keys:
        if key.name == cp.origin and verify_note_signature(note, key):
            cosigs = []
            for w in witness_keys:
                ts = verify_cosignature(note, w)
                if ts is not None:
                    cosigs.append((w, ts))
            return VerifiedCheckpoint(cp, note, key, tuple(cosigs))
    raise NoteError("checkpoint has no valid signature from a pinned log key")
