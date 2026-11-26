"""C2SP signed notes (https://c2sp.org/signed-note) with Ed25519 keys,
and C2SP tlog-cosignature (https://c2sp.org/tlog-cosignature) cosignatures.

Note format:

    <text, each line ends with \\n>
    \\n
    — <key name> <base64(key hash (4 bytes) || signature)>\\n
    ...

Key hash = SHA-256(key name || "\\n" || alg byte || public key)[:4].
Alg byte 0x01 = Ed25519 note signature; 0x04 = cosignature/v1.
Verifier key string: <name>+<key hash hex>+<base64(alg byte || public key)>.

A cosignature/v1 signs:

    cosignature/v1\\n
    time <unix seconds>\\n
    <checkpoint text>

and its signature line holds key hash || u64 time || signature.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from anagram.core.crypto.signing import SigningKey, verify_raw

ALG_ED25519 = 0x01
ALG_COSIGNATURE_V1 = 0x04
SIG_PREFIX = "— "  # em dash and space


class NoteError(ValueError):
    pass


def key_hash(name: str, alg: int, public: bytes) -> bytes:
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([alg]) + public).digest()[:4]


def _check_name(name: str) -> None:
    if not name or any(c.isspace() for c in name) or "+" in name:
        raise NoteError("bad key name")


@dataclass(frozen=True)
class NoteVerifier:
    name: str
    alg: int
    public: bytes

    @property
    def key_hash(self) -> bytes:
        return key_hash(self.name, self.alg, self.public)

    def vkey(self) -> str:
        enc = base64.b64encode(bytes([self.alg]) + self.public).decode()
        return f"{self.name}+{self.key_hash.hex()}+{enc}"

    @classmethod
    def parse(cls, vkey: str) -> NoteVerifier:
        try:
            name, khash, enc = vkey.strip().split("+", 2)
            raw = base64.b64decode(enc, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise NoteError("bad verifier key") from exc
        _check_name(name)
        if len(raw) != 33 or raw[0] not in (ALG_ED25519, ALG_COSIGNATURE_V1):
            raise NoteError("unsupported verifier key type")
        v = cls(name, raw[0], raw[1:])
        if v.key_hash.hex() != khash:
            raise NoteError("verifier key hash does not match")
        return v


class NoteSigner:
    def __init__(self, name: str, key: SigningKey, alg: int = ALG_ED25519) -> None:
        _check_name(name)
        self.name = name
        self.key = key
        self.alg = alg

    @property
    def verifier(self) -> NoteVerifier:
        return NoteVerifier(self.name, self.alg, self.key.public_bytes())

    def vkey(self) -> str:
        return self.verifier.vkey()

    def signature_line(self, text: str) -> str:
        if self.alg != ALG_ED25519:
            raise NoteError("use cosign() for a cosignature key")
        sig = self.key.sign_raw(text.encode("utf-8"))
        blob = base64.b64encode(self.verifier.key_hash + sig).decode()
        return f"{SIG_PREFIX}{self.name} {blob}\n"

    def cosign(self, checkpoint_text: str, timestamp: int) -> str:
        if self.alg != ALG_COSIGNATURE_V1:
            raise NoteError("not a cosignature key")
        msg = cosignature_message(checkpoint_text, timestamp)
        sig = self.key.sign_raw(msg)
        blob = self.verifier.key_hash + timestamp.to_bytes(8, "big") + sig
        return f"{SIG_PREFIX}{self.name} {base64.b64encode(blob).decode()}\n"


def cosignature_message(checkpoint_text: str, timestamp: int) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n{checkpoint_text}".encode()


@dataclass(frozen=True)
class NoteSignature:
    name: str
    key_hash: bytes
    blob: bytes  # everything after the key hash


@dataclass(frozen=True)
class Note:
    text: str
    signatures: tuple[NoteSignature, ...]

    def lines(self) -> list[str]:
        out = []
        for s in self.signatures:
            enc = base64.b64encode(s.key_hash + s.blob).decode()
            out.append(f"{SIG_PREFIX}{s.name} {enc}\n")
        return out

    def render(self) -> str:
        return self.text + "\n" + "".join(self.lines())


def parse_note(note: str) -> Note:
    sep = note.find("\n\n")
    if sep < 0 or not note.endswith("\n"):
        raise NoteError("malformed note")
    text = note[: sep + 1]
    sigs = []
    for line in note[sep + 2 :].split("\n")[:-1]:
        if not line.startswith(SIG_PREFIX):
            raise NoteError("malformed signature line")
        try:
            name, enc = line[len(SIG_PREFIX) :].split(" ")
            raw = base64.b64decode(enc, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise NoteError("malformed signature line") from exc
        if len(raw) < 5:
            raise NoteError("short signature")
        sigs.append(NoteSignature(name, raw[:4], raw[4:]))
    if not sigs:
        raise NoteError("note has no signatures")
    return Note(text, tuple(sigs))


def verify_note_signature(note: Note, verifier: NoteVerifier) -> bool:
    """True if `note` has a valid Ed25519 note signature from `verifier`."""
    if verifier.alg != ALG_ED25519:
        return False
    for s in note.signatures:
        if s.name == verifier.name and s.key_hash == verifier.key_hash:
            if verify_raw(verifier.public, note.text.encode("utf-8"), s.blob):
                return True
    return False


def verify_cosignature(note: Note, verifier: NoteVerifier) -> int | None:
    """Return the cosignature time if `verifier` cosigned the note, else None."""
    if verifier.alg != ALG_COSIGNATURE_V1:
        return None
    for s in note.signatures:
        if s.name == verifier.name and s.key_hash == verifier.key_hash and len(s.blob) == 72:
            ts = int.from_bytes(s.blob[:8], "big")
            if verify_raw(verifier.public, cosignature_message(note.text, ts), s.blob[8:]):
                return ts
    return None


def add_signature_lines(note: str, lines: list[str]) -> str:
    parse_note(note)
    return note + "".join(lines)
