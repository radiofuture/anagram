"""Fixed inputs of the enclave vectors, and reuse of random bytes.

Two values in these vectors come from a random source in their libraries:
HPKE ciphertexts (the ephemeral key) and Biscuit tokens (the key of the next
block). The builder keeps such a value from the vector file when it still
verifies against the same fixed inputs, so a run with no change writes the
same file. A verifier checks these values (open, verify); it recomputes all
other values.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats.strict import DAY, Refused
from anagram.network.matching.trust import descriptor

T0 = 1_795_608_000  # 2026-11-25T12:00:00Z
DAY0 = T0 // DAY
NETWORK = "net.anagram.example"
VOCAB = "anagram-vocab-2026-11"
STATEMENT = (
    "Anagram matches you inside a sealed service that runs our published code; "
    "other people see your name only after you both say yes."
)
DESCRIPTORS = [
    {
        "body": {
            "accepted_schemas": ["anagram.known.v1", "anagram.pack.v1"],
            "anonymity_min_nodes": 3,
            "anonymity_min_people": 10,
            "answer_day": 7,
            "card_option": "a",
            "consent_statement": STATEMENT,
            "network": NETWORK,
            "roster_key": SigningKey.from_seed(
                hashlib.sha256(b"anagram net vector seed: roster").digest()
            )
            .public_bytes()
            .hex(),
            "weekly_cap_max": 3,
        },
        "kind": "matching",
        "schema": descriptor.SCHEMA,
    },
    {
        "body": {
            "concepts": 120_000,
            "id": VOCAB,
            "sha256": hashlib.sha256(b"anagram net vector: vocabulary file").hexdigest(),
        },
        "kind": "vocabulary",
        "schema": descriptor.SCHEMA,
    },
]
STATEMENT_HASH = descriptor.statement_hash(DESCRIPTORS[0])
DESCRIPTOR_SET = descriptor.set_hash(DESCRIPTORS).hex()
ATTESTATION = hashlib.sha256(b"anagram net vector: attestation v3 digest").digest()


SEED_RULE = 'seed = SHA-256(UTF-8("anagram net vector seed: " || label))'


def seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram net vector seed: {label}".encode()).digest()


def seed_labels(**labels: str) -> dict:
    """The seed label of each key of a file (spec gap G6 of the conformance
    review): a verifier derives the private keys from these labels."""
    return {"keys": dict(sorted(labels.items())), "rule": SEED_RULE}


def ed(label: str) -> SigningKey:
    return SigningKey.from_seed(seed(label))


def x25519(label: str) -> Any:
    return hpke.private_from_bytes(seed(label))


def xpub(label: str) -> bytes:
    return hpke.public_bytes(x25519(label))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


@dataclass
class Reuse:
    """Random bytes of the last run, by label."""

    previous: dict[str, str] = field(default_factory=dict)
    used: dict[str, str] = field(default_factory=dict)

    def token(self, label: str, facts: Any, root: SigningKey, now: int) -> bytes:
        old = self.previous.get(label)
        if old is not None:
            raw = cred.unb64url(old)
            try:
                if _read(raw, facts, root, now) == facts:
                    self.used[label] = old
                    return raw
            except Refused:
                pass
        raw = cred.make_biscuit(facts, root)
        self.used[label] = b64url(raw)
        return raw

    def source_token(
        self, label: str, source: str, root: SigningKey, extra_block: str | None = None
    ) -> bytes:
        """A token from a raw Datalog source (a refusal vector). The old token
        stays when its blocks print the same as the new source."""
        import biscuit_auth as ba

        want = [str(ba.BlockBuilder(source))]
        if extra_block is not None:
            want.append(str(ba.BlockBuilder(extra_block)))
        old = self.previous.get(label)
        if old is not None:
            raw = cred.unb64url(old)
            try:
                if cred.token_blocks(raw, root.public_bytes().hex()) == want:
                    self.used[label] = old
                    return raw
            except Exception:  # noqa: S110 - any failure means "make it again"
                pass
        raw = cred.make_biscuit_source(source, root, extra_block)
        self.used[label] = b64url(raw)
        return raw

    def sealed(
        self, label: str, private: Any, open_fn: Any, expected: bytes, seal_fn: Any
    ) -> bytes:
        old = self.previous.get(label)
        if old is not None:
            raw = unb64(old)
            try:
                if open_fn(private, raw) == expected:
                    self.used[label] = old
                    return raw
            except Exception:  # noqa: S110 - any failure means "make it again"
                pass
        raw = seal_fn()
        self.used[label] = b64(raw)
        return raw


def _read(raw: bytes, facts: Any, root: SigningKey, now: int) -> Any:
    key = root.public_bytes().hex()
    if isinstance(facts, cred.MemberFacts):
        return cred.read_member_biscuit(raw, key, now)
    return cred.read_node_biscuit(raw, key, now)
