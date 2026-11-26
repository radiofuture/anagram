"""Ed25519 signatures through pyca `cryptography`.

All signed messages carry a domain tag (see hashing.tagged_message).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from anagram.core.crypto.hashing import tagged_message


class SigningKey:
    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> SigningKey:
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign_raw(self, message: bytes) -> bytes:
        """Sign bytes as they are. Use only for external formats (signed notes)."""
        return self._private.sign(message)

    def sign(self, tag: str, payload: bytes) -> bytes:
        return self._private.sign(tagged_message(tag, payload))


def verify_raw(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify(public: bytes, tag: str, payload: bytes, signature: bytes) -> bool:
    return verify_raw(public, tagged_message(tag, payload), signature)
