"""X25519 key pairs through pyca `cryptography`.

The device encryption key. Grants use it as the HPKE recipient key.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class X25519Key:
    def __init__(self, private: X25519PrivateKey) -> None:
        self._private = private

    @classmethod
    def generate(cls) -> X25519Key:
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> X25519Key:
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


def new_private() -> bytes:
    return X25519Key.generate().private_bytes()
