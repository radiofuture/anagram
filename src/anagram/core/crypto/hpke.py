"""HPKE (RFC 9180) through pyca `cryptography` (version 50 or later).

Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode.
We do not write cipher code. This module only picks the suite and passes data.

The output of `seal` is `enc (32 bytes) || AEAD ciphertext`, as pyca returns it.
The `info` value binds the ciphertext to its context. Each use must give its own
`info` value.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

HPKE_SUITE_NAME = "dhkem-x25519-hkdf-sha256/hkdf-sha256/chacha20-poly1305"
_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
KEY_LEN = 32


def generate() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def private_from_bytes(raw: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(raw)


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_bytes(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    if isinstance(key, X25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def seal(public: bytes, plaintext: bytes, info: bytes) -> bytes:
    """Encrypt to an X25519 public key. Return enc || ciphertext."""
    return _SUITE.encrypt(plaintext, X25519PublicKey.from_public_bytes(public), info=info)


def open_sealed(private: X25519PrivateKey, sealed: bytes, info: bytes) -> bytes:
    """Decrypt. Raise cryptography.exceptions.InvalidTag on any change or wrong info."""
    return _SUITE.decrypt(sealed, private, info=info)
