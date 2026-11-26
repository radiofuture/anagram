"""Authenticated encryption through pyca `cryptography` (ChaCha20-Poly1305).

We do not write cipher code. This module only picks nonces and passes data.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

AEAD_ALG = "chacha20-poly1305"
KEY_LEN = 32
NONCE_LEN = 12


def new_key() -> bytes:
    return ChaCha20Poly1305.generate_key()


def seal(
    key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None
) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext). The nonce is random (96 bits).

    Pass `nonce` only to make fixed test vectors. Never reuse a nonce with a key.
    """
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt. Raise cryptography.exceptions.InvalidTag on any change."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
