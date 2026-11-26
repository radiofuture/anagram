"""Signed public documents (spec/identity.md).

A signed document is canonical JSON. The signature is over the canonical JSON
of the document without its signature fields, with a domain tag:

    signature = Ed25519(key, u8(len(tag)) || tag || canonical_json(body))
"""

from __future__ import annotations

import base64
import binascii

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.errors import FormatError
from anagram.core.validate import HEX64, hex_field


def body_of(doc: JsonObject, *sig_fields: str) -> bytes:
    return canonical_json({k: v for k, v in doc.items() if k not in sig_fields})


def sign_doc(doc: JsonObject, tag: str, key: SigningKey) -> str:
    return key.sign(tag, body_of(doc, "signature")).hex()


def doc_signature_ok(doc: JsonObject, tag: str, public: bytes) -> bool:
    try:
        sig = bytes.fromhex(hex_field(doc.get("signature"), HEX64, "signature"))
        return verify(public, tag, body_of(doc, "signature"), sig)
    except (FormatError, CanonicalError):
        return False


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    """Strict: only the canonical unpadded form decodes, so one value has
    one text."""
    if not isinstance(text, str):
        raise FormatError("bad base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise FormatError("bad base64url") from exc
    if b64url(raw) != text:
        raise FormatError("bad base64url")
    return raw
