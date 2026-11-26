"""Encoding and crypto primitives (formats.md 2 and 3.1; enclave-messages.md 2).

HPKE is written here from RFC 9180 (base mode, DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, ChaCha20-Poly1305) so that the client does not share an HPKE
implementation with the reference code.
"""

from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import struct
import time as _time
import unicodedata

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAX_INT = 2**53 - 1


class Refused(Exception):
    """A check failed. `code` is the spec code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# ---- canonical JSON (formats.md 2.1) -------------------------------------------

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode(v: object) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if not -MAX_INT <= v <= MAX_INT:
            raise ValueError("integer out of range")
        return str(v)
    if isinstance(v, float):
        raise ValueError("float")
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, list | tuple):
        return "[" + ",".join(_encode(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _encode(v[k]) for k in keys) + "}"
    raise ValueError(f"not a JSON value: {type(v)}")


def cjson(v: object) -> bytes:
    return _encode(v).encode("utf-8")


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _no_float(_s: str) -> object:
    raise ValueError("float")


def parse_canonical(raw: bytes) -> object:
    """Parse bytes that must be canonical JSON; raise ValueError if not."""
    text = raw.decode("utf-8")
    v = json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    if cjson(v) != raw:
        raise ValueError("not canonical")
    return v


# ---- small encodings -----------------------------------------------------------


def u8(n: int) -> bytes:
    return bytes([n])


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def lp(b: bytes) -> bytes:
    return u32(len(b)) + b


def tagged_message(tag: str, payload: bytes) -> bytes:
    t = tag.encode("ascii")
    return u8(len(t)) + t + payload


def tagged_hash(tag: str, *parts: bytes) -> bytes:
    return hashlib.sha256(tagged_message(tag, b"".join(parts))).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def fmt_time(t: int) -> str:
    return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(t))


def parse_time(s: str) -> int:
    if not isinstance(s, str) or len(s) != 20:
        raise ValueError("bad time")
    t = calendar.timegm(_time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    if fmt_time(t) != s:
        raise ValueError("bad time")
    return t


def day_of(t: int) -> int:
    return t // 86_400


def is_hex(s: object, nbytes: int) -> bool:
    return isinstance(s, str) and len(s) == 2 * nbytes and all(c in "0123456789abcdef" for c in s)


def is_text(s: object, max_cp: int) -> bool:
    """`text` of pack.md 2."""
    if not isinstance(s, str) or not 1 <= len(s) <= max_cp:
        return False
    if unicodedata.normalize("NFC", s) != s or s != s.strip():
        return False
    return all(unicodedata.category(c) not in ("Cc", "Cs") for c in s)


# ---- Ed25519 ------------------------------------------------------------------


class Signer:
    def __init__(self, seed: bytes) -> None:
        self.seed = seed
        self._k = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._k.public_key().public_bytes_raw()

    @property
    def hex(self) -> str:
        return self.public.hex()

    def sign(self, tag: str, payload: bytes) -> bytes:
        return self._k.sign(tagged_message(tag, payload))

    def sign_doc(self, tag: str, doc: dict) -> dict:
        body = {k: v for k, v in doc.items() if k != "signature"}
        return {**body, "signature": self.sign(tag, cjson(body)).hex()}


def verify(public: bytes, tag: str, payload: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, tagged_message(tag, payload))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_doc(public_hex: str, tag: str, doc: dict) -> bool:
    if not is_hex(doc.get("signature"), 64) or not is_hex(public_hex, 32):
        return False
    body = {k: v for k, v in doc.items() if k != "signature"}
    return verify(bytes.fromhex(public_hex), tag, cjson(body), bytes.fromhex(doc["signature"]))


# ---- X25519 and HPKE (RFC 9180) ------------------------------------------------


def x25519_public(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


_KEM_ID = b"KEM" + (0x0020).to_bytes(2, "big")
_SUITE_ID = b"HPKE" + (0x0020).to_bytes(2, "big") + (1).to_bytes(2, "big") + (3).to_bytes(2, "big")


def _lx(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _le(suite: bytes, prk: bytes, label: bytes, info: bytes, n: int) -> bytes:
    return hkdf_expand(prk, n.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, n)


def _shared(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _lx(_KEM_ID, b"", b"eae_prk", dh)
    return _le(_KEM_ID, prk, b"shared_secret", enc + pk_r, 32)


def _schedule(shared: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _lx(_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _lx(_SUITE_ID, b"", b"info_hash", info)
    ctx = b"\x00" + psk_id_hash + info_hash
    secret = _lx(_SUITE_ID, shared, b"secret", b"")
    return _le(_SUITE_ID, secret, b"key", ctx, 32), _le(_SUITE_ID, secret, b"base_nonce", ctx, 12)


def hpke_seal(pk_r: bytes, plaintext: bytes, info: bytes) -> bytes:
    """Single-shot Seal with empty aad. Output `enc || ciphertext`.

    SPEC GAP (G1): enclave-messages.md 2 and enclave-trust.md 5.3 write
    `HPKE.Seal(key, plaintext, info)` with no `aad`. This code reads that as
    the empty aad of RFC 9180 single-shot Seal.
    """
    sk_e = X25519PrivateKey.from_private_bytes(os.urandom(32))
    enc = sk_e.public_key().public_bytes_raw()
    dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
    key, nonce = _schedule(_shared(dh, enc, pk_r), info)
    return enc + ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")


def hpke_open(sk_r: bytes, sealed: bytes, info: bytes) -> bytes | None:
    if len(sealed) < 48:
        return None
    enc, ct = sealed[:32], sealed[32:]
    sk = X25519PrivateKey.from_private_bytes(sk_r)
    pk_r = sk.public_key().public_bytes_raw()
    try:
        dh = sk.exchange(X25519PublicKey.from_public_bytes(enc))
    except ValueError:
        return None
    key, nonce = _schedule(_shared(dh, enc, pk_r), info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, b"")
    except InvalidTag:
        return None


# ---- padding and fillers (enclave-messages.md 2, 4.4, 6.3) -----------------------


def pad(body: bytes, size: int) -> bytes:
    if 4 + len(body) > size:
        raise Refused("too_large", "body longer than its class allows")
    return u32(len(body)) + body + b"\x00" * (size - 4 - len(body))


def unpad(plain: bytes) -> bytes | None:
    if len(plain) < 4:
        return None
    n = struct.unpack(">I", plain[:4])[0]
    if 4 + n > len(plain) or any(plain[4 + n :]):
        return None
    return plain[4 : 4 + n]


def filler(node_secret: bytes, key: bytes, info: str, length: int) -> bytes:
    prk = hmac.new(node_secret, key, hashlib.sha256).digest()
    return hkdf_expand(prk, info.encode("ascii"), length)
