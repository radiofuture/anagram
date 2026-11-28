"""Admission formats (layer L4, layers plan section 2.4; spec/admission.md).

The formats of the ways into a community. They are locked: this module only
holds them; their bytes, tags, and names are the same as before the move.

- Node invite (`anagram.invite.v1`) and invite receipt
  (`anagram.invite_receipt.v1`): the node signs them with its assertion key.
  The token is the secret of the link; the public ID is its hash.
- Lab invite (`anagram.lab_invite.v1`) and join request (`anagram.lab_join.v1`):
  the device of the creator signs the authorisation. A secret seed in the
  link gives two keys (HKDF-SHA256, no salt): an Ed25519 key that signs the
  join request, and an X25519 key that opens the lab key package of the
  invite. The node never gets the seed. The roster chain (`formats.lab`,
  layer L3) applies the `invite` and `join` entries with these checks through
  the port `AdmissionCheck` (`anagram.admission.check`).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from anagram.core.canonical import CanonicalError, canonical_json, loads
from anagram.core.crypto import hpke
from anagram.core.crypto.hashing import (
    TAG_INVITE_ID,
    TAG_LAB_INVITE,
    TAG_SIGN_INVITE,
    TAG_SIGN_INVITE_RECEIPT,
    TAG_SIGN_LAB_INVITE,
    TAG_SIGN_LAB_JOIN,
    tagged_hash,
    tagged_message,
)
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.errors import FormatError
from anagram.core.signed import b64url, body_of, doc_signature_ok, sign_doc, unb64url
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, exact_fields, hex_field, int_at_least
from anagram.identity.api import node_key_fingerprint, text_field, validate_lab_id, validate_subject
from anagram.network.api import ADMIN, MEMBER, check_name

INVITE_SCHEMA = "anagram.invite.v1"
RECEIPT_SCHEMA = "anagram.invite_receipt.v1"
LAB_INVITE_SCHEMA = "anagram.lab_invite.v1"
JOIN_SCHEMA = "anagram.lab_join.v1"
MAX_INVITE_USES = 25
MAX_INVITE_DAYS = 30
DEFAULT_INVITE_DAYS = 7

# ================================================================ node

# --------------------------------------------------------------------- invite

_INVITE_FIELDS = (
    "community",
    "expires_at",
    "node_key",
    "node_url",
    "schema",
    "signature",
    "token",
)


def make_invite(
    *,
    node_url: str,
    node_key: str,
    community: str,
    token: bytes,
    expires_at: datetime,
    assertion_key: SigningKey,
) -> dict:
    doc = {
        "community": community,
        "expires_at": format_time(expires_at),
        "node_key": node_key,
        "node_url": node_url.rstrip("/"),
        "schema": INVITE_SCHEMA,
        "token": token.hex(),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_INVITE, assertion_key)
    validate_invite(doc)
    return doc


def validate_invite(doc: Any) -> dict:
    exact_fields(doc, _INVITE_FIELDS, "invite")
    if doc["schema"] != INVITE_SCHEMA:
        raise FormatError("invite: unknown schema")
    if not isinstance(doc["node_url"], str) or not doc["node_url"].startswith(
        ("https://", "http://")
    ):
        raise FormatError("invite: node_url must be http(s)")
    hex_field(doc["node_key"], HEX32, "invite node_key")
    hex_field(doc["token"], HEX32, "invite token")
    hex_field(doc["signature"], HEX64, "invite signature")
    text_field(doc["community"], "community")
    parse_time(doc["expires_at"])
    return doc


def invite_url(doc: dict) -> str:
    """`<node_url>/join#<base64url(canonical_json(invite))>`. The fragment never
    goes to a server when a browser opens the link."""
    return f"{doc['node_url']}/join#{b64url(canonical_json(doc))}"


def parse_invite_url(url: str) -> dict:
    text = url.strip()
    if "#" in text:
        text = text.split("#", 1)[1]
    try:
        doc = loads(unb64url(text))
    except (CanonicalError, UnicodeDecodeError, ValueError) as exc:
        raise FormatError("invite link is damaged") from exc
    return validate_invite(doc)


def verify_invite(doc: dict, trust: dict) -> dict:
    """Check that the node in the trust document signed the invite."""
    validate_invite(doc)
    if doc["node_key"] != node_key_fingerprint(trust["log_keys"][0]):
        raise FormatError("invite node_key does not match the node")
    if not doc_signature_ok(doc, TAG_SIGN_INVITE, bytes.fromhex(trust["assertion_key"])):
        raise FormatError("invite signature is not valid (changed invite?)")
    return doc


# -------------------------------------------------------------- invite receipt

_RECEIPT_FIELDS = (
    "claimed_at",
    "community",
    "invite",
    "node_key",
    "schema",
    "signature",
    "subject",
)


def invite_id(token_hex: str) -> str:
    """Public ID of an invite: hash of the token. The token itself stays secret."""
    return tagged_hash(TAG_INVITE_ID, bytes.fromhex(token_hex)).hex()


def make_receipt(
    *, invite: str, subject: str, community: str, node_key: str, claimed_at: datetime, key
) -> dict:
    doc = {
        "claimed_at": format_time(claimed_at),
        "community": community,
        "invite": invite,
        "node_key": node_key,
        "schema": RECEIPT_SCHEMA,
        "subject": subject,
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_INVITE_RECEIPT, key)
    return doc


def verify_receipt(doc: Any, assertion_key: bytes, subject: str) -> dict:
    exact_fields(doc, _RECEIPT_FIELDS, "receipt")
    if doc["schema"] != RECEIPT_SCHEMA or doc["subject"] != subject:
        raise FormatError("receipt: wrong schema or subject")
    if not doc_signature_ok(doc, TAG_SIGN_INVITE_RECEIPT, assertion_key):
        raise FormatError("receipt: bad signature")
    return doc


# ================================================================ group

_LAB_INVITE_FIELDS = {
    "schema",
    "node_url",
    "node_key",
    "community",
    "lab_id",
    "lab_name",
    "genesis",
    "role",
    "invite_pub",
    "invite_x25519",
    "max_uses",
    "expires_at",
    "created_by",
    "creator_device",
    "created_at",
    "signature",
}
_JOIN_FIELDS = {
    "schema",
    "lab_id",
    "invite",
    "subject",
    "device",
    "at",
    "device_signature",
    "invite_signature",
}


def _hkdf(seed: bytes, label: bytes) -> bytes:
    info = tagged_message(TAG_LAB_INVITE, label)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(seed)


# ------------------------------------------------------------------ invite


def invite_keys(seed: bytes) -> tuple[SigningKey, bytes]:
    """The two invite keys from the seed: (Ed25519 signing key, X25519 private
    bytes)."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise FormatError("invite seed must be 32 bytes")
    return SigningKey.from_seed(_hkdf(seed, b"sign")), _hkdf(seed, b"kem")


def lab_invite_id(auth: dict) -> str:
    return tagged_hash(TAG_LAB_INVITE, b"id", canonical_json(auth))[:16].hex()


def make_lab_invite(
    *,
    seed: bytes,
    node_url: str,
    node_key: str,
    community: str,
    lab_id: str,
    lab_name: str,
    genesis: str,
    role: str,
    max_uses: int,
    expires_at: datetime,
    created_by: str,
    created_at: datetime,
    key: SigningKey,
) -> dict:
    """The public authorisation of an invite. The creator device signs it."""
    sign, kem = invite_keys(seed)
    doc = {
        "community": community,
        "created_at": format_time(created_at),
        "created_by": created_by,
        "creator_device": key.public_bytes().hex(),
        "expires_at": format_time(expires_at),
        "genesis": genesis,
        "invite_pub": sign.public_bytes().hex(),
        "invite_x25519": hpke.public_bytes(hpke.private_from_bytes(kem)).hex(),
        "lab_id": lab_id,
        "lab_name": lab_name,
        "max_uses": max_uses,
        "node_key": node_key,
        "node_url": node_url.rstrip("/"),
        "role": role,
        "schema": LAB_INVITE_SCHEMA,
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_LAB_INVITE, key)
    return verify_lab_invite(doc)


def validate_lab_invite(doc: Any) -> dict:
    if not isinstance(doc, dict) or set(doc) != _LAB_INVITE_FIELDS:
        raise FormatError("lab invite: fields do not match the schema")
    if doc["schema"] != LAB_INVITE_SCHEMA:
        raise FormatError("lab invite: unknown schema")
    if not isinstance(doc["node_url"], str) or not doc["node_url"].startswith(
        ("https://", "http://")
    ):
        raise FormatError("lab invite: node_url must be http(s)")
    hex_field(doc["node_key"], HEX32, "lab invite node_key")
    check_name(doc["community"], "community")
    validate_lab_id(doc["lab_id"])
    check_name(doc["lab_name"])
    hex_field(doc["genesis"], HEX32, "lab invite genesis")
    if doc["role"] not in (ADMIN, MEMBER):
        raise FormatError("lab invite: role admin or member")
    for name in ("invite_pub", "invite_x25519", "creator_device"):
        hex_field(doc[name], HEX32, f"lab invite {name}")
    uses = int_at_least(doc["max_uses"], "lab invite max_uses", 1)
    if uses > MAX_INVITE_USES:
        raise FormatError(f"lab invite: at most {MAX_INVITE_USES} uses")
    validate_subject(doc["created_by"])
    created, expires = parse_time(doc["created_at"]), parse_time(doc["expires_at"])
    if not created < expires <= created + timedelta(days=MAX_INVITE_DAYS):
        raise FormatError(f"lab invite: expiry after creation, at most {MAX_INVITE_DAYS} days")
    hex_field(doc["signature"], HEX64, "lab invite signature")
    return doc


def verify_lab_invite(doc: Any) -> dict:
    """Form and signature of the creator device. The roster check (the creator
    can invite) is in `LabState.apply`."""
    validate_lab_invite(doc)
    if not doc_signature_ok(doc, TAG_SIGN_LAB_INVITE, bytes.fromhex(doc["creator_device"])):
        raise FormatError("lab invite: bad signature")
    return doc


def lab_invite_url(auth: dict, seed: bytes) -> str:
    """`<node_url>/join#<base64url(canonical_json({"auth", "seed"}))>`. The
    fragment never goes to a server when a browser opens the link."""
    payload = {"auth": auth, "seed": seed.hex()}
    return f"{auth['node_url']}/join#{b64url(canonical_json(payload))}"


def parse_lab_invite_link(url: str) -> dict:
    """The one parser of a lab invite link: {"auth", "seed"}. It refuses a node
    invite link and a link whose seed does not give the keys of the
    authorisation (a damaged or changed link)."""
    if not isinstance(url, str):
        raise FormatError("lab invite link is damaged")
    text = url.strip()
    if text.startswith("anagram://join/"):
        text = text.removeprefix("anagram://join/")
    elif "#" in text:
        text = text.split("#", 1)[1]
    try:
        doc = loads(unb64url(text))
    except (CanonicalError, UnicodeDecodeError, ValueError) as exc:
        raise FormatError("lab invite link is damaged") from exc
    if not isinstance(doc, dict) or set(doc) != {"auth", "seed"}:
        raise FormatError("this is not a lab invite link")
    auth = verify_lab_invite(doc["auth"])
    seed = bytes.fromhex(hex_field(doc["seed"], HEX32, "lab invite seed"))
    sign, kem = invite_keys(seed)
    if (
        sign.public_bytes().hex() != auth["invite_pub"]
        or hpke.public_bytes(hpke.private_from_bytes(kem)).hex() != auth["invite_x25519"]
    ):
        raise FormatError("lab invite link is damaged (the seed does not match)")
    return {"auth": auth, "seed": doc["seed"]}


# ------------------------------------------------------------ join request


def _join_body(req: dict) -> bytes:
    return body_of(req, "device_signature", "invite_signature")


def make_join_request(
    *,
    auth: dict,
    seed: bytes,
    subject: str,
    device_key: SigningKey,
    at: datetime,
) -> dict:
    """The joiner signs two times: with the device key (the person wants this)
    and with the invite key (the person has the link)."""
    sign, _ = invite_keys(seed)
    req = {
        "at": format_time(at),
        "device": device_key.public_bytes().hex(),
        "invite": lab_invite_id(auth),
        "lab_id": auth["lab_id"],
        "schema": JOIN_SCHEMA,
        "subject": subject,
    }
    body = _join_body(req)
    req["device_signature"] = device_key.sign(TAG_SIGN_LAB_JOIN, body).hex()
    req["invite_signature"] = sign.sign(TAG_SIGN_LAB_JOIN, body).hex()
    return validate_join_request(req)


def validate_join_request(doc: Any) -> dict:
    if not isinstance(doc, dict) or set(doc) != _JOIN_FIELDS:
        raise FormatError("join request: fields do not match the schema")
    if doc["schema"] != JOIN_SCHEMA:
        raise FormatError("join request: unknown schema")
    validate_lab_id(doc["lab_id"])
    hex_field(doc["invite"], HEX16, "join request invite")
    validate_subject(doc["subject"])
    hex_field(doc["device"], HEX32, "join request device")
    parse_time(doc["at"])
    hex_field(doc["device_signature"], HEX64, "join request device_signature")
    hex_field(doc["invite_signature"], HEX64, "join request invite_signature")
    return doc


def verify_join_request(req: dict, auth: dict) -> dict:
    """Both signatures of the request. The use rules are in `LabState.apply`."""
    validate_join_request(req)
    if req["invite"] != lab_invite_id(auth) or req["lab_id"] != auth["lab_id"]:
        raise FormatError("join request is for another invite")
    body = _join_body(req)
    if not verify(
        bytes.fromhex(req["device"]),
        TAG_SIGN_LAB_JOIN,
        body,
        bytes.fromhex(req["device_signature"]),
    ):
        raise FormatError("join request: bad device signature")
    if not verify(
        bytes.fromhex(auth["invite_pub"]),
        TAG_SIGN_LAB_JOIN,
        body,
        bytes.fromhex(req["invite_signature"]),
    ):
        raise FormatError("join request: bad invite signature (no invite key)")
    return req


def request_hash(req: dict) -> str:
    return tagged_hash(TAG_LAB_INVITE, b"request", canonical_json(req)).hex()


TAG_SIGN_LAB_INVITE_SIGNIN = "anagram/v1/sign/lab-invite-signin"


def lab_invite_signin_message(invite: str, device_key: str, nonce: str) -> bytes:
    return canonical_json({"device_key": device_key, "invite": invite, "nonce": nonce})


def sign_lab_invite_signin(invite: str, device_key: str, nonce: str, key: SigningKey) -> str:
    """Prove possession of the lab invite seed at `POST /auth/invite`."""
    return key.sign(
        TAG_SIGN_LAB_INVITE_SIGNIN, lab_invite_signin_message(invite, device_key, nonce)
    ).hex()


def verify_lab_invite_signin(
    invite: str, device_key: str, nonce: str, invite_pub: str, signature: str
) -> bool:
    try:
        sig = bytes.fromhex(hex_field(signature, HEX64, "invite_signature"))
        pub = bytes.fromhex(hex_field(invite_pub, HEX32, "invite_pub"))
        msg = lab_invite_signin_message(invite, device_key, nonce)
        return verify(pub, TAG_SIGN_LAB_INVITE_SIGNIN, msg, sig)
    except (FormatError, ValueError):
        return False
