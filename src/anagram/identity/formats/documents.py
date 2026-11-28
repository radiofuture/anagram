"""Locked identity formats: node trust document, node assertion,
key-binding log entry, identity record, key backup. (The node invite and the
invite receipt are admission formats: `anagram.admission.formats`.)

These objects are public signed documents. They are not salted committed
objects. Each document is canonical JSON. The signature is over the canonical
JSON of the document without its signature fields, with a domain tag:

    signature = Ed25519(key, u8(len(tag)) || tag || canonical_json(body))

See spec/identity.md for the normative text.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anagram.core.canonical import canonical_json
from anagram.core.crypto.hashing import (
    SALT_LEN,
    TAG_KEY_BINDING_ENTRY,
    TAG_NODE_KEY_FP,
    TAG_ORCID_COMMIT,
    TAG_SIGN_DEVICE_SIGNIN,
    TAG_SIGN_IDENTITY,
    TAG_SIGN_KEY_BINDING,
    TAG_SIGN_KEY_POSSESSION,
    TAG_SIGN_NODE_ASSERTION,
    TAG_SIGN_NODE_TRUST,
    tagged_hash,
)
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.errors import FormatError
from anagram.core.signed import body_of, doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, exact_fields, hex_field
from anagram.proofs.log.note import NoteError, NoteVerifier

NODE_TRUST_SCHEMA = "anagram.node_trust.v1"
# v2 (2026-10-27): the subject is a private person ID (`pid:`). The ORCID iD is
# not in the log; only a salted commitment to it is.
ASSERTION_SCHEMA = "anagram.node_assertion.v2"
KEY_BINDING_SCHEMA = "anagram.key_binding.v2"
IDENTITY_SCHEMA = "anagram.identity_record.v2"
# Key backup v2 adds `index-key`. A client still reads v1.
KEY_BACKUP_SCHEMA = "anagram.key_backup.v2"
KEY_BACKUP_PAYLOAD_SCHEMA = "anagram.key_backup_payload.v2"
KEY_BACKUP_SCHEMA_V1 = "anagram.key_backup.v1"
KEY_BACKUP_PAYLOAD_SCHEMA_V1 = "anagram.key_backup_payload.v1"

KIND_KEY_BINDING = "key_binding"
OPS = ("add", "remove", "reset")
METHODS = ("orcid", "orcid-sandbox", "orcid-fake", "email", "invite")
# v3 (2026-11-16): methods with no ORCID commitment. "invite": the
# node checked an open invite; the inviter vouches for the person.
NO_ORCID_METHODS = ("email", "invite")
ORCID_MODES = ("production", "sandbox", "fake")

_ORCID = re.compile(r"^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$")
_FAKE_ID = re.compile(r"^fake-[0-9a-z][0-9a-z-]{0,62}$")
_ROR = re.compile(r"^0[0-9a-hj-km-np-tv-z]{6}[0-9]{2}$")
_PID = re.compile(r"^pid:[0-9a-f]{32}$")
_LAB_ID = re.compile(r"^lab-[0-9a-f]{16}$")
MAX_NAME = 200


# ------------------------------------------------------------------- helpers


def text_field(value: Any, what: str, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not 0 < len(value) <= MAX_NAME:
        raise FormatError(f"{what}: expected 1..{MAX_NAME} chars")
    if any(ord(c) < 0x20 for c in value):
        raise FormatError(f"{what}: control characters are not allowed")


def orcid_checksum_ok(orcid: str) -> bool:
    """ISO 7064 11-2 check digit, as ORCID uses."""
    digits = orcid.replace("-", "")
    total = 0
    for ch in digits[:-1]:
        total = (total + int(ch)) * 2
    check = (12 - total % 11) % 11
    return digits[-1] == ("X" if check == 10 else str(check))


def validate_orcid(orcid: Any) -> str:
    """A real ORCID iD (with a valid check digit) or a test ID `fake-...`."""
    if isinstance(orcid, str) and _FAKE_ID.match(orcid):
        return orcid
    if not isinstance(orcid, str) or not _ORCID.match(orcid) or not orcid_checksum_ok(orcid):
        raise FormatError(f"bad ORCID iD: {orcid!r}")
    return orcid


def validate_ror(ror: Any) -> str:
    """A bare ROR ID (for example 05dxps055) or a test ID `fake-...`."""
    if isinstance(ror, str) and (_ROR.match(ror) or _FAKE_ID.match(ror)):
        return ror
    raise FormatError(f"bad ROR ID: {ror!r}")


def new_pid() -> str:
    """A new person ID: `pid:` and 16 random bytes in hex. The person makes it
    at the first join. It never changes and it does not identify the person."""
    return "pid:" + secrets.token_hex(16)


def is_subject(value: Any) -> bool:
    return isinstance(value, str) and bool(_PID.match(value))


def validate_subject(subject: Any) -> str:
    if is_subject(subject):
        return subject
    raise FormatError(f"bad subject: {subject!r}")


def orcid_commitment(orcid: str, salt: bytes) -> str:
    """hex(tagged_hash("anagram/v1/orcid-commit", utf8(orcid) || salt)). The salt
    has a fixed length (32 bytes) and comes last, so the parts are unambiguous."""
    validate_orcid(orcid)
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise FormatError("ORCID salt must be 32 bytes")
    return tagged_hash(TAG_ORCID_COMMIT, orcid.encode("utf-8"), salt).hex()


def check_orcid_opening(commitment: str, orcid: str, salt: bytes) -> bool:
    """True if (orcid, salt) opens the commitment."""
    try:
        return orcid_commitment(orcid, salt) == commitment
    except FormatError:
        return False


def _commitment(value: Any, what: str = "orcid_commitment") -> None:
    if value is not None:
        hex_field(value, HEX32, what)


def node_key_fingerprint(log_vkey: str) -> str:
    """Fingerprint of the node log key: the root of trust in an invite."""
    NoteVerifier.parse(log_vkey)
    return tagged_hash(TAG_NODE_KEY_FP, log_vkey.encode("utf-8")).hex()


# ------------------------------------------------------------ node trust doc

_TRUST_FIELDS = (
    "assertion_key",
    "community",
    "fake_anchor_keys",
    "log_keys",
    "node_url",
    "orcid_mode",
    "schema",
    "signature",
    "witness_keys",
)


def make_node_trust(
    *,
    log_key: SigningKey,
    log_vkey: str,
    witness_vkeys: list[str],
    fake_anchor_keys: list[str],
    assertion_key: bytes,
    community: str,
    node_url: str,
    orcid_mode: str,
) -> dict:
    doc = {
        "assertion_key": assertion_key.hex(),
        "community": community,
        "fake_anchor_keys": list(fake_anchor_keys),
        "log_keys": [log_vkey],
        "node_url": node_url,
        "orcid_mode": orcid_mode,
        "schema": NODE_TRUST_SCHEMA,
        "witness_keys": list(witness_vkeys),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_NODE_TRUST, log_key)
    validate_node_trust(doc)
    return doc


def validate_node_trust(doc: Any) -> dict:
    exact_fields(doc, _TRUST_FIELDS, "node trust")
    if doc["schema"] != NODE_TRUST_SCHEMA or doc["orcid_mode"] not in ORCID_MODES:
        raise FormatError("node trust: unknown schema or ORCID mode")
    hex_field(doc["assertion_key"], HEX32, "assertion_key")
    text_field(doc["community"], "community")
    if not isinstance(doc["log_keys"], list) or len(doc["log_keys"]) != 1:
        raise FormatError("node trust: exactly one log key")
    try:
        for v in doc["log_keys"] + list(doc["witness_keys"]):
            NoteVerifier.parse(v)
    except (NoteError, TypeError) as exc:
        raise FormatError(f"node trust: {exc}") from exc
    for k in doc["fake_anchor_keys"]:
        hex_field(k, HEX32, "fake anchor key")
    return doc


def verify_node_trust(doc: Any, pinned_fp: str) -> dict:
    """Check the trust document against the fingerprint from the invite."""
    validate_node_trust(doc)
    log_vkey = doc["log_keys"][0]
    if node_key_fingerprint(log_vkey) != pinned_fp:
        raise FormatError("node log key does not match the pinned fingerprint")
    if not doc_signature_ok(doc, TAG_SIGN_NODE_TRUST, NoteVerifier.parse(log_vkey).public):
        raise FormatError("node trust document has a bad signature")
    return doc


# ------------------------------------------------------------- node assertion

_ASSERTION_FIELDS = (
    "audience",
    "community",
    "expires_at",
    "issued_at",
    "method",
    "node_key",
    "nonce",
    "orcid_commitment",
    "schema",
    "signature",
    "subject",
)


def make_assertion(
    *,
    subject: str,
    method: str,
    orcid_commitment: str | None,
    audience: bytes,
    nonce: str,
    community: str,
    node_key: str,
    issued_at: datetime,
    expires_at: datetime,
    key: SigningKey,
) -> dict:
    doc = {
        "audience": audience.hex(),
        "community": community,
        "expires_at": format_time(expires_at),
        "issued_at": format_time(issued_at),
        "method": method,
        "node_key": node_key,
        "nonce": nonce,
        "orcid_commitment": orcid_commitment,
        "schema": ASSERTION_SCHEMA,
        "subject": subject,
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_NODE_ASSERTION, key)
    validate_assertion(doc)
    return doc


def validate_assertion(doc: Any) -> dict:
    exact_fields(doc, _ASSERTION_FIELDS, "assertion")
    if doc["schema"] != ASSERTION_SCHEMA or doc["method"] not in METHODS:
        raise FormatError("assertion: unknown schema or method")
    validate_subject(doc["subject"])
    _commitment(doc["orcid_commitment"])
    if (doc["method"] in NO_ORCID_METHODS) != (doc["orcid_commitment"] is None):
        raise FormatError("assertion: an ORCID sign-in needs an ORCID commitment")
    hex_field(doc["audience"], HEX32, "audience")
    hex_field(doc["nonce"], HEX16, "nonce")
    hex_field(doc["node_key"], HEX32, "node_key")
    text_field(doc["community"], "community")
    parse_time(doc["issued_at"])
    parse_time(doc["expires_at"])
    return doc


def verify_assertion(
    doc: Any,
    *,
    assertion_key: bytes,
    node_key: str,
    audience: bytes | None = None,
    nonce: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Check a node assertion. Pass `audience`, `nonce`, and `now` when the
    caller is the device that asked for it."""
    validate_assertion(doc)
    if doc["node_key"] != node_key:
        raise FormatError("assertion: from a different node")
    if not doc_signature_ok(doc, TAG_SIGN_NODE_ASSERTION, assertion_key):
        raise FormatError("assertion: bad signature")
    if audience is not None and doc["audience"] != audience.hex():
        raise FormatError("assertion: issued for a different device key")
    if nonce is not None and doc["nonce"] != nonce:
        raise FormatError("assertion: wrong nonce")
    if now is not None and parse_time(doc["expires_at"]) < now:
        raise FormatError("assertion: expired")
    return doc


# ---------------------------------------------------------- key-binding entry

_BINDING_FIELDS = (
    "authority",
    "created_at",
    "device",
    "kind",
    "op",
    "orcid_commitment",
    "pop",
    "prev",
    "schema",
    "seq",
    "signature",
    "subject",
)


def device_json(ed25519: bytes, x25519: bytes) -> dict:
    return {"ed25519": ed25519.hex(), "x25519": x25519.hex()}


def possession_message(subject: str, device: dict) -> bytes:
    return canonical_json({"device": device, "subject": subject})


def sign_possession(subject: str, device: dict, key: SigningKey) -> str:
    """Proof that the holder of the new device key wants this binding. It does not
    depend on the log position, so a new device can make it before approval."""
    return key.sign(TAG_SIGN_KEY_POSSESSION, possession_message(subject, device)).hex()


TAG_SIGN_INVITE_REJOIN = "anagram/v1/sign/invite-rejoin"


def device_signin_message(subject: str, device: str, challenge: str, node_key: str) -> bytes:
    return canonical_json(
        {"challenge": challenge, "device": device, "node_key": node_key, "subject": subject}
    )


def sign_device_signin(subject: str, challenge: str, node_key: str, key: SigningKey) -> str:
    """Device sign-in: an active device key signs the node's challenge."""
    device = key.public_bytes().hex()
    msg = device_signin_message(subject, device, challenge, node_key)
    return key.sign(TAG_SIGN_DEVICE_SIGNIN, msg).hex()


def verify_device_signin(
    subject: str, device: str, challenge: str, node_key: str, signature: str
) -> bool:
    try:
        sig = bytes.fromhex(hex_field(signature, HEX64, "signature"))
        msg = device_signin_message(subject, device, challenge, node_key)
        return verify(bytes.fromhex(device), TAG_SIGN_DEVICE_SIGNIN, msg, sig)
    except (FormatError, ValueError):
        return False


def invite_rejoin_message(invite: str, pid: str, device_key: str, nonce: str) -> bytes:
    return canonical_json({"device_key": device_key, "invite": invite, "nonce": nonce, "pid": pid})


def sign_invite_rejoin(invite: str, pid: str, nonce: str, key: SigningKey) -> str:
    """Pre-binding retry proof of possession of the initial device key."""
    msg = invite_rejoin_message(invite, pid, key.public_bytes().hex(), nonce)
    return key.sign(TAG_SIGN_INVITE_REJOIN, msg).hex()


def verify_invite_rejoin(
    invite: str, pid: str, device_key: str, nonce: str, signature: str
) -> bool:
    try:
        sig = bytes.fromhex(hex_field(signature, HEX64, "device_signature"))
        pub = bytes.fromhex(hex_field(device_key, HEX32, "device_key"))
        msg = invite_rejoin_message(invite, pid, device_key, nonce)
        return verify(pub, TAG_SIGN_INVITE_REJOIN, msg, sig)
    except (FormatError, ValueError):
        return False


def binding_entry_hash(entry: dict) -> bytes:
    return tagged_hash(TAG_KEY_BINDING_ENTRY, canonical_json(entry))


def make_binding(
    *,
    subject: str,
    op: str,
    seq: int,
    prev: bytes | None,
    device: dict,
    created_at: datetime,
    authority: dict,
    orcid_commitment: str | None,
    pop: str | None = None,
    authority_key: SigningKey | None = None,
) -> dict:
    entry = {
        "authority": authority,
        "created_at": format_time(created_at),
        "device": device,
        "kind": KIND_KEY_BINDING,
        "op": op,
        "orcid_commitment": orcid_commitment,
        "pop": pop,
        "prev": prev.hex() if prev is not None else None,
        "schema": KEY_BINDING_SCHEMA,
        "seq": seq,
        "subject": subject,
    }
    if authority_key is not None:
        entry["signature"] = authority_key.sign(
            TAG_SIGN_KEY_BINDING, body_of(entry, "signature")
        ).hex()
    else:
        entry["signature"] = None
    validate_binding(entry)
    return entry


def validate_binding(entry: Any) -> dict:
    """Check the form of a key binding entry (the log service runs it for the
    kind `key_binding`, see `PUBLIC_LOG_KINDS`)."""
    exact_fields(entry, _BINDING_FIELDS, "key binding")
    if entry["schema"] != KEY_BINDING_SCHEMA or entry["kind"] != KIND_KEY_BINDING:
        raise FormatError("key binding: unknown schema")
    if entry["op"] not in OPS:
        raise FormatError("key binding: unknown op")
    validate_subject(entry["subject"])
    _commitment(entry["orcid_commitment"])
    seq = entry["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise FormatError("key binding: bad seq")
    if (seq == 0) != (entry["prev"] is None):
        raise FormatError("key binding: only seq 0 has no prev")
    if entry["prev"] is not None:
        hex_field(entry["prev"], HEX32, "prev")
    dev = exact_fields(entry["device"], ("ed25519", "x25519"), "device")
    hex_field(dev["ed25519"], HEX32, "device ed25519")
    hex_field(dev["x25519"], HEX32, "device x25519")
    parse_time(entry["created_at"])
    auth = entry["authority"]
    if not isinstance(auth, dict) or len(auth) != 1:
        raise FormatError("key binding: bad authority")
    if "assertion" in auth:
        validate_assertion(auth["assertion"])
        if auth["assertion"]["orcid_commitment"] != entry["orcid_commitment"]:
            raise FormatError("key binding: ORCID commitment differs from the assertion")
        if entry["op"] == "remove" or entry["signature"] is not None:
            raise FormatError("key binding: an assertion authorizes only add or reset")
    elif "device" in auth:
        hex_field(auth["device"], HEX32, "authority device")
        if entry["op"] == "reset":
            raise FormatError("key binding: reset needs a node assertion")
        hex_field(entry["signature"], HEX64, "signature")
    else:
        raise FormatError("key binding: bad authority")
    if entry["op"] in ("add", "reset"):
        hex_field(entry["pop"], HEX64, "pop")
    elif entry["pop"] is not None:
        raise FormatError("key binding: remove has no pop")
    return entry


class BindingError(FormatError):
    """A key-binding entry is valid in form but breaks the chain rules."""


@dataclass
class SubjectKeys:
    """Directory state of one subject, after a chain of binding entries."""

    subject: str
    seq: int = -1
    head: bytes | None = None
    devices: dict[str, dict] = field(default_factory=dict)  # ed25519 hex -> device
    history: list[dict] = field(default_factory=list)
    orcid_commitment: str | None = None  # from seq 0; it never changes

    def apply(self, entry: dict, *, assertion_key: bytes, node_key: str) -> None:
        """Check `entry` against the chain rules, then apply it."""
        validate_binding(entry)
        if entry["subject"] != self.subject:
            raise BindingError("entry is for a different subject")
        if entry["seq"] != self.seq + 1:
            raise BindingError("entry seq is not next in the chain")
        if entry["seq"] > 0 and entry["prev"] != self.head.hex():
            raise BindingError("entry prev does not match the chain head")
        if entry["seq"] > 0 and entry["orcid_commitment"] != self.orcid_commitment:
            raise BindingError("entry ORCID commitment differs from the chain")
        dev = entry["device"]
        self._check_authority(entry, assertion_key=assertion_key, node_key=node_key)
        if entry["op"] in ("add", "reset"):
            if not verify(
                bytes.fromhex(dev["ed25519"]),
                TAG_SIGN_KEY_POSSESSION,
                possession_message(self.subject, dev),
                bytes.fromhex(entry["pop"]),
            ):
                raise BindingError("bad proof of possession")
        self._change_devices(entry["op"], dev)
        self.seq = entry["seq"]
        self.head = binding_entry_hash(entry)
        self.orcid_commitment = entry["orcid_commitment"]
        self.history.append(entry)

    def _check_authority(self, entry: dict, *, assertion_key: bytes, node_key: str) -> None:
        """Check the authority of `entry`: a node assertion (first entry or
        reset) or the signature of an active device."""
        auth = entry["authority"]
        if "assertion" in auth:
            a = verify_assertion(auth["assertion"], assertion_key=assertion_key, node_key=node_key)
            if a["subject"] != self.subject or a["audience"] != entry["device"]["ed25519"]:
                raise BindingError("assertion is for a different subject or device")
            if entry["seq"] == 0 and entry["op"] != "add":
                raise BindingError("first entry must be add")
            if entry["seq"] > 0 and entry["op"] != "reset":
                raise BindingError("only reset may use an assertion after the first entry")
            return
        signer = auth["device"]
        if signer not in self.devices:
            raise BindingError("authority device is not active")
        body = body_of(entry, "signature")
        if not verify(bytes.fromhex(signer), TAG_SIGN_KEY_BINDING, body, _sig(entry)):
            raise BindingError("bad authority signature")

    def _change_devices(self, op: str, dev: dict) -> None:
        """Apply the operation `op` to the set of active devices."""
        if op == "add":
            if dev["ed25519"] in self.devices:
                raise BindingError("device is already active")
            self.devices[dev["ed25519"]] = dev
        elif op == "reset":
            self.devices = {dev["ed25519"]: dev}
        else:
            if dev["ed25519"] not in self.devices:
                raise BindingError("device to remove is not active")
            del self.devices[dev["ed25519"]]


def _sig(entry: dict) -> bytes:
    return bytes.fromhex(entry["signature"])


# ------------------------------------------------------------ identity record

_IDENTITY_FIELDS = (
    "devices",
    "display_name",
    "institution",
    "lab_id",
    "orcid_commitment",
    "schema",
    "signature",
    "signed_by",
    "subject",
    "updated_at",
)


def make_identity_record(
    *,
    subject: str,
    display_name: str,
    institution: str | None,
    lab_id: str | None,
    devices: list[dict],
    updated_at: datetime,
    key: SigningKey,
    orcid_commitment: str | None = None,
) -> dict:
    doc = {
        "devices": sorted(devices, key=lambda d: d["ed25519"]),
        "display_name": display_name,
        "institution": institution,
        "lab_id": lab_id,
        "orcid_commitment": orcid_commitment,
        "schema": IDENTITY_SCHEMA,
        "signed_by": key.public_bytes().hex(),
        "subject": subject,
        "updated_at": format_time(updated_at),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_IDENTITY, key)
    validate_identity_record(doc)
    return doc


def validate_identity_record(doc: Any) -> dict:
    exact_fields(doc, _IDENTITY_FIELDS, "identity record")
    if doc["schema"] != IDENTITY_SCHEMA:
        raise FormatError("identity record: unknown schema")
    validate_subject(doc["subject"])
    _commitment(doc["orcid_commitment"])
    text_field(doc["display_name"], "display_name")
    if doc["institution"] is not None:
        validate_ror(doc["institution"])
    if doc["lab_id"] is not None and (
        not isinstance(doc["lab_id"], str) or not _LAB_ID.match(doc["lab_id"])
    ):
        raise FormatError("identity record: bad lab_id")
    if not isinstance(doc["devices"], list) or not doc["devices"]:
        raise FormatError("identity record: needs devices")
    for d in doc["devices"]:
        exact_fields(d, ("ed25519", "x25519"), "device")
        hex_field(d["ed25519"], HEX32, "device")
        hex_field(d["x25519"], HEX32, "device")
    hex_field(doc["signed_by"], HEX32, "signed_by")
    parse_time(doc["updated_at"])
    return doc


def verify_identity_record(doc: Any, active: SubjectKeys) -> dict:
    """Check the record against the subject's directory state."""
    validate_identity_record(doc)
    if doc["subject"] != active.subject:
        raise FormatError("identity record: wrong subject")
    if doc["orcid_commitment"] != active.orcid_commitment:
        raise FormatError("identity record: ORCID commitment differs from the key directory")
    if doc["signed_by"] not in active.devices:
        raise FormatError("identity record: signer is not an active device")
    if not doc_signature_ok(doc, TAG_SIGN_IDENTITY, bytes.fromhex(doc["signed_by"])):
        raise FormatError("identity record: bad signature")
    if {d["ed25519"] for d in doc["devices"]} - set(active.devices):
        raise FormatError("identity record: lists a device that is not active")
    return doc


def new_lab_id(raw: bytes) -> str:
    return "lab-" + raw[:8].hex()


def validate_lab_id(lab_id: Any) -> str:
    if not isinstance(lab_id, str) or not _LAB_ID.match(lab_id):
        raise FormatError(f"bad lab id: {lab_id!r}")
    return lab_id


# The public log entries of L1, by kind: the node gives them to the log service.
PUBLIC_LOG_KINDS = {KIND_KEY_BINDING: validate_binding}
