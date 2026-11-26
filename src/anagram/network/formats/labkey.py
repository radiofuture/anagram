"""The lab key package (spec/lab.md). The lab key has epochs. A key
package wraps the keys of all epochs up to its own to each device of one
recipient (HPKE), or to the X25519 key of an invite. `LabStoreKeys` gives the
record keys of one epoch for the lab space."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from anagram.core.canonical import JsonObject, canonical_json, loads
from anagram.core.crypto import hpke
from anagram.core.crypto.hashing import TAG_HPKE_LAB_KEY, TAG_SIGN_LAB_KEY, lp, tagged_message, u32
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, hex_field, int_at_least
from anagram.core.wraps import find_wrap, validate_wraps, wrap_to_devices
from anagram.identity.api import StoreKeys, validate_lab_id, validate_subject

KEY_SCHEMA = "anagram.lab_key.v1"
KEY_PAYLOAD_SCHEMA = "anagram.lab_key_payload.v1"
MAX_EPOCH = 1 << 20
_KEY_FIELDS = {
    "schema",
    "lab_id",
    "epoch",
    "recipient",
    "roster_seq",
    "roster_head",
    "sender",
    "sender_device",
    "created_at",
    "wraps",
    "signature",
}
_INVITE_RECIPIENT = re.compile(r"^invite:[0-9a-f]{32}$")


def invite_recipient(invite_id: str) -> str:
    return "invite:" + hex_field(invite_id, HEX16, "invite id")


def lab_key_info(lab_id: str, epoch: int, device_ed25519: bytes) -> bytes:
    """HPKE `info` of one wrap: lp(lab_id) || u32(epoch) || device key."""
    return tagged_message(
        TAG_HPKE_LAB_KEY, lp(lab_id.encode("utf-8")) + u32(epoch) + device_ed25519
    )


def _check_keys(keys: Mapping[int, bytes], epoch: int) -> None:
    if sorted(keys) != list(range(1, epoch + 1)):
        raise FormatError("lab key package: needs the keys of epochs 1 to its epoch")
    if any(not isinstance(k, bytes) or len(k) != 32 for k in keys.values()):
        raise FormatError("lab key package: each key is 32 bytes")


def make_key_package(
    *,
    lab_id: str,
    epoch: int,
    keys: Mapping[int, bytes],
    recipient: str,
    devices: list[JsonObject],
    roster_seq: int,
    roster_head: str,
    sender: str,
    key: SigningKey,
    created_at: datetime,
) -> JsonObject:
    """Wrap the keys of epochs 1..`epoch` to each device of `devices`
    ({"ed25519", "x25519"} hex). For an invite, `recipient` is
    `invite:<id>` and the one device is (invite_pub, invite_x25519)."""
    int_at_least(epoch, "lab key epoch", 1)
    _check_keys(keys, epoch)
    payload = canonical_json(
        {
            "epoch": epoch,
            "keys": {str(n): keys[n].hex() for n in sorted(keys)},
            "lab_id": lab_id,
            "schema": KEY_PAYLOAD_SCHEMA,
        }
    )
    doc = {
        "created_at": format_time(created_at),
        "epoch": epoch,
        "lab_id": lab_id,
        "recipient": recipient,
        "roster_head": roster_head,
        "roster_seq": roster_seq,
        "schema": KEY_SCHEMA,
        "sender": sender,
        "sender_device": key.public_bytes().hex(),
        "wraps": wrap_to_devices(payload, devices, lambda d: lab_key_info(lab_id, epoch, d)),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_LAB_KEY, key)
    return validate_key_package(doc)


def validate_key_package(doc: Any) -> JsonObject:
    """Form only (the node does this; it has no key)."""
    if not isinstance(doc, dict) or set(doc) != _KEY_FIELDS:
        raise FormatError("lab key package: fields do not match the schema")
    if doc["schema"] != KEY_SCHEMA:
        raise FormatError("lab key package: unknown schema")
    validate_lab_id(doc["lab_id"])
    epoch = int_at_least(doc["epoch"], "lab key epoch", 1)
    if epoch > MAX_EPOCH:
        raise FormatError("lab key package: epoch is too large")
    r = doc["recipient"]
    if not (isinstance(r, str) and _INVITE_RECIPIENT.match(r)):
        validate_subject(r)
    int_at_least(doc["roster_seq"], "lab key roster_seq")
    hex_field(doc["roster_head"], HEX32, "lab key roster_head")
    validate_subject(doc["sender"])
    hex_field(doc["sender_device"], HEX32, "lab key sender_device")
    parse_time(doc["created_at"])
    validate_wraps(doc["wraps"])
    hex_field(doc["signature"], HEX64, "lab key signature")
    return doc


def open_key_package(doc: JsonObject, *, device: str, private_x25519: bytes) -> dict[int, bytes]:
    """Check the signature of the sender device and open the wrap for
    `device` (ed25519 hex). The caller checks the roster rules (the sender
    can give keys, and `sender_device` is a key of `sender`)."""
    validate_key_package(doc)
    if not doc_signature_ok(doc, TAG_SIGN_LAB_KEY, bytes.fromhex(doc["sender_device"])):
        raise FormatError("lab key package: bad signature")
    sealed = find_wrap(doc["wraps"], device)
    if sealed is None:
        raise FormatError("lab key package: no wrap for this device")
    try:
        plain = hpke.open_sealed(
            hpke.private_from_bytes(private_x25519),
            sealed,
            lab_key_info(doc["lab_id"], doc["epoch"], bytes.fromhex(device)),
        )
        payload = loads(plain)
    except Exception as exc:  # each fault means: it does not open
        raise FormatError("lab key package does not open") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"epoch", "keys", "lab_id", "schema"}
        or payload["schema"] != KEY_PAYLOAD_SCHEMA
        or payload["lab_id"] != doc["lab_id"]
        or payload["epoch"] != doc["epoch"]
        or not isinstance(payload["keys"], dict)
    ):
        raise FormatError("lab key payload does not match its package")
    try:
        keys = {int(n): bytes.fromhex(v) for n, v in payload["keys"].items()}
    except (ValueError, TypeError) as exc:
        raise FormatError("lab key payload: bad keys") from exc
    _check_keys(keys, doc["epoch"])
    return keys


class LabStoreKeys(StoreKeys):
    """Record keys of one lab epoch. The encryption key and `key_id` come from
    the key of the epoch. The record ID key comes from the key of epoch 1, so
    the ID of a record stays the same over epochs, and a new version of an
    item replaces the old version on the node."""

    def __init__(self, epoch_key: bytes, first_key: bytes) -> None:
        super().__init__(epoch_key)
        self.ids = StoreKeys(first_key).ids
