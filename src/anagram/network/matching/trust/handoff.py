"""The state-key handoff message (spec/enclave-trust.md section 5.3; W4
finding M-f).

The live instance seals the state key to the successor's intake key and
signs the message with its own output key. The successor accepts it only
from a holder of the line in the log, at the line's latest logged counter
and snapshot digest. HPKE base mode alone does not say who sealed; the
signature does.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidTag

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json, loads_canonical
from anagram.core.crypto import hpke
from anagram.core.crypto.hashing import tagged_message
from anagram.core.crypto.signing import SigningKey, verify
from anagram.network.formats.strict import HEX32, MAX_SAFE, Refused
from anagram.network.matching.trust.lines import latest_epoch
from anagram.network.matching.trust.logview import LogView

SCHEMA = "anagram.enclave.handoff.v1"
TAG_HPKE_HANDOFF = "anagram/v1/enclave/hpke/handoff"
TAG_SIGN_HANDOFF = "anagram/v1/enclave/sign/handoff"
READY_SCHEMA = "anagram.enclave.handoff_ready.v1"
TAG_SIGN_READY = "anagram/v1/enclave/sign/handoff-ready"
READY_FIELDS = {"handoff", "schema", "signature", "signer"}
FIELDS = {
    "ciphertext",
    "counter",
    "line_id",
    "schema",
    "signature",
    "signer",
    "snapshot_digest",
    "successor",
}


def info(successor: bytes) -> bytes:
    """`successor` is the attestation digest of the successor's document."""
    return tagged_message(TAG_HPKE_HANDOFF, successor)


def secret(state_key: bytes, line_id: str, counter: int, snapshot_digest: str) -> bytes:
    return canonical_json(
        {
            "counter": counter,
            "line_id": line_id,
            "snapshot_digest": snapshot_digest,
            "state_key": state_key.hex(),
        }
    )


def _body(msg: JsonObject) -> bytes:
    return canonical_json({k: v for k, v in msg.items() if k != "signature"})


def make(
    ciphertext: bytes,
    line_id: str,
    counter: int,
    snapshot_digest: str,
    successor: bytes,
    output_key: SigningKey,
) -> JsonObject:
    msg = {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "counter": counter,
        "line_id": line_id,
        "schema": SCHEMA,
        "signer": output_key.public_bytes().hex(),
        "snapshot_digest": snapshot_digest,
        "successor": successor.hex(),
    }
    msg["signature"] = output_key.sign(TAG_SIGN_HANDOFF, _body(msg)).hex()
    return msg


def _holder_keys(view: LogView, line_id: str) -> set[str]:
    """Output keys of the instances that hold the line's state key now."""
    epoch = latest_epoch(view, line_id)
    holders = set(epoch["holders"]) if epoch else set()
    return {
        e["signer"]
        for _, e in view.of_kind("enclave_instance_key")
        if e["line_id"] == line_id and e["instance_id"] in holders
    }


def accept(msg: object, view: LogView, successor: bytes, intake_private: bytes) -> bytes:
    """The successor's checks. Return the state key, or raise Refused with
    `handoff_bad_sender`, `snapshot_unknown` or `handoff_bad_ciphertext`.
    Total on any message: no other exception leaves it."""
    if not isinstance(msg, dict) or set(msg) != FIELDS or msg["schema"] != SCHEMA:
        raise Refused("handoff_bad_ciphertext", "fields")
    counter = msg["counter"]
    if not all(isinstance(msg[k], str) for k in FIELDS - {"counter"}) or not (
        type(counter) is int and 0 <= counter <= MAX_SAFE
    ):
        raise Refused("handoff_bad_ciphertext", "field form")
    if msg["signer"] not in _holder_keys(view, msg["line_id"]):
        raise Refused("handoff_bad_sender", "not a holder of the line")
    try:
        sig = bytes.fromhex(msg["signature"])
    except (TypeError, ValueError) as exc:
        raise Refused("handoff_bad_sender", "signature form") from exc
    if not verify(bytes.fromhex(msg["signer"]), TAG_SIGN_HANDOFF, _body(msg), sig):
        raise Refused("handoff_bad_sender", "signature")
    epoch = latest_epoch(view, msg["line_id"])
    if epoch is None or (msg["counter"], msg["snapshot_digest"]) != (
        epoch["counter"],
        epoch["snapshot_digest"],
    ):
        raise Refused("snapshot_unknown", "not the latest logged state epoch")
    if msg["successor"] != successor.hex():
        raise Refused("handoff_bad_ciphertext", "for another successor")
    try:
        raw = base64.b64decode(msg["ciphertext"], validate=True)
        plain = hpke.open_sealed(hpke.private_from_bytes(intake_private), raw, info(successor))
        inner = loads_canonical(plain)
    except (InvalidTag, binascii.Error, CanonicalError, ValueError) as exc:
        raise Refused("handoff_bad_ciphertext", "does not open") from exc
    want = {"counter", "line_id", "snapshot_digest", "state_key"}
    if not isinstance(inner, dict) or set(inner) != want:
        raise Refused("handoff_bad_ciphertext", "inner fields")
    outer = (msg["line_id"], msg["counter"], msg["snapshot_digest"])
    if (inner["line_id"], inner["counter"], inner["snapshot_digest"]) != outer:
        raise Refused("handoff_bad_ciphertext", "inner values differ")
    key = inner["state_key"]
    if not (isinstance(key, str) and HEX32.match(key)):
        raise Refused("handoff_bad_ciphertext", "state key form")
    return bytes.fromhex(key)


# ---- the successor says it holds the key (host API, not in the spec) ---------


def _message_digest(msg: JsonObject) -> str:
    return hashlib.sha256(canonical_json(msg)).hexdigest()


def ready(msg: JsonObject, output_key: SigningKey) -> JsonObject:
    """The successor's signed note that it accepted `msg`. The writer
    writes the epoch that adds the successor only after it checks this note
    (`check_ready`), so no other caller can make the writer add a holder."""
    doc = {
        "handoff": _message_digest(msg),
        "schema": READY_SCHEMA,
        "signer": output_key.public_bytes().hex(),
    }
    doc["signature"] = output_key.sign(TAG_SIGN_READY, _body(doc)).hex()
    return doc


def check_ready(doc: object, sent: JsonObject, successor_key: str) -> None:
    """The writer's check of a `ready` note: signed by the output key of the
    successor document that the writer sealed `sent` to. Total on any note."""
    if not isinstance(doc, dict) or set(doc) != READY_FIELDS or doc["schema"] != READY_SCHEMA:
        raise Refused("handoff_not_successor", "ready fields")
    if not all(isinstance(doc[k], str) for k in READY_FIELDS):
        raise Refused("handoff_not_successor", "ready field form")
    if doc["signer"] != successor_key or doc["handoff"] != _message_digest(sent):
        raise Refused("handoff_not_successor", "not the successor of this handoff")
    try:
        sig = bytes.fromhex(doc["signature"])
    except ValueError as exc:
        raise Refused("handoff_not_successor", "signature form") from exc
    if not verify(bytes.fromhex(successor_key), TAG_SIGN_READY, _body(doc), sig):
        raise Refused("handoff_not_successor", "signature")
