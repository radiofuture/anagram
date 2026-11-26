"""Test vectors for the lab formats (spec/lab.md). Fixed inputs only.

`anagram.vectors.build` writes them to spec/vectors/lab.json. Ed25519
signatures are deterministic, so the vectors give full signed documents. A
verifier applies the roster entries in order with `device_ok` that accepts the
device keys in `keys`, and gets `state`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from anagram.admission.api import GroupAdmission, lab_invite_id
from anagram.admission.formats import lab_invite_url, make_join_request, make_lab_invite
from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.identity.api import seal_record
from anagram.network.api import LabState, make_join_entry, make_roster_entry
from anagram.network.formats.lab import entry_hash
from anagram.network.formats.labitem import KIND_ITEM, KIND_ITEM_TEXT, make_lab_item, part_ref
from anagram.network.formats.labkey import KEY_PAYLOAD_SCHEMA, LabStoreKeys, lab_key_info
from anagram.network.formats.labsettings import KIND_SETTINGS, SETTINGS_REF
from anagram.network.formats.labsettings import make_settings as make_lab_settings
from anagram.network.formats.labsettings import sections_of as settings_sections

T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)
LAB_ID = "lab-" + "1a" * 8
PI = "pid:" + "a1" * 16
ADMIN = "pid:" + "b2" * 16
MEMBER = "pid:" + "c3" * 16
NODE_URL = "https://node.example"
NODE_KEY = "9f" * 32


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram lab vector seed: {label}".encode()).digest()


def _key(label: str) -> SigningKey:
    return SigningKey.from_seed(_seed(label))


def roster() -> dict:
    """The roster chain of the vectors and the inputs that make it."""
    keys = {PI: _key("pi"), ADMIN: _key("admin"), MEMBER: _key("member")}
    devices = {pid: k.public_bytes().hex() for pid, k in keys.items()}

    def device_ok(subject: str, device: str, at: datetime) -> bool:
        return devices.get(subject) == device

    state = LabState(LAB_ID, admission=GroupAdmission())
    entries: list[dict] = []
    auths: dict[str, dict] = {}

    def add(entry: dict) -> None:
        state.apply(entry, device_ok, auths)
        entries.append(entry)

    def at(minutes: int) -> datetime:
        return T0 + timedelta(minutes=minutes)

    add(
        make_roster_entry(
            state=state,
            op="create",
            actor=PI,
            key=keys[PI],
            at=at(0),
            subject=PI,
            role="pi",
            name="Vector Lab",
        )
    )
    add(
        make_roster_entry(
            state=state,
            op="add",
            actor=PI,
            key=keys[PI],
            at=at(1),
            subject=ADMIN,
            role="admin",
        )
    )
    seed = _seed("invite")
    auth = make_lab_invite(
        seed=seed,
        node_url=NODE_URL,
        node_key=NODE_KEY,
        community="Vector community",
        lab_id=LAB_ID,
        lab_name="Vector Lab",
        genesis=state.genesis,
        role="member",
        max_uses=1,
        expires_at=at(2) + timedelta(days=7),
        created_by=ADMIN,
        created_at=at(2),
        key=keys[ADMIN],
    )
    iid = lab_invite_id(auth)
    auths[iid] = auth
    add(
        make_roster_entry(
            state=state, op="invite", actor=ADMIN, key=keys[ADMIN], at=at(2), invite=iid
        )
    )
    request = make_join_request(
        auth=auth, seed=seed, subject=MEMBER, device_key=keys[MEMBER], at=at(3)
    )
    add(make_join_entry(state=state, request=request, role="member", at=at(3)))
    add(
        make_roster_entry(
            state=state,
            op="rename",
            actor=ADMIN,
            key=keys[ADMIN],
            at=at(4),
            name="Vector Lab (renamed)",
        )
    )
    add(
        make_roster_entry(
            state=state, op="remove", actor=PI, key=keys[PI], at=at(5), subject=MEMBER
        )
    )
    return {
        "auths": auths,
        "devices": devices,
        "entries": entries,
        "hashes": [entry_hash(e) for e in entries],
        "invite": {
            "auth": auth,
            "id": iid,
            "link": lab_invite_url(auth, seed),
            "seed": seed.hex(),
        },
        "keys": {pid: k.seed().hex() for pid, k in keys.items()},
        "request": request,
        "state": {
            "genesis": state.genesis,
            "head": state.head,
            "members": state.members,
            "name": state.name,
            "removed_at": state.removed_at,
            "seq": state.seq,
        },
    }


def build() -> dict:
    r = roster()
    return {
        "description": (
            "Lab roster chain, invite, join request, key package info, lab item, and settings (spec/lab.md). Apply the "
            "entries in order; a device is valid if it is the device of `devices` "
            "for that person."
        ),
        "lab_id": LAB_ID,
        "roster": {k: r[k] for k in ("auths", "devices", "entries", "hashes", "state")},
        "invite": {**r["invite"], "request": r["request"]},
        "signing_seeds": r["keys"],
        "space": space(r),
    }


def space(r: dict) -> dict:
    """Key package `info`, a signed lab item, and a signed settings record,
    each sealed as a lab space record with a fixed nonce."""
    epoch_keys = {1: _seed("epoch 1"), 2: _seed("epoch 2")}
    keys = LabStoreKeys(epoch_keys[2], epoch_keys[1])
    pi_key = SigningKey.from_seed(bytes.fromhex(r["keys"][PI]))
    head = {"head": r["state"]["head"], "seq": r["state"]["seq"]}
    device = r["devices"][ADMIN]
    payload = {
        "epoch": 2,
        "keys": {str(n): k.hex() for n, k in epoch_keys.items()},
        "lab_id": LAB_ID,
        "schema": KEY_PAYLOAD_SCHEMA,
    }
    item = make_lab_item(
        lab_id=LAB_ID,
        item_id="17" * 16,
        rev=1,
        kind="note",
        title="Vector note",
        text="A short note for the lab.",
        author=PI,
        key=pi_key,
        roster=head,
        published_at=T0,
        updated_at=T0,
        origin={"source_kind": "note", "name": None, "media_type": "text/markdown", "time": None},
        type="note",
        facts=[{"kind": "method", "value": "PCR", "score": 900}],
    )
    settings = make_lab_settings(
        lab_id=LAB_ID,
        rev=1,
        sections={"matching": {"enabled": False}, "sources": {"lab_default": "lab"}},
        updated_by=PI,
        key=pi_key,
        roster=head,
        updated_at=T0,
    )
    nonce = bytes(range(12))
    return {
        "epoch_keys": {str(n): k.hex() for n, k in epoch_keys.items()},
        "key_package": {
            "device": device,
            "epoch": 2,
            "info_hex": lab_key_info(LAB_ID, 2, bytes.fromhex(device)).hex(),
            "payload_canonical": canonical_json(payload).decode(),
        },
        "item": {
            "value": item,
            "text": "A short note for the lab.",
            "record": seal_record(keys, KIND_ITEM, item["item_id"], item, 1, nonce),
            "text_record": seal_record(
                keys,
                KIND_ITEM_TEXT,
                part_ref(item["item_id"], 0),
                {"text": "A short note for the lab."},
                1,
                nonce,
            ),
        },
        "settings": {
            "value": settings,
            "sections": settings_sections(settings),
            "record": seal_record(keys, KIND_SETTINGS, SETTINGS_REF, settings, 1, nonce),
        },
    }
