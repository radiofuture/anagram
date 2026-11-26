"""Test vectors for the identity formats (spec/identity.md). Fixed inputs only.

`anagram.vectors.build` writes them to spec/vectors/identity.json.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from anagram.admission.formats import invite_id, invite_url, make_invite, make_receipt
from anagram.core.crypto.signing import SigningKey
from anagram.core.crypto.x25519 import X25519Key
from anagram.identity.api import (
    StoreKeys,
    SubjectKeys,
    make_node_trust,
    node_key_fingerprint,
    seal_record,
)
from anagram.identity.formats.backup import backup_id, encode_secret, seal_backup
from anagram.identity.formats.documents import (
    binding_entry_hash,
    device_json,
    make_assertion,
    make_binding,
    make_identity_record,
    orcid_commitment,
    sign_device_signin,
    sign_possession,
)
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner

T0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
NODE_URL = "https://node.anagram.example"
ORIGIN = "node.anagram.example/log"
COMMUNITY = "Example structural biology community"
ORCID = "0000-0002-1825-0097"  # the ORCID documentation example iD


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram identity vector seed: {label}".encode()).digest()


def _invite_join(fp: str, assertion_key: SigningKey) -> dict:
    """v3: a person who joins with an invite and no ORCID iD.
    The assertion method is `invite`; the commitment is null everywhere."""
    subject = "pid:" + _seed("invite person id")[:16].hex()
    dev = SigningKey.from_seed(_seed("invite device"))
    x = X25519Key.from_private_bytes(_seed("invite device x25519"))
    d = device_json(dev.public_bytes(), x.public_bytes())
    assertion = make_assertion(
        subject=subject,
        orcid_commitment=None,
        method="invite",
        audience=dev.public_bytes(),
        nonce=_seed("invite nonce")[:16].hex(),
        community=COMMUNITY,
        node_key=fp,
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=10),
        key=assertion_key,
    )
    binding = make_binding(
        subject=subject,
        op="add",
        seq=0,
        prev=None,
        device=d,
        created_at=T0,
        authority={"assertion": assertion},
        orcid_commitment=None,
        pop=sign_possession(subject, d, dev),
    )
    record = make_identity_record(
        subject=subject,
        display_name="Ada Invited",
        institution=None,
        lab_id=None,
        devices=[d],
        updated_at=T0 + timedelta(minutes=1),
        key=dev,
        orcid_commitment=None,
    )
    return {
        "assertion": assertion,
        "binding": binding,
        "device_seed": dev.seed().hex(),
        "identity_record": record,
        "subject": subject,
    }


def build() -> dict:
    log_key = SigningKey.from_seed(_seed("log"))
    log = NoteSigner(ORIGIN, log_key)
    witness = NoteSigner(
        "node.anagram.example/witness",
        SigningKey.from_seed(_seed("witness")),
        alg=ALG_COSIGNATURE_V1,
    )
    assertion_key = SigningKey.from_seed(_seed("assertion"))
    fp = node_key_fingerprint(log.vkey())
    trust = make_node_trust(
        log_key=log_key,
        log_vkey=log.vkey(),
        witness_vkeys=[witness.vkey()],
        fake_anchor_keys=[],
        assertion_key=assertion_key.public_bytes(),
        community=COMMUNITY,
        node_url=NODE_URL,
        orcid_mode="production",
    )
    token = _seed("invite token")
    invite = make_invite(
        node_url=NODE_URL,
        node_key=fp,
        community=COMMUNITY,
        token=token,
        expires_at=T0 + timedelta(days=7),
        assertion_key=assertion_key,
    )
    subject = "pid:" + _seed("person id")[:16].hex()
    orcid_salt = _seed("orcid salt")
    commitment = orcid_commitment(ORCID, orcid_salt)
    receipt = make_receipt(
        invite=invite_id(token.hex()),
        subject=subject,
        community=COMMUNITY,
        node_key=fp,
        claimed_at=T0,
        key=assertion_key,
    )

    dev1 = SigningKey.from_seed(_seed("device 1"))
    x1 = X25519Key.from_private_bytes(_seed("device 1 x25519"))
    dev2 = SigningKey.from_seed(_seed("device 2"))
    x2 = X25519Key.from_private_bytes(_seed("device 2 x25519"))
    d1 = device_json(dev1.public_bytes(), x1.public_bytes())
    d2 = device_json(dev2.public_bytes(), x2.public_bytes())

    assertion = make_assertion(
        subject=subject,
        orcid_commitment=commitment,
        method="orcid",
        audience=dev1.public_bytes(),
        nonce=_seed("nonce")[:16].hex(),
        community=COMMUNITY,
        node_key=fp,
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=10),
        key=assertion_key,
    )
    first = make_binding(
        subject=subject,
        op="add",
        seq=0,
        prev=None,
        device=d1,
        created_at=T0,
        authority={"assertion": assertion},
        orcid_commitment=commitment,
        pop=sign_possession(subject, d1, dev1),
    )
    second = make_binding(
        subject=subject,
        op="add",
        seq=1,
        prev=binding_entry_hash(first),
        device=d2,
        created_at=T0 + timedelta(minutes=5),
        authority={"device": d1["ed25519"]},
        orcid_commitment=commitment,
        pop=sign_possession(subject, d2, dev2),
        authority_key=dev1,
    )
    third = make_binding(
        subject=subject,
        op="remove",
        seq=2,
        prev=binding_entry_hash(second),
        device=d1,
        created_at=T0 + timedelta(minutes=9),
        authority={"device": d2["ed25519"]},
        orcid_commitment=commitment,
        authority_key=dev2,
    )
    state = SubjectKeys(subject)
    for e in (first, second, third):
        state.apply(e, assertion_key=assertion_key.public_bytes(), node_key=fp)

    record = make_identity_record(
        subject=subject,
        display_name="Josiah Carberry",
        institution="fake-northbridge-university",
        lab_id="lab-" + _seed("lab")[:8].hex(),
        devices=[d2],
        updated_at=T0 + timedelta(minutes=10),
        key=dev2,
        orcid_commitment=commitment,
    )

    secret = _seed("recovery secret")[:20]
    backup = seal_backup(
        secret,
        subject,
        {
            "device-ed25519": dev1.seed(),
            "device-x25519": x1.private_bytes(),
            "index-key": _seed("index key"),
            "vault-key": _seed("vault key"),
        },
        nonce=_seed("backup nonce")[:12],
    )
    store = StoreKeys(_seed("vault key"))
    store_record = seal_record(
        store,
        "finding",
        "00" * 32,
        {"example": True},
        1,
        nonce=_seed("store nonce")[:12],
    )
    challenge = _seed("device sign-in challenge").hex()

    return {
        "description": "Identity formats v3: node trust, invite, receipt, assertion, key "
        "bindings (pid subject, ORCID commitment), identity record, key backup v2, device "
        "sign-in, personal store record, invite join with no ORCID (v3). Fixed seeds; Ed25519 "
        "is deterministic. HPKE output "
        "is random, so the person-keys package is not a fixed vector (see the tests).",
        "seeds": {
            "log": _seed("log").hex(),
            "assertion": assertion_key.seed().hex(),
            "device_1": dev1.seed().hex(),
            "device_1_x25519": x1.private_bytes().hex(),
            "device_2": dev2.seed().hex(),
            "device_2_x25519": x2.private_bytes().hex(),
        },
        "node_key_fingerprint": fp,
        "node_trust": trust,
        "invite": invite,
        "invite_url": invite_url(invite),
        "invite_id": invite_id(token.hex()),
        "receipt": receipt,
        "subject": subject,
        "orcid_commitment": {
            "orcid": ORCID,
            "salt": orcid_salt.hex(),
            "commitment": commitment,
        },
        "assertion": assertion,
        "bindings": [first, second, third],
        "binding_hashes": [binding_entry_hash(e).hex() for e in (first, second, third)],
        "active_devices_after": sorted(state.devices),
        "identity_record": record,
        "recovery": {
            "secret_hex": secret.hex(),
            "code": encode_secret(secret),
            "backup_id": backup_id(secret),
            "backup": backup,
        },
        "invite_join": _invite_join(fp, assertion_key),
        "device_signin": {
            "challenge": challenge,
            "signature": sign_device_signin(subject, challenge, fp, dev2),
        },
        "personal_store": {
            "vault_key": _seed("vault key").hex(),
            "key_id": store.key_id,
            "record_id": store.record_id("finding", "00" * 32),
            "record": store_record,
        },
    }
