"""Tagged SHA-256 hashes and salts.

Each use of a hash has its own domain tag. The tag registry below is part of the
locked formats (see spec/formats.md). Do not change a tag. Add a new tag for a
new use.
"""

from __future__ import annotations

import hashlib
import secrets

HASH_LEN = 32
SALT_LEN = 32

# Domain tags. Each tag is used for exactly one purpose.
TAG_FIELD = "anagram/v1/field"
TAG_EVIDENCE_ROOT = "anagram/v1/evidence-root"
TAG_FINDING_ROOT = "anagram/v1/finding-root"
TAG_STREAM_ROOT = "anagram/v1/stream-checkpoint-root"
TAG_STREAM_ITEMS = "anagram/v1/stream-items"
TAG_CONTENT = "anagram/v1/content"
TAG_LOG_ENTRY = "anagram/v1/log-entry"
TAG_SIGN_FINDING = "anagram/v1/sign/finding"
TAG_SIGN_STREAM = "anagram/v1/sign/stream-checkpoint"
TAG_FAKE_ANCHOR = "anagram/v1/fake-anchor"
TAG_VAULT_KEY_ID = "anagram/v1/vault-key-id"
# Identity and joining.
TAG_NODE_KEY_FP = "anagram/v1/node-key-fingerprint"
TAG_SIGN_NODE_TRUST = "anagram/v1/sign/node-trust"
TAG_SIGN_INVITE = "anagram/v1/sign/invite"
TAG_SIGN_INVITE_RECEIPT = "anagram/v1/sign/invite-receipt"
TAG_SIGN_NODE_ASSERTION = "anagram/v1/sign/node-assertion"
TAG_SIGN_KEY_BINDING = "anagram/v1/sign/key-binding"
TAG_SIGN_KEY_POSSESSION = "anagram/v1/sign/key-possession"
TAG_SIGN_IDENTITY = "anagram/v1/sign/identity-record"
TAG_KEY_BINDING_ENTRY = "anagram/v1/key-binding-entry"
TAG_INVITE_ID = "anagram/v1/invite-id"
# P3b: vault, grants, rings, guardians (spec/vault.md).
TAG_BLOB_KEY = "anagram/v1/blob/key"
TAG_BLOB_CHUNK = "anagram/v1/blob/chunk"
TAG_GRANT_RECEIPT = "anagram/v1/grant-receipt"
TAG_SIGN_GRANT_RECEIPT = "anagram/v1/sign/grant-receipt"
TAG_HPKE_GRANT = "anagram/v1/hpke/grant"
TAG_HPKE_GUARDIAN = "anagram/v1/hpke/guardian-share"
TAG_HPKE_RECOVERY = "anagram/v1/hpke/recovery-share"
TAG_RECOVERY_REQUEST_ID = "anagram/v1/recovery-request-id"
TAG_VAULT_ITEM = "anagram/v1/vault/item"
# v2 foundations: private person IDs, device sign-in, person keys on each
# device, personal store (spec/identity.md, spec/vault.md section 11).
TAG_ORCID_COMMIT = "anagram/v1/orcid-commit"
TAG_SIGN_DEVICE_SIGNIN = "anagram/v1/sign/device-signin"
TAG_SIGN_PERSON_KEYS = "anagram/v1/sign/person-keys"
TAG_HPKE_PERSON_KEYS = "anagram/v1/hpke/person-keys"
TAG_STORE_KEY = "anagram/v1/store/key"
TAG_STORE_RECORD_ID = "anagram/v1/store/record-id"
TAG_STORE_RECORD = "anagram/v1/store/record"
# The lab unit (roster, invites, lab keys, lab space, settings).
TAG_LAB_ROSTER = "anagram/v1/lab/roster"
TAG_SIGN_LAB_ROSTER = "anagram/v1/sign/lab-roster"
TAG_LAB_INVITE = "anagram/v1/lab/invite"
TAG_SIGN_LAB_INVITE = "anagram/v1/sign/lab-invite"
TAG_SIGN_LAB_JOIN = "anagram/v1/sign/lab-join"
TAG_HPKE_LAB_KEY = "anagram/v1/hpke/lab-key"
TAG_SIGN_LAB_KEY = "anagram/v1/sign/lab-key"
TAG_LAB_ITEM = "anagram/v1/lab/item"
TAG_SIGN_LAB_ITEM = "anagram/v1/sign/lab-item"
TAG_SIGN_LAB_SETTINGS = "anagram/v1/sign/lab-settings"
# Sharing: read receipts, fetch events, reading copy (spec/vault.md sections
# 12 to 14). Tags for guest readers are later work.
TAG_READ_RECEIPT = "anagram/v1/read-receipt"
TAG_SIGN_READ_RECEIPT = "anagram/v1/sign/read-receipt"
TAG_SIGN_FETCH_EVENT = "anagram/v1/sign/fetch-event"
TAG_READING_KEY = "anagram/v1/reading/key"
TAG_READING_BLOB_ID = "anagram/v1/reading/blob-id"
TAG_READING_EVIDENCE_ROOT = "anagram/v1/reading/evidence-root"

ALL_TAGS = (
    TAG_FIELD,
    TAG_EVIDENCE_ROOT,
    TAG_FINDING_ROOT,
    TAG_STREAM_ROOT,
    TAG_STREAM_ITEMS,
    TAG_CONTENT,
    TAG_LOG_ENTRY,
    TAG_SIGN_FINDING,
    TAG_SIGN_STREAM,
    TAG_FAKE_ANCHOR,
    TAG_VAULT_KEY_ID,
    TAG_NODE_KEY_FP,
    TAG_SIGN_NODE_TRUST,
    TAG_SIGN_INVITE,
    TAG_SIGN_INVITE_RECEIPT,
    TAG_SIGN_NODE_ASSERTION,
    TAG_SIGN_KEY_BINDING,
    TAG_SIGN_KEY_POSSESSION,
    TAG_SIGN_IDENTITY,
    TAG_KEY_BINDING_ENTRY,
    TAG_INVITE_ID,
    TAG_BLOB_KEY,
    TAG_BLOB_CHUNK,
    TAG_GRANT_RECEIPT,
    TAG_SIGN_GRANT_RECEIPT,
    TAG_HPKE_GRANT,
    TAG_HPKE_GUARDIAN,
    TAG_HPKE_RECOVERY,
    TAG_RECOVERY_REQUEST_ID,
    TAG_VAULT_ITEM,
    TAG_ORCID_COMMIT,
    TAG_SIGN_DEVICE_SIGNIN,
    TAG_SIGN_PERSON_KEYS,
    TAG_HPKE_PERSON_KEYS,
    TAG_STORE_KEY,
    TAG_STORE_RECORD_ID,
    TAG_STORE_RECORD,
    TAG_LAB_ROSTER,
    TAG_SIGN_LAB_ROSTER,
    TAG_LAB_INVITE,
    TAG_SIGN_LAB_INVITE,
    TAG_SIGN_LAB_JOIN,
    TAG_HPKE_LAB_KEY,
    TAG_SIGN_LAB_KEY,
    TAG_LAB_ITEM,
    TAG_SIGN_LAB_ITEM,
    TAG_SIGN_LAB_SETTINGS,
    # sharing
    TAG_READ_RECEIPT,
    TAG_SIGN_READ_RECEIPT,
    TAG_SIGN_FETCH_EVENT,
    TAG_READING_KEY,
    TAG_READING_BLOB_ID,
    TAG_READING_EVIDENCE_ROOT,
)


def _tag_prefix(tag: str) -> bytes:
    raw = tag.encode("utf-8")
    if not 0 < len(raw) < 256:
        raise ValueError("tag length must be 1..255 bytes")
    return len(raw).to_bytes(1, "big") + raw


def tagged_hash(tag: str, *parts: bytes) -> bytes:
    """Return SHA-256(len(tag) || tag || part1 || part2 ...).

    The caller must make the parts unambiguous: use fixed-length parts, or
    use `lp()` for each variable-length part except the last.
    """
    h = hashlib.sha256(_tag_prefix(tag))
    for part in parts:
        h.update(part)
    return h.digest()


def tagged_message(tag: str, payload: bytes) -> bytes:
    """Return the bytes to sign: len(tag) || tag || payload."""
    return _tag_prefix(tag) + payload


def lp(data: bytes) -> bytes:
    """Length-prefix: 4-byte big-endian length, then the data."""
    return len(data).to_bytes(4, "big") + data


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def new_salt() -> bytes:
    """Return a new random 32-byte salt from the OS CSPRNG."""
    return secrets.token_bytes(SALT_LEN)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
