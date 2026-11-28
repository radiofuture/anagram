"""Locked record formats: committed objects, evidence, finding, link, stream checkpoint.

A committed object is a flat map of named fields. Each field has its own random
32-byte salt. The field leaf is

    tagged_hash(TAG_FIELD, salt || lp(name) || canonical_json(value))

The leaves, in sorted field-name order, form an RFC 6962 Merkle tree. The
layout is the sorted list of field names (each name once). The root of the
object is

    tagged_hash(<object tag>, lp(canonical_json(layout)) || MTH)

The owner can open one field (salt, value, inclusion path, layout) and keep the
other fields hidden. The layout binds each name to one fixed leaf position, so
an owner cannot commit two leaves with the same name and open the one that
suits a later result.

See spec/formats.md for the normative text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import ContentDigest
from anagram.core.crypto.hashing import (
    SALT_LEN,
    TAG_EVIDENCE_ROOT,
    TAG_FIELD,
    TAG_FINDING_ROOT,
    TAG_LOG_ENTRY,
    TAG_SIGN_FINDING,
    TAG_SIGN_STREAM,
    TAG_STREAM_ITEMS,
    TAG_STREAM_ROOT,
    lp,
    new_salt,
    tagged_hash,
    u64,
)
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.errors import FormatError
from anagram.core.timefmt import format_time, parse_time

EVIDENCE_SCHEMA = "anagram.evidence.v1"
FINDING_SCHEMA = "anagram.finding.v1"
STREAM_SCHEMA = "anagram.stream_checkpoint.v1"
LOG_ENTRY_SCHEMA = "anagram.log_entry.v1"

KIND_FINDING = "finding"
KIND_STREAM = "stream_checkpoint"
KINDS = {
    KIND_FINDING: (TAG_FINDING_ROOT, TAG_SIGN_FINDING),
    KIND_STREAM: (TAG_STREAM_ROOT, TAG_SIGN_STREAM),
}
# Log-only kinds: the node itself logs these. They have no signed subject.
# The node no longer writes `match_round` or `operator_attestation`
# (spec/matching.md section 8); a log reader still accepts them.
KIND_MATCH_ROUND = "match_round"
KIND_OPERATOR_ATTESTATION = "operator_attestation"
# A hidden grant receipt (spec/vault.md section 4). A member submits it.
KIND_GRANT_RECEIPT = "grant_receipt"
# A hidden read receipt (spec/vault.md section 12). The node submits it
# for the reader when it accepts the receipt.
KIND_READ_RECEIPT = "read_receipt"
LOG_ONLY_KINDS = (
    KIND_MATCH_ROUND,
    KIND_OPERATOR_ATTESTATION,
    KIND_GRANT_RECEIPT,
    KIND_READ_RECEIPT,
)

LINK_SUPERSEDES = "supersedes"
LINK_BUILDS_ON = "builds_on"
LINK_INCLUDES = "includes"
LINK_TYPES = (LINK_SUPERSEDES, LINK_BUILDS_ON, LINK_INCLUDES)

OWNER_ALG = "ed25519"
_FIELD_NAME = re.compile(r"\A[a-z][a-z0-9_]*(\.(0|[1-9][0-9]*))?\Z")
MAX_FIELDS = 1 << 16
_HEX32 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"\A[0-9a-f]{32}\Z")


# --------------------------------------------------------------------------- time


def _hex32(s: Any, what: str) -> bytes:
    if not isinstance(s, str) or not _HEX32.match(s):
        raise FormatError(f"{what}: expected 64 lowercase hex chars")
    return bytes.fromhex(s)


# ------------------------------------------------------------- committed objects


def field_leaf(name: str, salt: bytes, value: Any) -> bytes:
    if len(salt) != SALT_LEN:
        raise FormatError("salt must be 32 bytes")
    return tagged_hash(TAG_FIELD, salt, lp(name.encode("ascii")), canonical_json(value))


def check_layout(layout: tuple[str, ...] | list[str]) -> None:
    """A layout is a non-empty list of valid field names in strict byte order
    (so each name is there once)."""
    if not isinstance(layout, list | tuple) or not 0 < len(layout) <= MAX_FIELDS:
        raise FormatError("bad layout size")
    for name in layout:
        if not isinstance(name, str) or not _FIELD_NAME.match(name):
            raise FormatError(f"bad field name in layout: {name!r}")
    for a, b in zip(layout, layout[1:], strict=False):
        if not a.encode("ascii") < b.encode("ascii"):
            raise FormatError("layout is not strictly sorted")


def object_root(root_tag: str, layout: tuple[str, ...] | list[str], mth: bytes) -> bytes:
    """Root of a committed object: binds the object tag, the field layout, and
    the Merkle tree hash of the field leaves."""
    check_layout(layout)
    return tagged_hash(root_tag, lp(canonical_json(list(layout))), mth)


@dataclass(frozen=True)
class FieldProof:
    """Selective opening of one field of a committed object.

    `layout` is the sorted list of all field names of the object. It shows the
    names and the count of the fields, but no value or salt."""

    name: str
    salt: bytes
    value: Any
    index: int
    size: int
    path: tuple[bytes, ...]
    layout: tuple[str, ...] = ()

    def compute_root(self, root_tag: str) -> bytes | None:
        check_layout(self.layout)
        if self.size != len(self.layout) or not 0 <= self.index < self.size:
            return None
        if self.layout[self.index] != self.name:
            return None
        leaf = merkle.leaf_hash(field_leaf(self.name, self.salt, self.value))
        mth = merkle.root_from_inclusion(leaf, self.index, self.size, self.path)
        if mth is None:
            return None
        return object_root(root_tag, self.layout, mth)

    def verify(self, root_tag: str, root: bytes) -> bool:
        try:
            return self.compute_root(root_tag) == root
        except (FormatError, ValueError, UnicodeError):
            return False

    def to_json(self) -> dict:
        return {
            "index": self.index,
            "layout": list(self.layout),
            "name": self.name,
            "path": [p.hex() for p in self.path],
            "salt": self.salt.hex(),
            "size": self.size,
            "value": self.value,
        }

    @classmethod
    def from_json(cls, obj: dict) -> FieldProof:
        try:
            layout = obj["layout"]
            if not isinstance(layout, list) or not all(isinstance(n, str) for n in layout):
                raise FormatError("layout must be a list of strings")
            return cls(
                name=str(obj["name"]),
                salt=bytes.fromhex(obj["salt"]),
                value=obj["value"],
                index=int(obj["index"]),
                size=int(obj["size"]),
                path=tuple(_hex32(p, "path") for p in obj["path"]),
                layout=tuple(layout),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FormatError(f"bad field proof: {exc}") from exc


@dataclass(frozen=True)
class Opening:
    """Full opening data of one committed object: all field values and salts."""

    root_tag: str
    fields: dict[str, Any]
    salts: dict[str, bytes]

    def __post_init__(self) -> None:
        if set(self.fields) != set(self.salts):
            raise FormatError("fields and salts must have the same names")
        for name in self.fields:
            if not _FIELD_NAME.match(name):
                raise FormatError(f"bad field name: {name!r}")
        canonical_json(self.fields)

    @classmethod
    def create(
        cls,
        root_tag: str,
        fields: dict[str, Any],
        salt_fn: Callable[[], bytes] = new_salt,
    ) -> Opening:
        return cls(root_tag, dict(fields), {name: salt_fn() for name in sorted(fields)})

    def names(self) -> list[str]:
        return sorted(self.fields)

    def leaf_hashes(self) -> list[bytes]:
        return [
            merkle.leaf_hash(field_leaf(n, self.salts[n], self.fields[n])) for n in self.names()
        ]

    def root(self) -> bytes:
        return object_root(self.root_tag, self.names(), merkle.root(self.leaf_hashes()))

    def prove(self, name: str) -> FieldProof:
        names = self.names()
        if name not in self.fields:
            raise KeyError(name)
        idx = names.index(name)
        hashes = self.leaf_hashes()
        path = merkle.inclusion_path(merkle.list_subtree(hashes), idx, len(hashes))
        return FieldProof(
            name=name,
            salt=self.salts[name],
            value=self.fields[name],
            index=idx,
            size=len(hashes),
            path=tuple(path),
            layout=tuple(names),
        )

    def to_json(self) -> dict:
        return {
            "fields": self.fields,
            "salts": {k: v.hex() for k, v in sorted(self.salts.items())},
        }

    @classmethod
    def from_json(cls, root_tag: str, obj: dict) -> Opening:
        try:
            salts = {k: bytes.fromhex(v) for k, v in obj["salts"].items()}
            return cls(root_tag, dict(obj["fields"]), salts)
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise FormatError(f"bad opening: {exc}") from exc


# ---------------------------------------------------------------------- evidence


def evidence_fields(
    content: ContentDigest, media_type: str, name: str | None, source: str
) -> dict[str, Any]:
    if not isinstance(media_type, str) or "/" not in media_type:
        raise FormatError("media_type must look like type/subtype")
    return {
        "content": content.to_json(),
        "media_type": media_type,
        "name": name,
        "schema": EVIDENCE_SCHEMA,
        "source": source,
    }


def evidence_opening(fields: dict[str, Any], salt_fn: Callable[[], bytes] = new_salt) -> Opening:
    validate_evidence_fields(fields)
    return Opening.create(TAG_EVIDENCE_ROOT, fields, salt_fn)


def validate_evidence_fields(fields: dict[str, Any]) -> None:
    if set(fields) != {"content", "media_type", "name", "schema", "source"}:
        raise FormatError("evidence fields do not match the schema")
    if fields["schema"] != EVIDENCE_SCHEMA:
        raise FormatError("unknown evidence schema")
    ContentDigest.from_json(fields["content"])


# ------------------------------------------------------------------------- links


@dataclass(frozen=True)
class Link:
    type: str
    target: bytes  # root of the target finding version

    def __post_init__(self) -> None:
        if self.type not in LINK_TYPES:
            raise FormatError(f"unknown link type: {self.type!r}")
        if len(self.target) != 32:
            raise FormatError("link target must be a 32-byte root")

    def to_json(self) -> dict:
        return {"target": self.target.hex(), "type": self.type}

    @classmethod
    def from_json(cls, obj: dict) -> Link:
        if not isinstance(obj, dict) or set(obj) != {"target", "type"}:
            raise FormatError("bad link")
        return cls(type=obj["type"], target=_hex32(obj["target"], "link target"))


# ----------------------------------------------------------------------- finding


def owner_json(public_key: bytes) -> dict:
    return {"alg": OWNER_ALG, "key": public_key.hex()}


def finding_fields(
    *,
    finding_id: bytes,
    version: int,
    owner_key: bytes,
    created_at: datetime,
    evidence_roots: list[bytes],
    claim: str | None = None,
    links: list[Link] | tuple[Link, ...] = (),
) -> dict[str, Any]:
    if len(finding_id) != 16:
        raise FormatError("finding_id must be 16 bytes")
    if version < 1:
        raise FormatError("version starts at 1")
    supersedes = [lk for lk in links if lk.type == LINK_SUPERSEDES]
    if len(supersedes) > 1:
        raise FormatError("a finding supersedes at most one version")
    if version > 1 and not supersedes:
        raise FormatError("a version after 1 must supersede the previous version")
    fields: dict[str, Any] = {
        "claim": claim,
        "created_at": format_time(created_at),
        "evidence_count": len(evidence_roots),
        "finding_id": finding_id.hex(),
        "link_count": len(links),
        "owner": owner_json(owner_key),
        "schema": FINDING_SCHEMA,
        "version": version,
    }
    for i, root in enumerate(evidence_roots):
        fields[f"evidence.{i}"] = root.hex()
    for i, link in enumerate(links):
        fields[f"links.{i}"] = link.to_json()
    validate_finding_fields(fields)
    return fields


def finding_opening(fields: dict[str, Any], salt_fn: Callable[[], bytes] = new_salt) -> Opening:
    validate_finding_fields(fields)
    return Opening.create(TAG_FINDING_ROOT, fields, salt_fn)


def validate_finding_fields(fields: dict[str, Any]) -> None:
    if fields.get("schema") != FINDING_SCHEMA:
        raise FormatError("unknown finding schema")
    n_ev = fields.get("evidence_count")
    n_ln = fields.get("link_count")
    if not isinstance(n_ev, int) or not isinstance(n_ln, int) or n_ev < 0 or n_ln < 0:
        raise FormatError("bad counts")
    expected = {
        "claim",
        "created_at",
        "evidence_count",
        "finding_id",
        "link_count",
        "owner",
        "schema",
        "version",
    }
    expected |= {f"evidence.{i}" for i in range(n_ev)}
    expected |= {f"links.{i}" for i in range(n_ln)}
    if set(fields) != expected:
        raise FormatError("finding fields do not match the schema")
    if fields["claim"] is not None and not isinstance(fields["claim"], str):
        raise FormatError("claim must be a string or null")
    parse_time(fields["created_at"])
    if not isinstance(fields["finding_id"], str) or not _HEX16.match(fields["finding_id"]):
        raise FormatError("bad finding_id")
    if not isinstance(fields["version"], int) or fields["version"] < 1:
        raise FormatError("bad version")
    owner = fields["owner"]
    if not isinstance(owner, dict) or owner.get("alg") != OWNER_ALG or set(owner) != {"alg", "key"}:
        raise FormatError("bad owner")
    _hex32(owner["key"], "owner key")
    for i in range(n_ev):
        _hex32(fields[f"evidence.{i}"], "evidence root")
    for i in range(n_ln):
        Link.from_json(fields[f"links.{i}"])


def finding_links(fields: dict[str, Any]) -> list[Link]:
    return [Link.from_json(fields[f"links.{i}"]) for i in range(fields["link_count"])]


# ------------------------------------------------------------- stream checkpoint


def stream_items_root(item_roots: list[bytes]) -> bytes:
    mth = merkle.root([merkle.leaf_hash(r) for r in item_roots])
    return tagged_hash(TAG_STREAM_ITEMS, u64(len(item_roots)), mth)


def stream_checkpoint_fields(
    *,
    stream_id: bytes,
    seq: int,
    prev: bytes | None,
    start: int,
    item_roots: list[bytes],
    owner_key: bytes,
    created_at: datetime,
) -> dict[str, Any]:
    fields = {
        "created_at": format_time(created_at),
        "item_count": len(item_roots),
        "items_root": stream_items_root(item_roots).hex(),
        "owner": owner_json(owner_key),
        "prev": prev.hex() if prev is not None else None,
        "schema": STREAM_SCHEMA,
        "seq": seq,
        "start": start,
        "stream_id": stream_id.hex(),
    }
    validate_stream_fields(fields)
    return fields


def validate_stream_fields(fields: dict[str, Any]) -> None:
    names = {
        "created_at",
        "item_count",
        "items_root",
        "owner",
        "prev",
        "schema",
        "seq",
        "start",
        "stream_id",
    }
    if set(fields) != names or fields["schema"] != STREAM_SCHEMA:
        raise FormatError("stream checkpoint fields do not match the schema")
    if fields["seq"] < 0 or fields["start"] < 0 or fields["item_count"] < 0:
        raise FormatError("bad stream counters")
    if (fields["seq"] == 0) != (fields["prev"] is None):
        raise FormatError("only seq 0 has no prev")
    if fields["prev"] is not None:
        _hex32(fields["prev"], "prev")
    _hex32(fields["items_root"], "items_root")
    if not isinstance(fields["stream_id"], str) or not _HEX16.match(fields["stream_id"]):
        raise FormatError("bad stream_id")
    parse_time(fields["created_at"])


def stream_opening(fields: dict[str, Any], salt_fn: Callable[[], bytes] = new_salt) -> Opening:
    validate_stream_fields(fields)
    return Opening.create(TAG_STREAM_ROOT, fields, salt_fn)


# ------------------------------------------------------------ schema layouts

_FINDING_FIXED = (
    "claim",
    "created_at",
    "evidence_count",
    "finding_id",
    "link_count",
    "owner",
    "schema",
    "version",
)
_EVIDENCE_NAMES = ("content", "media_type", "name", "schema", "source")
_STREAM_NAMES = (
    "created_at",
    "item_count",
    "items_root",
    "owner",
    "prev",
    "schema",
    "seq",
    "start",
    "stream_id",
)


def _list_count(layout: tuple[str, ...] | list[str], prefix: str) -> int:
    """Number of `<prefix>.N` names. They must be exactly 0 .. n-1."""
    idx = sorted(int(n.split(".")[1]) for n in layout if n.startswith(prefix + "."))
    if idx != list(range(len(idx))):
        raise FormatError(f"{prefix}.N names are not 0 .. n-1")
    return len(idx)


def check_schema_layout(root_tag: str, layout: tuple[str, ...] | list[str]) -> None:
    """Check that a layout is a valid layout for the schema of the object tag.
    For an unknown tag, check only the generic layout rules."""
    check_layout(layout)
    names = set(layout)
    if root_tag == TAG_FINDING_ROOT:
        n_ev = _list_count(layout, "evidence")
        n_ln = _list_count(layout, "links")
        expected = set(_FINDING_FIXED)
        expected |= {f"evidence.{i}" for i in range(n_ev)}
        expected |= {f"links.{i}" for i in range(n_ln)}
    elif root_tag == TAG_EVIDENCE_ROOT:
        expected = set(_EVIDENCE_NAMES)
    elif root_tag == TAG_STREAM_ROOT:
        expected = set(_STREAM_NAMES)
    else:
        return
    if names != expected:
        raise FormatError("layout does not match the schema")


# ---------------------------------------------------------------- signed subject


@dataclass(frozen=True)
class SignedSubject:
    """A committed root that its owner signed. This is what the log records."""

    kind: str
    root: bytes
    owner_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise FormatError(f"unknown kind: {self.kind!r}")
        if len(self.root) != 32 or len(self.owner_key) != 32 or len(self.signature) != 64:
            raise FormatError("bad subject sizes")

    @property
    def root_tag(self) -> str:
        return KINDS[self.kind][0]

    @classmethod
    def sign(cls, kind: str, root: bytes, key: SigningKey) -> SignedSubject:
        sig = key.sign(KINDS[kind][1], root)
        return cls(kind, root, key.public_bytes(), sig)

    def signature_ok(self) -> bool:
        return verify(self.owner_key, KINDS[self.kind][1], self.root, self.signature)

    def log_commitment(self) -> bytes:
        return tagged_hash(
            TAG_LOG_ENTRY,
            lp(self.kind.encode("ascii")),
            self.root,
            self.owner_key,
            self.signature,
        )

    def log_entry(self) -> dict:
        """The public log entry. It shows only the kind and a hash."""
        return {
            "commitment": self.log_commitment().hex(),
            "kind": self.kind,
            "schema": LOG_ENTRY_SCHEMA,
        }

    def log_entry_bytes(self) -> bytes:
        return canonical_json(self.log_entry())

    def to_json(self) -> dict:
        return {
            "kind": self.kind,
            "owner": owner_json(self.owner_key),
            "root": self.root.hex(),
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_json(cls, obj: dict) -> SignedSubject:
        try:
            owner = obj["owner"]
            if owner.get("alg") != OWNER_ALG:
                raise FormatError("unknown owner alg")
            return cls(
                kind=obj["kind"],
                root=_hex32(obj["root"], "root"),
                owner_key=_hex32(owner["key"], "owner key"),
                signature=bytes.fromhex(obj["signature"]),
            )
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise FormatError(f"bad subject: {exc}") from exc


@dataclass
class OpeningDocument:
    """All opening data of one finding: finding opening plus evidence openings."""

    finding: Opening
    evidence: list[Opening] = field(default_factory=list)

    SCHEMA = "anagram.opening.v1"

    def to_json(self) -> dict:
        return {
            "evidence": [e.to_json() for e in self.evidence],
            "finding": self.finding.to_json(),
            "schema": self.SCHEMA,
        }

    @classmethod
    def from_json(cls, obj: dict, root_tag: str = TAG_FINDING_ROOT) -> OpeningDocument:
        if obj.get("schema") != cls.SCHEMA:
            raise FormatError("unknown opening schema")
        return cls(
            finding=Opening.from_json(root_tag, obj["finding"]),
            evidence=[Opening.from_json(TAG_EVIDENCE_ROOT, e) for e in obj["evidence"]],
        )
