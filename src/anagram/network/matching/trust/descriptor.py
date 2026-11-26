"""The release descriptor set (spec/enclave-trust.md section 3.6; W4 finding
H-e).

A release names its descriptors by hash in `descriptor_hashes`. A descriptor
fixes a value that the app shows or checks and that the measurement alone
does not make readable: the consent statement, the card option, the network
pin, the accepted schemas, the vocabulary and the models. The app gets the
descriptors from `GET /enclave/attestation`, checks each hash, and uses only
these values.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import sha256, tagged_hash
from anagram.network.formats.strict import HEX32, Refused
from anagram.network.matching.trust.binding import descriptor_set_hash

SCHEMA = "anagram.enclave.descriptor.v1"
TAG_DESCRIPTOR = "anagram/v1/enclave/descriptor"

_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,31}$")
_NETWORK = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
_SCHEMA_NAME = re.compile(r"^anagram\.[a-z_.]+\.v[0-9]+$")
ROLES = ("embed", "judge", "screen")
WEEKLY_CAP_LIMIT = 10  # C43: the largest `weekly_cap_max` of a release (pack.md 3.3)


class DescriptorError(Refused):
    """A descriptor or a descriptor set that does not follow the spec."""

    def __init__(self, detail: str) -> None:
        super().__init__("bad_descriptor", detail)


def _text(v: object, n: int) -> bool:
    return isinstance(v, str) and 0 < len(v) <= n and v == v.strip()


def _int(lo: int, hi: int) -> Callable[[object], bool]:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _schemas(v: object) -> bool:
    return (
        isinstance(v, list)
        and 1 <= len(v) <= 8
        and v == sorted(set(v))
        and all(isinstance(x, str) and bool(_SCHEMA_NAME.match(x)) for x in v)
    )


def _match(pattern: re.Pattern[str]) -> Callable[[object], bool]:
    return lambda v: isinstance(v, str) and bool(pattern.match(v))


BODIES: dict[str, dict[str, Callable[[object], bool]]] = {
    "matching": {
        "accepted_schemas": _schemas,
        "anonymity_min_nodes": _int(1, 100),
        "anonymity_min_people": _int(2, 1000),
        "answer_day": _int(1, 7),
        "card_option": lambda v: v in ("a", "b"),
        "consent_statement": lambda v: _text(v, 1000),
        "network": _match(_NETWORK),
        "roster_key": _match(HEX32),
        "weekly_cap_max": _int(1, WEEKLY_CAP_LIMIT),
    },
    "vocabulary": {
        "concepts": _int(1, 2**32 - 1),
        "id": _match(_ID),
        "sha256": _match(HEX32),
    },
    "model": {
        "digest": _match(_IMAGE),
        "name": lambda v: _text(v, 128),
        "role": lambda v: v in ROLES,
    },
}


def check_descriptor(doc: object) -> JsonObject:
    if not isinstance(doc, dict) or set(doc) != {"body", "kind", "schema"}:
        raise DescriptorError("fields")
    if doc["schema"] != SCHEMA or doc["kind"] not in BODIES:
        raise DescriptorError("schema or kind")
    rules = BODIES[doc["kind"]]
    body = doc["body"]
    if not isinstance(body, dict) or set(body) != set(rules):
        raise DescriptorError(f"{doc['kind']}: body fields")
    for name, ok in rules.items():
        if not ok(body[name]):
            raise DescriptorError(f"{doc['kind']}: {name}")
    return doc


def descriptor_hash(doc: JsonObject) -> bytes:
    return tagged_hash(TAG_DESCRIPTOR, canonical_json(check_descriptor(doc)))


def statement_hash(matching: JsonObject) -> str:
    """The `consent.statement` value of a pack (spec/pack.md section 3.2)."""
    return sha256(matching["body"]["consent_statement"].encode("utf-8")).hex()


def check_set(docs: list[JsonObject], hashes: list[str]) -> dict[str, list[JsonObject]]:
    """Check that the documents are exactly the release's descriptors, with
    one `matching`, one `vocabulary` and at most 16 `model` descriptors.
    Return the documents by kind."""
    got = sorted(descriptor_hash(d).hex() for d in docs)
    if got != sorted(hashes) or len(set(got)) != len(got):
        raise DescriptorError("documents do not match descriptor_hashes")
    by_kind: dict[str, list[JsonObject]] = {k: [] for k in BODIES}
    for d in docs:
        by_kind[d["kind"]].append(d)
    if len(by_kind["matching"]) != 1 or len(by_kind["vocabulary"]) != 1:
        raise DescriptorError("one matching and one vocabulary descriptor")
    if len(by_kind["model"]) > 16:
        raise DescriptorError("at most 16 model descriptors")
    return by_kind


def set_hash(docs: list[JsonObject]) -> bytes:
    """The descriptor set hash (section 3.2) of a list of documents."""
    return descriptor_set_hash([descriptor_hash(d) for d in docs])
