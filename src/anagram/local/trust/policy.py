"""The trust policy (spec/trust.md): one signed,
versioned document for each person that says which items the agent of the
person may use, and which people, labs, organisations and communities the
person may reach.

Tiers, from narrow to wide:

- `private`: only the person and agents with a grant on this device.
- `discoverable`: the agent of the person may use it to find fits and to
  answer typed questions. It never quotes it to a peer.
- `shared`: as `discoverable`, and the person may give it to named people
  or groups by the present share flow. The recipients stay in the share
  records; the policy does not copy them.

Rules:

- The narrower tier wins: source, then folder, then item, then reading (a
  reading is never wider than the narrowest tier of its basis items).
- A source with no mark has the default of own items (`discoverable`). An
  item that another person wrote (`third_party` mark, spec/threat-model.md
  section 16) is always `private`, whatever the marks.
- Deny wins over allow. Allow only widens who may be a candidate across a
  boundary (`in_scope=False`). Deny matches any verified attribute of the
  peer: pid, lab, organisation (`ror:<ROR ID>` or `domain:<verified email
  domain>`), community (host name). Self-stated attributes must not go into
  a `Peer`.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from functools import cached_property
from typing import Any

from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX32, HEX64, exact_fields, hex_field, int_at_least
from anagram.identity.api import validate_lab_id, validate_ror, validate_subject

SCHEMA = "anagram.trust_policy.v1"
# A tag of its own, outside the locked registry `ALL_TAGS` (as the room tags).
TAG_SIGN_TRUST_POLICY = "anagram/v1/trust/sign/policy"
TRUST_TAGS = (TAG_SIGN_TRUST_POLICY,)

PRIVATE = "private"
DISCOVERABLE = "discoverable"
SHARED = "shared"
TIERS = (PRIVATE, DISCOVERABLE, SHARED)  # narrow to wide
_RANK = {tier: n for n, tier in enumerate(TIERS)}

OWN_DEFAULT = DISCOVERABLE

PEOPLE = "people"
LABS = "labs"
ORGS = "orgs"
COMMUNITIES = "communities"
SUBJECT_KINDS = (PEOPLE, LABS, ORGS, COMMUNITIES)

MAX_SUBJECTS = 256  # for each kind (spec/trust.md)
MAX_MARKS = 10_000  # all source, folder and item marks together
MAX_ID = 200  # source ID
MAX_KEY = 1024  # item key or folder prefix

_FIELDS = (
    "schema",
    "owner",
    "rev",
    "updated_at",
    "updated_device",
    "defaults",
    "sources",
    "folders",
    "items",
    "allow",
    "deny",
    "signature",
)
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_ROR_PREFIX = "ror:"
_DOMAIN_PREFIX = "domain:"


# ----------------------------------------------------------------- tiers


def check_tier(value: Any, what: str = "tier") -> str:
    if value not in _RANK:
        raise FormatError(f"{what}: a tier is 'private', 'discoverable' or 'shared'")
    return value


def narrowest(tiers: Iterable[str]) -> str:
    """The narrowest tier of `tiers`. No tier gives `private` (fail closed)."""
    ranks = [_RANK[check_tier(t)] for t in tiers]
    return TIERS[min(ranks)] if ranks else PRIVATE


def reading_tier(basis: Iterable[str]) -> str:
    """The tier of a reading: the narrowest tier of its basis items. A
    reading with no basis item is `private`."""
    return narrowest(basis)


def at_least(tier: str, need: str) -> bool:
    """True if `tier` is `need` or wider."""
    return _RANK[check_tier(tier)] >= _RANK[check_tier(need)]


# --------------------------------------------------------------- subjects


def check_org(value: Any) -> str:
    """`ror:<ROR ID>` or `domain:<host name>` (a verified email domain)."""
    if isinstance(value, str) and value.startswith(_ROR_PREFIX):
        validate_ror(value[len(_ROR_PREFIX) :])
        return value
    if isinstance(value, str) and value.startswith(_DOMAIN_PREFIX):
        check_host(value[len(_DOMAIN_PREFIX) :], "organisation domain")
        return value
    raise FormatError("an organisation is 'ror:<ROR ID>' or 'domain:<host name>'")


def check_host(value: Any, what: str = "community") -> str:
    if not isinstance(value, str) or not _HOST.match(value):
        raise FormatError(f"{what}: expected a lowercase host name")
    return value


_SUBJECT_CHECK = {
    PEOPLE: validate_subject,
    LABS: validate_lab_id,
    ORGS: check_org,
    COMMUNITIES: check_host,
}


def _subjects(value: Any, what: str) -> dict:
    exact_fields(value, SUBJECT_KINDS, what)
    for kind in SUBJECT_KINDS:
        ids = value[kind]
        if not isinstance(ids, list) or len(ids) > MAX_SUBJECTS:
            raise FormatError(f"{what}.{kind}: a list of at most {MAX_SUBJECTS}")
        for one in ids:
            _SUBJECT_CHECK[kind](one)
        if ids != sorted(set(ids)):
            raise FormatError(f"{what}.{kind}: sorted, with no repeats")
    return value


def subjects_json(subjects: Mapping[str, Iterable[str]] | None) -> dict:
    """The JSON form of a subject list: each kind sorted, no repeats."""
    subjects = subjects or {}
    unknown = set(subjects) - set(SUBJECT_KINDS)
    if unknown:
        raise FormatError(f"unknown subject kind: {sorted(unknown)[0]}")
    return {kind: sorted(set(subjects.get(kind, ()))) for kind in SUBJECT_KINDS}


def _pairs(doc_subjects: Mapping[str, Iterable[str]]) -> frozenset[tuple[str, str]]:
    return frozenset((kind, one) for kind in SUBJECT_KINDS for one in doc_subjects.get(kind, ()))


@dataclass(frozen=True)
class Peer:
    """The verified attributes of another person, from L4 and L1 (a lab
    roster, a verified email domain, the community of the host). A
    self-stated affiliation must not go here."""

    pid: str | None = None
    labs: frozenset[str] = frozenset()
    orgs: frozenset[str] = frozenset()
    communities: frozenset[str] = frozenset()

    @cached_property
    def subjects(self) -> frozenset[tuple[str, str]]:
        out = {(LABS, x) for x in self.labs}
        out |= {(ORGS, x) for x in self.orgs}
        out |= {(COMMUNITIES, x) for x in self.communities}
        if self.pid is not None:
            out.add((PEOPLE, self.pid))
        return frozenset(out)


class Reach(StrEnum):
    DENIED = "denied"  # a deny entry covers the peer (deny wins)
    ALLOWED = "allowed"  # an allow entry covers the peer, no deny entry
    IN_SCOPE = "in_scope"  # no entry; the peer is inside the boundary
    OUT_OF_SCOPE = "out_of_scope"  # no entry; the peer is outside it


# ------------------------------------------------------------------ marks


def _id(value: Any, limit: int, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise FormatError(f"{what}: text of 1 to {limit} characters")
    return value


def _tier_map(value: Any, limit: int, what: str) -> int:
    if not isinstance(value, dict):
        raise FormatError(f"{what}: expected an object")
    for key, tier in value.items():
        _id(key, limit, what)
        check_tier(tier, what)
    return len(value)


def _nested(value: Any, what: str) -> int:
    if not isinstance(value, dict):
        raise FormatError(f"{what}: expected an object")
    count = 0
    for sid, marks in value.items():
        _id(sid, MAX_ID, f"{what} source")
        n = _tier_map(marks, MAX_KEY, what)
        if n == 0:
            raise FormatError(f"{what}: a source entry has one mark or more")
        count += n
    return count


def _defaults(value: Any) -> None:
    exact_fields(value, ("own",), "trust policy defaults")
    check_tier(value["own"], "trust policy defaults.own")


# ----------------------------------------------------------------- format


def validate_policy(doc: Any) -> dict:
    """The form of a policy document. It does not check the signature."""
    exact_fields(doc, _FIELDS, "trust policy")
    if doc["schema"] != SCHEMA:
        raise FormatError(f"trust policy: schema is not {SCHEMA}")
    validate_subject(doc["owner"])
    int_at_least(doc["rev"], "trust policy rev", 1)
    if not isinstance(doc["updated_at"], str):
        raise FormatError("trust policy updated_at: expected text")
    parse_time(doc["updated_at"])
    hex_field(doc["updated_device"], HEX32, "trust policy updated_device")
    _defaults(doc["defaults"])
    marks = _tier_map(doc["sources"], MAX_ID, "trust policy sources")
    marks += _nested(doc["folders"], "trust policy folders")
    marks += _nested(doc["items"], "trust policy items")
    if marks > MAX_MARKS:
        raise FormatError(f"trust policy: at most {MAX_MARKS} marks")
    _subjects(doc["allow"], "trust policy allow")
    _subjects(doc["deny"], "trust policy deny")
    hex_field(doc["signature"], HEX64, "trust policy signature")
    return doc


def make_policy(  # noqa: PLR0913 (one keyword for each field of the format)
    *,
    owner: str,
    rev: int,
    key: SigningKey,
    updated_at: datetime,
    own_default: str = OWN_DEFAULT,
    sources: Mapping[str, str] | None = None,
    folders: Mapping[str, Mapping[str, str]] | None = None,
    items: Mapping[str, Mapping[str, str]] | None = None,
    allow: Mapping[str, Iterable[str]] | None = None,
    deny: Mapping[str, Iterable[str]] | None = None,
) -> dict:
    """A new signed policy document. `key` is a device key of `owner`."""
    doc: dict[str, Any] = {
        "allow": subjects_json(allow),
        "defaults": {"own": own_default},
        "deny": subjects_json(deny),
        "folders": {sid: dict(m) for sid, m in (folders or {}).items() if m},
        "items": {sid: dict(m) for sid, m in (items or {}).items() if m},
        "owner": owner,
        "rev": rev,
        "schema": SCHEMA,
        "sources": dict(sources or {}),
        "updated_at": format_time(updated_at),
        "updated_device": key.public_bytes().hex(),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_TRUST_POLICY, key)
    return validate_policy(doc)


def verify_policy(doc: Any, owner_devices: Collection[bytes]) -> dict:
    """Form, signature, and signer. `owner_devices` are the device keys of
    the owner (from the key directory or this device). A document that a key
    of another person signed is refused: no person can set the policy of
    another person."""
    validate_policy(doc)
    device = bytes.fromhex(doc["updated_device"])
    if device not in set(owner_devices):
        raise FormatError("trust policy: the signer is not a device of the owner")
    if not doc_signature_ok(doc, TAG_SIGN_TRUST_POLICY, device):
        raise FormatError("trust policy: bad signature")
    return doc


# ------------------------------------------------------------- evaluation


@dataclass(frozen=True)
class TrustPolicy:
    """The evaluation of one policy. `rev` 0 is the default policy of a
    person who has not saved one (it is not signed)."""

    owner: str
    rev: int = 0
    own_default: str = OWN_DEFAULT
    sources: Mapping[str, str] = field(default_factory=dict)
    folders: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    items: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    allow: frozenset[tuple[str, str]] = frozenset()
    deny: frozenset[tuple[str, str]] = frozenset()

    @classmethod
    def default(cls, owner: str) -> TrustPolicy:
        return cls(owner=validate_subject(owner))

    @classmethod
    def from_doc(cls, doc: dict) -> TrustPolicy:
        """From a document that `verify_policy` accepted."""
        return cls(
            owner=doc["owner"],
            rev=doc["rev"],
            own_default=doc["defaults"]["own"],
            sources=dict(doc["sources"]),
            folders={sid: dict(m) for sid, m in doc["folders"].items()},
            items={sid: dict(m) for sid, m in doc["items"].items()},
            allow=_pairs(doc["allow"]),
            deny=_pairs(doc["deny"]),
        )

    def subjects(self, which: str) -> dict:
        """The JSON form of `allow` or `deny`."""
        pairs = self.allow if which == "allow" else self.deny
        out: dict[str, list[str]] = {kind: [] for kind in SUBJECT_KINDS}
        for kind, one in pairs:
            out[kind].append(one)
        return subjects_json(out)

    # -- tiers

    def source_tier(self, sid: str) -> str:
        return self.sources.get(sid, self.own_default)

    def item_tier(self, sid: str, key: str, *, third_party: bool) -> str:
        """The tier of one item: the narrowest of its source, each folder
        that holds it (key prefix on a `/` path boundary), and its own mark.
        An item that another person wrote is `private`."""
        if third_party:
            return PRIVATE
        tiers = [self.source_tier(sid)]
        for prefix, t in self.folders.get(sid, {}).items():
            clean = prefix.rstrip("/")
            if not clean or key == clean or key.startswith(clean + "/"):
                tiers.append(t)
        mark = self.items.get(sid, {}).get(key)
        if mark is not None:
            tiers.append(mark)
        return narrowest(tiers)

    # -- people

    def denies(self, peer: Peer) -> bool:
        return not self.deny.isdisjoint(peer.subjects)

    def allows(self, peer: Peer) -> bool:
        return not self.allow.isdisjoint(peer.subjects)

    def reach(self, peer: Peer, *, in_scope: bool) -> Reach:
        """Deny first, always. `in_scope` says if the peer is inside the
        boundary of this use (for example the same community)."""
        if self.denies(peer):
            return Reach.DENIED
        if self.allows(peer):
            return Reach.ALLOWED
        return Reach.IN_SCOPE if in_scope else Reach.OUT_OF_SCOPE

    def may_reach(self, peer: Peer, *, in_scope: bool) -> bool:
        return self.reach(peer, in_scope=in_scope) in (Reach.ALLOWED, Reach.IN_SCOPE)

    def room_blocks(self) -> dict:
        """The deny entries in the list form of the `room_blocks` vector
        (spec/trust.md 2: `orcids` also holds pids, `labs`, `rors`).
        Domain and community entries have no such form; `unmapped` counts
        them."""
        deny = self.subjects("deny")
        rors = [o[len(_ROR_PREFIX) :] for o in deny[ORGS] if o.startswith(_ROR_PREFIX)]
        domains = [o for o in deny[ORGS] if o.startswith(_DOMAIN_PREFIX)]
        return {
            "blocks": {"labs": deny[LABS], "orcids": deny[PEOPLE], "rors": sorted(rors)},
            "unmapped": len(domains) + len(deny[COMMUNITIES]),
        }


def mutual_deny(a: TrustPolicy, b_seen_by_a: Peer, b: TrustPolicy, a_seen_by_b: Peer) -> bool:
    """True if either side denies the other. The allow list of one side
    never cancels a deny of the other side."""
    return a.denies(b_seen_by_a) or b.denies(a_seen_by_b)
