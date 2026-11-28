"""Entries of the enclave transparency log (spec/enclave-trust.md section 2).

Each entry is a public signed document. Its leaf data in the log is
`canonical_json(entry)`. The signer signs `canonical_json(entry without
"signature")` under the tag of its kind.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import tagged_hash
from anagram.core.crypto.signing import SigningKey, verify
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.trust.policy import CLOUD_PINS

TAG_ENTRY = "anagram/v1/enclave/log-entry"

_HEX = re.compile(r"^[0-9a-f]*$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_NODE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}$")

_NETWORK = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")

PROFILES = ("simulated", "raw-snp", "raw-tdx", "gcp-cs", "azure-cvm-gpu")
LINE_REASONS = ("first", "shard", "total_loss")
MAX_LINE_INSTANCES = 64
REVOKE_REASONS = ("vulnerability", "malicious", "key_compromise", "broken_build", "superseded")


class EntryError(Refused):
    """A log entry that does not follow the spec. `code` is `bad_entry` or
    `bad_entry_signature`."""


def _hex(n: int) -> Callable[[object], bool]:
    return lambda v: isinstance(v, str) and len(v) == 2 * n and bool(_HEX.match(v))


def _hex_or_null(n: int) -> Callable[[object], bool]:
    return lambda v: v is None or _hex(n)(v)


def _int(lo: int, hi: int = 2**53 - 1) -> Callable[[object], bool]:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _bool(v: object) -> bool:
    return isinstance(v, bool)


def _time(v: object) -> bool:
    """A real UTC time with whole seconds: the pattern alone takes month 13."""
    try:
        parse_time(v, "time")
    except Refused:
        return False
    return True


def _hex_list(n: int, lo: int, hi: int) -> Callable[[object], bool]:
    def check(v: object) -> bool:
        return (
            isinstance(v, list)
            and lo <= len(v) <= hi
            and all(_hex(n)(x) for x in v)
            and v == sorted(set(v))
        )

    return check


def _named_digests(v: object) -> bool:
    """`[{"name", "digest"}, ...]`, sorted by name, names unique. The form of
    each element is checked before the order: `sorted` raises TypeError on a
    missing or non-text name."""
    if not isinstance(v, list) or len(v) > 64:
        return False
    names: list[str] = []
    for x in v:
        if not (
            isinstance(x, dict)
            and set(x) == {"name", "digest"}
            and isinstance(x["name"], str)
            and 0 < len(x["name"]) <= 128
            and isinstance(x["digest"], str)
            and _IMAGE.match(x["digest"])
        ):
            return False
        names.append(x["name"])
    return names == sorted(set(names))


def _build(v: object) -> bool:
    return (
        isinstance(v, dict)
        and set(v) == {"builder", "lock_sha256", "source_date_epoch"}
        and isinstance(v["builder"], str)
        and bool(_IMAGE.match(v["builder"]))
        and _hex(32)(v["lock_sha256"])
        and _int(0)(v["source_date_epoch"])
    )


def _floor(v: object) -> bool:
    """A TCB floor: an object of named minimums. Integers are SVNs;
    strings are dotted versions (GPU driver, VBIOS) or exact values."""
    return isinstance(v, dict) and all(
        isinstance(k, str) and (_int(0)(x) or isinstance(x, str | list)) for k, x in v.items()
    )


def _pins(v: object) -> bool:
    """1 to 16 distinct non-empty strings, sorted."""
    return (
        isinstance(v, list)
        and 1 <= len(v) <= 16
        and all(isinstance(x, str) and 0 < len(x) <= 128 for x in v)
        and v == sorted(set(v))
    )


def _cloud(profile: str, v: object) -> bool:
    """The cloud pins of a profile (section 2.3): exactly its pin names."""
    names = CLOUD_PINS[profile]
    return isinstance(v, dict) and set(v) == set(names) and all(_pins(v[n]) for n in names)


def _profiles(v: object) -> bool:
    if not isinstance(v, dict) or not v or any(p not in PROFILES for p in v):
        return False
    base = {"measurement", "reference", "tcb_floor"}
    return all(
        isinstance(x, dict)
        and set(x) == (base if p == "simulated" else base | {"cloud"})
        and (p == "simulated" or _cloud(p, x["cloud"]))
        and _hex(32)(x["measurement"])
        and isinstance(x["reference"], dict)
        and _floor(x["tcb_floor"])
        for p, x in v.items()
    )


def _measurements(v: object) -> bool:
    return (
        isinstance(v, dict) and bool(v) and all(p in PROFILES and _hex(32)(m) for p, m in v.items())
    )


def _target(v: object) -> bool:
    return (
        isinstance(v, dict)
        and len(v) == 1
        and (
            _hex(32)(v.get("release"))
            or _hex(16)(v.get("instance_id"))
            or _hex(16)(v.get("line_id"))
        )
    )


def _shard(v: object) -> bool:
    return (
        isinstance(v, dict)
        and set(v) == {"k", "n"}
        and _int(1, 64)(v["n"])
        and _int(0, 63)(v["k"])
        and v["k"] < v["n"]
    )


def _network(v: object) -> bool:
    return isinstance(v, str) and bool(_NETWORK.match(v))


def _image(v: object) -> bool:
    return isinstance(v, str) and bool(_IMAGE.match(v))


def _version(v: object) -> bool:
    return isinstance(v, str) and bool(_VERSION.match(v))


def _node(v: object) -> bool:
    return isinstance(v, str) and bool(_NODE.match(v))


def _one_of(values: tuple[str, ...]) -> Callable[[object], bool]:
    return lambda v: v in values


# kind -> (schema, signing tag, field checks). Every entry also has
# "kind", "schema", "signer" (hex Ed25519) and "signature" (hex).
KINDS: dict[str, tuple[str, str, dict[str, Callable[[object], bool]]]] = {
    "enclave_release": (
        "anagram.enclave.release.v1",
        "anagram/v1/enclave/sign/release",
        {
            "build": _build,
            "descriptor_hashes": _hex_list(32, 1, 64),
            "image_digest": _image,
            "max_instances": _int(1, 64),
            "min_app_version": _version,
            "not_before": _time,
            "profiles": _profiles,
            "security_fix": _bool,
            "source_commit": _hex(20),
            "successor_of": _hex_or_null(32),
            "vendor_digests": _named_digests,
            "weights": _named_digests,
        },
    ),
    "enclave_rebuild": (
        "anagram.enclave.rebuild.v1",
        "anagram/v1/enclave/sign/rebuild",
        {
            "image_digest": _image,
            "measurements": _measurements,
            "release": _hex(32),
            "same": _bool,
        },
    ),
    "enclave_revoke": (
        "anagram.enclave.revoke.v1",
        "anagram/v1/enclave/sign/revoke",
        {"reason": _one_of(REVOKE_REASONS), "target": _target},
    ),
    "enclave_floor": (
        "anagram.enclave.floor.v1",
        "anagram/v1/enclave/sign/floor",
        {"profile": _one_of(PROFILES), "release": _hex(32), "tcb_floor": _floor},
    ),
    "enclave_instance_key": (
        "anagram.enclave.instance_key.v1",
        "anagram/v1/enclave/sign/instance-key",
        {
            "evidence_digest": _hex(32),
            "instance_id": _hex(16),
            "intake_key": _hex(32),
            "key_epoch": _int(0),
            "lease_until": _time,
            "line_id": _hex(16),
            "profile": _one_of(PROFILES),
            "release": _hex(32),
        },
    ),
    "enclave_state_epoch": (
        "anagram.enclave.state_epoch.v1",
        "anagram/v1/enclave/sign/state-epoch",
        {
            "checkpoint": _hex(32),
            "counter": _int(0),
            "instance_id": _hex(16),
            "holders": _hex_list(16, 1, MAX_LINE_INSTANCES),
            "line_id": _hex(16),
            "next_writer": _hex_or_null(16),
            "prev": _hex_or_null(32),
            "rekey": _bool,
            "snapshot_digest": _hex(32),
            "snapshot_size": _int(0),
        },
    ),
    "enclave_line": (
        "anagram.enclave.line.v1",
        "anagram/v1/enclave/sign/line",
        {
            "line_id": _hex(16),
            "reason": _one_of(LINE_REASONS),
            "release": _hex(32),
            "replaces": _hex_or_null(16),
            "shard": _shard,
        },
    ),
    "enclave_writer": (
        "anagram.enclave.writer.v1",
        "anagram/v1/enclave/sign/writer",
        {"counter": _int(0), "epoch": _hex(32), "line_id": _hex(16), "writer": _hex(16)},
    ),
    "roster_checkpoint": (
        "anagram.net.roster_checkpoint.v1",
        "anagram/v1/net/sign/roster-checkpoint",
        {"head": _hex(32), "network": _network, "seq": _int(0), "time": _time},
    ),
    "enclave_entry_cosign": (
        "anagram.enclave.entry_cosign.v1",
        "anagram/v1/enclave/sign/entry-cosign",
        {"entry": _hex(32), "time": _int(0)},
    ),
    "node_admission": (
        "anagram.enclave.node_admission.v1",
        "anagram/v1/enclave/sign/node-admission",
        {"node_id": _node, "record_digest": _hex(32)},
    ),
    "member_credential": (
        "anagram.enclave.member_credential.v1",
        "anagram/v1/enclave/sign/member-credential",
        {
            "credential_hash": _hex(32),
            "expires": _time,
            "member": _hex_or_null(32),
            "node_id": _node,
        },
    ),
}


def entry_digest(entry: JsonObject) -> bytes:
    return tagged_hash(TAG_ENTRY, canonical_json(entry))


def _body(entry: JsonObject) -> bytes:
    return canonical_json({k: v for k, v in entry.items() if k != "signature"})


def sign_entry(kind: str, fields: JsonObject, key: SigningKey) -> JsonObject:
    schema, tag, _ = KINDS[kind]
    entry = {**fields, "kind": kind, "schema": schema, "signer": key.public_bytes().hex()}
    entry["signature"] = key.sign(tag, _body(entry)).hex()
    check_entry(entry)
    return entry


def check_entry(entry: object) -> JsonObject:
    """Check the form and the signature of an entry. Return it."""
    kind = entry.get("kind") if isinstance(entry, dict) else None
    if not isinstance(entry, dict) or not isinstance(kind, str) or kind not in KINDS:
        raise EntryError("bad_entry", "unknown kind")  # a list or dict kind is not hashable
    schema, tag, fields = KINDS[kind]
    if entry.get("schema") != schema:
        raise EntryError("bad_entry", "wrong schema")
    if set(entry) != set(fields) | {"kind", "schema", "signer", "signature"}:
        raise EntryError("bad_entry", "wrong field set")
    for name, ok in fields.items():
        if not ok(entry[name]):
            raise EntryError("bad_entry", f"bad field {name}")
    if not (_hex(32)(entry["signer"]) and _hex(64)(entry["signature"])):
        raise EntryError("bad_entry", "bad signer or signature form")
    signer = bytes.fromhex(entry["signer"])
    if not verify(signer, tag, _body(entry), bytes.fromhex(entry["signature"])):
        raise EntryError("bad_entry_signature", entry["kind"])
    return entry
