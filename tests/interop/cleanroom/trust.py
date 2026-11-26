"""The app's checks of enclave-trust.md for the `simulated` profile: log
entries (2.2, 2.3), release acceptance (2.5), the attestation document
(3.1 to 3.5, 4.2), descriptors (3.6), lines, writers and forks (5.5 to
5.7), and the small derived values (shard, tombstone, decline, clock).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import (
    Refused,
    cjson,
    is_hex,
    parse_time,
    sha256,
    tagged_hash,
    u32,
    u64,
    verify,
    verify_doc,
)
from .logs import Checkpoint, NoteKey, leaf_hash, lower, mth, parse_checkpoint, upper

DAY = 86_400
HOUR = 3_600

SIGN_TAG = {
    "enclave_release": "anagram/v1/enclave/sign/release",
    "enclave_rebuild": "anagram/v1/enclave/sign/rebuild",
    "enclave_revoke": "anagram/v1/enclave/sign/revoke",
    "enclave_floor": "anagram/v1/enclave/sign/floor",
    "enclave_instance_key": "anagram/v1/enclave/sign/instance-key",
    "enclave_state_epoch": "anagram/v1/enclave/sign/state-epoch",
    "enclave_line": "anagram/v1/enclave/sign/line",
    "enclave_writer": "anagram/v1/enclave/sign/writer",
    "roster_checkpoint": "anagram/v1/net/sign/roster-checkpoint",
    "enclave_entry_cosign": "anagram/v1/enclave/sign/entry-cosign",
    "node_admission": "anagram/v1/enclave/sign/node-admission",
    "member_credential": "anagram/v1/enclave/sign/member-credential",
}
SCHEMA = {
    "enclave_release": "anagram.enclave.release.v1",
    "enclave_rebuild": "anagram.enclave.rebuild.v1",
    "enclave_revoke": "anagram.enclave.revoke.v1",
    "enclave_floor": "anagram.enclave.floor.v1",
    "enclave_instance_key": "anagram.enclave.instance_key.v1",
    "enclave_state_epoch": "anagram.enclave.state_epoch.v1",
    "enclave_line": "anagram.enclave.line.v1",
    "enclave_writer": "anagram.enclave.writer.v1",
    "roster_checkpoint": "anagram.net.roster_checkpoint.v1",
    "enclave_entry_cosign": "anagram.enclave.entry_cosign.v1",
    "node_admission": "anagram.enclave.node_admission.v1",
    "member_credential": "anagram.enclave.member_credential.v1",
}
DOC_FIELDS = {
    "checkpoint", "descriptor_hashes", "gpu_evidence", "instance_id", "intake_key",
    "key_epoch", "line_id", "log_proof", "output_key", "platform_evidence", "profile",
    "release", "schema", "signature",
}  # fmt: skip


def entry_digest(e: dict) -> str:
    return tagged_hash("anagram/v1/enclave/log-entry", cjson(e)).hex()


def entry_ok(e: dict) -> bool:
    kind = e.get("kind")
    if kind not in SIGN_TAG or e.get("schema") != SCHEMA[kind]:
        return False
    return verify_doc(e.get("signer", ""), SIGN_TAG[kind], e)


@dataclass
class Pins:
    log_key: NoteKey
    witnesses: list[dict]  # {"key": NoteKey, "entry_key": hex, "independent": bool, "name"}
    release_key: str
    rebuilders: list[str]
    dev_root: str

    @classmethod
    def from_vector(cls, roots: dict) -> Pins:
        ws = [{**w, "key": NoteKey.parse(w["cosign"])} for w in roots["witnesses"]]
        return cls(
            NoteKey.parse(roots["log_key"]),
            ws,
            roots["release_key"],
            list(roots["rebuilders"]),
            roots["dev_root"],
        )


@dataclass
class Log:
    """What the app knows of the enclave log: entries in log order and the
    checkpoints that it accepted."""

    pins: Pins
    entries: list[dict]
    checkpoints: list[Checkpoint] = field(default_factory=list)

    def accept(self, note: str) -> Checkpoint:
        cp = parse_checkpoint(note, self.pins.log_key, self.pins.witnesses)
        lower(cp, self.pins.witnesses)  # raises without a quorum
        if cp.size > len(self.entries):
            raise Refused("bad_checkpoint", "more entries than read")
        if mth([leaf_hash(cjson(e)) for e in self.entries[: cp.size]]) != cp.root:
            raise Refused("bad_checkpoint", "root")
        self.checkpoints.append(cp)
        return cp

    @property
    def latest(self) -> Checkpoint:
        return max(self.checkpoints, key=lambda c: c.size)

    def visible(self) -> list[tuple[int, dict]]:
        n = self.latest.size if self.checkpoints else len(self.entries)
        return [(i, e) for i, e in enumerate(self.entries[:n]) if entry_ok(e)]

    def logged_by(self, index: int) -> int | None:
        times = [upper(c, self.pins.witnesses) for c in self.checkpoints if c.size > index]
        return min(times) if times else None

    def now(self, clock: int) -> int:
        return max(clock, lower(self.latest, self.pins.witnesses)) if self.checkpoints else clock

    # -- queries --

    def of_kind(self, kind: str) -> list[tuple[int, dict]]:
        return [(i, e) for i, e in self.visible() if e["kind"] == kind]

    def cosigns(self, digest: str) -> dict[str, tuple[int, int]]:
        """Witness entry key -> (log index, time) of `enclave_entry_cosign`."""
        keys = {w["entry_key"] for w in self.pins.witnesses}
        out: dict[str, tuple[int, int]] = {}
        for i, e in self.of_kind("enclave_entry_cosign"):
            if e["entry"] == digest and e["signer"] in keys and e["signer"] not in out:
                out[e["signer"]] = (i, e["time"])
        return out

    def independent_quorum(self, digest: str) -> dict[str, tuple[int, int]] | None:
        indep = [w["entry_key"] for w in self.pins.witnesses if w["independent"]]
        got = self.cosigns(digest)
        if all(k in got for k in indep):
            return {k: got[k] for k in indep}
        return None

    def revoked(self, target: dict) -> bool:
        for _i, e in self.of_kind("enclave_revoke"):
            if e["target"] != target:
                continue
            if e["signer"] == self.pins.release_key:
                return True
            if self.independent_quorum(entry_digest(e)) is not None:
                return True
        return False


# ---- release acceptance (2.5) ----------------------------------------------------


def _version(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in s.split("."))


def accept_release(log: Log, release: dict, app_version: str, now: int) -> None:
    d = entry_digest(release)
    found = [(i, e) for i, e in log.of_kind("enclave_release") if entry_digest(e) == d]
    if not found or release.get("signer") != log.pins.release_key:
        raise Refused("release_not_logged")
    index = found[0][0]
    if log.revoked({"release": d}):
        raise Refused("release_revoked")
    if _version(app_version) < _version(release["min_app_version"]):
        raise Refused("release_app_too_old")
    not_before = parse_time(release["not_before"])
    measurements = {p: v["measurement"] for p, v in release["profiles"].items()}
    rebuilds = [e for _i, e in log.of_kind("enclave_rebuild") if e["release"] == d]
    by: dict[str, list[tuple[int, dict]]] = {r: [] for r in log.pins.rebuilders}
    for i, e in log.of_kind("enclave_rebuild"):
        if e["release"] == d and e["signer"] in by:
            by[e["signer"]].append((i, e))
    # SPEC GAP (G3): 2.5 rule 4 does not say which code wins when one
    # rebuilder differs and another is missing. This code checks "differs"
    # over all pinned rebuilders first.
    for r in log.pins.rebuilders:
        for _i, e in by[r]:
            if (
                not e["same"]
                or e["image_digest"] != release["image_digest"]
                or e["measurements"] != measurements
            ):
                raise Refused("release_rebuild_differs")
    for r in log.pins.rebuilders:
        times = [log.logged_by(i) for i, _e in by[r]]
        if not times or all(t is None or t > not_before for t in times):
            raise Refused("release_rebuilds_missing")
    del rebuilds
    lb = log.logged_by(index)
    if lb is None or lb + 14 * DAY > not_before:
        if not release["security_fix"]:
            raise Refused("release_notice_short")
        q = log.independent_quorum(d)
        if q is None or any(t > not_before - 48 * HOUR for _i, t in q.values()):
            raise Refused("release_fix_not_cosigned")
        if lb is None or lb + 48 * HOUR > not_before:
            raise Refused("release_notice_short")
    if now < not_before:
        raise Refused("release_not_yet")


# ---- descriptors (3.6) -----------------------------------------------------------

_BODY = {
    "matching": {
        "accepted_schemas", "anonymity_min_nodes", "anonymity_min_people", "answer_day",
        "card_option", "consent_statement", "network", "roster_key", "weekly_cap_max",
    },
    "vocabulary": {"concepts", "id", "sha256"},
    "model": {"digest", "name", "role"},
}  # fmt: skip


def _int_in(v: object, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def descriptor_ok(d: dict) -> bool:
    if set(d) != {"body", "kind", "schema"} or d["schema"] != "anagram.enclave.descriptor.v1":
        return False
    kind, b = d["kind"], d["body"]
    if kind not in _BODY or not isinstance(b, dict) or set(b) != _BODY[kind]:
        return False
    if kind == "matching":
        return (
            _int_in(b["anonymity_min_nodes"], 1, 100)
            and _int_in(b["anonymity_min_people"], 2, 1000)
            and _int_in(b["answer_day"], 1, 7)
            and b["card_option"] in ("a", "b")
            and _int_in(b["weekly_cap_max"], 1, 10)
            and b["accepted_schemas"] == sorted(set(b["accepted_schemas"]))
            and is_hex(b["roster_key"], 32)
        )
    if kind == "model":
        return b["role"] in ("embed", "screen", "judge")
    return _int_in(b["concepts"], 0, 2**32)


def descriptor_hash(d: dict) -> str:
    return tagged_hash("anagram/v1/enclave/descriptor", cjson(d)).hex()


def descriptor_set(hashes: list[str]) -> str:
    hs = sorted(hashes)
    return tagged_hash(
        "anagram/v1/enclave/descriptor-set", u32(len(hs)), *[bytes.fromhex(h) for h in hs]
    ).hex()


def check_descriptors(docs: list[dict], hashes: list[str]) -> dict[str, dict]:
    if not all(descriptor_ok(d) for d in docs):
        raise Refused("bad_attestation", "descriptor")
    if sorted(descriptor_hash(d) for d in docs) != sorted(hashes):
        raise Refused("bad_attestation", "descriptor hashes")
    kinds = [d["kind"] for d in docs]
    if kinds.count("matching") != 1 or kinds.count("vocabulary") != 1 or kinds.count("model") > 16:
        raise Refused("bad_attestation", "descriptor set")
    return {d["kind"]: d["body"] for d in docs if d["kind"] != "model"}


# ---- derived values ----------------------------------------------------------------


def measurement(profile: str, reference: dict) -> str:
    p = profile.encode()
    return tagged_hash("anagram/v1/enclave/measurement", u32(len(p)) + p, cjson(reference)).hex()


def binding(doc: dict, anchor: bytes) -> bytes:
    return tagged_hash(
        "anagram/v1/enclave/report-data",
        bytes.fromhex(doc["line_id"]),
        bytes.fromhex(doc["instance_id"]),
        u64(doc["key_epoch"]),
        bytes.fromhex(doc["intake_key"]),
        bytes.fromhex(doc["output_key"]),
        bytes.fromhex(descriptor_set(doc["descriptor_hashes"])),
        bytes.fromhex(doc["release"]),
        anchor,
    )


def gpu_nonce(b: bytes) -> bytes:
    return tagged_hash("anagram/v1/enclave/gpu-nonce", b)


def report_data_gpu(b: bytes, gpu_bytes: bytes) -> bytes:
    return tagged_hash("anagram/v1/enclave/report-data-gpu", b + sha256(gpu_bytes))


def attestation_digest(doc: dict) -> str:
    return tagged_hash("anagram/v1/room/attestation", cjson(doc)).hex()


def shard(subject_hex: str, n: int) -> int:
    h = tagged_hash("anagram/v1/enclave/shard", bytes.fromhex(subject_hex))
    return int.from_bytes(h[:4], "big") % n


def tombstone_id(subject_hex: str) -> str:
    return tagged_hash("anagram/v1/enclave/tombstone", bytes.fromhex(subject_hex)).hex()


def decline_id(decliner_hex: str, other_hex: str, match_type: str) -> str:
    """7.1: the match type is part of the ID."""
    data = bytes.fromhex(decliner_hex) + bytes.fromhex(other_hex) + match_type.encode("ascii")
    return tagged_hash("anagram/v1/enclave/decline", data).hex()


def clock_safe(lower_: int, upper_: int, max_seen: int, host: int, fresh_age: int) -> bool:
    """6.4 clock rule."""
    return not (
        fresh_age > HOUR
        or upper_ - lower_ > 300
        or lower_ < max_seen - 300
        or abs(host - (lower_ + upper_) / 2) > 300
    )


# ---- lines, epochs, writers (5.5 to 5.7) --------------------------------------------


def _instance_keys(log: Log, line_id: str) -> list[tuple[int, dict]]:
    return [(i, e) for i, e in log.of_kind("enclave_instance_key") if e["line_id"] == line_id]


def _failover_holds(log: Log, w: tuple[int, dict], epochs: list, writer: str) -> int | None:
    """Position at which `enclave_writer` entry `w` takes effect, or None."""
    wi, we = w
    if we["signer"] != log.pins.release_key:
        return None
    q = log.independent_quorum(entry_digest(we))
    if q is None or any(i < wi for i, _t in q.values()):
        return None
    pos = max(i for i, _t in q.values())
    before = [(i, e) for i, e in epochs if i < pos]
    if not before:
        return None
    _li, latest = before[-1]
    if latest["counter"] != we["counter"] or entry_digest(latest) != we["epoch"]:
        return None
    if we["writer"] not in latest["holders"] or we["writer"] == writer:
        return None
    times = [t for _i, t in q.values()]
    for i, e in _instance_keys(log, we["line_id"]):
        if (
            i < pos
            and e["instance_id"] == writer
            and any(parse_time(e["lease_until"]) > t for t in times)
        ):
            return None
    return pos


def line_state(log: Log, line_id: str) -> tuple[bool, str | None, dict | None]:
    """(forked, the instance that may write next, latest epoch)."""
    epochs = [(i, e) for i, e in log.of_kind("enclave_state_epoch") if e["line_id"] == line_id]
    keys = _instance_keys(log, line_id)
    writers = [(i, e) for i, e in log.of_kind("enclave_writer") if e["line_id"] == line_id]
    writer: str | None = None
    prev: dict | None = None
    pending = list(writers)
    for i, e in epochs:
        # apply failovers that took effect before this epoch
        for w in list(pending):
            pos = _failover_holds(log, w, [x for x in epochs if x[0] < i], writer or "")
            if pos is not None and pos < i:
                writer = w[1]["writer"]
                pending.remove(w)
        if prev is None:
            if e["counter"] != 0 or e["prev"] is not None:
                return True, None, None
            writer = e["instance_id"]
        elif e["counter"] != prev["counter"] + 1 or e["prev"] != entry_digest(prev):
            return True, None, None
        if e["instance_id"] != writer:
            return True, None, None
        if not any(
            k["instance_id"] == e["instance_id"] and k["signer"] == e["signer"] for _j, k in keys
        ):
            return True, None, None
        if writer not in e["holders"] or (
            e["next_writer"] and e["next_writer"] not in e["holders"]
        ):
            return True, None, None
        writer = e["next_writer"] or e["instance_id"]
        prev = e
    for w in pending:
        if _failover_holds(log, w, epochs, writer or "") is not None:
            writer = w[1]["writer"]
    return False, writer, prev


def line_authorised(log: Log, line_id: str, subject: str | None) -> bool:
    """5.6: one entry for the line, valid by its reason rules, and not
    replaced by a valid total-loss line."""
    lines = [(i, e) for i, e in log.of_kind("enclave_line") if e["line_id"] == line_id]
    if len(lines) != 1:
        return False
    i, e = lines[0]
    if not _line_valid(log, i, e):
        return False
    if subject is not None and shard(subject, e["shard"]["n"]) != e["shard"]["k"]:
        return False
    return not any(
        x["reason"] == "total_loss" and x["replaces"] == line_id and _line_valid(log, j, x)
        for j, x in log.of_kind("enclave_line")
    )


def _line_signed(log: Log, e: dict) -> bool:
    if e["signer"] != log.pins.release_key or log.independent_quorum(entry_digest(e)) is None:
        return False
    # v1 has one shard (5.6, W4 re-check R4)
    return e["shard"] == {"k": 0, "n": 1}


def _line_valid(log: Log, i: int, e: dict) -> bool:
    if not _line_signed(log, e):
        return False
    if e["reason"] in ("first", "shard"):
        return e["replaces"] is None
    if e["reason"] != "total_loss":
        return False
    old = [(j, x) for j, x in log.of_kind("enclave_line") if x["line_id"] == e["replaces"]]
    # SPEC GAP (G6): "replaces names an authorised line" is circular when
    # the new line itself un-authorises the old one. This code reads it as:
    # the old line has a valid first or shard entry of its own.
    if len(old) != 1 or old[0][1]["shard"] != e["shard"] or not _line_signed(log, old[0][1]):
        return False
    lb = log.logged_by(i)
    if lb is None:
        return False
    if any(parse_time(k["lease_until"]) > lb for _j, k in _instance_keys(log, e["replaces"])):
        return False
    for j, x in log.of_kind("enclave_line"):
        if (
            j < i
            and x["reason"] == "total_loss"
            and x["shard"] == e["shard"]
            and _line_signed(log, x)
        ):
            xl = log.logged_by(j)
            if xl is not None and lb - xl < 30 * DAY:
                return False
    return True


# ---- the attestation document (3.4, 3.5, 4.2) -------------------------------------


def _floor(log: Log, release: dict, profile: str) -> dict:
    floor = dict(release["profiles"][profile]["tcb_floor"])
    d = entry_digest(release)
    for _i, e in log.of_kind("enclave_floor"):
        if e["release"] != d or e["profile"] != profile or e["signer"] != log.pins.release_key:
            continue
        for k, v in e["tcb_floor"].items():
            old = floor.get(k)
            if isinstance(v, int) and isinstance(old, int):
                floor[k] = max(old, v)
            elif isinstance(v, list) and isinstance(old, list):
                floor[k] = [x for x in old if x in v]
            elif isinstance(v, str) and isinstance(old, str):
                floor[k] = max(old, v, key=lambda s, k=k: _dotted(k, s))
            elif old is None:
                floor[k] = v
    return floor


def _dotted(item: str, s: str) -> tuple[int, ...]:
    base = 16 if item == "gpu_vbios" else 10
    return tuple(int(x, base) for x in s.split("."))


def _pre_checks(log: Log, doc: dict, app_version: str, now: int) -> tuple[dict, Checkpoint]:
    if set(doc) != DOC_FIELDS or doc.get("schema") != "anagram.operator_attestation.v3":
        raise Refused("bad_attestation", "fields")
    rel = [e for _i, e in log.of_kind("enclave_release") if entry_digest(e) == doc["release"]]
    if not rel:
        raise Refused("bad_attestation", "release")
    release = rel[0]
    try:
        accept_release(log, release, app_version, now)
    except Refused as r:
        raise Refused("bad_attestation", r.code) from r
    if doc["descriptor_hashes"] != release["descriptor_hashes"]:
        raise Refused("bad_attestation", "descriptor hashes")
    if not verify_doc(doc["output_key"], "anagram/v1/enclave/sign/attestation", doc):
        raise Refused("bad_attestation", "signature")
    try:
        cp = parse_checkpoint(doc["checkpoint"], log.pins.log_key, log.pins.witnesses)
        lower(cp, log.pins.witnesses)
    except (Refused, ValueError) as r:
        raise Refused("bad_attestation", "checkpoint") from r
    if doc["profile"] not in release["profiles"] or doc["profile"] != "simulated":
        raise Refused("unknown_profile")
    return release, cp


def _evidence_rules(log: Log, doc: dict, release: dict, cp: Checkpoint, now: int) -> None:
    pe, ge = doc["platform_evidence"], doc["gpu_evidence"]
    root = log.pins.dev_root
    sim = "anagram/v1/enclave/sign/simulated-evidence"
    if not _evidence_signed(pe, root, sim):
        raise Refused("untrusted_root")
    if ge is not None:
        gtag = "anagram/v1/enclave/sign/simulated-gpu"
        if not _evidence_signed(ge, root, gtag):
            raise Refused("untrusted_root")
        if ge["report"]["ocsp"] != "good":
            raise Refused("cert_revoked")
    lo = lower(cp, log.pins.witnesses)
    if now - lo > 24 * HOUR or lo > now + 300:
        raise Refused("evidence_expired")
    r = pe["report"]
    if r["debug"] or r["migratable"]:
        raise Refused("policy_refused")
    if ge is not None and (
        ge["report"]["dbgstat"] != "disabled" or ge["report"]["cc_mode"] != "ON"
    ):
        raise Refused("policy_refused")
    floor = _floor(log, release, "simulated")
    if r["tcb"]["svn"] < floor.get("svn", 0):
        raise Refused("tcb_below_floor")
    # SPEC GAP (G4): 4.8 lists gpu_driver and gpu_vbios floor items for
    # `simulated` but does not say what happens when there is no GPU
    # evidence. This code checks them only when GPU evidence is present.
    if ge is not None:
        for item, claim in (("gpu_driver", "driver_version"), ("gpu_vbios", "vbios_version")):
            if item in floor and _dotted(item, ge["report"][claim]) < _dotted(item, floor[item]):
                raise Refused("tcb_below_floor")
    if measurement("simulated", r["reference"]) != release["profiles"]["simulated"]["measurement"]:
        raise Refused("measurement_mismatch")
    b = binding(doc, cp.anchor)
    gpu_form = report_data_gpu(b, cjson(ge)) if ge is not None else None
    if r["report_data"] not in (b.hex(), gpu_form.hex() if gpu_form else None):
        raise Refused("binding_mismatch")
    if release["profiles"]["simulated"]["reference"].get("gpu"):
        if (
            ge is None
            or ge["report"]["nonce"] != gpu_nonce(b).hex()
            or r["report_data"] != (gpu_form.hex() if gpu_form else None)
        ):
            raise Refused("gpu_binding_mismatch")


def _evidence_signed(ev: dict, root: str, tag: str) -> bool:
    if ev.get("signer") != root or not is_hex(ev.get("signature"), 64):
        return False
    return verify(bytes.fromhex(root), tag, cjson(ev["report"]), bytes.fromhex(ev["signature"]))


def _rule7(log: Log, doc: dict, release: dict, subject: str | None, now: int) -> None:
    d = doc["release"]
    keys = [
        (i, e)
        for i, e in log.of_kind("enclave_instance_key")
        if e["release"] == d
        and e["line_id"] == doc["line_id"]
        and e["instance_id"] == doc["instance_id"]
        and e["key_epoch"] == doc["key_epoch"]
        and e["intake_key"] == doc["intake_key"]
        and e["profile"] == doc["profile"]
        and e["signer"] == doc["output_key"]
    ]
    if not keys:
        raise Refused("instance_not_logged")
    i, e = keys[-1]
    lease = parse_time(e["lease_until"])
    lb = log.logged_by(i)
    if not (now < lease and lb is not None and lease <= lb + 24 * HOUR):
        raise Refused("instance_not_logged")
    if not line_authorised(log, doc["line_id"], subject):
        raise Refused("line_not_authorised")
    if log.revoked({"instance_id": doc["instance_id"]}) or log.revoked({"line_id": doc["line_id"]}):
        raise Refused("instance_revoked")
    forked, writer, latest = line_state(log, doc["line_id"])
    if forked:
        raise Refused("line_forked")
    if writer != doc["instance_id"]:
        raise Refused("instance_not_writer")
    if latest is None or len(latest["holders"]) > release["max_instances"]:
        raise Refused("instance_limit")


def verify_attestation(
    log: Log, doc: dict, subject: str | None, now: int, app_version: str = "1.2.0"
) -> dict:
    """Return the release of a document that passes 3.4; raise Refused."""
    release, cp = _pre_checks(log, doc, app_version, now)
    _evidence_rules(log, doc, release, cp, now)
    _rule7(log, doc, release, subject, now)
    return release
