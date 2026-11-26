"""Test vectors for spec/enclave-trust.md. Fixed inputs only.

    uv run python -m anagram.vectors.enclave_trust spec/vectors

writes spec/vectors/enclave-trust.json. `tests/test_enclave_trust.py`
checks that the file is current and recomputes each case.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke, merkle
from anagram.core.crypto.hashing import sha256, tagged_hash
from anagram.core.crypto.signing import SigningKey
from anagram.core.crypto.x25519 import X25519Key
from anagram.network.formats.strict import DAY, fmt_time
from anagram.network.matching.enclave.ledger import TAG_DECLINE, TAG_TOMBSTONE
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust import handoff as ho
from anagram.network.matching.trust import snapshot as snap
from anagram.network.matching.trust.attestation import sign_attestation
from anagram.network.matching.trust.bundle import TAG_ATTESTATION
from anagram.network.matching.trust.entries import entry_digest, sign_entry
from anagram.network.matching.trust.lines import TAG_SHARD, shard
from anagram.network.matching.trust.profiles import snp, tdx
from anagram.network.matching.trust.profiles.simulated import (
    TAG_SIGN_SIM_EVIDENCE,
    TAG_SIGN_SIM_GPU,
    sign_simulated,
)
from anagram.network.matching.trust.snapshot import _seal_with_nonce
from anagram.proofs.log.checkpoint import Checkpoint, sign_checkpoint
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner, add_signature_lines
from anagram.vectors.cli import output_dir

FILE = "enclave-trust.json"

T0 = int(datetime(2026, 12, 1, tzinfo=UTC).timestamp())
T1 = T0 + 16 * DAY  # "now" of the base case
LOG_ORIGIN = "enclave.anagram.example/log"

TAGS = [
    "anagram/v1/enclave/measurement",
    "anagram/v1/enclave/descriptor-set",
    "anagram/v1/enclave/report-data",
    "anagram/v1/enclave/report-data-gpu",
    "anagram/v1/enclave/gpu-nonce",
    "anagram/v1/enclave/log-entry",
    "anagram/v1/enclave/sign/release",
    "anagram/v1/enclave/sign/rebuild",
    "anagram/v1/enclave/sign/revoke",
    "anagram/v1/enclave/sign/floor",
    "anagram/v1/enclave/sign/instance-key",
    "anagram/v1/enclave/sign/state-epoch",
    "anagram/v1/enclave/sign/entry-cosign",
    "anagram/v1/enclave/sign/node-admission",
    "anagram/v1/enclave/sign/member-credential",
    "anagram/v1/enclave/sign/attestation",
    "anagram/v1/enclave/sign/simulated-evidence",
    "anagram/v1/enclave/sign/simulated-gpu",
    "anagram/v1/enclave/hpke/handoff",
    "anagram/v1/enclave/tombstone",
    "anagram/v1/enclave/sign/line",
    "anagram/v1/enclave/sign/handoff",
    "anagram/v1/enclave/shard",
    "anagram/v1/enclave/descriptor",
    "anagram/v1/enclave/sign/writer",
    "anagram/v1/enclave/decline",
]


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram enclave-trust vector seed: {label}".encode()).digest()


def _key(label: str) -> SigningKey:
    return SigningKey.from_seed(_seed(label))


def _x(label: str) -> X25519Key:
    return X25519Key.from_private_bytes(_seed(label))


def _id(label: str, n: int = 16) -> str:
    return _seed(label)[:n].hex()


LOG = NoteSigner(LOG_ORIGIN, _key("log"))
WITNESSES = {
    "rf": (NoteSigner("witness.radiofuture.example", _key("w-rf"), ALG_COSIGNATURE_V1), False),
    "uni": (NoteSigner("witness.uni.example", _key("w-uni"), ALG_COSIGNATURE_V1), True),
    "pub": (NoteSigner("witness.public.example", _key("w-pub"), ALG_COSIGNATURE_V1), True),
}
ENTRY_KEYS = {name: _key(f"w-{name}-entry") for name in WITNESSES}
RELEASE_KEY = _key("release")
REBUILDERS = {"ci": _key("rebuild-ci"), "ext": _key("rebuild-ext")}
NODE_KEY = _key("node")
ROSTER_KEY = _key("roster")
DEV_ROOT = _key("dev-root")
OTHER_ROOT = _key("not-the-dev-root")
LINE = _id("line-1")
LINE_2 = _id("line-2")
INSTANCES = {
    name: {"output": _key(f"out-{name}"), "intake": _x(f"intake-{name}"), "id": _id(f"inst-{name}")}
    for name in ("a", "b", "c", "d")
}
STATEMENT = (
    "Anagram matches you inside a sealed service that runs our published code; "
    "other people see your name only after you both say yes."
)
DESCRIPTOR_DOCS = [
    {
        "body": {
            "accepted_schemas": ["anagram.known.v1", "anagram.pack.v1"],
            "anonymity_min_nodes": 3,
            "anonymity_min_people": 10,
            "answer_day": 7,
            "card_option": "a",
            "consent_statement": STATEMENT,
            "network": "net.anagram.example",
            "roster_key": _key("roster").public_bytes().hex(),
            "weekly_cap_max": 3,
        },
        "kind": "matching",
        "schema": dsc.SCHEMA,
    },
    {
        "body": {"concepts": 120000, "id": "anagram-vocab-2026-11", "sha256": _seed("vocab").hex()},
        "kind": "vocabulary",
        "schema": dsc.SCHEMA,
    },
    {
        "body": {"digest": "sha256:" + _seed("weights").hex(), "name": "judge", "role": "judge"},
        "kind": "model",
        "schema": dsc.SCHEMA,
    },
]
DESCRIPTORS = sorted(dsc.descriptor_hash(d).hex() for d in DESCRIPTOR_DOCS)
IMAGE = "sha256:" + _seed("image").hex()
REFERENCE = {"gpu": True, "image_digest": IMAGE}
SUBJECT = _key("subject").public_bytes()
FLOOR = {"gpu_driver": "550.54.15", "gpu_vbios": "96.00.88.00.01", "svn": 2}


def roots_json() -> dict:
    return {
        "dev_root": DEV_ROOT.public_bytes().hex(),
        "log_key": LOG.vkey(),
        "rebuilders": sorted(k.public_bytes().hex() for k in REBUILDERS.values()),
        "release_key": RELEASE_KEY.public_bytes().hex(),
        "witnesses": [
            {
                "cosign": w.vkey(),
                "entry_key": ENTRY_KEYS[name].public_bytes().hex(),
                "independent": ind,
                "name": name,
            }
            for name, (w, ind) in WITNESSES.items()
        ],
    }


def release(**over: object) -> dict:
    fields = {
        "build": {
            "builder": "sha256:" + _seed("builder").hex(),
            "lock_sha256": _seed("uv.lock").hex(),
            "source_date_epoch": T0 - DAY,
        },
        "descriptor_hashes": DESCRIPTORS,
        "image_digest": IMAGE,
        "max_instances": 2,
        "min_app_version": "1.0.0",
        "not_before": fmt_time(T0 + 15 * DAY),
        "profiles": {
            "simulated": {
                "measurement": b.measurement("simulated", REFERENCE).hex(),
                "reference": REFERENCE,
                "tcb_floor": FLOOR,
            }
        },
        "security_fix": False,
        "source_commit": _seed("commit")[:20].hex(),
        "successor_of": None,
        "vendor_digests": [{"digest": "sha256:" + _seed("cuda").hex(), "name": "nvidia/cuda"}],
        "weights": [{"digest": "sha256:" + _seed("weights").hex(), "name": "judge"}],
    }
    fields.update(over)
    return sign_entry("enclave_release", fields, RELEASE_KEY)


def rebuild(rel: dict, who: str, same: bool = True) -> dict:
    return sign_entry(
        "enclave_rebuild",
        {
            "image_digest": rel["image_digest"],
            "measurements": {p: v["measurement"] for p, v in rel["profiles"].items()},
            "release": entry_digest(rel).hex(),
            "same": same,
        },
        REBUILDERS[who],
    )


def instance_key(rel: dict, name: str, lease_until: int = T1 + DAY // 2, line: str = LINE) -> dict:
    inst = INSTANCES[name]
    return sign_entry(
        "enclave_instance_key",
        {
            "evidence_digest": _seed(f"evidence-{name}").hex(),
            "instance_id": inst["id"],
            "intake_key": inst["intake"].public_bytes().hex(),
            "key_epoch": 0,
            "lease_until": fmt_time(lease_until),
            "line_id": line,
            "profile": "simulated",
            "release": entry_digest(rel).hex(),
        },
        inst["output"],
    )


def state_epoch(
    name: str,
    counter: int,
    prev: dict | None,
    next_writer: str | None = None,
    digest: bytes | None = None,
    holders: tuple[str, ...] | None = None,
    line: str = LINE,
) -> dict:
    ids = sorted({INSTANCES[h]["id"] for h in holders or (name,)})
    return sign_entry(
        "enclave_state_epoch",
        {
            "checkpoint": _seed(f"cp-seen-{counter}").hex(),
            "counter": counter,
            "holders": ids,
            "instance_id": INSTANCES[name]["id"],
            "line_id": line,
            "next_writer": next_writer,
            "prev": entry_digest(prev).hex() if prev else None,
            "rekey": False,
            "snapshot_digest": (digest or snapshot_digest(counter)).hex(),
            "snapshot_size": SNAPSHOT_SIZE,
        },
        INSTANCES[name]["output"],
    )


def entry_cosign(entry: dict, witness: str, time: int) -> dict:
    return sign_entry(
        "enclave_entry_cosign",
        {"entry": entry_digest(entry).hex(), "time": time},
        ENTRY_KEYS[witness],
    )


def revoke(target: dict, reason: str = "vulnerability", key: SigningKey = RELEASE_KEY) -> dict:
    return sign_entry("enclave_revoke", {"reason": reason, "target": target}, key)


def line_entry(
    line: str, reason: str = "first", replaces: str | None = None, k: int = 0, n: int = 1
) -> dict:
    return sign_entry(
        "enclave_line",
        {
            "line_id": line,
            "reason": reason,
            "release": entry_digest(REL).hex(),
            "replaces": replaces,
            "shard": {"k": k, "n": n},
        },
        RELEASE_KEY,
    )


def cosigned(entry: dict, time: int, witnesses: tuple[str, ...] = ("uni", "pub")) -> list[dict]:
    """The entry and the enclave_entry_cosign entries of the witnesses."""
    return [entry, *(entry_cosign(entry, w, time) for w in witnesses)]


# ---- sealed snapshot (spec section 6.1) ------------------------------------

SNAPSHOT_SIZE = 4096
STATE_KEY = _seed("state-key")


def snapshot(counter: int) -> tuple[dict, bytes]:
    body = canonical_json({"packs": counter, "tombstones": []})
    nonce = _seed(f"snapshot-nonce-{counter}")[:12]
    sealed = _seal_with_nonce(STATE_KEY, LINE, counter, SNAPSHOT_SIZE, body, nonce)
    return snap.header(LINE, counter, SNAPSHOT_SIZE), sealed


def snapshot_digest(counter: int) -> bytes:
    return sha256(snapshot(counter)[1])


# ---- log and checkpoints ----------------------------------------------------

CP1 = {"rf": T0 + 60, "uni": T0 + 90}
CP2 = {"rf": T1 - 600, "uni": T1 - 500, "pub": T1 - 400}
CP3 = {"rf": T1 - 300, "uni": T1 - 250}


def note(entries: list[dict], size: int, times: dict[str, int]) -> str:
    leaves = [merkle.leaf_hash(canonical_json(e)) for e in entries[:size]]
    cp = Checkpoint(LOG_ORIGIN, size, merkle.root(leaves))
    signed = sign_checkpoint(cp, LOG)
    lines = [WITNESSES[w][0].cosign(cp.text(), t) for w, t in sorted(times.items())]
    return add_signature_lines(signed, lines)


REL = release()
A_KEY = instance_key(REL, "a")
SE0 = state_epoch("a", 0, None)
SE1 = state_epoch("a", 1, SE0)
ROSTER_CHECKPOINT = sign_entry(
    "roster_checkpoint",
    {
        "head": _seed("roster-head").hex(),
        "network": "net.anagram.example",
        "seq": 7,
        "time": fmt_time(T1 - 900),
    },
    ROSTER_KEY,
)
BASE = [
    REL,
    rebuild(REL, "ci"),
    rebuild(REL, "ext"),
    sign_entry(
        "node_admission",
        {"node_id": "node-a.anagram.example", "record_digest": _seed("admission").hex()},
        ROSTER_KEY,
    ),
    sign_entry(
        "member_credential",
        {
            "credential_hash": _seed("credential").hex(),
            "expires": fmt_time(T0 + DAY),
            "member": _seed("join commitment").hex(),  # a join entry (network.md 6.5)
            "node_id": "node-a.anagram.example",
        },
        NODE_KEY,
    ),
    A_KEY,
    SE0,
    SE1,
    *cosigned(line_entry(LINE), T0 + 120),
    ROSTER_CHECKPOINT,
]
BASE_CP1 = note(BASE, 5, CP1)
BASE_CP2 = note(BASE, len(BASE), CP2)


def checkpoints(extra: list[dict]) -> list[str]:
    out = [BASE_CP1, BASE_CP2]
    if extra:
        out.append(note(BASE + extra, len(BASE) + len(extra), CP3))
    return out


def anchor(note_text: str) -> bytes:
    text = note_text[: note_text.index("\n\n") + 1]
    return hashlib.sha256(text.encode()).digest()


# ---- attestation documents (simulated profile) -----------------------------


def binding_for(name: str, cp_note: str = BASE_CP2, rel: dict = REL, line: str = LINE) -> b.Binding:
    inst = INSTANCES[name]
    return b.Binding(
        line_id=bytes.fromhex(line),
        instance_id=bytes.fromhex(inst["id"]),
        key_epoch=0,
        intake_key=inst["intake"].public_bytes(),
        output_key=inst["output"].public_bytes(),
        descriptor_set=b.descriptor_set_hash([bytes.fromhex(h) for h in DESCRIPTORS]),
        release=entry_digest(rel),
        checkpoint=anchor(cp_note),
    )


def gpu_report(gpu_nonce: bytes, over: dict | None = None) -> dict:
    report = {
        "cc_mode": "ON",
        "dbgstat": "disabled",
        "driver_version": "550.90.07",
        "nonce": gpu_nonce.hex(),
        "ocsp": "good",
        "vbios_version": "96.00.9F.00.01",
    }
    report.update(over or {})
    return report


def attestation(
    name: str = "a",
    cp_note: str = BASE_CP2,
    cpu_over: dict | None = None,
    gpu_over: dict | None = None,
    gpu: bool = True,
    cpu_root: SigningKey = DEV_ROOT,
    report_data: str | None = None,
    bind_name: str | None = None,
    line: str = LINE,
) -> dict:
    inst = INSTANCES[name]
    bind = binding_for(bind_name or name, cp_note, line=line).value()
    gpu_ev = None
    if gpu:
        gpu_ev = sign_simulated(gpu_report(b.gpu_nonce(bind), gpu_over), DEV_ROOT, TAG_SIGN_SIM_GPU)
    rd = b.report_data(bind, canonical_json(gpu_ev) if gpu_ev else None).hex()
    cpu = {
        "debug": False,
        "migratable": False,
        "reference": REFERENCE,
        "report_data": report_data or rd,
        "tcb": {"svn": 3},
    }
    cpu.update(cpu_over or {})
    doc = {
        "checkpoint": cp_note,
        "descriptor_hashes": DESCRIPTORS,
        "gpu_evidence": gpu_ev,
        "instance_id": inst["id"],
        "intake_key": inst["intake"].public_bytes().hex(),
        "key_epoch": 0,
        "line_id": line,
        "log_proof": {"index": 5},
        "output_key": inst["output"].public_bytes().hex(),
        "platform_evidence": sign_simulated(cpu, cpu_root, TAG_SIGN_SIM_EVIDENCE),
        "profile": "simulated",
        "release": entry_digest(REL).hex(),
        "schema": "anagram.operator_attestation.v3",
        "signature": "",
    }
    return sign_attestation(doc, inst["output"])


def attestation_cases() -> list[dict]:
    base = attestation()
    bind_a = binding_for("a").value()
    b_key, c_key = instance_key(REL, "b"), instance_key(REL, "c")
    d_doc = attestation(name="d", line=LINE_2)
    d_line = [instance_key(REL, "d", line=LINE_2), state_epoch("d", 0, None, line=LINE_2)]
    my_shard_of_2 = shard(SUBJECT, 2)
    too_many = state_epoch("a", 2, SE1, holders=("a", "b", "c"))
    forked = state_epoch("a", 1, SE0, digest=_seed("fork"))  # a second counter 1
    floor_raise = sign_entry(
        "enclave_floor",
        {"profile": "simulated", "release": entry_digest(REL).hex(), "tcb_floor": {"svn": 4}},
        RELEASE_KEY,
    )
    bad_schema = {**base, "schema": "anagram.operator_attestation.v2"}
    cases = [
        ("ok", base, [], None),
        ("ok_after_floor_raise_to_3", base, [], None),
        ("pre_bad_schema", bad_schema, [], "bad_attestation"),
        (
            "pre_unknown_profile",
            sign_attestation({**base, "profile": "raw-snp"}, INSTANCES["a"]["output"]),
            [],
            "unknown_profile",
        ),
        # 3.4 step 1: a bad output-key signature comes before the profile.
        ("pre_bad_signature_before_profile", {**base, "profile": "raw-snp"}, [], "bad_attestation"),
        ("r8_untrusted_root", attestation(cpu_root=OTHER_ROOT), [], "untrusted_root"),
        ("r8_gpu_ocsp_revoked", attestation(gpu_over={"ocsp": "revoked"}), [], "cert_revoked"),
        ("r4_old_checkpoint", attestation(cp_note=BASE_CP1), [], "evidence_expired"),
        ("r3_cpu_debug", attestation(cpu_over={"debug": True}), [], "policy_refused"),
        ("r3_cpu_migratable", attestation(cpu_over={"migratable": True}), [], "policy_refused"),
        ("r3_gpu_debug", attestation(gpu_over={"dbgstat": "enabled"}), [], "policy_refused"),
        ("r3_gpu_cc_off", attestation(gpu_over={"cc_mode": "OFF"}), [], "policy_refused"),
        ("r2_cpu_svn", attestation(cpu_over={"tcb": {"svn": 1}}), [], "tcb_below_floor"),
        (
            "r2_gpu_driver",
            attestation(gpu_over={"driver_version": "535.104.05"}),
            [],
            "tcb_below_floor",
        ),
        ("r2_floor_raised", base, [floor_raise], "tcb_below_floor"),
        (
            "r1_measurement",
            attestation(
                cpu_over={"reference": {**REFERENCE, "image_digest": "sha256:" + "0" * 64}}
            ),
            [],
            "measurement_mismatch",
        ),
        ("r5_other_key", attestation(bind_name="b"), [], "binding_mismatch"),
        (
            "r6_cpu_does_not_cover_gpu",
            attestation(report_data=b.report_data(bind_a).hex()),
            [],
            "gpu_binding_mismatch",
        ),
        ("r6_gpu_nonce", attestation(gpu_over={"nonce": "00" * 32}), [], "gpu_binding_mismatch"),
        ("r6_no_gpu", attestation(gpu=False), [], "gpu_binding_mismatch"),
        ("r7_clone_not_logged", attestation(name="c"), [], "instance_not_logged"),
        (
            "r7_lease_longer_than_24h",
            base,
            [instance_key(REL, "a", lease_until=T1 + 2 * DAY)],
            "instance_not_logged",
        ),
        ("r7_line_without_entry", d_doc, d_line, "line_not_authorised"),
        (
            "r7_line_cosigned_with_radiofuture_witness",
            d_doc,
            [*d_line, *cosigned(line_entry(LINE_2, "shard", k=0, n=1), T1 - 900, ("rf", "uni"))],
            "line_not_authorised",
        ),
        (
            "r7_line_with_two_shards_in_v1",
            d_doc,
            [*d_line, *cosigned(line_entry(LINE_2, "shard", k=my_shard_of_2, n=2), T1 - 900)],
            "line_not_authorised",
        ),
        (
            "ok_line_with_one_shard",
            d_doc,
            [*d_line, *cosigned(line_entry(LINE_2, "shard", k=0, n=1), T1 - 900)],
            None,
        ),
        (
            "r7_clone_logged_not_writer",
            attestation(name="c"),
            [c_key],
            "instance_not_writer",
        ),
        (
            "r7_lease_expired",
            base,
            [instance_key(REL, "a", lease_until=T1 - 60)],
            "instance_not_logged",
        ),
        (
            "r7_instance_revoked",
            base,
            [revoke({"instance_id": INSTANCES["a"]["id"]})],
            "instance_revoked",
        ),
        ("r7_line_forked", base, [forked], "line_forked"),
        ("r7_over_max_instances", base, [b_key, c_key, too_many], "instance_limit"),
    ]
    out = []
    for name, doc, extra, expect in cases:
        if name == "ok_after_floor_raise_to_3":
            extra = [
                sign_entry(
                    "enclave_floor",
                    {
                        "profile": "simulated",
                        "release": entry_digest(REL).hex(),
                        "tcb_floor": {"svn": 3},
                    },
                    RELEASE_KEY,
                )
            ]
        out.append(
            {
                "checkpoints": checkpoints(extra),
                "doc": doc,
                "expect": expect or "ok",
                "extra_entries": extra,
                "name": name,
                "now": T1,
                "subject": SUBJECT.hex(),
            }
        )
    return out


# ---- release acceptance -----------------------------------------------------


def release_cases() -> list[dict]:
    logged_extra = CP3["uni"]  # the latest quorum time of the checkpoint over extras
    short = release(not_before=fmt_time(logged_extra + 10 * DAY), successor_of=None)
    fix = release(not_before=fmt_time(logged_extra + 3 * DAY), security_fix=True)
    unlogged = release(min_app_version="1.0.1")
    old_app = release(min_app_version="2.0.0")

    def full(rel: dict, *more: dict) -> list[dict]:
        return [rel, rebuild(rel, "ci"), rebuild(rel, "ext"), *more]

    fix_cosigns = [entry_cosign(fix, "uni", T1 - 200), entry_cosign(fix, "pub", T1 - 150)]
    rf_cosign = entry_cosign(fix, "rf", T1 - 180)
    other_key = _key("not-the-release-key")
    quorum_revoke = revoke({"release": entry_digest(REL).hex()}, "key_compromise", other_key)
    cases = [
        ("ok", REL, [], "1.2.0", T1, "ok"),
        ("not_logged", unlogged, [], "1.2.0", T1, "release_not_logged"),
        (
            "revoked",
            REL,
            [revoke({"release": entry_digest(REL).hex()})],
            "1.2.0",
            T1,
            "release_revoked",
        ),
        ("app_too_old", old_app, full(old_app), "1.9.9", T1 + 30 * DAY, "release_app_too_old"),
        (
            "rebuild_differs",
            short,
            [short, rebuild(short, "ci"), rebuild(short, "ext", same=False)],
            "1.2.0",
            T1 + 30 * DAY,
            "release_rebuild_differs",
        ),
        (
            "rebuild_missing",
            short,
            [short, rebuild(short, "ci")],
            "1.2.0",
            T1 + 30 * DAY,
            "release_rebuilds_missing",
        ),
        ("notice_short", short, full(short), "1.2.0", T1 + 30 * DAY, "release_notice_short"),
        ("fix_not_cosigned", fix, full(fix), "1.2.0", T1 + 30 * DAY, "release_fix_not_cosigned"),
        (
            "fix_cosigned_by_radiofuture_only",
            fix,
            full(fix, rf_cosign),
            "1.2.0",
            T1 + 30 * DAY,
            "release_fix_not_cosigned",
        ),
        (
            "fix_cosigned_by_radiofuture_and_one_independent",
            fix,
            full(fix, rf_cosign, fix_cosigns[0]),
            "1.2.0",
            T1 + 30 * DAY,
            "release_fix_not_cosigned",
        ),
        (
            "revoked_by_quorum_of_independent_witnesses",
            REL,
            cosigned(quorum_revoke, T1 - 300),
            "1.2.0",
            T1,
            "release_revoked",
        ),
        (
            "quorum_revoke_with_radiofuture_witness_has_no_effect",
            REL,
            cosigned(quorum_revoke, T1 - 300, ("rf", "uni")),
            "1.2.0",
            T1,
            "ok",
        ),
        ("fix_cosigned", fix, full(fix, *fix_cosigns), "1.2.0", T1 + 30 * DAY, "ok"),
        # Rule 6 uses the app's now, max(clock, lower(latest checkpoint)) (3.5):
        # here the app has seen only the first checkpoint, from before not_before.
        ("not_yet", REL, [], "1.2.0", T0 + 15 * DAY - 1, "release_not_yet", [BASE_CP1]),
        ("not_yet_clock_behind_checkpoint", REL, [], "1.2.0", T0 + 15 * DAY - 1, "ok"),
    ]
    return [
        {
            "app_version": case[3],
            "checkpoints": case[6] if len(case) > 6 else checkpoints(case[2]),
            "expect": case[5],
            "extra_entries": case[2],
            "name": case[0],
            "now": case[4],
            "release": case[1],
        }
        for case in cases
    ]


def handoff_cases() -> list[dict]:
    succ = release(successor_of=entry_digest(REL).hex(), min_app_version="1.1.0")
    other = release(min_app_version="1.0.2")
    return [
        {"name": "same_release", "own": REL, "successor": REL, "expect": "ok"},
        {"name": "named_successor", "own": REL, "successor": succ, "expect": "ok"},
        {
            "name": "not_a_successor",
            "own": REL,
            "successor": other,
            "expect": "handoff_not_successor",
        },
        {"name": "no_downgrade", "own": succ, "successor": REL, "expect": "handoff_not_successor"},
    ]


# ---- snapshots, tombstones, clock (enclave rules; recomputed by the test) --


def _load_case(name: str, counter: int, line: str, expect: str, **over: object) -> dict:
    case = {
        "name": name,
        "counter": counter,
        "digest": snapshot_digest(counter).hex(),
        "handoff": None,
        "line": line,
        "expect": expect,
    }
    return {**case, **over}


def _handoff(counter: int, loader: str = "b", digest: bytes | None = None) -> dict:
    """What the loader got in its handoff message (section 5.3)."""
    return {
        "loader": INSTANCES[loader]["id"],
        "counter": counter,
        "digest": (digest or snapshot_digest(counter)).hex(),
    }


def snapshot_cases() -> dict:
    """Load cases (section 6.2). A restart loads with no handoff. A
    successor loads the epoch after the one its handoff message named: the
    writer's step 5 epoch, which names it `next_writer`."""
    header, sealed = snapshot(1)
    forked_line = [SE0, SE1, state_epoch("a", 1, SE0, next_writer=INSTANCES["b"]["id"])]
    b_id = INSTANCES["b"]["id"]
    handoff_line = [SE0, SE1, state_epoch("a", 2, SE1, next_writer=b_id, holders=("a", "b"))]
    return {
        "sealed_counter_1": {
            "header": header,
            "sealed_hex": sealed.hex(),
            "state_key_hex": STATE_KEY.hex(),
            "digest": sha256(sealed).hex(),
        },
        "line": [SE0, SE1],
        "forked_line": forked_line,
        "handoff_line": handoff_line,
        "cases": [
            _load_case("latest", 1, "line", "ok"),
            _load_case("older", 0, "line", "snapshot_stale"),
            _load_case(
                "wrong_digest", 1, "line", "snapshot_unknown", digest=snapshot_digest(0).hex()
            ),
            _load_case("ahead_of_log", 2, "line", "snapshot_unknown"),
            _load_case("forked", 1, "forked_line", "line_forked"),
            _load_case(
                "successor_loads_the_epoch_that_names_it",
                2,
                "handoff_line",
                "ok",
                handoff=_handoff(1),
            ),
            _load_case(
                "handoff_names_the_loaded_epoch",
                2,
                "handoff_line",
                "snapshot_unknown",
                handoff=_handoff(2),
            ),
            _load_case(
                "epoch_names_another_successor",
                2,
                "handoff_line",
                "snapshot_unknown",
                handoff=_handoff(1, loader="c"),
            ),
            _load_case(
                "handoff_names_another_snapshot",
                2,
                "handoff_line",
                "snapshot_unknown",
                handoff=_handoff(1, digest=snapshot_digest(0)),
            ),
            _load_case(
                "successor_without_the_step_5_epoch",
                1,
                "line",
                "snapshot_unknown",
                handoff=_handoff(0),
            ),
        ],
    }


def writer_entry(counter: int, epoch: dict, writer: str, key: SigningKey = RELEASE_KEY) -> dict:
    return sign_entry(
        "enclave_writer",
        {
            "counter": counter,
            "epoch": entry_digest(epoch).hex(),
            "line_id": LINE,
            "writer": INSTANCES[writer]["id"],
        },
        key,
    )


def writer_cases() -> list[dict]:
    """Writer failover (section 5.7). Writer a stops; b holds the state key
    (epoch 2 adds it). An `enclave_writer` entry names b; then b writes
    epoch 3. Each case gives whether the line is forked and who may write
    next. A failover that does not hold changes nothing and so never forks
    the line: an epoch by b after it is the fork."""
    se2 = state_epoch("a", 2, SE1, holders=("a", "b"))
    ended = T1 + DAY  # after a's lease (T1 + 12 h)
    live = T1  # before it
    by_b = state_epoch("b", 3, se2, holders=("b",))
    by_a = state_epoch("a", 3, se2, holders=("a", "b"))
    good = writer_entry(2, se2, "b")
    a_id, b_id = INSTANCES["a"]["id"], INSTANCES["b"]["id"]
    b_key = instance_key(REL, "b")
    cases = [
        ("no_failover", [], False, a_id),
        ("failover_after_the_lease_ended", cosigned(good, ended) + [by_b], False, b_id),
        ("failover_before_its_epoch", cosigned(good, ended), False, b_id),
        ("lease_not_ended", cosigned(good, live) + [by_b], True, None),
        (
            "cosigned_by_one_independent_witness",
            cosigned(good, ended, ("rf", "uni")) + [by_b],
            True,
            None,
        ),
        (
            "not_signed_by_the_release_key",
            cosigned(writer_entry(2, se2, "b", NODE_KEY), ended) + [by_b],
            True,
            None,
        ),
        ("names_an_old_epoch", cosigned(writer_entry(1, SE1, "b"), ended) + [by_b], True, None),
        (
            "names_an_instance_that_is_not_a_holder",
            cosigned(writer_entry(2, se2, "c"), ended),
            False,
            a_id,
        ),
        ("old_writer_after_the_failover", cosigned(good, ended) + [by_a], True, None),
        ("old_writer_wrote_first", [by_a, *cosigned(good, ended)], False, a_id),
    ]
    return [
        {
            "name": name,
            "extra_entries": [b_key, se2, *extra],
            "forked": forked,
            "writer": writer,
        }
        for name, extra, forked, writer in cases
    ]


PACK_LIFE = 30 * DAY
KEY_OVERLAP = 7 * DAY
SKEW_MARGIN = DAY
TOMBSTONE_LIFE = PACK_LIFE + KEY_OVERLAP + SKEW_MARGIN


def tombstone_cases() -> dict:
    subject = _key("person").public_bytes().hex()
    t = T1
    return {
        "subject": subject,
        "tombstone_id": tagged_hash(TAG_TOMBSTONE, bytes.fromhex(subject)).hex(),
        "tombstone": {"time": t, "version": 7},
        "life_seconds": TOMBSTONE_LIFE,
        "cases": [
            {
                "name": "replay_same_version",
                "version": 7,
                "created": t - DAY,
                "now": t + DAY,
                "expect": "tombstoned",
            },
            {
                "name": "replay_old_version",
                "version": 5,
                "created": t - 3600,
                "now": t + DAY,
                "expect": "tombstoned",
            },
            {
                "name": "higher_version_made_before_withdrawal",
                "version": 8,
                "created": t - 60,
                "now": t + DAY,
                "expect": "tombstoned",
            },
            {
                "name": "made_at_the_withdrawal_time",
                "version": 8,
                "created": t,
                "now": t + DAY,
                "expect": "tombstoned",
            },
            {
                "name": "older_than_48_hours",
                "version": 8,
                "created": t + 60,
                "now": t + 2 * DAY + 61,
                "expect": "expired",
            },
            {
                "name": "comes_back",
                "version": 8,
                "created": t + 3600,
                "now": t + DAY,
                "expect": "ok",
            },
            {
                "name": "after_tombstone_life_old_pack_expired",
                "version": 7,
                "created": t - DAY,
                "now": t + TOMBSTONE_LIFE + 1,
                "expect": "expired",
            },
        ],
    }


def decline_cases() -> dict:
    """Decline record IDs (section 7.1): the declined match
    type is part of the ID, so a `no` blocks only that type."""
    decliner = _key("person").public_bytes().hex()
    other = _key("other person").public_bytes().hex()
    rule = 'tagged_hash("anagram/v1/enclave/decline", decliner key || other key || ASCII(type))'
    cases = []
    for first, second in ((decliner, other), (other, decliner)):
        for kind in ("method_help", "research_fit"):
            data = bytes.fromhex(first) + bytes.fromhex(second) + kind.encode("ascii")
            cases.append(
                {
                    "decliner": first,
                    "other": second,
                    "type": kind,
                    "decline_id": tagged_hash(TAG_DECLINE, data).hex(),
                }
            )
    return {"rule": rule, "life_seconds": 365 * DAY, "cases": cases}


def line_cases() -> list[dict]:
    """Rule 7 (b) for total-loss lines (section 5.6). Each case asks whether
    `line` is authorised, with the extra entries in one later checkpoint."""
    late = {"rf": T1 + 2 * DAY, "uni": T1 + 2 * DAY + 60}
    later = {"rf": T1 + 5 * DAY, "uni": T1 + 5 * DAY + 60}
    early = {"rf": T1 - 300, "uni": T1 - 250}
    loss_2 = cosigned(line_entry(LINE_2, "total_loss", replaces=LINE), T1 - 200)
    line_3 = _id("line-3")
    loss_3 = cosigned(line_entry(line_3, "total_loss", replaces=LINE_2), T1 + 4 * DAY)
    cases = [
        ("first_line", LINE, [], [], "ok"),
        ("total_loss_while_the_old_line_runs", LINE_2, loss_2, [early], "line_not_authorised"),
        ("old_line_still_authorised", LINE, loss_2, [early], "ok"),
        ("total_loss_after_every_lease_ended", LINE_2, loss_2, [late], "ok"),
        ("replaced_line", LINE, loss_2, [late], "line_not_authorised"),
        (
            "second_total_loss_within_30_days",
            line_3,
            loss_2 + loss_3,
            [late, later],
            "line_not_authorised",
        ),
    ]
    out = []
    for name, line, extra, times, expect in cases:
        notes = [BASE_CP1, BASE_CP2]
        for i, t in enumerate(times):
            size = len(BASE) + (len(loss_2) if i == 0 and len(times) > 1 else len(extra))
            notes.append(note(BASE + extra, size, t))
        out.append(
            {
                "checkpoints": notes,
                "expect": expect,
                "extra_entries": extra,
                "line": line,
                "name": name,
            }
        )
    return out


def handoff_messages(previous: dict | None) -> dict:
    """The state-key handoff from instance a (the writer) to instance b
    (section 5.3). The HPKE ciphertext is random; it stays from the last run
    when it still opens to the same secret."""
    doc_b = attestation(name="b")
    successor = tagged_hash(TAG_ATTESTATION, canonical_json(doc_b))
    epoch = SE1
    plain = ho.secret(STATE_KEY, LINE, epoch["counter"], epoch["snapshot_digest"])
    intake = INSTANCES["b"]["intake"]
    old = (previous or {}).get("handoff_messages", {}).get("ciphertext_b64")
    raw = base64.b64decode(old) if old else b""
    try:
        priv = hpke.private_from_bytes(intake.private_bytes())
        if hpke.open_sealed(priv, raw, ho.info(successor)) != plain:
            raw = b""
    except Exception:  # noqa: BLE001 - any failure means "seal again"
        raw = b""
    if not raw:
        raw = hpke.seal(intake.public_bytes(), plain, ho.info(successor))
    a, c = INSTANCES["a"]["output"], INSTANCES["c"]["output"]
    other = tagged_hash(TAG_ATTESTATION, canonical_json(attestation(name="c")))
    sd = epoch["snapshot_digest"]
    extra = [instance_key(REL, "b"), instance_key(REL, "c")]
    return {
        "ciphertext_b64": base64.b64encode(raw).decode("ascii"),
        "successor_attestation": doc_b,
        "successor_digest": successor.hex(),
        "successor_intake_private_hex": intake.private_bytes().hex(),
        "state_key_hex": STATE_KEY.hex(),
        "extra_entries": extra,
        "checkpoints": checkpoints(extra),
        "cases": [
            {"name": "ok", "msg": ho.make(raw, LINE, 1, sd, successor, a), "expect": "ok"},
            {
                "name": "sender_not_a_holder",
                "msg": ho.make(raw, LINE, 1, sd, successor, c),
                "expect": "handoff_bad_sender",
            },
            {
                "name": "older_counter",
                "msg": ho.make(raw, LINE, 0, snapshot_digest(0).hex(), successor, a),
                "expect": "snapshot_unknown",
            },
            {
                "name": "for_another_successor",
                "msg": ho.make(raw, LINE, 1, sd, other, a),
                "expect": "handoff_bad_ciphertext",
            },
        ],
    }


def descriptor_vectors() -> dict:
    two_matching = [
        *DESCRIPTOR_DOCS,
        {**DESCRIPTOR_DOCS[0], "body": {**DESCRIPTOR_DOCS[0]["body"], "weekly_cap_max": 2}},
    ]
    return {
        "documents": DESCRIPTOR_DOCS,
        "hashes": [dsc.descriptor_hash(d).hex() for d in DESCRIPTOR_DOCS],
        "set_hash": dsc.set_hash(DESCRIPTOR_DOCS).hex(),
        "statement_sha256": dsc.statement_hash(DESCRIPTOR_DOCS[0]),
        "bad": [
            {
                "name": "extra_body_field",
                "doc": {**DESCRIPTOR_DOCS[1], "body": {**DESCRIPTOR_DOCS[1]["body"], "x": 1}},
            },
            {"name": "unknown_kind", "doc": {**DESCRIPTOR_DOCS[1], "kind": "policy"}},
            {
                "name": "answer_day_8",
                "doc": {
                    **DESCRIPTOR_DOCS[0],
                    "body": {**DESCRIPTOR_DOCS[0]["body"], "answer_day": 8},
                },
            },
            {
                "name": "card_option_c",
                "doc": {
                    **DESCRIPTOR_DOCS[0],
                    "body": {**DESCRIPTOR_DOCS[0]["body"], "card_option": "c"},
                },
            },
        ],
        "bad_sets": [
            {
                "name": "two_matching",
                "documents": two_matching,
                "hashes": sorted(dsc.descriptor_hash(d).hex() for d in two_matching),
            },
            {"name": "missing_document", "documents": DESCRIPTOR_DOCS[:2], "hashes": DESCRIPTORS},
        ],
        "shard_example": {
            "subject": SUBJECT.hex(),
            "tag": TAG_SHARD,
            "n": 2,
            "shard": shard(SUBJECT, 2),
        },
    }


def clock_cases() -> list[dict]:
    """Inputs of the clock rule (spec section 6.4); times are unix seconds."""
    return [
        {
            "name": "agree",
            "host": T1,
            "lower": T1 - 30,
            "upper": T1 + 40,
            "fresh_age": 600,
            "max_seen": T1 - 100,
            "expect": "ok",
        },
        {
            "name": "host_one_hour_ahead",
            "host": T1 + 3600,
            "lower": T1 - 30,
            "upper": T1 + 40,
            "fresh_age": 600,
            "max_seen": T1 - 100,
            "expect": "clock_unsafe",
        },
        {
            "name": "host_one_hour_behind",
            "host": T1 - 3600,
            "lower": T1 - 30,
            "upper": T1 + 40,
            "fresh_age": 600,
            "max_seen": T1 - 100,
            "expect": "clock_unsafe",
        },
        {
            "name": "sources_too_wide",
            "host": T1,
            "lower": T1 - 400,
            "upper": T1 + 400,
            "fresh_age": 600,
            "max_seen": T1 - 100,
            "expect": "clock_unsafe",
        },
        {
            "name": "no_fresh_source",
            "host": T1,
            "lower": T1 - 30,
            "upper": T1 + 40,
            "fresh_age": 3601,
            "max_seen": T1 - 100,
            "expect": "clock_unsafe",
        },
        {
            "name": "time_goes_back",
            "host": T1,
            "lower": T1 - 30,
            "upper": T1 + 40,
            "fresh_age": 600,
            "max_seen": T1 + 1000,
            "expect": "clock_unsafe",
        },
    ]


# ---- SEV-SNP and TDX fixtures (constructed; not real hardware evidence) ----


def snp_report(policy: int = 0x30000, version: int = 5, size: int = snp.REPORT_SIZE) -> bytes:
    d = bytearray(snp.REPORT_SIZE)
    d[0x00:0x04] = version.to_bytes(4, "little")
    d[0x04:0x08] = (1).to_bytes(4, "little")
    d[0x08:0x10] = policy.to_bytes(8, "little")
    d[0x10:0x20] = _seed("snp-family")[:16]
    d[0x20:0x30] = _seed("snp-image")[:16]
    d[0x30:0x34] = (0).to_bytes(4, "little")
    d[0x34:0x38] = (1).to_bytes(4, "little")
    tcb = bytes([0x04, 0x00, 0, 0, 0, 0, 0x16, 0xDB])  # Genoa layout: bl 4, tee 0, snp 22, uc 219
    d[0x38:0x40] = tcb
    d[0x40:0x48] = (0x3).to_bytes(8, "little")
    d[0x50:0x90] = b.report_data_field(binding_for("a").value())
    d[0x90:0xC0] = _seed("snp-launch-digest") + _seed("snp-launch-digest-2")[:16]
    d[0xC0:0xE0] = _seed("snp-host-data")
    d[0x140:0x160] = _seed("snp-report-id")
    d[0x180:0x188] = tcb
    if version >= 3:
        d[0x188:0x18B] = bytes([0x19, 0x11, 0x01])
    d[0x1A0:0x1E0] = _seed("chip-1") + _seed("chip-2")
    d[0x1E0:0x1E8] = tcb
    d[0x1E8:0x1EB] = bytes([0x15, 0x37, 0x01])  # build 21, minor 55, major 1
    d[0x1EC:0x1EF] = bytes([0x15, 0x37, 0x01])
    d[0x1F0:0x1F8] = tcb
    d[0x2A0:0x2E8] = _seed("sig-r") + _seed("sig-r2") + _seed("sig-r3")[:8]
    d[0x2E8:0x330] = _seed("sig-s") + _seed("sig-s2") + _seed("sig-s3")[:8]
    return bytes(d[:size]) if size <= snp.REPORT_SIZE else bytes(d) + bytes(size - len(d))


def snp_vectors() -> dict:
    good = snp_report()
    debug = snp_report(policy=0x30000 | 1 << snp.POLICY_DEBUG | 1 << snp.POLICY_MIGRATE_MA)
    rpt = snp.parse_report(good)
    reserved = bytearray(good)
    reserved[0x1FF + 0x10] = 1  # inside the zero area after the mitigation vectors
    return {
        "good": {"hex": good.hex(), "claims": snp.claims(rpt)},
        "debug_and_migration": {"hex": debug.hex(), "claims": snp.claims(snp.parse_report(debug))},
        "bad": [
            {"name": "short", "hex": good[:-1].hex()},
            {"name": "policy_bit_17_zero", "hex": snp_report(policy=0x0).hex()},
            {"name": "policy_high_bit", "hex": snp_report(policy=0x30000 | 1 << 40).hex()},
            {"name": "reserved_not_zero", "hex": bytes(reserved).hex()},
        ],
        "turin_tcb": {
            "raw_hex": bytes([0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0x05]).hex(),
            "decoded": snp.decode_tcb(
                int.from_bytes(bytes([1, 2, 3, 4, 0, 0, 0, 5]), "little"), "turin"
            ),
        },
    }


def tdx_quote(attrs: int = 1 << tdx.ATTR_SEPT_VE_DISABLE, version: int = 4) -> bytes:
    header = (
        version.to_bytes(2, "little")
        + tdx.ATT_KEY_ECDSA_P256.to_bytes(2, "little")
        + tdx.TEE_TDX.to_bytes(4, "little")
        + bytes(4)
        + tdx.INTEL_QE_VENDOR_ID
        + bytes(20)
    )
    parts = []
    for name, size in tdx.BODY_FIELDS:
        if name == "td_attributes":
            parts.append(attrs.to_bytes(8, "little"))
        elif name == "report_data":
            parts.append(b.report_data_field(binding_for("a").value()))
        elif name == "tee_tcb_svn":
            parts.append(bytes([0x03, 0x01, 0x02] + [0] * 13))
        else:
            parts.append((_seed(f"tdx-{name}") * 2)[:size])
    body = b"".join(parts)
    cert = b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
    sig = _seed("tdx-sig") * 2 + _seed("tdx-ak") * 2 + (5).to_bytes(2, "little")
    sig += len(cert).to_bytes(4, "little") + cert
    return header + body + len(sig).to_bytes(4, "little") + sig


def tdx_vectors() -> dict:
    good = tdx_quote()
    debug = tdx_quote(attrs=1 << tdx.ATTR_DEBUG | 1 << tdx.ATTR_MIGRATABLE)
    return {
        "good": {"hex": good.hex(), "claims": tdx.claims(tdx.parse_quote(good))},
        "debug_and_migratable": {"hex": debug.hex(), "claims": tdx.claims(tdx.parse_quote(debug))},
        "bad": [
            {"name": "version_5_not_parsed_here", "hex": tdx_quote(version=5).hex()},
            {"name": "short", "hex": good[:600].hex()},
            {"name": "signature_length", "hex": (good + b"\x00").hex()},
        ],
    }


# ---- measurement examples for each profile (spec section 4) ----------------

PROFILE_REFERENCES = {
    "simulated": REFERENCE,
    "raw-snp": {
        "family_id": _seed("snp-family")[:16].hex(),
        "host_data": "00" * 32,
        "image_id": _seed("snp-image")[:16].hex(),
        "measurement": (_seed("snp-launch-digest") + _seed("snp-launch-digest-2")[:16]).hex(),
        "product": "genoa",
        "vmpl": 0,
    },
    "raw-tdx": {
        "mr_config_id": "00" * 48,
        "mr_owner": "00" * 48,
        "mr_owner_config": "00" * 48,
        "mr_td": (_seed("tdx-mr_td") * 2)[:48].hex(),
        "rtmr0": (_seed("tdx-rtmr0") * 2)[:48].hex(),
        "rtmr1": (_seed("tdx-rtmr1") * 2)[:48].hex(),
        "rtmr2": (_seed("tdx-rtmr2") * 2)[:48].hex(),
        "rtmr3": "00" * 48,
        "xfam": (_seed("tdx-xfam") * 2)[:8].hex(),
    },
    "gcp-cs": {
        "args": ["/app/enclave"],
        "env": {},
        "gpu": True,
        "hwmodel": "GCP_INTEL_TDX",
        "image_digest": IMAGE,
        "restart_policy": "Never",
        "swname": "CONFIDENTIAL_SPACE",
    },
    "azure-cvm-gpu": {
        "gpu": True,
        "pcrs_sha256": {str(i): _seed(f"pcr-{i}").hex() for i in (4, 7, 8, 9, 11)},
    },
}


def seed_labels() -> dict:
    """The seed label of each key (spec gap G6 of the conformance review)."""
    keys = {
        "dev_root": "dev-root",
        "log": "log",
        "node": "node",
        "rebuilder_ci": "rebuild-ci",
        "rebuilder_ext": "rebuild-ext",
        "release": "release",
        "roster": "roster",
        "state_key": "state-key",
    }
    for name in WITNESSES:
        keys[f"witness_{name}_cosign"] = f"w-{name}"
        keys[f"witness_{name}_entry"] = f"w-{name}-entry"
    for name in INSTANCES:
        keys[f"instance_{name}_output"] = f"out-{name}"
        keys[f"instance_{name}_intake"] = f"intake-{name}"
    return {
        "keys": dict(sorted(keys.items())),
        "rule": 'seed = SHA-256(UTF-8("anagram enclave-trust vector seed: " || label))',
    }


def build(previous: dict | None = None) -> dict:
    bind = binding_for("a")
    return {
        "seed_labels": seed_labels(),
        "tags": TAGS,
        "roots": roots_json(),
        "times": {"T0": T0, "T1": T1},
        "base_entries": BASE,
        "base_entry_digests": [entry_digest(e).hex() for e in BASE],
        "base_leaves_hex": [canonical_json(e).hex() for e in BASE],
        "base_checkpoints": [BASE_CP1, BASE_CP2],
        "measurements": {
            p: {"reference": r, "measurement": b.measurement(p, r).hex()}
            for p, r in PROFILE_REFERENCES.items()
        },
        "binding": {
            "inputs": {
                "line_id": bind.line_id.hex(),
                "instance_id": bind.instance_id.hex(),
                "key_epoch": bind.key_epoch,
                "intake_key": bind.intake_key.hex(),
                "output_key": bind.output_key.hex(),
                "descriptor_hashes": DESCRIPTORS,
                "descriptor_set": bind.descriptor_set.hex(),
                "release": bind.release.hex(),
                "checkpoint": bind.checkpoint.hex(),
            },
            "value": bind.value().hex(),
            "gpu_nonce": b.gpu_nonce(bind.value()).hex(),
            "gpu_evidence_example_hex": b"example GPU evidence".hex(),
            "report_data_with_gpu": b.report_data(bind.value(), b"example GPU evidence").hex(),
        },
        "release_cases": release_cases(),
        "attestation_cases": attestation_cases(),
        "handoff_cases": handoff_cases(),
        "handoff_messages": handoff_messages(previous),
        "line_cases": line_cases(),
        "descriptors": descriptor_vectors(),
        "snapshot": snapshot_cases(),
        "writer_cases": writer_cases(),
        "tombstone": tombstone_cases(),
        "decline": decline_cases(),
        "clock": clock_cases(),
        "snp": snp_vectors(),
        "tdx": tdx_vectors(),
    }


def main(argv: list[str] | None = None) -> None:
    out = (
        output_dir(argv, prog="python -m anagram.vectors.enclave_trust", description=__doc__) / FILE
    )
    previous = json.loads(out.read_text()) if out.exists() else None
    out.write_text(json.dumps(build(previous), indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
