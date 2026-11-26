"""spec/enclave-trust.md: the vectors in spec/vectors/enclave-trust.json are
current, and each case gives its expected result when it is recomputed.

The snapshot, tombstone and clock cases run on the enclave's own code
(`anagram.network.matching.trust.snapshot`, `.clock`, and the ledger of
`anagram.network.matching.enclave`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from anagram.core.canonical import canonical_json
from anagram.core.crypto.hashing import ALL_TAGS, tagged_hash
from anagram.network.formats.pack import check_age
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.ledger import (
    TOMBSTONE_LIFE,
    tombstone_id,
    tombstone_refusal,
)
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust import handoff as ho
from anagram.network.matching.trust import snapshot as snap
from anagram.network.matching.trust.attestation import PRE_CODES, RULE_CODES, verify_attestation
from anagram.network.matching.trust.clock import SignedClock, clock_safe
from anagram.network.matching.trust.entries import EntryError, check_entry, entry_digest
from anagram.network.matching.trust.lines import line_authorised, line_forked, line_writer, shard
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.profiles import snp, tdx
from anagram.network.matching.trust.release import (
    HANDOFF_CODES,
    RELEASE_CODES,
    accept_release,
    check_successor,
)
from anagram.network.matching.trust.roots import Roots, Witness, app_now
from anagram.proofs.log.note import NoteVerifier
from anagram.vectors import enclave_trust

SPEC = Path(__file__).parent.parent / "spec"
V = json.loads((SPEC / "vectors" / "enclave-trust.json").read_text())


def test_vectors_are_current():
    assert V == json.loads(json.dumps(enclave_trust.build(V)))


def test_tags_are_new_and_in_the_spec():
    text = (SPEC / "enclave-trust.md").read_text()
    room = (SPEC / "matching.md").read_text()
    for tag in V["tags"]:
        assert tag not in ALL_TAGS
        assert f"`{tag}`" not in room
        assert f"`{tag}`" in text, tag


def roots(dev: bool = True) -> Roots:
    r = V["roots"]
    return Roots(
        log_key=NoteVerifier.parse(r["log_key"]),
        witnesses=tuple(
            Witness(NoteVerifier.parse(w["cosign"]), w["entry_key"], w["independent"])
            for w in r["witnesses"]
        ),
        release_key=r["release_key"],
        rebuilders=tuple(r["rebuilders"]),
        dev_root=r["dev_root"] if dev else None,
    )


def view(case: dict) -> LogView:
    """The entries that the app read: those under its latest checkpoint."""
    size = int(case["checkpoints"][-1].split("\n")[1])
    entries = (V["base_entries"] + case["extra_entries"])[:size]
    return LogView.from_checkpoints(entries, case["checkpoints"], roots())


def now_of(case: dict) -> int:
    """The app's now (3.5): the case's clock, or `lower` of its latest
    checkpoint if that is later."""
    return app_now(case["now"], case["checkpoints"][-1], roots())


def outcome(fn, *args) -> str:
    try:
        fn(*args)
    except Refused as exc:
        return exc.code
    return "ok"


def test_base_entries():
    for e, digest, leaf in zip(
        V["base_entries"], V["base_entry_digests"], V["base_leaves_hex"], strict=True
    ):
        assert check_entry(e) is e
        assert entry_digest(e).hex() == digest
        assert canonical_json(e).hex() == leaf
    kinds = {e["kind"] for e in V["base_entries"]}
    assert kinds >= {
        "enclave_release",
        "enclave_rebuild",
        "node_admission",
        "member_credential",
        "enclave_instance_key",
        "enclave_state_epoch",
        "enclave_line",
        "enclave_entry_cosign",
        "roster_checkpoint",
    }


@pytest.mark.parametrize(
    "change, code",
    [
        (lambda e: e.update(extra=1), "bad_entry"),
        (lambda e: e.update(schema="anagram.enclave.release.v2"), "bad_entry"),
        (lambda e: e.update(max_instances=0), "bad_entry"),
        (lambda e: e.update(descriptor_hashes=list(reversed(e["descriptor_hashes"]))), "bad_entry"),
        (lambda e: e.update(security_fix=True), "bad_entry_signature"),
    ],
)
def test_bad_entry(change, code):
    e = json.loads(json.dumps(V["base_entries"][0]))
    change(e)
    with pytest.raises(EntryError) as exc:
        check_entry(e)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(kind=["enclave_release"]),
        lambda e: e["weights"].insert(0, {"digest": e["weights"][0]["digest"]}),
        lambda e: e["weights"].append({"digest": e["weights"][0]["digest"], "name": 7}),
        lambda e: e["weights"].append({"digest": e["weights"][0]["digest"], "name": []}),
    ],
)
def test_an_entry_of_the_wrong_types_is_bad_entry(change):
    """A kind or digest name that is not text is `bad_entry`. It must not
    raise TypeError (`sorted` and dict lookups need text)."""
    e = json.loads(json.dumps(next(x for x in V["base_entries"] if "weights" in x)))
    change(e)
    with pytest.raises(EntryError) as exc:
        check_entry(e)
    assert exc.value.code == "bad_entry"


@pytest.mark.parametrize("case", V["release_cases"], ids=lambda c: c["name"])
def test_release_case(case):
    got = outcome(
        accept_release, case["release"], view(case), roots(), case["app_version"], now_of(case)
    )
    assert got == case["expect"]


def test_release_cases_cover_every_code():
    assert {c["expect"] for c in V["release_cases"]} == set(RELEASE_CODES) | {"ok"}


@pytest.mark.parametrize("case", V["attestation_cases"], ids=lambda c: c["name"])
def test_attestation_case(case):
    rel = V["base_entries"][0]
    lv = view(case)
    accept_release(rel, lv, roots(), "1.2.0", now_of(case))
    subject = bytes.fromhex(case["subject"])
    got = outcome(verify_attestation, case["doc"], rel, lv, roots(), now_of(case), subject)
    assert got == case["expect"]


def test_attestation_cases_cover_every_rule():
    codes = {c["expect"] for c in V["attestation_cases"]}
    for rule, rule_codes in RULE_CODES.items():
        assert set(rule_codes) <= codes, rule
    assert set(PRE_CODES) <= codes


def test_simulated_needs_a_dev_root():
    """A production app pins no development root, so it refuses `simulated`."""
    case = V["attestation_cases"][0]
    rel = V["base_entries"][0]
    got = outcome(verify_attestation, case["doc"], rel, view(case), roots(dev=False), case["now"])
    assert got == "untrusted_root"


@pytest.mark.parametrize("case", V["handoff_cases"], ids=lambda c: c["name"])
def test_handoff_case(case):
    assert outcome(check_successor, case["own"], case["successor"]) == case["expect"]
    assert case["expect"] in set(HANDOFF_CODES) | {"ok"}


@pytest.mark.parametrize("case", V["line_cases"], ids=lambda c: c["name"])
def test_line_case(case):
    lv = LogView.from_checkpoints(
        V["base_entries"] + case["extra_entries"], case["checkpoints"], roots()
    )
    assert outcome(line_authorised, lv, case["line"], roots(), None) == case["expect"]


@pytest.mark.parametrize("case", V["handoff_messages"]["cases"], ids=lambda c: c["name"])
def test_handoff_message(case):
    h = V["handoff_messages"]
    lv = LogView.from_checkpoints(V["base_entries"] + h["extra_entries"], h["checkpoints"], roots())
    successor = tagged_hash(
        "anagram/v1/room/attestation", canonical_json(h["successor_attestation"])
    )
    assert successor.hex() == h["successor_digest"]
    key = bytes.fromhex(h["successor_intake_private_hex"])
    try:
        got = ho.accept(case["msg"], lv, successor, key).hex()
    except Refused as exc:
        got = exc.code
    assert got == (h["state_key_hex"] if case["expect"] == "ok" else case["expect"])
    assert case["expect"] in set(HANDOFF_CODES) | {"ok", "snapshot_unknown"}


def test_descriptor_set():
    d = V["descriptors"]
    assert [dsc.descriptor_hash(x).hex() for x in d["documents"]] == d["hashes"]
    assert dsc.set_hash(d["documents"]).hex() == d["set_hash"]
    assert sorted(d["hashes"]) == V["base_entries"][0]["descriptor_hashes"]
    assert dsc.check_set(d["documents"], d["hashes"])["matching"][0] == d["documents"][0]
    assert dsc.statement_hash(d["documents"][0]) == d["statement_sha256"]
    for case in d["bad"]:
        with pytest.raises(dsc.DescriptorError):
            dsc.check_descriptor(case["doc"])
    for case in d["bad_sets"]:
        with pytest.raises(dsc.DescriptorError):
            dsc.check_set(case["documents"], case["hashes"])
    ex = d["shard_example"]
    assert shard(bytes.fromhex(ex["subject"]), ex["n"]) == ex["shard"]
    assert V["binding"]["inputs"]["descriptor_set"] == d["set_hash"]


def test_measurements_and_binding():
    for profile, m in V["measurements"].items():
        assert b.measurement(profile, m["reference"]).hex() == m["measurement"]
    i = V["binding"]["inputs"]
    assert (
        b.descriptor_set_hash([bytes.fromhex(h) for h in i["descriptor_hashes"]]).hex()
        == i["descriptor_set"]
    )
    bind = b.Binding(
        line_id=bytes.fromhex(i["line_id"]),
        instance_id=bytes.fromhex(i["instance_id"]),
        key_epoch=i["key_epoch"],
        intake_key=bytes.fromhex(i["intake_key"]),
        output_key=bytes.fromhex(i["output_key"]),
        descriptor_set=bytes.fromhex(i["descriptor_set"]),
        release=bytes.fromhex(i["release"]),
        checkpoint=bytes.fromhex(i["checkpoint"]),
    )
    assert bind.value().hex() == V["binding"]["value"]
    assert b.gpu_nonce(bind.value()).hex() == V["binding"]["gpu_nonce"]
    gpu = bytes.fromhex(V["binding"]["gpu_evidence_example_hex"])
    assert b.report_data(bind.value(), gpu).hex() == V["binding"]["report_data_with_gpu"]


# ---- enclave rules: the vectors run on the enclave's own code -------------


def snapshot_rule(counter: int, digest: str, handoff: dict | None, line: list[dict]) -> str:
    keys = [e for e in V["base_entries"] if e["kind"] == "enclave_instance_key"]
    lv = LogView(keys + line, [0] * (len(keys) + len(line)))
    got = (handoff["loader"], handoff["counter"], handoff["digest"]) if handoff else None
    try:
        snap.check_load(lv, roots(), line[0]["line_id"], counter, digest, got)
    except Refused as exc:
        return exc.code
    return "ok"


def test_sealed_snapshot():
    s = V["snapshot"]["sealed_counter_1"]
    sealed = bytes.fromhex(s["sealed_hex"])
    assert snap.digest(sealed).hex() == s["digest"]
    header, body = snap.open_snapshot(bytes.fromhex(s["state_key_hex"]), sealed)
    assert header == s["header"]
    assert json.loads(body) == {"packs": 1, "tombstones": []}
    assert s["digest"] == V["snapshot"]["line"][-1]["snapshot_digest"]
    with pytest.raises(Refused, match="snapshot_unknown"):
        snap.open_snapshot(bytes(32), sealed)


@pytest.mark.parametrize("case", V["snapshot"]["cases"], ids=lambda c: c["name"])
def test_snapshot_case(case):
    line = V["snapshot"][case["line"]]
    got = snapshot_rule(case["counter"], case["digest"], case["handoff"], line)
    assert got == case["expect"]


@pytest.mark.parametrize("case", V["writer_cases"], ids=lambda c: c["name"])
def test_writer_case(case):
    """Writer failover (section 5.7): the walk of the line's entries."""
    entries = V["base_entries"] + case["extra_entries"]
    lv = LogView(entries, [0] * len(entries))
    line = case["extra_entries"][1]["line_id"]  # the epoch that adds the holder
    assert line_forked(lv, line, roots()) is case["forked"]
    assert line_writer(lv, line, roots()) == case["writer"]


def tombstone_rule(t: dict, version: int, created: int, now: int) -> str:
    """pack.md section 8 in intake order: age first, then the tombstone."""
    try:
        check_age(created, now)
    except Refused as exc:
        return exc.code
    return tombstone_refusal({**t, "reason": "withdrawn"}, version, created, now) or "ok"


def test_tombstones():
    v = V["tombstone"]
    assert v["life_seconds"] == TOMBSTONE_LIFE == (30 + 7 + 1) * 86400
    assert tombstone_id(v["subject"]) == v["tombstone_id"]
    for c in v["cases"]:
        got = tombstone_rule(v["tombstone"], c["version"], c["created"], c["now"])
        assert got == c["expect"], c["name"]


@pytest.mark.parametrize("case", V["clock"], ids=lambda c: c["name"])
def test_clock_case(case):
    args = (case["host"], case["lower"], case["upper"], case["fresh_age"], case["max_seen"])
    assert clock_safe(*args) == (case["expect"] == "ok")


# ---- pure parsers -----------------------------------------------------------


def test_snp_parse():
    v = V["snp"]
    for name in ("good", "debug_and_migration"):
        rpt = snp.parse_report(bytes.fromhex(v[name]["hex"]))
        assert json.loads(json.dumps(snp.claims(rpt))) == v[name]["claims"]
    good = v["good"]["claims"]
    assert good["policy"]["debug"] is False and good["policy"]["migrate_ma"] is False
    assert good["product"] == "genoa"
    assert good["reported_tcb"] == {"boot_loader": 4, "microcode": 219, "snp": 22, "tee": 0}
    assert good["report_data"] == V["binding"]["value"] + "00" * 32
    bad = v["debug_and_migration"]["claims"]["policy"]
    assert bad["debug"] is True and bad["migrate_ma"] is True
    for case in v["bad"]:
        with pytest.raises(snp.SnpFormatError):
            snp.parse_report(bytes.fromhex(case["hex"]))
    raw = int.from_bytes(bytes.fromhex(v["turin_tcb"]["raw_hex"]), "little")
    assert snp.decode_tcb(raw, "turin") == v["turin_tcb"]["decoded"]
    assert v["turin_tcb"]["decoded"] == {
        "boot_loader": 2,
        "fmc": 1,
        "microcode": 5,
        "snp": 4,
        "tee": 3,
    }


def test_tdx_parse():
    v = V["tdx"]
    for name in ("good", "debug_and_migratable"):
        q = tdx.parse_quote(bytes.fromhex(v[name]["hex"]))
        assert tdx.claims(q) == v[name]["claims"]
    good = v["good"]["claims"]["td_attributes_bits"]
    assert good["debug"] is False and good["migratable"] is False and good["sept_ve_disable"]
    bad = v["debug_and_migratable"]["claims"]["td_attributes_bits"]
    assert bad["debug"] and bad["migratable"]
    assert v["good"]["claims"]["report_data"] == V["binding"]["value"] + "00" * 32
    for case in v["bad"]:
        with pytest.raises(tdx.TdxFormatError):
            tdx.parse_quote(bytes.fromhex(case["hex"]))


# ---- SignedClock (enclave-trust.md 6.4; code quality review M4) -------------------


def test_the_signed_clock_carries_the_bounds_forward_by_elapsed_time() -> None:
    clock = SignedClock()
    assert clock.now(1_000) is None  # no signed source yet
    clock.observe(1_000, 1_100, host=1_050)
    assert clock.now(1_050) == 1_000
    assert clock.now(1_650) == 1_600
    assert clock.max_seen == 1_600


def test_the_signed_clock_refuses_a_host_time_before_the_source() -> None:
    """A guest clock that goes back is `clock_unsafe`: signed time never
    goes back with it."""
    clock = SignedClock()
    clock.observe(1_000, 1_100, host=1_050)
    assert clock.now(1_049) is None
    assert clock.now(1_050 - 10_000) is None
    assert clock.max_seen == 0


def test_the_signed_clock_is_unsafe_when_the_source_is_old_or_wide() -> None:
    clock = SignedClock()
    clock.observe(1_000, 1_400, host=1_200)  # wider than 300 s
    assert clock.now(1_200) is None
    clock = SignedClock()
    clock.observe(1_000, 1_100, host=1_050)
    assert clock.now(1_050 + 3_601) is None  # no signed source newer than 1 hour


def test_an_older_checkpoint_does_not_move_the_signed_clock_back() -> None:
    clock = SignedClock()
    clock.observe(2_000, 2_100, host=2_050)
    clock.observe(1_000, 1_100, host=2_060)
    assert clock.now(2_060) == 2_010
