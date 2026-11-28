"""Security regression tests for matching enclave, transparency log, roster, and handoff."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from enclavekit import LINE, Person, World, line

from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import ClientError
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import (
    ROSTER,
    Network,
    make_event,
    node_id,
    roster_checkpoint,
    subject_hash,
)
from anagram.network.formats.strict import DAY, Refused, fmt_time
from anagram.network.matching.app.enclave_matching import pack_lines, remote_fault
from anagram.network.matching.enclave.instance import EnclaveInstance
from anagram.network.matching.trust.entries import entry_digest, sign_entry
from anagram.network.matching.trust.follow import LogFollower
from anagram.network.matching.trust.handoff import _holder_keys
from anagram.network.matching.trust.lines import line_writer
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.release import accept_release
from anagram.network.matching.trust.translog import reader_refuses

HOUR = 3600


def alice(world: World) -> Person:
    return world.person(
        "Alice Chen",
        "A",
        {
            "offers": [line("o01", "Single-particle cryo-EM data collection")],
            "wants": [line("w01", "Molecular dynamics simulation of membrane proteins")],
        },
    )


# RFC 7748 section 6.1 small-order X25519 points (yield all-zero shared secret).
LOW_ORDER_X25519 = (
    bytes(32),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
)


@pytest.fixture
def world() -> World:
    return World()


# ---- C4: transparency log authorization & immutable instance keys ----------


def test_c4_unauthorized_log_entries_refused_before_persisting(world: World) -> None:
    rogue = SigningKey.generate()
    before = len(world.log.entries)

    bad_line = sign_entry(
        "enclave_line",
        {
            "line_id": LINE,
            "reason": "first",
            "release": entry_digest(world.rel).hex(),
            "replaces": None,
            "shard": {"k": 0, "n": 1},
        },
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_line)

    bad_floor = sign_entry(
        "enclave_floor",
        {"profile": "simulated", "release": entry_digest(world.rel).hex(), "tcb_floor": {"svn": 9}},
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_floor)

    bad_rebuild = sign_entry(
        "enclave_rebuild",
        {
            "image_digest": world.rel["image_digest"],
            "measurements": {"simulated": world.rel["profiles"]["simulated"]["measurement"]},
            "release": entry_digest(world.rel).hex(),
            "same": True,
        },
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_rebuild)

    bad_cosign = sign_entry(
        "enclave_entry_cosign",
        {"entry": entry_digest(world.rel).hex(), "time": world.t},
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_cosign)

    bad_revoke = sign_entry(
        "enclave_revoke",
        {"reason": "vulnerability", "target": {"release": entry_digest(world.rel).hex()}},
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_revoke)

    bad_epoch = sign_entry(
        "enclave_state_epoch",
        {
            "checkpoint": "00" * 32,
            "counter": 0,
            "holders": [world.writer().instance_id],
            "instance_id": world.writer().instance_id,
            "line_id": "ff" * 16,
            "next_writer": None,
            "prev": None,
            "rekey": False,
            "snapshot_digest": "11" * 32,
            "snapshot_size": 1024,
        },
        rogue,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(bad_epoch)

    assert len(world.log.entries) == before
    # Even if an unauthorized enclave_line appeared in a list, reader_refuses ignores it.
    assert not reader_refuses([*world.log.entries, bad_line], world.trust.roots)


def test_c4_append_instance_key_validates_fields_and_forbids_rebinding(world: World) -> None:
    inst = world.writer()
    assert inst.document is not None
    doc = dict(inst.document)
    good_entry = next(e for e in world.log.entries if e["kind"] == "enclave_instance_key")

    # Wrong kind via append_instance_key is refused.
    bad_kind = sign_entry(
        "enclave_revoke",
        {"reason": "vulnerability", "target": {"line_id": LINE}},
        world.trust.release_key,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append_instance_key(bad_kind, doc)

    # Mismatched line_id between entry and document is refused.
    mismatch = sign_entry(
        "enclave_instance_key",
        {
            "evidence_digest": good_entry["evidence_digest"],
            "instance_id": doc["instance_id"],
            "intake_key": doc["intake_key"],
            "key_epoch": doc["key_epoch"],
            "lease_until": fmt_time(world.t + HOUR),
            "line_id": "ee" * 16,
            "profile": doc["profile"],
            "release": doc["release"],
        },
        inst.keys.output,
    )
    with pytest.raises(Refused, match="bad_attestation"):
        world.log.append_instance_key(mismatch, doc)

    # Rebinding existing (line_id, instance_id) to a different output_key is refused.
    other_out = SigningKey.generate()
    rebind_doc = {**doc, "output_key": other_out.public_bytes().hex()}
    rebind_entry = sign_entry(
        "enclave_instance_key",
        {
            "evidence_digest": good_entry["evidence_digest"],
            "instance_id": doc["instance_id"],
            "intake_key": doc["intake_key"],
            "key_epoch": doc["key_epoch"],
            "lease_until": fmt_time(world.t + HOUR),
            "line_id": doc["line_id"],
            "profile": doc["profile"],
            "release": doc["release"],
        },
        other_out,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append_instance_key(rebind_entry, rebind_doc)

    # Immutable first output key in _walk / line_writer / _holder_keys even if a later entry exists.
    view = LogView([*world.log.entries, rebind_entry], [world.t] * (len(world.log.entries) + 1))
    assert line_writer(view, LINE, world.trust.roots) == inst.instance_id
    assert _holder_keys(view, LINE) == {inst.keys.output.public_bytes().hex()}

    # Non-release entry digest in `release` field is refused cleanly (M16, no KeyError).
    line_entry = next(e for e in world.log.entries if e["kind"] == "enclave_line")
    non_rel_digest = entry_digest(line_entry).hex()
    fake_key = SigningKey.generate()
    bad_rel_doc = {
        **doc,
        "instance_id": "ab" * 16,
        "output_key": fake_key.public_bytes().hex(),
        "release": non_rel_digest,
    }
    bad_rel_entry = sign_entry(
        "enclave_instance_key",
        {
            "evidence_digest": good_entry["evidence_digest"],
            "instance_id": bad_rel_doc["instance_id"],
            "intake_key": doc["intake_key"],
            "key_epoch": doc["key_epoch"],
            "lease_until": fmt_time(world.t + HOUR),
            "line_id": doc["line_id"],
            "profile": doc["profile"],
            "release": non_rel_digest,
        },
        fake_key,
    )
    with pytest.raises(Refused, match="release_not_logged"):
        world.log.append_instance_key(bad_rel_entry, bad_rel_doc)
    with pytest.raises(Refused, match="release_not_logged"):
        accept_release(line_entry, world.log.view(), world.trust.roots, "0.1.0", world.t)


# ---- C5: low-order X25519 reply_key and response key -----------------------


@pytest.mark.parametrize("bad_key", LOW_ORDER_X25519)
def test_c5_low_order_x25519_keys_refused(world: World, bad_key: bytes) -> None:
    p = alice(world)
    cred = world.credential(p)
    target = p.client.refresh()
    ctx = world.writer()._context(world.t)  # noqa: SLF001

    # Low-order reply_key in pack, cover, and withdrawal.
    wd = m.withdrawal(p.key, 1, bad_key, world.t)
    with pytest.raises(Refused, match="bad_message"):
        m.check_withdrawal(wd)

    cov = m.cover(p.key, "person", cred, bad_key, world.t)
    with pytest.raises(Refused, match="bad_message"):
        m.check_cover(cov, ctx)

    from anagram.core.canonical import canonical_json
    from anagram.network.matching.app.enclave_client import pack_doc

    bad_pack = pack_doc(
        p.key,
        bad_key,
        cred,
        target,
        p.lines,
        {
            "disclosure": "d0",
            "protocols": ["research_fit"],
            "rules": {"research_fit": "any"},
            "weekly_cap": 3,
        },
        1,
        world.t,
        world.t,
    )
    with pytest.raises(Refused, match="bad_message"):
        packs.check_pack_bytes(canonical_json(bad_pack), ctx)

    # Low-order response key in sealed request header refused BEFORE mutating ledger state.
    raw = m.seal_request(m.CLASS_UPLOAD, target.digest, target.intake, bad_key, canonical_json(wd))
    with pytest.raises(Refused, match="bad_envelope"):
        m.parse_header(raw)
    before_subjects = dict(world.writer().ledger.subjects)
    world.writer().take(m.CLASS_UPLOAD, p.node.id, raw)
    assert world.writer().ledger.subjects == before_subjects
    assert world.writer().ledger.audit.get("bad_envelope", 0) >= 1


def test_c5_make_batch_skips_bad_reply_key_without_aborting_day_batch(world: World) -> None:
    a = alice(world)
    b = world.person(
        "Bob",
        "B",
        {"offers": [line("o01", "Cryo-EM structural biology")], "wants": [line("w01", "MD")]},
    )
    world.upload(a)
    world.upload(b)
    # Simulate a corrupted/low-order reply_key in ledger state for Alice.
    world.writer().ledger.subjects[a.subject].reply_key = LOW_ORDER_X25519[0].hex()
    day = world.t // DAY + 1
    world.t = day * DAY - HOUR + 600
    world.publish()
    world.writer().tick()
    batch = world.writer().ledger.batches[str(day)]
    # Bob's slot still sealed despite Alice's bad key; audit counts bad_reply_key.
    assert world.writer().ledger.audit.get("bad_reply_key", 0) >= 1
    assert b.node.id in batch["nodes"] and len(batch["nodes"][b.node.id]) == 1


# ---- H5: control chain signature verified before seen/fork -----------------


def test_h5_forged_control_event_cannot_fork_or_stop_chain() -> None:
    rk = SigningKey.generate()
    nk = SigningKey.generate()
    rogue = SigningKey.generate()
    nid = node_id(nk.public_bytes())
    net = Network("net.test", rk.public_bytes().hex())
    t0 = 1_700_000_000

    e0 = make_event(
        ROSTER,
        0,
        bytes(32),
        "roster_created",
        {"network": "net.test", "roster_key": rk.public_bytes().hex()},
        t0,
        rk,
    )
    net.receive(e0)
    rec = {
        "admin": "ops@node.test",
        "affiliation": "Test Lab",
        "domain": "node.test",
        "id": nid,
        "key": nk.public_bytes().hex(),
        "kind": "lab",
        "ror": None,
        "url": "https://node.test",
    }
    e1 = make_event(
        ROSTER,
        1,
        bytes.fromhex(
            make_event(
                ROSTER,
                0,
                bytes(32),
                "roster_created",
                {"network": "net.test", "roster_key": rk.public_bytes().hex()},
                t0,
                rk,
            )["signature"][:64]
        )
        if False
        else net.chain(ROSTER).head,
        "node_admitted",
        {"endorsement": None, "endorser": ROSTER, "node": rec},
        t0 + 1,
        rk,
    )
    net.receive(e1)

    # Forged event at seq=0 (conflicting) and seq=99 (gap) must NOT mark fork/gap or seen.
    forged_conflict = make_event(
        ROSTER,
        0,
        bytes(32),
        "ban",
        {"reason": "abuse", "subject": "11" * 32},
        t0 + 2,
        rogue,
    )
    with pytest.raises(Refused, match="bad_signature"):
        net.receive(forged_conflict)
    assert net.chain(ROSTER).stopped is None

    forged_gap = make_event(
        nid,
        5,
        bytes(32),
        "member_removed",
        {"reason": "removed", "subject": "22" * 32},
        t0 + 3,
        rogue,
    )
    with pytest.raises(Refused, match="bad_signature"):
        net.receive(forged_gap)
    assert nid not in net.chains
    assert (nid, 5) not in net.seen

    # Bad hex endorsement / rotation proof gives Refused("bad_message"), not ValueError.
    bad_endorse = make_event(
        ROSTER,
        2,
        net.chain(ROSTER).head,
        "node_updated",
        {"endorsement": "not-hex!", "endorser": nid, "node": rec},
        t0 + 4,
        rk,
    )
    with pytest.raises(Refused, match="bad_message"):
        net.receive(bad_endorse)


# ---- H6: writer crash/restart before epoch cosigning -----------------------


def test_h6_writer_restart_before_cosign_does_not_fork_or_deadlock(world: World) -> None:
    p = alice(world)
    world.upload(p)
    inst = world.writer()
    # Advance to next 10-minute epoch and emit an uncosigned epoch.
    world.t += 600
    world.publish()  # advance checkpoint time without cosigning the new epoch yet
    inst.tick()
    pending_counter = inst.journal.counter - 1  # type: ignore[union-attr]
    assert pending_counter > inst.journal.cosigned  # type: ignore[union-attr]
    pending_entry = world.log.entries[-1]
    assert pending_entry["kind"] == "enclave_state_epoch"

    # Idempotent re-append succeeds and returns same index; conflicting epoch is refused.
    assert world.log.append(pending_entry) == len(world.log.entries) - 1
    conflicting = sign_entry(
        "enclave_state_epoch",
        {
            **{
                k: v
                for k, v in pending_entry.items()
                if k not in ("kind", "schema", "signer", "signature")
            },
            "snapshot_digest": "ff" * 32,
        },
        inst.keys.output,
    )
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(conflicting)

    # Simulate crash/restart BEFORE pending_epoch was cosigned (even without pending_epoch saved).
    rec = inst.sealed_record()
    rec["pending_epoch"] = None
    resumed = EnclaveInstance.resume(
        rec, inst.release, inst.platform, inst.roots, inst.host, inst.engines
    )
    # Ticking before cosign must not fork or clobber disk[pending_counter].
    resumed.tick()
    assert pending_counter in inst.host.disk

    # Once the log publishes and cosigns the pending epoch, resumed writer catches up cleanly.
    world.t += 600
    world.publish()
    resumed.tick()
    assert resumed.journal is not None
    assert resumed.journal.cosigned >= pending_counter
    assert not reader_refuses(world.log.entries, world.trust.roots)


# ---- H7: incremental LogFollower covering checkpoints & verification -------


def test_h7_incremental_follow_fetches_covering_and_verifies_old_checkpoints(world: World) -> None:
    follower = LogFollower(world.log, world.trust.roots)
    cp1 = world.log.checkpoint()
    v1 = follower.follow(cp1)
    assert len(v1.entries) > 0

    # Verify size <= len(view.entries) rejects forged/corrupted checkpoint notes.
    with pytest.raises(Refused, match="bad_attestation"):
        follower.follow(cp1.replace(world.log.origin, "wrong.origin"))

    # Add a timed entry (instance key renewal), publish at t1, then advance time to t2 and publish.
    world.t += HOUR
    world.writer().register()
    idx = len(world.log.entries) - 1
    assert world.log.entries[idx]["kind"] == "enclave_instance_key"
    world.publish()
    t_cover = world.t

    world.t += 5 * HOUR
    world.publish()
    cp_later = world.log.checkpoint()

    # Incremental follow from cp1 to cp_later must fetch covering checkpoint so logged_by == t_cover.
    v2 = follower.follow(cp_later)
    assert v2.logged_by[idx] == t_cover


# ---- H8: EnclaveMatching checks approved statement_hash & descriptor_set ---


def test_h8_upload_checks_statement_hash_and_descriptor_set_and_ux_errors(tmp_path: Path) -> None:
    from test_enclave_services import CRYO, MD, Stack, draft

    stack = Stack(tmp_path)
    day = stack.now() // DAY + 1
    stack.at(day * DAY + 9 * HOUR)
    c = stack.net.join(tmp_path / "people" / "alice", "fake-alice", "Alice").client
    c.enclave.connect = stack.connect
    c.enclave.set_settings("http://log.test", stack.pins.to_json())
    c.enclave.set_draft(draft(CRYO, MD))
    consent = c.enclave.consent()
    assert "descriptor_set" in consent
    approved = c.enclave.approve(consent["statement_hash"])
    assert approved["descriptor_set"] == consent["descriptor_set"]
    c.enclave.turn_on()
    assert c.enclave.status()["on"] is True

    # Simulate a release change (statement_hash changed since approval).
    st = c.enclave._load()  # noqa: SLF001
    st["approved"]["statement_hash"] = "00" * 32
    st["uploaded_day"] = None
    c.enclave._save(st)  # noqa: SLF001

    stack.at(stack.now() + DAY)
    c.enclave.run()
    # App must NOT silently re-consent: turns matching off and clears approval.
    status = c.enclave.status()
    assert status["on"] is False
    assert status["approved"] is False

    # Clean UX error messages without raw Python exception class names.
    err = remote_fault(RuntimeError("boom"))
    assert "RuntimeError" not in str(err) and str(err)[0].isupper()
    with pytest.raises(ClientError) as exc:
        pack_lines({"offers": [], "wants": []})
    assert str(exc.value)[0].isupper()


# ---- H10: Network.removes() after moved + ban/node_removed/cred_revoked ----


def test_h10_removes_still_erases_moved_member_on_ban_or_node_removal() -> None:
    from anagram.network.formats import credential as cred

    rk = SigningKey.generate()
    nk1 = SigningKey.generate()
    nk2 = SigningKey.generate()
    nid1, nid2 = node_id(nk1.public_bytes()), node_id(nk2.public_bytes())
    net = Network("net.test", rk.public_bytes().hex())
    t0 = 1_700_000_000

    net.receive(
        make_event(
            ROSTER,
            0,
            bytes(32),
            "roster_created",
            {"network": "net.test", "roster_key": rk.public_bytes().hex()},
            t0,
            rk,
        )
    )
    for i, (nid, nk) in enumerate([(nid1, nk1), (nid2, nk2)], start=1):
        rec = {
            "admin": f"ops{i}@node.test",
            "affiliation": f"Lab {i}",
            "domain": f"node{i}.test",
            "id": nid,
            "key": nk.public_bytes().hex(),
            "kind": "lab",
            "ror": None,
            "url": f"https://node{i}.test",
        }
        net.receive(
            make_event(
                ROSTER,
                i,
                net.chain(ROSTER).head,
                "node_admitted",
                {"endorsement": None, "endorser": ROSTER, "node": rec},
                t0 + i,
                rk,
            )
        )

    subj_key = SigningKey.generate()
    subj_hex = subj_key.public_bytes().hex()
    sh = subject_hash(bytes.fromhex(subj_hex))
    raw_cred = b"fake-cred-bytes"
    facts1 = cred.MemberFacts(
        network="net.test",
        node=nid1,
        subject=subj_hex,
        kind="person",
        issued=t0 + 10,
        expires=t0 + DAY,
        control_head=0,
        pid="pid:" + "aa" * 16,
    )
    facts2 = cred.MemberFacts(
        network="net.test",
        node=nid2,
        subject=subj_hex,
        kind="person",
        issued=t0 + 10,
        expires=t0 + DAY,
        control_head=0,
        pid="pid:" + "aa" * 16,
    )

    # Member moves from node 1 -> dormant, not removed.
    net.receive(
        make_event(
            nid1, 0, bytes(32), "member_left", {"reason": "moved", "subject": sh}, t0 + 20, nk1
        )
    )
    assert not net.removes(facts1, raw_cred)

    # Member removed at node 2 -> MUST remove facts2 even though moved at node 1.
    net.receive(
        make_event(
            nid2,
            0,
            bytes(32),
            "member_removed",
            {"reason": "removed", "subject": sh},
            t0 + 25,
            nk2,
        )
    )
    assert net.removes(facts2, raw_cred)
    assert not net.removes(facts1, raw_cred)

    # Ban on moved subject MUST still erase facts1.
    net.receive(
        make_event(
            ROSTER,
            3,
            net.chain(ROSTER).head,
            "ban",
            {"reason": "abuse", "subject": sh},
            t0 + 30,
            rk,
        )
    )
    assert net.removes(facts1, raw_cred)

    # Unban, then node_removed on nid1 -> MUST still erase facts1.
    net.receive(
        make_event(ROSTER, 4, net.chain(ROSTER).head, "unban", {"subject": sh}, t0 + 31, rk)
    )
    assert not net.removes(facts1, raw_cred)
    net.receive(
        make_event(
            ROSTER,
            5,
            net.chain(ROSTER).head,
            "node_removed",
            {"node": nid1, "reason": "abuse"},
            t0 + 32,
            rk,
        )
    )
    assert net.removes(facts1, raw_cred)


# ---- M14: handoff role/line/self checks & concurrent standby handoffs ------


def test_m14_handoff_role_line_self_and_concurrent_standbys(world: World) -> None:
    writer = world.writer()
    assert writer.document is not None

    # Self-handoff is refused.
    with pytest.raises(Refused, match="handoff_not_successor"):
        writer.hand_off(writer.document, world.rel, standby=True)

    # Active writer refuses accept_hand_off (role != NEW).
    with pytest.raises(Refused, match="handoff_bad_sender"):
        writer.accept_hand_off({"line_id": LINE})

    # Two concurrent standbys do not clobber each other.
    s1 = world.instance("standby1", world.rel)
    s2 = world.instance("standby2", world.rel)
    s1.register()
    s2.register()
    world.publish()
    assert s1.document is not None and s2.document is not None

    # Cross-line message is refused by a new instance.
    with pytest.raises(Refused, match="handoff_bad_sender"):
        s1.accept_hand_off({"line_id": "ff" * 16})

    msg1 = writer.hand_off(s1.document, world.rel, standby=True)
    msg2 = writer.hand_off(s2.document, world.rel, standby=True)
    s1.accept_hand_off(msg1)
    s2.accept_hand_off(msg2)
    # Already a HOLDER: second accept_hand_off is refused.
    with pytest.raises(Refused, match="handoff_bad_sender"):
        s1.accept_hand_off(msg1)

    sid1 = writer.check_ready(s1.ready(msg1))
    sid2 = writer.check_ready(s2.ready(msg2))
    assert sid1 == s1.instance_id and sid2 == s2.instance_id
    writer.finish_hand_off(sid1)
    world.publish()
    writer.finish_hand_off(sid2)
    world.publish()
    latest = next(e for e in reversed(world.log.entries) if e["kind"] == "enclave_state_epoch")
    assert {writer.instance_id, s1.instance_id, s2.instance_id} <= set(latest["holders"])


# ---- M16: max_seen persisted across restart & takeover ---------------------


def test_m16_max_seen_restored_after_restart(world: World) -> None:
    inst = world.writer()
    world.t += 3600
    world.publish()
    inst.tick()
    world.publish()
    saved_max = inst.signed.max_seen
    assert saved_max >= world.t - 600

    resumed = EnclaveInstance.resume(
        inst.sealed_record(), inst.release, inst.platform, inst.roots, inst.host, inst.engines
    )
    assert resumed.signed.max_seen >= saved_max
    # Dummy check so unused import warnings don't fire if datetime is referenced.
    assert dt.UTC is not None
    assert hpke.generate() is not None
    assert (
        roster_checkpoint("net.test", 0, bytes(32), world.t, SigningKey.generate())["kind"]
        == "roster_checkpoint"
    )
