"""Lab settings and policy."""

from __future__ import annotations

import pytest

from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.formats.personal_store import seal_record
from anagram.network.formats import lab, labkey, labsettings
from anagram.network.groups.app.labrecords import LabPolicy
from anagram.network.groups.app.labroster import LabError


@pytest.fixture
def lab3(net, tmp_path):
    pi, ad, mem = (
        net.join(tmp_path / n, f"fake-{n}").client for n in ("st-pi", "st-admin", "st-member")
    )
    lab_id = pi.labs.lab_create("Settings Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject, role="admin")
    pi.labs.lab_add(lab_id, mem.device.subject)
    for c in (ad, mem):
        c.labs.lab_sync(lab_id)
    return lab_id, pi, ad, mem


def test_defaults(net, lab3):
    lab_id, pi, _, mem = lab3
    got = mem.lab_space.lab_settings(lab_id)
    assert got["rev"] == 0 and got["sections"] == labsettings.section_defaults()
    pol = mem.lab_space.lab_policy(lab_id)
    assert pol.allows_source("gdrive") and pol.lab_default() == "private"
    assert pol.matching_enabled() and not pol.allows_assistant()
    assert not pol.allows_recipient("model:claude")


def test_admin_writes_and_members_read(net, lab3):
    lab_id, pi, ad, mem = lab3
    out = ad.lab_space.lab_set_settings(
        lab_id,
        {
            "matching": {"enabled": False},
            "sources": {"allowed_kinds": ["folder"], "lab_default": "lab"},
        },
    )
    assert out["rev"] == 1 and out["sections"]["matching"] == {"enabled": False}
    out = pi.lab_space.lab_set_settings(
        lab_id, {"disclosure": {"allow_external": ["model:claude"]}}
    )
    assert out["rev"] == 2 and out["sections"]["sources"]["lab_default"] == "lab"  # kept
    assert mem.labs.lab_sync(lab_id)["labs"][lab_id]["settings"] == 2
    pol = mem.lab_space.lab_policy(lab_id)
    assert not pol.matching_enabled() and pol.lab_default() == "lab"
    assert pol.allows_source("folder") and not pol.allows_source("gdrive")
    assert pol.allows_recipient("model:claude") and not pol.allows_recipient("model:other")
    # The node holds the record as ciphertext only.
    raw = (net.home.dir / "labs.sqlite").read_bytes()
    assert b"model:claude" not in raw and b"allowed_kinds" not in raw
    for bad in ({"nothing": {}}, {"matching": {"enabled": "yes"}}, {}):
        with pytest.raises(LabError):
            pi.lab_space.lab_set_settings(lab_id, bad)


def test_member_write_refused_by_readers(net, lab3):
    lab_id, pi, ad, mem = lab3
    with pytest.raises(LabError, match="role"):
        mem.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": False}})
    # The member writes the record directly (the node cannot read it).
    state = mem.lab_roster.lab_state(lab_id)
    _, key = mem.lab_keys.lab_key(lab_id)
    doc = labsettings.make_settings(
        lab_id=lab_id,
        rev=5,
        sections={"matching": {"enabled": False}},
        updated_by=mem.device.subject,
        key=mem.device.device_key(),
        roster=lab.roster_ref(state),
        updated_at=mem.device.now(),
    )
    rec = seal_record(
        labkey.LabStoreKeys(key, key), labsettings.KIND_SETTINGS, labsettings.SETTINGS_REF, doc, 5
    )
    # The node refuses a member writing under topic="settings" (403).
    with pytest.raises(NodeHTTPError) as exc:
        mem.device.http.call(
            "PUT",
            f"/labs/{lab_id}/space/records/{rec['record_id']}",
            {"record": rec, "topic": "settings"},
            auth=True,
        )
    assert exc.value.status == 403
    # Even if a member hides a settings record under topic="space", readers refuse it.
    mem.device.http.call(
        "PUT",
        f"/labs/{lab_id}/space/records/{rec['record_id']}",
        {"record": rec, "topic": "space"},
        auth=True,
    )
    pi.labs.lab_sync(lab_id)
    assert pi.lab_space.lab_settings(lab_id)["rev"] == 0
    assert pi.lab_space.lab_policy(lab_id).matching_enabled()
    # The change feed names the topic when an admin writes settings.
    ad.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": False}})
    feed = net.labs.changes(pi.device.subject, 0)["changes"]
    assert any(c["topic"] == "settings" for c in feed)


def test_higher_rev_wins(net, lab3):
    lab_id, pi, ad, mem = lab3
    pi.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": False}})
    ad.labs.lab_sync(lab_id)
    ad.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": True}})
    mem.labs.lab_sync(lab_id)
    assert mem.lab_space.lab_settings(lab_id)["rev"] == 2
    assert mem.lab_space.lab_policy(lab_id).matching_enabled()
    # An old record again changes nothing.
    mem.lab_space.take_settings(lab_id, mem.lab_roster.lab_state(lab_id), {"rev": 1})
    assert mem.lab_space.lab_settings(lab_id)["rev"] == 2


def test_policy_recipients_and_access(net, lab3, tmp_path):
    pol = LabPolicy(
        "lab-" + "0" * 16,
        **{
            **labsettings.section_defaults(),
            "disclosure": {"allow_external": ["model:x"], "allow_assistant": True},
        },
    )
    assert pol.allows_recipient("model:local-thing", external=False)
    assert pol.allows_recipient("model:x") and not pol.allows_recipient("model:y")
    assert pol.allows_recipient("mcp") and pol.allows_assistant()
    lab_id, pi, _, mem = lab3
    outsider = net.join(tmp_path / "o", "fake-st-out").client
    with pytest.raises(LabError):
        outsider.lab_space.lab_policy(lab_id)
    mem.labs.lab_leave(lab_id)
    with pytest.raises(LabError):
        mem.lab_space.lab_policy(lab_id)


def test_h3_demoted_admin_cannot_overwrite_settings_or_lock_out(net, lab3):
    lab_id, pi, ad, mem = lab3
    # Admin writes settings at rev 1 (when admin at seq 2).
    old_state = ad.lab_roster.lab_state(lab_id)
    ad.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": False}})
    pi.labs.lab_sync(lab_id)
    # PI demotes admin (seq 3) and updates settings (author transfers to PI, roster.seq=3).
    pi.labs.lab_set_role(lab_id, ad.device.subject, "member")
    pi.lab_space.lab_set_settings(lab_id, {"matching": {"enabled": True}})
    for c in (ad, mem):
        c.labs.lab_sync(lab_id)

    # Demoted admin cannot write settings (node 403 on topic="settings" AND topic="space").
    _, key = ad.lab_keys.lab_key(lab_id)
    sk = labkey.LabStoreKeys(key, key)
    stale_doc = labsettings.make_settings(
        lab_id=lab_id,
        rev=3,
        sections={"matching": {"enabled": False}},
        updated_by=ad.device.subject,
        key=ad.device.device_key(),
        roster=lab.roster_ref(old_state),
        updated_at=ad.device.now(),
    )
    rec = seal_record(sk, labsettings.KIND_SETTINGS, labsettings.SETTINGS_REF, stale_doc, 3)
    for topic in ("settings", "space"):
        with pytest.raises(NodeHTTPError) as exc:
            ad.device.http.call(
                "PUT",
                f"/labs/{lab_id}/space/records/{rec['record_id']}",
                {"record": rec, "topic": topic},
                auth=True,
            )
        assert exc.value.status == 403

    # Even if served directly to a client, take_settings rejects stale roster.seq.
    mem.lab_space.take_settings(lab_id, mem.lab_roster.lab_state(lab_id), stale_doc)
    assert mem.lab_space.lab_settings(lab_id)["rev"] == 2
    assert mem.lab_space.lab_policy(lab_id).matching_enabled() is True

    # was_keeper checks role specifically at from_seq (not any later seq).
    assert mem.lab_roster.was_keeper(lab_id, ad.device.subject, old_state.seq) is True
    assert (
        mem.lab_roster.was_keeper(lab_id, ad.device.subject, mem.lab_roster.lab_state(lab_id).seq)
        is False
    )

    # Huge version jump is refused by node (no permanent lockout).
    huge_rec = seal_record(
        sk, labsettings.KIND_SETTINGS, labsettings.SETTINGS_REF, stale_doc, 2**31
    )
    with pytest.raises(NodeHTTPError) as exc2:
        pi.device.http.call(
            "PUT",
            f"/labs/{lab_id}/space/records/{huge_rec['record_id']}",
            {"record": huge_rec, "topic": "settings"},
            auth=True,
        )
    assert exc2.value.status == 400


def test_h4_closed_lab_refuses_writes(net, lab3):
    lab_id, pi, _, mem = lab3
    pi.lab_roster.submit(lab_id, "close")
    state = mem.lab_roster.lab_state(lab_id)
    assert state.closed
    _, key = mem.lab_keys.lab_key(lab_id)
    sk = labkey.LabStoreKeys(key, key)
    rec = seal_record(sk, "lab_item_text", "abc:0", {"text": "after close"}, 1)
    with pytest.raises(NodeHTTPError) as exc:
        mem.device.http.call(
            "PUT",
            f"/labs/{lab_id}/space/records/{rec['record_id']}",
            {"record": rec, "topic": "space"},
            auth=True,
        )
    assert exc.value.status == 403


def test_m16_leave_revokes_member_invites(net, tmp_path):
    pi, joiner = (net.join(tmp_path / n, f"fake-lv-{n}").client for n in ("pi", "joiner"))
    lab_id = pi.labs.lab_create("Leave Invite Lab")["lab_id"]
    inv = pi.admission.lab_invite(lab_id, max_uses=5)
    joiner.admission.lab_join(inv["url"])
    joiner.labs.lab_leave(lab_id)
    state = pi.lab_roster.lab_state(lab_id)
    assert state.invites[inv["invite_id"]]["revoked"] is True
    # Leave still does not bar the person from being re-added.
    assert joiner.device.subject not in state.removed
