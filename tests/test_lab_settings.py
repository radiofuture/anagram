"""Lab settings and policy."""

from __future__ import annotations

import pytest

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
    mem.device.http.call(
        "PUT",
        f"/labs/{lab_id}/space/records/{rec['record_id']}",
        {"record": rec, "topic": "settings"},
        auth=True,
    )
    pi.labs.lab_sync(lab_id)
    assert pi.lab_space.lab_settings(lab_id)["rev"] == 0
    assert pi.lab_space.lab_policy(lab_id).matching_enabled()
    # The change feed names the topic.
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
