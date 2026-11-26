"""Lab key epochs (plan R2, step S4): packages, invite package, rotation on
remove, leave, and device change, second device, readable spaces."""

from __future__ import annotations

import copy

import pytest

from anagram.admission import formats as admfmt
from anagram.core.errors import LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.local.index import spaces
from anagram.network.formats import labkey
from anagram.network.groups.app.labroster import LabError


@pytest.fixture
def trio(net, tmp_path):
    return [
        net.join(tmp_path / n, f"fake-{n}").client for n in ("key-pi", "key-admin", "key-member")
    ]


def node_bytes(net) -> bytes:
    """Each file of the node data directory, joined."""
    return b"".join(p.read_bytes() for p in net.home.dir.rglob("*") if p.is_file())


def test_create_gives_epoch_one_and_add_gives_the_key(net, trio):
    pi, ad, _ = trio
    lab_id = pi.labs.lab_create("Key Lab")["lab_id"]
    n, key = pi.lab_keys.lab_key(lab_id)
    assert n == 1 and len(key) == 32
    pi.labs.lab_add(lab_id, ad.device.subject)
    assert ad.lab_keys.lab_key(lab_id) == (1, key)
    assert pi.lab_keys.readable_labs() == [lab_id]
    assert spaces.readable_spaces(pi.lab_context) == {"private", f"lab:{lab_id}"}


def test_joiner_opens_the_key_with_the_link_only(net, trio, tmp_path):
    pi, _, _ = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    url = pi.admission.lab_invite(lab_id)["url"]
    new = net.join(tmp_path / "joiner", "fake-key-joiner", invite=url).client
    assert new.lab_keys.lab_key(lab_id) == pi.lab_keys.lab_key(lab_id)
    assert spaces.lab_space(lab_id) in spaces.readable_spaces(new.lab_context)


def test_node_holds_no_key_bytes(net, trio, tmp_path):
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject, role="admin")
    pi.labs.lab_add(lab_id, mem.device.subject)
    url = ad.admission.lab_invite(lab_id, max_uses=2)["url"]
    pi.labs.lab_remove(lab_id, mem.device.subject)  # epoch 2, also for the open invite
    net.join(tmp_path / "late", "fake-key-late", invite=url)
    raw = node_bytes(net)
    for n in (1, 2):
        _, key = pi.lab_keys.lab_key(lab_id, n)
        assert key not in raw and key.hex().encode() not in raw


def test_removed_member_cannot_open_the_next_epoch(net, trio):
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject, role="admin")
    pi.labs.lab_add(lab_id, mem.device.subject)
    assert mem.lab_keys.lab_key(lab_id)[0] == 1
    ad.labs.lab_remove(lab_id, mem.device.subject)  # the admin who removes also rotates
    assert pi.labs.lab_sync(lab_id)["labs"][lab_id]["epoch"] == 2
    assert pi.lab_keys.lab_key(lab_id)[0] == 2 == ad.lab_keys.lab_key(lab_id)[0]
    with pytest.raises(LabError):
        mem.lab_keys.lab_key(lab_id, 2)
    # The node has no package of epoch 2 for the removed member.
    rows = net.labs._db.execute(
        "SELECT recipient FROM lab_keys WHERE lab_id = ? AND epoch = 2", (lab_id,)
    ).fetchall()
    assert mem.device.subject not in {r[0] for r in rows}
    # The old key stays on the device, but the lab is not readable now.
    assert 1 in mem.lab_keys.epoch_keys(lab_id)
    assert (
        mem.lab_keys.readable_labs() == []
        and spaces.readable_spaces(mem.lab_context) == spaces.PRIVATE_SCOPE
    )


def test_removed_joiner_cannot_come_back_with_the_same_link(net, trio, tmp_path):
    """P0-3: a member who joined with a link for many people is removed. The
    link is revoked in the remove entry, the new epoch has no package for it,
    the node gives the removed person no package, and the join is refused."""
    pi, _, _ = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    url = pi.admission.lab_invite(lab_id, max_uses=5)["url"]
    iid = admfmt.lab_invite_id(admfmt.parse_lab_invite_link(url)["auth"])
    mem = net.join(tmp_path / "joiner", "fake-key-joiner", invite=url).client
    assert mem.lab_keys.lab_key(lab_id)[0] == 1
    pi.labs.lab_remove(lab_id, mem.device.subject)
    assert pi.lab_keys.lab_key(lab_id)[0] == 2
    rows = net.labs._db.execute(
        "SELECT recipient FROM lab_keys WHERE lab_id = ? AND epoch = 2", (lab_id,)
    ).fetchall()
    assert {r[0] for r in rows} == {pi.device.subject}
    info = mem.device.http.call("GET", f"/labs/invites/{iid}", auth=True)
    assert info["package"] is None and info["open"] is False
    with pytest.raises(LabError):
        mem.admission.lab_join(url)
    assert mem.device.subject not in pi.lab_roster.lab_state(lab_id).members
    with pytest.raises(LabError):
        mem.lab_keys.lab_key(lab_id, 2)


def test_node_refuses_the_join_of_a_removed_person(net, trio):
    """Defense in depth: the node refuses too, before a client sees it."""
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, mem.device.subject)
    pi.labs.lab_remove(lab_id, mem.device.subject)
    url = pi.admission.lab_invite(lab_id, max_uses=5)["url"]
    link = admfmt.parse_lab_invite_link(url)
    req = admfmt.make_join_request(
        auth=link["auth"],
        seed=bytes.fromhex(link["seed"]),
        subject=mem.device.subject,
        device_key=mem.device.device_key(),
        at=mem.device.now(),
    )
    with pytest.raises(NodeHTTPError) as exc:
        mem.device.http.call("POST", f"/labs/{lab_id}/join", {"request": req}, auth=True)
    assert exc.value.status == 410
    pi.labs.lab_add(lab_id, mem.device.subject)  # an explicit add takes the person back
    assert mem.lab_keys.lab_key(lab_id)[0] == 2


def test_new_member_opens_all_epochs(net, trio):
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.lab_keys.lab_rotate(lab_id)
    pi.lab_keys.lab_rotate(lab_id)
    pi.labs.lab_add(lab_id, mem.device.subject)
    for n in (1, 2, 3):
        assert mem.lab_keys.lab_key(lab_id, n) == pi.lab_keys.lab_key(lab_id, n)
    assert mem.lab_keys.lab_key(lab_id)[0] == 3


def test_package_from_a_member_is_refused(net, trio):
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject)  # role member
    pi.labs.lab_add(lab_id, mem.device.subject)
    state = mem.lab_roster.lab_state(lab_id)
    # The member makes a package with a key of its own and the node gives it.
    forged = labkey.make_key_package(
        lab_id=lab_id,
        epoch=2,
        keys={1: b"\1" * 32, 2: b"\2" * 32},
        recipient=mem.device.subject,
        devices=[mem.device.my_device()],
        roster_seq=state.seq,
        roster_head=state.head,
        sender=ad.device.subject,
        key=ad.device.device_key(),
        created_at=ad.device.now(),
    )
    real = mem.device.http.transport

    def swap(method, path, body, headers=None):
        out = real(method, path, body, headers)
        if method == "GET" and path.endswith("/keys"):
            out = {**copy.deepcopy(out), "epoch": 2, "packages": [*out["packages"], forged]}
        return out

    mem.device.http.transport = swap
    with pytest.raises(LogMisbehaved, match="cannot give keys"):
        mem.labs.lab_sync(lab_id)
    # The node itself refuses keys from a member.
    with pytest.raises(NodeHTTPError) as err:
        real("PUT", f"/labs/{lab_id}/keys/2", {"packages": [forged]}, _auth(ad))
    assert err.value.status == 403


def _auth(client) -> dict:
    return {"Authorization": f"Bearer {client.device.http.token}"}


def test_two_rotations_race_one_wins(net, trio):
    pi, ad, _ = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject, role="admin")
    ad.lab_keys.lab_key(lab_id)
    s_pi, s_ad = pi.lab_roster.lab_state(lab_id), ad.lab_roster.lab_state(lab_id)
    keys_pi = {**pi.lab_keys.epoch_keys(lab_id), 2: b"\3" * 32}
    keys_ad = {**ad.lab_keys.epoch_keys(lab_id), 2: b"\4" * 32}
    first = pi.lab_keys.epoch_packages(s_pi, 2, keys_pi)
    second = ad.lab_keys.epoch_packages(s_ad, 2, keys_ad)
    pi.device.http.call("PUT", f"/labs/{lab_id}/keys/2", {"packages": first}, auth=True)
    with pytest.raises(NodeHTTPError) as err:
        ad.device.http.call("PUT", f"/labs/{lab_id}/keys/2", {"packages": second}, auth=True)
    assert err.value.status == 409
    ad.labs.lab_sync(lab_id)
    assert ad.lab_keys.lab_key(lab_id) == (2, b"\3" * 32)


def test_second_device_gets_the_keys_through_the_personal_store(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-key-two", invite=link).client
    lab_id = first.labs.lab_create("Lab")["lab_id"]
    _, key = first.lab_keys.lab_key(lab_id)
    r = net.join(tmp_path / "desktop", "fake-key-two", invite=link)
    first.account.add_device(r.device_request)
    first.personal.sync_store()
    second = net.join(tmp_path / "desktop", "fake-key-two", invite=link).client
    assert second.lab_keys.lab_key(lab_id) == (1, key)
    assert second.lab_keys.readable_labs() == []  # no cache yet
    assert second.labs.lab_sync()["labs"][lab_id]["epoch"] == 1
    assert second.lab_keys.readable_labs() == [lab_id]


def test_leave_makes_rotation_due_and_the_pi_rotates(net, trio):
    pi, ad, mem = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, mem.device.subject)
    mem.lab_keys.lab_key(lab_id)
    mem.labs.lab_leave(lab_id)
    assert mem.lab_keys.readable_labs() == []
    pi.lab_roster.lab_state(lab_id)
    assert pi.labs.lab_list()[0]["rotation_due"] is True
    out = pi.labs.lab_sync(lab_id)["labs"][lab_id]
    assert out["rotated"] is True and out["epoch"] == 2
    assert pi.labs.lab_list()[0]["rotation_due"] is False
    assert pi.labs.lab_sync(lab_id)["labs"][lab_id]["rotated"] is False  # safe to run again


def test_device_reset_triggers_rotation(net, trio, tmp_path):
    pi, _, _ = trio
    old = net.join(tmp_path / "dev-a", "fake-key-reset").client
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, old.device.subject)
    assert pi.labs.lab_sync(lab_id)["labs"][lab_id]["rotated"] is False
    new = net.join(tmp_path / "dev-b", "fake-key-reset", reset=True).client  # old device goes
    out = pi.labs.lab_sync(lab_id)["labs"][lab_id]
    assert out["rotated"] is True and out["epoch"] == 2
    assert new.lab_keys.lab_key(lab_id) == pi.lab_keys.lab_key(lab_id)


def _two_devices(net, tmp_path, orcid: str):
    """The first and the second device of one person."""
    link = net.invite()
    first = net.join(tmp_path / f"{orcid}-1", orcid, invite=link).client
    r = net.join(tmp_path / f"{orcid}-2", orcid, invite=link)
    first.account.add_device(r.device_request)
    first.personal.sync_store()
    second = net.join(tmp_path / f"{orcid}-2", orcid, invite=link).client
    return first, second


def test_pi_removes_a_device_and_the_lab_key_changes(net, tmp_path):
    first, second = _two_devices(net, tmp_path, "fake-key-rmdev")
    lab_id = first.labs.lab_create("Lab")["lab_id"]
    first.personal.sync_store()
    assert second.labs.lab_sync()["labs"][lab_id]["epoch"] == 1
    gone = second.device.my_device()["ed25519"]
    out = first.labs.remove_device(gone)
    assert out == {"device": gone, "due": [], "rotated": [lab_id]}
    assert gone not in first.directory.lookup(first.device.subject).devices
    assert first.lab_keys.lab_key(lab_id)[0] == 2
    doc = net.labs._db.execute(
        "SELECT doc FROM lab_keys WHERE lab_id = ? AND epoch = 2 AND recipient = ?",
        (lab_id, first.device.subject),
    ).fetchone()[0]
    assert gone not in doc  # no wrap for the removed device
    with pytest.raises(LabError, match="itself"):
        first.labs.remove_device(first.device.my_device()["ed25519"])
    with pytest.raises(LabError, match="not one of your devices"):
        first.labs.remove_device(gone)


def test_member_removes_a_device_and_the_pi_rotates(net, trio, tmp_path):
    pi, _, _ = trio
    first, second = _two_devices(net, tmp_path, "fake-key-rmdev-m")
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, first.device.subject)
    first.labs.lab_sync(lab_id)
    out = first.labs.remove_device(second.device.my_device()["ed25519"])
    assert out["rotated"] == [] and out["due"] == [lab_id]
    got = pi.labs.lab_sync(lab_id)["labs"][lab_id]
    assert got["rotated"] is True and got["epoch"] == 2
    assert first.labs.lab_sync(lab_id)["labs"][lab_id]["epoch"] == 2
    assert first.lab_keys.lab_key(lab_id) == pi.lab_keys.lab_key(lab_id)
