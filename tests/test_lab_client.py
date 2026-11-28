"""Client lab unit: verified roster, actions,
node faults, and the join with a lab invite link."""

from __future__ import annotations

import copy

import pytest

from anagram.admission import formats as admfmt
from anagram.admission.check import GroupAdmission
from anagram.core.errors import LogMisbehaved
from anagram.network.formats import lab
from anagram.network.groups.app.labroster import LabError


def tamper(transport, fn):
    """A node that changes its answer to `GET /labs/{id}/roster`."""

    def call(method, path, body, headers=None):
        out = transport(method, path, body, headers)
        if method == "GET" and "/roster" in path:
            out = fn(copy.deepcopy(out))
        return out

    return call


@pytest.fixture
def trio(net, tmp_path):
    return [
        net.join(tmp_path / n, f"fake-{n}").client for n in ("chen-pi", "chen-postdoc", "outside")
    ]


def test_create_add_and_roles(net, trio):
    pi, pd, out = trio
    created = pi.labs.lab_create("  Chen Lab ")
    lab_id = created["lab_id"]
    assert created == {"lab_id": lab_id, "name": "Chen Lab"}
    view = pi.labs.lab_add(lab_id, pd.device.subject)
    assert view["roles"] == {pi.device.subject: "pi", pd.device.subject: "member"}
    assert pd.lab_roster.lab_state(lab_id).members == view["roles"]
    assert pi.labs.lab_list() == [
        {"lab_id": lab_id, "members": 2, "name": "Chen Lab", "role": "pi", "rotation_due": False}
    ]
    assert pd.labs.lab_list()[0]["role"] == "member"  # from the cache of the pull above
    assert out.labs.lab_list() == []
    with pytest.raises(LabError, match="role"):
        pd.labs.lab_rename(lab_id, "Mine")
    pi.labs.lab_set_role(lab_id, pd.device.subject, "admin")
    pd.labs.lab_rename(lab_id, "Chen Group")
    assert pi.lab_roster.lab_state(lab_id).name == "Chen Group"
    with pytest.raises(LabError, match="PI"):
        pi.labs.lab_leave(lab_id)
    pi.labs.lab_transfer(lab_id, pd.device.subject)
    pi.labs.lab_leave(lab_id)
    assert pi.labs.lab_list() == []
    with pytest.raises(LabError):
        pi.lab_roster.lab_state(lab_id)
    assert pd.lab_roster.lab_state(lab_id).members == {pd.device.subject: "pi"}
    with pytest.raises(LabError):
        out.lab_roster.lab_state(lab_id)


def test_remove_and_three_clients(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject)
    pi.labs.lab_add(lab_id, out.device.subject)
    assert out.lab_roster.lab_members(lab_id) == {
        pi.device.subject,
        pd.device.subject,
        out.device.subject,
    }
    pi.labs.lab_remove(lab_id, out.device.subject)
    assert out.lab_roster.lab_members(lab_id) == set()
    assert pd.lab_roster.lab_members(lab_id) == {pi.device.subject, pd.device.subject}
    assert net.labs.directory.labs_of(out.device.subject) == []


def test_conflict_retries(net, trio):
    pi, pd, _ = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject, role="admin")
    pd.lab_roster.lab_state(lab_id)
    pi.labs.lab_rename(lab_id, "One")  # pd's pin is old now
    pd.labs.lab_rename(lab_id, "Two")  # 409 on the first send is not possible here: pd pulls first
    assert pi.lab_roster.lab_state(lab_id).name == "Two"


def test_forged_entry_raises(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject)
    # The node adds an entry that it signed with a key of its own.
    from anagram.core.crypto.signing import SigningKey

    def forge(data):
        st = lab.replay(
            lab_id, data["entries"], lambda *_: True, data["invites"], admission=GroupAdmission()
        )
        e = lab.make_roster_entry(
            state=st,
            op="add",
            actor=pi.device.subject,
            key=SigningKey.generate(),
            at=pi.device.now(),
            subject=out.device.subject,
            role="member",
        )
        data["entries"].append(e)
        data["seq"], data["head"] = e["seq"], lab.entry_hash(e)
        return data

    pd.device.http.transport = tamper(pd.device.http.transport, forge)
    with pytest.raises(LogMisbehaved):
        pd.lab_roster.lab_state(lab_id)
    assert pd.lab_roster.labcache.state(lab_id) is None  # nothing stored


def test_dropped_entry_raises(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject)
    pi.labs.lab_add(lab_id, out.device.subject)

    def drop(data):
        del data["entries"][1]
        return data

    pd.device.http.transport = tamper(pd.device.http.transport, drop)
    with pytest.raises(LogMisbehaved):
        pd.lab_roster.lab_state(lab_id)


def test_shorter_chain_refused(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject)
    pi.labs.lab_add(lab_id, out.device.subject)
    pd.lab_roster.lab_state(lab_id)  # pin at seq 2
    real = pd.device.http.transport

    def rollback(data):
        return {
            "entries": [],
            "head": pi.lab_roster.labcache.state(lab_id).heads[1],
            "invites": {},
            "seq": 1,
        }

    pd.device.http.transport = tamper(real, rollback)
    with pytest.raises(LogMisbehaved):
        pd.lab_roster.lab_state(lab_id)

    def fork(data):
        data["head"] = "ab" * 32
        return data

    pd.device.http.transport = tamper(real, fork)
    with pytest.raises(LogMisbehaved):
        pd.lab_roster.lab_state(lab_id)


def test_ring_kind_lab_reads_the_verified_roster(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject)
    pd.grants.ring_create("my lab")
    pd.grants.ring_add("my lab", [f"lab:{lab_id}"])
    subjects, _ = pd.grants.ring_recipients("my lab")
    assert subjects == {pi.device.subject}
    out.grants.ring_create("theirs")
    out.grants.ring_add("theirs", [f"lab:{lab_id}"])
    assert out.grants.ring_recipients("theirs")[0] == set()  # not in the lab: no members


def test_cache_is_encrypted(net, trio):
    pi, _, _ = trio
    pi.labs.lab_create("Secret Name Lab")
    raw = (pi.home / "labspace.sqlite").read_bytes()
    assert b"Secret Name Lab" not in raw and not raw.startswith(b"SQLite format 3")
    assert pi.keystore.get("lab-cache-key") is not None


# ------------------------------------------------------------ S3b: invites


def test_new_person_joins_node_and_lab_with_the_link_only(net, tmp_path):
    pi = net.join(tmp_path / "pi", "fake-inv-pi").client
    lab_id = pi.labs.lab_create("Chen Lab")["lab_id"]
    inv = pi.admission.lab_invite(lab_id)
    assert set(inv) == {"invite_id", "url", "expires_at"}
    assert inv["url"].startswith("https://node.test/join#")
    # The node has the authorisation, never the seed.
    seed = admfmt.parse_lab_invite_link(inv["url"])["seed"]
    raw = (net.home.dir / "labs.sqlite").read_bytes()
    assert seed.encode() not in raw and bytes.fromhex(seed) not in raw
    r = net.join(tmp_path / "new", "fake-inv-new", invite=inv["url"])
    assert r.status == "joined" and r.receipt is None
    new = r.client
    assert new.lab_roster.lab_state(lab_id).members == {
        pi.device.subject: "pi",
        new.device.subject: "member",
    }
    assert net.identity.is_member(new.device.subject)
    assert new.account.whoami()["identity"]["lab_id"] == lab_id  # the record takes the lab
    # Join again on the same home: safe; nothing new in the roster.
    seq = pi.lab_roster.lab_state(lab_id).seq
    again = net.join(tmp_path / "new", "fake-inv-new", invite=inv["url"])
    assert again.status == "joined" and pi.lab_roster.lab_state(lab_id).seq == seq
    # The link was for one person.
    with pytest.raises(LabError, match="used"):
        net.join(tmp_path / "third", "fake-inv-third", invite=inv["url"])


def test_node_member_joins_a_second_lab(net, trio):
    pi, pd, _ = trio
    one = pi.labs.lab_create("One")["lab_id"]
    two = pd.labs.lab_create("Two")["lab_id"]
    pi.labs.lab_add(one, pd.device.subject)
    url = pi.admission.lab_invite(one, max_uses=3)["url"]
    assert pd.admission.lab_join(url) == {
        "lab_id": one,
        "name": "One",
        "role": "member",
    }  # in it already
    url = pd.admission.lab_invite(two, role="admin")["url"]
    assert pi.admission.lab_join(url) == {"lab_id": two, "name": "Two", "role": "admin"}
    assert {x["lab_id"] for x in pi.labs.lab_list()} == {one, two}


def test_revoked_invite_refused(net, trio):
    pi, pd, out = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    pi.labs.lab_add(lab_id, pd.device.subject, role="admin")
    inv = pd.admission.lab_invite(lab_id)
    pi.admission.lab_revoke_invite(lab_id, inv["invite_id"])
    with pytest.raises(LabError, match="no longer valid"):
        out.admission.lab_join(inv["url"])
    assert out.device.subject not in pi.lab_roster.lab_state(lab_id).members
    with pytest.raises(LabError, match="role"):
        pd.admission.lab_invite(lab_id, role="admin")  # an admin invites members only
    pi.labs.lab_set_role(lab_id, pd.device.subject, "member")
    with pytest.raises(LabError, match="role"):
        pd.admission.lab_invite(lab_id)
    for bad in ({"max_uses": 0}, {"max_uses": 26}, {"expires_days": 31}):
        with pytest.raises(LabError):
            pi.admission.lab_invite(lab_id, **bad)


def test_lab_link_creator_is_checked_before_sign_in(net, trio, tmp_path):
    from anagram.core.crypto.signing import SigningKey
    from anagram.core.timefmt import parse_time

    pi, _, _ = trio
    lab_id = pi.labs.lab_create("Lab")["lab_id"]
    parsed = admfmt.parse_lab_invite_link(pi.admission.lab_invite(lab_id)["url"])
    seed, auth = bytes.fromhex(parsed["seed"]), parsed["auth"]
    # A link that names the PI, signed by a device key that is not the PI's.
    forged = admfmt.make_lab_invite(
        seed=seed,
        **{k: auth[k] for k in ("node_url", "node_key", "community", "lab_id", "lab_name")},
        genesis=auth["genesis"],
        role="member",
        max_uses=1,
        expires_at=parse_time(auth["expires_at"]),
        created_by=pi.device.subject,
        created_at=parse_time(auth["created_at"]),
        key=SigningKey.generate(),
    )
    with pytest.raises(LabError, match="not from a member"):
        net.join(tmp_path / "victim", "fake-victim", invite=admfmt.lab_invite_url(forged, seed))
    assert net.identity.subject_for_orcid("fake-victim") is None  # no sign-in happened


def test_ui_service_accepts_a_lab_link(net, trio, tmp_path):
    from anagram.shell.ui.errors import UIError
    from anagram.shell.ui.service import UIService

    pi, _, _ = trio
    url = pi.admission.lab_invite(pi.labs.lab_create("UI Lab")["lab_id"])["url"]
    svc = UIService(tmp_path / "ui-home", transport=net.transport, clock=net.clock)
    svc.join.prepare(url)
    info = svc.join.invite_info()
    assert info["community_url"] == "https://node.test" and info["lab"] == "UI Lab"
    with pytest.raises(UIError):
        svc.join.start_join("https://node.test/join#bm90LWEtbGluaw")
