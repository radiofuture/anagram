"""Node lab unit: roster routes, access from the
roster only, invites, join, node membership, and the changes feed."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from anagram.admission import formats as admfmt
from anagram.admission.check import GroupAdmission
from anagram.admission.model import NodePolicy
from anagram.admission.node.service import group_creation
from anagram.identity.formats.documents import new_lab_id
from anagram.network.formats import lab
from anagram.network.groups.node.labs import LabService, lab_policy_from_env


class Person:
    def __init__(self, net, home, orcid: str) -> None:
        self.net = net
        self.client = net.join(home, orcid).client
        self.subject = self.client.device.subject
        self.key = self.client.device.device_key()

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.client.device.http.token}"}

    def get(self, path: str):
        return self.net.tc.get(path, headers=self.headers)

    def post(self, path: str, body: dict):
        return self.net.tc.post(path, json=body, headers=self.headers)

    def now(self) -> datetime:
        return datetime.fromtimestamp(int(self.net.clock()), UTC)


def state_of(person: Person, lab_id: str) -> lab.LabState:
    r = person.get(f"/labs/{lab_id}/roster")
    assert r.status_code == 200, r.text
    data = r.json()
    return lab.replay(
        lab_id, data["entries"], lambda *_: True, data["invites"], admission=GroupAdmission()
    )


def create(person: Person, name: str = "Chen Lab") -> str:
    lab_id = new_lab_id(secrets.token_bytes(8))
    entry = lab.make_roster_entry(
        state=lab.LabState(lab_id, admission=GroupAdmission()),
        op="create",
        actor=person.subject,
        key=person.key,
        at=person.now(),
        subject=person.subject,
        role="pi",
        name=name,
    )
    r = person.post("/labs", {"entry": entry})
    assert r.status_code == 200, r.text
    assert r.json()["seq"] == 0
    return lab_id


def entry(person: Person, lab_id: str, op: str, **kw) -> dict:
    return lab.make_roster_entry(
        state=state_of(person, lab_id),
        op=op,
        actor=person.subject,
        key=person.key,
        at=person.now(),
        **kw,
    )


def submit(person: Person, lab_id: str, op: str, **kw):
    return person.post(f"/labs/{lab_id}/roster", {"entry": entry(person, lab_id, op, **kw)})


@pytest.fixture
def people(net, tmp_path):
    return {
        name: Person(net, tmp_path / name, f"fake-{name}")
        for name in ("pi", "admin", "member", "outside")
    }


def test_create_add_remove_leave_transfer(net, people):
    pi, adm, mem, out = people["pi"], people["admin"], people["member"], people["outside"]
    lab_id = create(pi)
    assert submit(pi, lab_id, "add", subject=adm.subject, role="admin").status_code == 200
    assert submit(adm, lab_id, "add", subject=mem.subject, role="member").status_code == 200
    view = mem.get(f"/labs/{lab_id}").json()
    assert view["roles"] == {pi.subject: "pi", adm.subject: "admin", mem.subject: "member"}
    assert view["pi"] == pi.subject and view["seq"] == 2
    assert net.labs.directory.labs_of(mem.subject) == [lab_id]  # the cache follows
    assert net.labs.directory.name(lab_id) == "Chen Lab"
    # remove: refused for a member, done by an admin
    assert submit(mem, lab_id, "remove", subject=adm.subject).status_code == 400
    assert submit(adm, lab_id, "remove", subject=mem.subject).status_code == 200
    assert mem.get(f"/labs/{lab_id}/roster").status_code == 404
    assert net.labs.directory.labs_of(mem.subject) == []
    # transfer, then the old PI leaves
    assert submit(pi, lab_id, "transfer", subject=adm.subject).status_code == 200
    assert submit(pi, lab_id, "leave").status_code == 200
    view = adm.get(f"/labs/{lab_id}").json()
    assert view["roles"] == {adm.subject: "pi"} and view["pi"] == adm.subject
    assert out.get(f"/labs/{lab_id}/roster").status_code == 404


def test_non_member_gets_no_member_list(people):
    pi, out = people["pi"], people["outside"]
    lab_id = create(pi, "Okafor Lab")
    view = out.get(f"/labs/{lab_id}")
    assert view.status_code == 200 and view.json() == {"lab_id": lab_id, "name": "Okafor Lab"}
    assert out.get(f"/labs/{lab_id}/roster").status_code == 404
    e = entry(pi, lab_id, "rename", name="Taken")
    assert out.post(f"/labs/{lab_id}/roster", {"entry": e}).status_code == 404
    assert out.get("/labs/lab-0000000000000000/roster").status_code == 404
    assert out.get("/labs/not-a-lab/roster").status_code == 404


def test_stale_seq_gives_409(people):
    pi, adm = people["pi"], people["admin"]
    lab_id = create(pi)
    stale = entry(pi, lab_id, "rename", name="One")
    assert submit(pi, lab_id, "add", subject=adm.subject, role="admin").status_code == 200
    r = pi.post(f"/labs/{lab_id}/roster", {"entry": stale})
    assert r.status_code == 409


def test_node_refuses_bad_entries(people):
    pi, adm = people["pi"], people["admin"]
    lab_id = create(pi)
    # An entry of another person: the session person signs their own entries.
    e = entry(pi, lab_id, "add", subject=adm.subject, role="admin")
    assert adm.post(f"/labs/{lab_id}/roster", {"entry": e}).status_code == 404
    submit(pi, lab_id, "add", subject=adm.subject, role="member")
    e = entry(adm, lab_id, "rename", name="X")
    e["name"] = "Changed"  # the signature does not match now
    assert adm.post(f"/labs/{lab_id}/roster", {"entry": e}).status_code == 400
    # A device key that is not bound to the person.
    forged = lab.make_roster_entry(
        state=state_of(pi, lab_id),
        op="rename",
        actor=pi.subject,
        key=lab.SigningKey.generate(),
        at=pi.now(),
        name="Forged",
    )
    assert pi.post(f"/labs/{lab_id}/roster", {"entry": forged}).status_code == 400
    # Create through the roster route is refused.
    assert submit(pi, lab_id, "close").status_code == 200
    assert submit(pi, lab_id, "rename", name="After close").status_code == 400


def test_node_table_row_without_roster_entry_gives_no_access(net, people):
    pi, out = people["pi"], people["outside"]
    lab_id = create(pi)
    # An operator writes rows into the cache. They give no access.
    net.labs.directory.put(lab_id, "Chen Lab", pi.subject, [pi.subject, out.subject], 0)
    assert lab_id in net.labs.directory.labs_of(out.subject)
    assert out.get(f"/labs/{lab_id}/roster").status_code == 404
    assert "members" not in out.get(f"/labs/{lab_id}").json()


def test_state_survives_a_restart(net, people, tmp_path):
    pi, adm = people["pi"], people["admin"]
    lab_id = create(pi)
    submit(pi, lab_id, "add", subject=adm.subject, role="admin")
    again = LabService(
        net.home.dir / "labs.sqlite",
        net.identity,
        net.home.lab_directory(),
        net.labs.may_create,
        GroupAdmission(),
    )
    assert again.get_lab(adm.subject, lab_id)["roles"][adm.subject] == "admin"


# Legacy second member cache schema of labs.sqlite (migrated away from).
OLD_LABS_TABLES = """
CREATE TABLE lab_roles (lab_id TEXT NOT NULL, subject TEXT NOT NULL,
    role TEXT NOT NULL, joined_at INTEGER NOT NULL, PRIMARY KEY (lab_id, subject));
"""


def _tables(path) -> set[str]:
    con = sqlite3.connect(path)
    try:
        return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        con.close()


def test_lab_from_before_the_roster(net, people):
    """A node from before the roster has a lab with rows in the lab
    directory only. The rows count for `labs_of` and the organizer, and the
    lab ID stays taken."""
    pi, mem = people["pi"], people["member"]
    lab_id = create(pi)
    submit(pi, lab_id, "add", subject=mem.subject, role="member")
    old_lab = "lab-" + "ab" * 8  # from before the roster: rows only
    labs_db = net.home.dir / "labs.sqlite"
    con = sqlite3.connect(labs_db)
    con.executescript(OLD_LABS_TABLES)
    con.execute("INSERT INTO labs VALUES (?, ?, ?, ?)", (old_lab, "Old Lab", mem.subject, 5))
    con.execute("INSERT INTO lab_members VALUES (?, ?)", (old_lab, mem.subject))
    con.commit()
    con.close()

    groups = net.home.lab_directory()
    assert groups.labs_of(mem.subject) == sorted([lab_id, old_lab])
    assert groups.name(old_lab) == "Old Lab" and groups.pi(old_lab) == mem.subject
    assert groups.counts() == [
        {"members": 2, "name": "Chen Lab"},
        {"members": 1, "name": "Old Lab"},
    ]
    assert mem.get("/me").json()["labs"] == sorted([lab_id, old_lab])
    # The node opens again: the unread member cache is gone, the roster stays.
    again = net.home.labs(net.identity)
    assert "lab_roles" not in _tables(labs_db)
    assert again.get_lab(mem.subject, lab_id)["roles"][mem.subject] == "member"
    # The ID of the old lab stays taken for another person.
    e = lab.make_roster_entry(
        state=lab.LabState(old_lab, admission=GroupAdmission()),
        op="create",
        actor=pi.subject,
        key=pi.key,
        at=pi.now(),
        subject=pi.subject,
        role="pi",
        name="Take over",
    )
    assert pi.post("/labs", {"entry": e}).status_code == 409


def test_create_policy(net, people, tmp_path):
    pi = people["pi"]
    assert net.admission.policy.create_group == "organizer_invite"
    assert net.labs.may_create(pi.subject)  # came in with a node invite
    net.identity.db.execute("UPDATE members SET invite = 'lab:x' WHERE subject = ?", (pi.subject,))
    assert not net.labs.may_create(pi.subject)
    lab_id = new_lab_id(secrets.token_bytes(8))
    e = lab.make_roster_entry(
        state=lab.LabState(lab_id, admission=GroupAdmission()),
        op="create",
        actor=pi.subject,
        key=pi.key,
        at=pi.now(),
        subject=pi.subject,
        role="pi",
        name="No",
    )
    assert pi.post("/labs", {"entry": e}).status_code == 403
    net.labs.may_create = group_creation(net.identity, NodePolicy(create_group="member"))
    assert pi.post("/labs", {"entry": e}).status_code == 200
    assert pi.post("/labs", {"entry": e}).status_code == 409  # the ID exists


def test_lab_policy_from_env():
    assert lab_policy_from_env({}) == (2048 << 20, "organizer_invite")
    assert lab_policy_from_env({"ANAGRAM_LAB_QUOTA_MB": "5", "ANAGRAM_LAB_CREATE": "member"}) == (
        5 << 20,
        "member",
    )
    for bad in ({"ANAGRAM_LAB_QUOTA_MB": "x"}, {"ANAGRAM_LAB_CREATE": "anyone"}):
        with pytest.raises(ValueError):
            lab_policy_from_env(bad)


def test_create_needs_own_entry(people):
    pi, adm = people["pi"], people["admin"]
    lab_id = new_lab_id(secrets.token_bytes(8))
    e = lab.make_roster_entry(
        state=lab.LabState(lab_id, admission=GroupAdmission()),
        op="create",
        actor=pi.subject,
        key=pi.key,
        at=pi.now(),
        subject=pi.subject,
        role="pi",
        name="Mine",
    )
    assert adm.post("/labs", {"entry": e}).status_code == 400


def test_entry_times_are_in_the_window(net, people):
    """A device check uses the entry time; this node checks active devices."""
    pi = people["pi"]
    lab_id = create(pi)
    late = lab.make_roster_entry(
        state=state_of(pi, lab_id),
        op="rename",
        actor=pi.subject,
        key=pi.key,
        at=pi.now() + timedelta(days=1),
        name="Later",
    )
    assert pi.post(f"/labs/{lab_id}/roster", {"entry": late}).status_code == 200


# ------------------------------------------------------- S2b: invites, join


def make_invite(person: Person, lab_id: str, role="member", uses=1, days=7):
    st = state_of(person, lab_id)
    seed = secrets.token_bytes(32)
    auth = admfmt.make_lab_invite(
        seed=seed,
        node_url="https://node.test",
        node_key=person.client.device.identity_config()["node_key"],
        community="Test community",
        lab_id=lab_id,
        lab_name=st.name,
        genesis=st.genesis,
        role=role,
        max_uses=uses,
        expires_at=person.now() + timedelta(days=days),
        created_by=person.subject,
        created_at=person.now(),
        key=person.key,
    )
    iid = admfmt.lab_invite_id(auth)
    e = lab.make_roster_entry(
        state=st, op="invite", actor=person.subject, key=person.key, at=person.now(), invite=iid
    )
    r = person.post(f"/labs/{lab_id}/invites", {"auth": auth, "package": None, "entry": e})
    assert r.status_code == 200, r.text
    assert r.json()["invite_id"] == iid
    return auth, seed, iid


def join_request(person, auth, seed, device_key=None):
    return admfmt.make_join_request(
        auth=auth,
        seed=seed,
        subject=person.subject,
        device_key=device_key or person.key,
        at=person.now(),
    )


def test_node_member_joins_by_invite(net, people):
    pi, mem = people["pi"], people["member"]
    lab_id = create(pi)
    auth, seed, iid = make_invite(pi, lab_id)
    info = mem.get(f"/labs/invites/{iid}").json()
    assert info["open"] and info["auth"] == auth and info["package"] is None
    r = mem.post(f"/labs/{lab_id}/join", {"request": join_request(mem, auth, seed)})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "member"
    assert state_of(mem, lab_id).members[mem.subject] == "member"
    assert mem.get(f"/labs/invites/{iid}").json()["open"] is False
    # The same request again: safe, the same answer.
    again = mem.post(f"/labs/{lab_id}/join", {"request": join_request(mem, auth, seed)})
    assert again.status_code == 200 and again.json()["seq"] == r.json()["seq"]


def test_used_expired_and_revoked_invites(net, people):
    pi, adm, mem, out = people["pi"], people["admin"], people["member"], people["outside"]
    lab_id = create(pi)
    auth, seed, iid = make_invite(pi, lab_id)
    assert (
        mem.post(f"/labs/{lab_id}/join", {"request": join_request(mem, auth, seed)}).status_code
        == 200
    )
    used = out.post(f"/labs/{lab_id}/join", {"request": join_request(out, auth, seed)})
    assert used.status_code == 409 and "was used" in used.json()["detail"]
    auth, seed, iid = make_invite(pi, lab_id, days=1)
    net.clock.t += 2 * 86400
    late = out.post(f"/labs/{lab_id}/join", {"request": join_request(out, auth, seed)})
    assert late.status_code == 410
    auth, seed, iid = make_invite(pi, lab_id)
    assert submit(pi, lab_id, "revoke_invite", invite=iid).status_code == 200
    gone = adm.post(f"/labs/{lab_id}/join", {"request": join_request(adm, auth, seed)})
    assert gone.status_code == 410
    assert out.get(f"/labs/invites/{iid}").json()["open"] is False


def test_join_needs_invite_key_on_node(people):
    pi, mem = people["pi"], people["member"]
    lab_id = create(pi)
    auth, seed, iid = make_invite(pi, lab_id)
    fake = join_request(mem, auth, secrets.token_bytes(32))
    assert mem.post(f"/labs/{lab_id}/join", {"request": fake}).status_code == 400
    other = people["outside"]
    stolen = join_request(mem, auth, seed)
    # A request of another person cannot be sent with my session.
    assert other.post(f"/labs/{lab_id}/join", {"request": stolen}).status_code == 403


def test_invite_route_rules(people):
    pi, adm, mem = people["pi"], people["admin"], people["member"]
    lab_id = create(pi)
    submit(pi, lab_id, "add", subject=adm.subject, role="admin")
    submit(pi, lab_id, "add", subject=mem.subject, role="member")
    with pytest.raises(AssertionError):
        make_invite(mem, lab_id)  # a member cannot invite
    with pytest.raises(AssertionError):
        make_invite(adm, lab_id, role="admin")  # an admin invite needs the PI
    make_invite(adm, lab_id)
    assert mem.get("/labs/invites/" + "0" * 32).status_code == 404


def test_new_person_joins_node_with_lab_invite(net, people, tmp_path):
    """A person with a session but no node membership (sign-in only): the
    first call makes the node member and asks for the device binding."""
    from anagram.core.crypto.signing import SigningKey
    from anagram.core.nodeapi import HttpNode
    from anagram.identity.app.identity import SignInWith, sign_in

    pi = people["pi"]
    lab_id = create(pi)
    auth, seed, iid = make_invite(pi, lab_id, uses=2)
    node = HttpNode("https://node.test", net.transport)
    key = SigningKey.generate()
    assertion, signed = sign_in(
        node,
        net.identity.trust,
        auth["node_key"],
        key.public_bytes(),
        SignInWith(browser=net.browser(), login_hint="fake-new-person"),
        now=pi.now(),
    )
    subject = assertion["subject"]
    assert not net.identity.is_member(subject)
    req = admfmt.make_join_request(
        auth=auth, seed=seed, subject=subject, device_key=key, at=pi.now()
    )
    headers = {"Authorization": "Bearer " + signed["session"]["token"]}
    r = net.tc.post(f"/labs/{lab_id}/join", json={"request": req}, headers=headers)
    assert r.status_code == 202 and r.json() == {"status": "bind_device"}
    assert net.identity.is_member(subject)
    row = net.identity._one("SELECT role, invite FROM members WHERE subject = ?", subject)
    assert row == ("member", "lab:" + iid)
    assert not net.labs.may_create(subject)  # a lab invite gives no right to start a lab
    assert state_of(pi, lab_id).invites[iid]["uses"] == 0  # no use counted yet


def test_lab_invite_member_limit(net, people):
    from anagram.core.errors import Conflict
    from anagram.identity.ports import Admission

    def admit(pid: str) -> bool:
        return net.identity.add_member(Admission(pid, "lab:" + "1" * 32, limit=1))

    admit("pid:" + "aa" * 16)
    with pytest.raises(Conflict):
        admit("pid:" + "bb" * 16)
    # Idempotent for the same person; nothing changes for a member.
    assert admit("pid:" + "aa" * 16) is False


def test_changes_feed_and_long_poll(net, people):
    import threading
    import time

    pi, adm, out = people["pi"], people["admin"], people["outside"]
    lab_id = create(pi)
    feed = pi.get("/labs/changes?after=0").json()
    assert [c["topic"] for c in feed["changes"]] == ["members"]
    assert out.get("/labs/changes?after=0").json()["changes"] == []  # not in the lab
    after = feed["next"]
    auth, seed, iid = make_invite(pi, lab_id)
    topics = [c["topic"] for c in pi.get(f"/labs/changes?after={after}").json()["changes"]]
    assert topics == ["invites"]
    after = pi.get(f"/labs/changes?after={after}").json()["next"]
    got = {}

    def poll():
        t0 = time.monotonic()
        got["r"] = net.labs.changes(pi.subject, after, wait=10)
        got["s"] = time.monotonic() - t0

    th = threading.Thread(target=poll)
    th.start()
    time.sleep(0.2)
    submit(pi, lab_id, "add", subject=adm.subject, role="admin")
    th.join(5)
    assert not th.is_alive() and got["s"] < 5
    assert [c["topic"] for c in got["r"]["changes"]] == ["members"]
    t0 = time.monotonic()
    empty = net.labs.changes(pi.subject, got["r"]["next"], wait=0.3)
    assert empty["changes"] == [] and time.monotonic() - t0 >= 0.25
