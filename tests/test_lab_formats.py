"""Lab formats (plan R2, steps S1a and S1b): roster entries, the chain rules,
the permission table (section 4.1), invites, join requests, and the vectors."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from anagram.admission import formats as admfmt
from anagram.admission.check import GroupAdmission
from anagram.admission.formats import invite_url, make_invite
from anagram.core.crypto.hashing import ALL_TAGS
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.network.formats import lab, labitem, labkey, labsettings

VEC = json.loads((Path(__file__).parent.parent / "spec" / "vectors" / "lab.json").read_text())
T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)
LAB = "lab-" + "0f" * 8


def pid(n: int) -> str:
    return "pid:" + f"{n:02x}" * 16


PI, ADM, MEM, MEM2, OUT = pid(1), pid(2), pid(3), pid(4), pid(9)


class World:
    """One lab with a PI, an admin, and a member, and an outsider."""

    def __init__(self) -> None:
        self.keys = {p: SigningKey.generate() for p in (PI, ADM, MEM, MEM2, OUT)}
        self.devices = {p: k.public_bytes().hex() for p, k in self.keys.items()}
        self.state = lab.LabState(LAB, admission=GroupAdmission())
        self.auths: dict[str, dict] = {}
        self.t = T0
        self.apply(self.entry("create", PI, subject=PI, role="pi", name="Lab A"))
        self.apply(self.entry("add", PI, subject=ADM, role="admin"))
        self.apply(self.entry("add", PI, subject=MEM, role="member"))

    def device_ok(self, subject: str, device: str, at: datetime) -> bool:
        return self.devices.get(subject) == device

    def tick(self) -> datetime:
        self.t += timedelta(minutes=1)
        return self.t

    def entry(self, op: str, actor: str, key: SigningKey | None = None, **kw) -> dict:
        return lab.make_roster_entry(
            state=self.state, op=op, actor=actor, key=key or self.keys[actor], at=self.tick(), **kw
        )

    def apply(self, entry: dict) -> None:
        self.state.apply(entry, self.device_ok, self.auths)

    def refused(self, op: str, actor: str, **kw) -> None:
        before = (self.state.seq, self.state.head, dict(self.state.members))
        with pytest.raises(FormatError):
            self.apply(self.entry(op, actor, **kw))
        assert (self.state.seq, self.state.head, self.state.members) == (
            before[0],
            before[1],
            before[2],
        )

    def invite(self, actor: str, role: str = "member", uses: int = 1, days: float = 7):
        seed = secrets.token_bytes(32)
        auth = admfmt.make_lab_invite(
            seed=seed,
            node_url="https://node.test",
            node_key="ab" * 32,
            community="Test community",
            lab_id=LAB,
            lab_name=self.state.name,
            genesis=self.state.genesis,
            role=role,
            max_uses=uses,
            expires_at=self.t + timedelta(days=days),
            created_by=actor,
            created_at=self.t,
            key=self.keys[actor],
        )
        iid = admfmt.lab_invite_id(auth)
        self.auths[iid] = auth
        return auth, seed, iid

    def join(self, who: str, auth: dict, seed: bytes, at: datetime | None = None) -> dict:
        req = admfmt.make_join_request(
            auth=auth, seed=seed, subject=who, device_key=self.keys[who], at=at or self.tick()
        )
        return lab.make_join_entry(state=self.state, request=req, role=auth["role"], at=self.t)


@pytest.fixture
def w() -> World:
    return World()


# ------------------------------------------------------------- tags, form


def test_tags_are_registered_and_unique():
    names = [t for t in ALL_TAGS if "/lab" in t]
    assert len(names) == 10 and len(set(ALL_TAGS)) == len(ALL_TAGS)


def test_state_after_create_and_add(w):
    assert w.state.seq == 2 and w.state.pi() == PI
    assert w.state.members == {PI: "pi", ADM: "admin", MEM: "member"}
    assert w.state.genesis == w.state.heads[0] and w.state.head == w.state.heads[2]


def test_entry_form_is_checked(w):
    e = w.entry("rename", PI, name="New")
    for bad in (
        {**e, "extra": 1},
        {**e, "op": "grow"},
        {**e, "name": None},
        {**e, "subject": PI},
        {**e, "signature": None},
        {**e, "seq": -1},
        {**e, "name": " padded"},
    ):
        with pytest.raises(FormatError):
            lab.validate_roster_entry(bad, GroupAdmission())


def test_chain_rules(w):
    e = w.entry("rename", PI, name="New")
    with pytest.raises(FormatError):  # bad prev
        w.apply({**e, "prev": "11" * 32})
    with pytest.raises(FormatError):  # seq is not next
        w.apply({**e, "seq": e["seq"] + 1})
    changed = {**e, "name": "Other"}  # the signature is over the old name
    with pytest.raises(FormatError):
        w.apply(changed)
    with pytest.raises(FormatError):  # another lab
        w.apply({**e, "lab_id": "lab-" + "ee" * 8})
    w.apply(e)
    with pytest.raises(FormatError):  # the same entry two times
        w.apply(e)


def test_device_must_be_a_key_of_the_actor(w):
    stolen = SigningKey.generate()
    w.refused("rename", PI, key=stolen, name="X")
    # A key of another person also is refused.
    w.refused("rename", PI, key=w.keys[ADM], name="X")


def test_first_entry_must_be_create():
    keys = SigningKey.generate()
    st = lab.LabState(LAB, admission=GroupAdmission())
    e = lab.make_roster_entry(
        state=st, op="add", actor=PI, key=keys, at=T0, subject=MEM, role="member"
    )
    with pytest.raises(FormatError):
        st.apply(e, lambda s, d, a: True)
    bad = lab.make_roster_entry(
        state=st, op="create", actor=PI, key=keys, at=T0, subject=MEM, role="pi", name="L"
    )
    with pytest.raises(FormatError):  # the creator is the PI
        st.apply(bad, lambda s, d, a: True)


# ------------------------------------------------------- permission table


def test_add(w):
    w.refused("add", MEM, subject=MEM2, role="member")  # member cannot add
    w.refused("add", ADM, subject=MEM2, role="admin")  # admin adds members only
    w.refused("add", PI, subject=MEM2, role="pi")  # no second PI
    w.refused("add", PI, subject=MEM, role="member")  # already in the lab
    w.refused("add", OUT, subject=MEM2, role="member")  # not in the lab
    w.apply(w.entry("add", ADM, subject=MEM2, role="member"))
    assert w.state.members[MEM2] == "member"


def test_remove(w):
    w.apply(w.entry("add", PI, subject=MEM2, role="admin"))
    w.refused("remove", MEM, subject=MEM2)  # member cannot remove
    w.refused("remove", ADM, subject=MEM2)  # admin removes members only
    w.refused("remove", ADM, subject=PI)  # nobody removes the PI
    w.refused("remove", PI, subject=PI)  # not self
    w.refused("remove", PI, subject=OUT)  # not in the lab
    w.apply(w.entry("remove", ADM, subject=MEM))
    w.apply(w.entry("remove", PI, subject=MEM2))
    assert MEM not in w.state.members and w.state.removed_at == w.state.seq
    w.refused("rename", MEM, name="X")  # a removed person signs nothing


def test_leave(w):
    w.refused("leave", PI)  # the PI transfers first
    w.apply(w.entry("leave", MEM))
    w.apply(w.entry("leave", ADM))
    assert set(w.state.members) == {PI} and w.state.removed_at == w.state.seq


def test_role(w):
    w.refused("role", ADM, subject=MEM, role="admin")  # only the PI
    w.refused("role", PI, subject=MEM, role="pi")  # use transfer
    w.refused("role", PI, subject=PI, role="member")
    w.apply(w.entry("role", PI, subject=MEM, role="admin"))
    w.apply(w.entry("role", PI, subject=ADM, role="member"))
    assert w.state.members[MEM] == "admin" and w.state.members[ADM] == "member"


def test_transfer(w):
    w.refused("transfer", ADM, subject=MEM)
    w.refused("transfer", PI, subject=OUT)
    w.refused("transfer", PI, subject=PI)
    w.apply(w.entry("transfer", PI, subject=MEM))
    assert w.state.pi() == MEM and w.state.members[PI] == "admin"
    assert list(w.state.members.values()).count("pi") == 1
    w.apply(w.entry("leave", PI))  # after transfer, the old PI can leave


def test_rename_and_close(w):
    w.refused("rename", MEM, name="X")
    w.apply(w.entry("rename", ADM, name="Lab B"))
    assert w.state.name == "Lab B"
    w.refused("close", ADM)
    w.apply(w.entry("close", PI))
    assert w.state.closed
    w.refused("rename", PI, name="Lab C")  # no entry after close


def test_can_matches_the_table(w):
    s = w.state
    for action in ("read", "publish"):
        assert all(s.can(p, action) for p in (PI, ADM, MEM))
    for action in ("invite", "revoke_invite", "tombstone", "settings", "rename", "rotate"):
        assert s.can(PI, action) and s.can(ADM, action) and not s.can(MEM, action)
    for action in ("role", "transfer", "close", "invite_admin"):
        assert s.can(PI, action) and not s.can(ADM, action) and not s.can(MEM, action)
    assert s.can(ADM, "add", "member") and not s.can(ADM, "add", "admin")
    assert s.can(ADM, "remove", "member") and not s.can(ADM, "remove", "admin")
    assert not s.can(PI, "remove", "pi")
    assert s.can(ADM, "invite", "member") and not s.can(ADM, "invite", "admin")
    assert s.can(PI, "invite", "admin")
    assert not s.can(PI, "leave") and s.can(ADM, "leave") and s.can(MEM, "leave")
    assert not s.can(OUT, "read")


# ------------------------------------------------------------- invite, join


def test_invite_and_join(w):
    auth, seed, iid = w.invite(ADM)
    w.apply(w.entry("invite", ADM, invite=iid))
    assert w.state.open_invites(w.t) == [iid]
    w.apply(w.join(MEM2, auth, seed))
    assert w.state.members[MEM2] == "member" and w.state.invites[iid]["uses"] == 1
    assert w.state.open_invites(w.t) == []


def test_roster_without_an_admission_check_refuses_invite_and_join(w):
    """The caller gives the admission checks (L4) to each state; nothing in
    the module gives a default. A state with no check refuses each `invite`
    and `join` entry, and has no open invites to show."""
    assert not hasattr(lab, "use_admission") and not hasattr(lab, "admission")
    auth, seed, iid = w.invite(ADM)
    invite = w.entry("invite", ADM, invite=iid)
    plain = w.state.copy()
    plain.admission = None
    with pytest.raises(FormatError, match="no admission check"):
        plain.apply(invite, w.device_ok, w.auths)
    assert iid not in plain.invites  # the state did not change
    w.apply(invite)
    join = w.join(MEM2, auth, seed)
    plain = w.state.copy()
    plain.admission = None
    with pytest.raises(FormatError, match="no admission check"):
        plain.apply(join, w.device_ok)
    with pytest.raises(FormatError, match="no admission check"):
        plain.open_invites(w.t)
    with pytest.raises(FormatError, match="no admission check"):
        lab.make_join_entry(state=plain, request=join["request"], role="member", at=w.t)
    with pytest.raises(FormatError, match="no admission check"):
        lab.validate_roster_entry(join, None)
    assert MEM2 not in plain.members
    w.apply(join)  # the same entry with the check
    assert w.state.members[MEM2] == "member"


def test_invite_rules(w):
    auth, _, iid = w.invite(ADM, role="admin")
    w.refused("invite", ADM, invite=iid)  # an admin invite needs the PI
    auth, _, iid = w.invite(MEM)
    w.refused("invite", MEM, invite=iid)  # a member cannot invite
    auth, _, iid = w.invite(PI)
    w.refused("invite", ADM, invite=iid)  # the authorisation is from another person
    w.auths.pop(iid)
    w.refused("invite", PI, invite=iid)  # no authorisation
    auth, _, iid = w.invite(PI, role="admin")
    w.apply(w.entry("invite", PI, invite=iid))
    w.refused("invite", PI, invite=iid)  # an ID one time only


def test_join_needs_invite_key(w):
    auth, seed, iid = w.invite(PI)
    w.apply(w.entry("invite", PI, invite=iid))
    entry = w.join(MEM2, auth, secrets.token_bytes(32))  # the node has no seed
    with pytest.raises(FormatError):
        w.apply(entry)
    good = w.join(MEM2, auth, seed)
    forged = dict(good)
    forged["request"] = {**good["request"], "subject": OUT}
    forged["actor"] = forged["subject"] = OUT
    with pytest.raises(FormatError):  # the signatures cover the subject
        w.apply(forged)
    w.apply(good)


def test_invite_use_limit_in_chain(w):
    auth, seed, iid = w.invite(PI, uses=2)
    w.apply(w.entry("invite", PI, invite=iid))
    w.apply(w.join(MEM2, auth, seed))
    w.apply(w.join(OUT, auth, seed))
    w.devices[pid(7)] = (k := SigningKey.generate()).public_bytes().hex()
    w.keys[pid(7)] = k
    with pytest.raises(FormatError):  # the third use
        w.apply(w.join(pid(7), auth, seed))


def test_replayed_join_refused(w):
    auth, seed, iid = w.invite(PI, uses=5)
    w.apply(w.entry("invite", PI, invite=iid))
    first = w.join(MEM2, auth, seed)
    w.apply(first)
    w.apply(w.entry("leave", MEM2))
    replay = lab.make_join_entry(state=w.state, request=first["request"], role="member", at=w.t)
    with pytest.raises(FormatError):  # the node cannot add the person again
        w.apply(replay)


def test_expired_invite_refused(w):
    auth, seed, iid = w.invite(PI, days=1)
    w.apply(w.entry("invite", PI, invite=iid))
    late = w.join(MEM2, auth, seed, at=w.t + timedelta(days=2))
    with pytest.raises(FormatError):
        w.apply(late)


def test_revoked_invite_refused(w):
    auth, seed, iid = w.invite(ADM)
    w.apply(w.entry("invite", ADM, invite=iid))
    w.refused("revoke_invite", MEM, invite=iid)
    w.apply(w.entry("revoke_invite", ADM, invite=iid))
    w.refused("revoke_invite", ADM, invite=iid)  # one time
    with pytest.raises(FormatError):
        w.apply(w.join(MEM2, auth, seed))


def test_admin_invite_revoke_needs_pi(w):
    auth, _, iid = w.invite(PI, role="admin")
    w.apply(w.entry("invite", PI, invite=iid))
    w.refused("revoke_invite", ADM, invite=iid)
    w.apply(w.entry("revoke_invite", PI, invite=iid))


def test_invite_of_a_removed_admin_stops(w):
    auth, seed, iid = w.invite(ADM)
    w.apply(w.entry("invite", ADM, invite=iid))
    w.apply(w.entry("role", PI, subject=ADM, role="member"))
    with pytest.raises(FormatError):  # the creator cannot invite now
        w.apply(w.join(MEM2, auth, seed))


def test_person_in_lab_cannot_join_again(w):
    auth, seed, iid = w.invite(PI)
    w.apply(w.entry("invite", PI, invite=iid))
    with pytest.raises(FormatError):
        w.apply(w.join(MEM, auth, seed))


def test_removed_member_cannot_join_again_with_the_same_link(w):
    """P0-3: a removal is final. The invite that the person used is revoked
    in the same entry, and no other invite takes the person back."""
    auth, seed, iid = w.invite(PI, uses=5)
    w.apply(w.entry("invite", PI, invite=iid))
    other, other_seed, other_iid = w.invite(PI, uses=5)
    w.apply(w.entry("invite", PI, invite=other_iid))
    w.apply(w.join(MEM2, auth, seed))
    w.apply(w.entry("remove", PI, subject=MEM2))
    assert MEM2 not in w.state.members and MEM2 in w.state.removed
    assert iid not in w.state.open_invites(w.t)  # no rotation wraps a new key to it
    assert other_iid in w.state.open_invites(w.t)
    with pytest.raises(FormatError):  # the same link, a new request
        w.apply(w.join(MEM2, auth, seed))
    with pytest.raises(FormatError):  # another open link
        w.apply(w.join(MEM2, other, other_seed))
    # The device of the removed person is barred under another person too.
    w.keys[OUT] = w.keys[MEM2]
    w.devices[OUT] = w.devices[MEM2]
    with pytest.raises(FormatError):
        w.apply(w.join(OUT, other, other_seed))
    # An explicit add by a PI or admin takes the person back.
    w.apply(w.entry("add", ADM, subject=MEM2, role="member"))
    assert MEM2 in w.state.members and MEM2 not in w.state.removed
    assert not w.state.barred


def test_remove_revokes_the_invites_of_the_removed_person(w):
    auth, seed, iid = w.invite(ADM, uses=5)
    w.apply(w.entry("invite", ADM, invite=iid))
    w.apply(w.entry("remove", PI, subject=ADM))
    assert w.state.invites[iid]["revoked"]
    w.apply(w.entry("add", PI, subject=ADM, role="admin"))  # back, but the link stays closed
    assert iid not in w.state.open_invites(w.t)
    with pytest.raises(FormatError):
        w.apply(w.join(MEM2, auth, seed))


def test_leave_is_not_a_bar(w):
    auth, seed, iid = w.invite(PI)
    w.apply(w.entry("invite", PI, invite=iid))
    w.apply(w.entry("leave", MEM))
    w.apply(w.join(MEM, auth, seed))
    assert MEM in w.state.members


def test_join_device_must_be_the_persons(w):
    auth, seed, iid = w.invite(PI)
    w.apply(w.entry("invite", PI, invite=iid))
    w.devices[MEM2] = SigningKey.generate().public_bytes().hex()  # not bound
    with pytest.raises(FormatError):
        w.apply(w.join(MEM2, auth, seed))


def test_invite_authorisation_form(w):
    auth, seed, _ = w.invite(PI)
    with pytest.raises(FormatError):
        admfmt.verify_lab_invite({**auth, "max_uses": 26})
    with pytest.raises(FormatError):
        admfmt.verify_lab_invite({**auth, "lab_name": "Other"})  # signature
    long = admfmt.make_lab_invite(
        seed=seed,
        node_url="https://n",
        node_key="ab" * 32,
        community="C",
        lab_id=LAB,
        lab_name="L",
        genesis=w.state.genesis,
        role="member",
        max_uses=1,
        expires_at=T0 + timedelta(days=30),
        created_by=PI,
        created_at=T0,
        key=w.keys[PI],
    )
    assert long["max_uses"] == 1
    with pytest.raises(FormatError):
        admfmt.make_lab_invite(
            seed=seed,
            node_url="https://n",
            node_key="ab" * 32,
            community="C",
            lab_id=LAB,
            lab_name="L",
            genesis=w.state.genesis,
            role="member",
            max_uses=1,
            expires_at=T0 + timedelta(days=31),
            created_by=PI,
            created_at=T0,
            key=w.keys[PI],
        )


def test_invite_link_round_trip(w):
    auth, seed, _ = w.invite(PI)
    url = admfmt.lab_invite_url(auth, seed)
    assert url.startswith("https://node.test/join#")
    got = admfmt.parse_lab_invite_link(url)
    assert got == {"auth": auth, "seed": seed.hex()}
    scheme = "anagram://join/" + url.split("#", 1)[1]
    assert admfmt.parse_lab_invite_link(scheme) == got
    other = admfmt.lab_invite_url(auth, secrets.token_bytes(32))
    with pytest.raises(FormatError):  # the seed does not give the keys
        admfmt.parse_lab_invite_link(other)
    with pytest.raises(FormatError):
        admfmt.parse_lab_invite_link(url[:-6])


def test_node_invite_link_is_refused():
    node_inv = make_invite(
        node_url="https://node.test",
        node_key="ab" * 32,
        community="C",
        token=secrets.token_bytes(32),
        expires_at=T0,
        assertion_key=SigningKey.generate(),
    )
    with pytest.raises(FormatError):
        admfmt.parse_lab_invite_link(invite_url(node_inv))


# ------------------------------------------------------------------ vectors


def test_vectors_round_trip():
    r = VEC["roster"]
    devices = r["devices"]
    st = lab.replay(
        VEC["lab_id"],
        r["entries"],
        lambda s, d, a: devices.get(s) == d,
        r["auths"],
        admission=GroupAdmission(),
    )
    assert st.head == r["state"]["head"] and st.genesis == r["state"]["genesis"]
    assert st.members == r["state"]["members"] and st.name == r["state"]["name"]
    assert [lab.entry_hash(e) for e in r["entries"]] == r["hashes"]
    inv = VEC["invite"]
    assert admfmt.parse_lab_invite_link(inv["link"]) == {"auth": inv["auth"], "seed": inv["seed"]}
    assert admfmt.lab_invite_id(inv["auth"]) == inv["id"]
    admfmt.verify_join_request(inv["request"], inv["auth"])
    for pid_, seed in VEC["signing_seeds"].items():
        assert SigningKey.from_seed(bytes.fromhex(seed)).public_bytes().hex() == devices[pid_]


# ------------------------------------------------- S1b: key package, item, settings


def _device() -> tuple[dict, bytes]:
    from anagram.core.crypto import hpke

    sk = SigningKey.generate()
    x = hpke.generate()
    return (
        {"ed25519": sk.public_bytes().hex(), "x25519": hpke.public_bytes(x).hex()},
        hpke.private_bytes(x),
    )


def _package(w, keys, devices, sender=PI, recipient=MEM, epoch=None):
    return labkey.make_key_package(
        lab_id=LAB,
        epoch=epoch or max(keys),
        keys=keys,
        recipient=recipient,
        devices=devices,
        roster_seq=w.state.seq,
        roster_head=w.state.head,
        sender=sender,
        key=w.keys[sender],
        created_at=T0,
    )


def test_key_package_round_trip(w):
    keys = {1: secrets.token_bytes(32), 2: secrets.token_bytes(32)}
    (d1, x1), (d2, x2) = _device(), _device()
    pkg = _package(w, keys, [d1, d2])
    assert labkey.open_key_package(pkg, device=d1["ed25519"], private_x25519=x1) == keys
    assert labkey.open_key_package(pkg, device=d2["ed25519"], private_x25519=x2) == keys
    other, xo = _device()
    with pytest.raises(FormatError):  # no wrap for this device
        labkey.open_key_package(pkg, device=other["ed25519"], private_x25519=xo)
    with pytest.raises(FormatError):  # a wrap for another device does not open with this key
        labkey.open_key_package(pkg, device=d1["ed25519"], private_x25519=x2)
    with pytest.raises(FormatError):  # the signature covers the epoch and the head
        labkey.open_key_package({**pkg, "roster_seq": 0}, device=d1["ed25519"], private_x25519=x1)


def test_key_package_needs_all_epochs(w):
    d, _ = _device()
    with pytest.raises(FormatError):
        _package(w, {2: secrets.token_bytes(32)}, [d], epoch=2)
    with pytest.raises(FormatError):
        _package(w, {1: b"short"}, [d])


def test_invite_key_package(w):
    auth, seed, iid = w.invite(PI)
    sign, kem = admfmt.invite_keys(seed)
    dev = {"ed25519": auth["invite_pub"], "x25519": auth["invite_x25519"]}
    keys = {1: secrets.token_bytes(32)}
    pkg = _package(w, keys, [dev], recipient=labkey.invite_recipient(iid))
    assert pkg["recipient"] == "invite:" + iid
    assert labkey.open_key_package(pkg, device=auth["invite_pub"], private_x25519=kem) == keys


def test_lab_store_keys_keep_record_ids_over_epochs():
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    e1, e2 = labkey.LabStoreKeys(k1, k1), labkey.LabStoreKeys(k2, k1)
    assert e1.record_id("lab_item", "a" * 32) == e2.record_id("lab_item", "a" * 32)
    assert e1.key_id != e2.key_id and e1.enc != e2.enc


def _item(w, **kw):
    args = dict(
        lab_id=LAB,
        item_id="ab" * 16,
        rev=1,
        kind="note",
        title="Notes on PCR",
        text="text",
        author=MEM,
        key=w.keys[MEM],
        roster=lab.roster_ref(w.state),
        published_at=T0,
        updated_at=T0,
    )
    args.update(kw)
    return labitem.make_lab_item(**args)


def test_lab_item_round_trip(w):
    item = _item(w, facts=[{"kind": "method", "value": "PCR", "score": None}])
    assert labitem.verify_lab_item(item) is item
    assert item["text_digest"] == labitem.text_digest("text") and item["text_parts"] == 1
    with pytest.raises(FormatError):  # the signature covers the title
        labitem.verify_lab_item({**item, "title": "Other"})
    for bad in (
        {**item, "kind": "secret"},
        {**item, "origin": {**item["origin"], "path": "/x"}},
        {**item, "facts": [{"kind": "k", "value": "v", "score": 0.5}]},
        {**item, "extra": 1},
    ):
        with pytest.raises(FormatError):
            labitem.validate_lab_item(bad)


def test_removed_item_has_no_content(w):
    gone = _item(w, text="", deleted=True)
    assert gone["deleted"] and gone["text_parts"] == 0
    with pytest.raises(FormatError):
        _item(w, text="still here", deleted=True)


def test_text_parts():
    big = "é" * (labitem.MAX_TEXT_PART // 2 + 10)  # two bytes each: over 1 MiB
    parts = labitem.split_text(big)
    assert len(parts) == 2 and "".join(parts) == big
    assert all(len(p.encode()) <= labitem.MAX_TEXT_PART for p in parts)
    assert labitem.split_text("") == []


def _settings(w, sections, who=PI, rev=1):
    return labsettings.make_settings(
        lab_id=LAB,
        rev=rev,
        sections=sections,
        updated_by=who,
        key=w.keys[who],
        roster=lab.roster_ref(w.state),
        updated_at=T0,
    )


def test_settings_defaults():
    got = labsettings.sections_of(None)
    assert got == {
        "models": {"profiles": [], "use": {}, "kind_hints": [], "person_facts": True},
        "disclosure": {"allow_external": [], "allow_assistant": False},
        "oauth_clients": {},
        "sources": {"allowed_kinds": None, "lab_default": "private"},
        "matching": {"enabled": True},
    }


def test_settings_round_trip(w):
    doc = _settings(
        w,
        {
            "models": {"use": {"draft": None}, "kind_hints": [{"text": "SOP", "kind": "protocol"}]},
            "disclosure": {"allow_external": ["model:abc"]},
            "oauth_clients": {"google": {"client_id": "id.apps", "client_secret": "s"}},
            "sources": {"allowed_kinds": ["folder"], "lab_default": "lab"},
            "matching": {"enabled": False},
        },
    )
    assert labsettings.verify_settings(doc) is doc
    got = labsettings.sections_of(doc)
    assert got["matching"] == {"enabled": False}
    assert got["models"]["person_facts"] is True  # an absent key takes its default
    assert got["disclosure"] == {"allow_external": ["model:abc"], "allow_assistant": False}
    with pytest.raises(FormatError):
        labsettings.verify_settings({**doc, "rev": 2})


@pytest.mark.parametrize(
    "section,value",
    [
        ("models", {"profile": []}),
        ("models", {"kind_hints": [{"text": "a", "kind": "b", "x": 1}]}),
        ("disclosure", {"allow_all": True}),
        ("oauth_clients", {"dropbox": {"client_id": "x"}}),
        ("oauth_clients", {"google": {"client_id": "x", "scope": "all"}}),
        ("sources", {"lab_default": "public"}),
        ("sources", {"kinds": []}),
        ("matching", {"enabled": True, "round": 1}),
        ("matching", {"enabled": "yes"}),
    ],
)
def test_each_section_refuses_unknown_keys(section, value):
    with pytest.raises(FormatError):
        labsettings.validate_section(section, value)


def test_settings_refuse_unknown_section(w):
    doc = _settings(w, {})
    with pytest.raises(FormatError):
        labsettings.validate_settings({**doc, "budget": {}})


def test_space_vectors_round_trip():
    from anagram.identity.formats.personal_store import open_record

    v = VEC["space"]
    ek = {int(n): bytes.fromhex(k) for n, k in v["epoch_keys"].items()}
    keys = labkey.LabStoreKeys(ek[2], ek[1])
    kind, ref, value = open_record(keys, v["item"]["record"])
    assert (kind, ref, value) == (
        labitem.KIND_ITEM,
        v["item"]["value"]["item_id"],
        v["item"]["value"],
    )
    labitem.verify_lab_item(value)
    _, _, part = open_record(keys, v["item"]["text_record"])
    assert labitem.text_digest(part["text"]) == value["text_digest"]
    kind, ref, value = open_record(keys, v["settings"]["record"])
    assert (kind, ref) == (labsettings.KIND_SETTINGS, labsettings.SETTINGS_REF)
    assert labsettings.sections_of(labsettings.verify_settings(value)) == v["settings"]["sections"]
    kp = v["key_package"]
    assert (
        labkey.lab_key_info(VEC["lab_id"], kp["epoch"], bytes.fromhex(kp["device"])).hex()
        == (kp["info_hex"])
    )
