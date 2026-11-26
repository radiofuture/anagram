"""Lab space records (plan R2, step S5): publish, read, revise, tombstone,
node holds no plaintext, non-member author, fork alert, quota."""

from __future__ import annotations

import copy

import pytest

from anagram.core.errors import LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.formats.personal_store import seal_record
from anagram.network.formats import lab, labitem, labkey
from anagram.network.groups.app.labrecords import LabItemDraft
from anagram.network.groups.app.labroster import LabError

ORIGIN = {"source_kind": "folder", "name": "notes.md", "media_type": "text/markdown"}


def note(title: str, text: str, **kw) -> LabItemDraft:
    return LabItemDraft(kind="note", title=title, text=text, origin=ORIGIN, **kw)


@pytest.fixture
def lab3(net, tmp_path):
    pi, ad, mem = (
        net.join(tmp_path / n, f"fake-{n}").client for n in ("sp-pi", "sp-admin", "sp-member")
    )
    lab_id = pi.labs.lab_create("Space Lab")["lab_id"]
    pi.labs.lab_add(lab_id, ad.device.subject, role="admin")
    pi.labs.lab_add(lab_id, mem.device.subject)
    return lab_id, pi, ad, mem


def test_publish_and_read_by_another_member(net, lab3):
    lab_id, pi, ad, mem = lab3
    item_id = mem.lab_space.lab_publish(
        lab_id, note("Kinase screen", "# Result\nThe screen found 3 hits.", type="result")
    )
    out = pi.labs.lab_sync(lab_id)["labs"][lab_id]
    assert out["items"] == 1
    [row] = pi.lab_space.lab_items(lab_id)
    assert row["item_id"] == item_id and row["title"] == "Kinase screen"
    assert row["author"] == mem.device.subject and row["type"] == "result" and row["rev"] == 1
    got = pi.lab_space.lab_item(lab_id, item_id)
    assert got["text"] == "# Result\nThe screen found 3 hits."
    assert pi.labs.lab_sync(lab_id)["labs"][lab_id]["items"] == 0  # safe to run again
    # A new revision by the author replaces the old one.
    mem.lab_space.lab_publish(lab_id, note("Kinase screen v2", "Four hits.", item_id=item_id))
    ad.labs.lab_sync(lab_id)
    assert ad.lab_space.lab_item(lab_id, item_id)["item"]["rev"] == 2
    assert ad.lab_space.lab_item(lab_id, item_id)["text"] == "Four hits."
    # Another member cannot change the item.
    pi.labs.lab_sync(lab_id)
    with pytest.raises(LabError):
        pi.lab_space.lab_publish(lab_id, note("Mine now", "x", item_id=item_id))


def test_text_over_one_mib_in_parts(net, lab3):
    lab_id, pi, _, mem = lab3
    text = ("é" * 400_000) + "\n" + ("data line\n" * 160_000)
    assert len(text.encode()) > 2 * labitem.MAX_TEXT_PART
    item_id = mem.lab_space.lab_publish(lab_id, note("Big", text))
    pi.labs.lab_sync(lab_id)
    got = pi.lab_space.lab_item(lab_id, item_id)
    assert got["text"] == text and got["item"]["text_parts"] == 3


def test_tombstone_by_author_and_by_admin(net, lab3):
    lab_id, pi, ad, mem = lab3
    a = mem.lab_space.lab_publish(lab_id, note("A", "text a"))
    b = mem.lab_space.lab_publish(lab_id, note("B", "text b"))
    c = ad.lab_space.lab_publish(lab_id, note("C", "text c"))
    mem.lab_space.lab_unpublish(lab_id, a)
    ad.labs.lab_sync(lab_id)
    ad.lab_space.lab_unpublish(lab_id, b)  # an admin removes an item of another person
    mem.labs.lab_sync(lab_id)
    with pytest.raises(LabError):
        mem.lab_space.lab_unpublish(lab_id, c)  # a member cannot
    pi.labs.lab_sync(lab_id)
    assert [x["item_id"] for x in pi.lab_space.lab_items(lab_id)] == [c]
    with pytest.raises(LabError):
        pi.lab_space.lab_item(lab_id, a)
    # The node deleted the text records of the removed items.
    n = net.labs._db.execute("SELECT COUNT(*) FROM lab_records WHERE lab_id = ?", (lab_id,))
    assert n.fetchone()[0] == 4  # three item records and the text of C


def test_node_holds_no_plaintext(net, lab3):
    lab_id, pi, _, mem = lab3
    mem.lab_space.lab_publish(
        lab_id, note("Unpublished Zebrafish Title", "Secret body of the zebrafish")
    )
    pi.labs.lab_sync(lab_id)
    raw = b"".join(p.read_bytes() for p in net.home.dir.rglob("*") if p.is_file())
    for word in (b"Zebrafish", b"zebrafish", b"notes.md"):
        assert word not in raw


def test_record_from_a_non_member_author_is_dropped(net, lab3, tmp_path):
    lab_id, pi, _, mem = lab3
    outsider = net.join(tmp_path / "out", "fake-sp-out").client
    # The outsider has the keys (a node fault gives them) and writes an item.
    keys = {n: pi.lab_keys.lab_key(lab_id, n)[1] for n in (1,)}
    state = pi.lab_roster.lab_state(lab_id)
    value = labitem.make_lab_item(
        lab_id=lab_id,
        item_id="ab" * 16,
        rev=1,
        kind="note",
        title="Forged",
        text="",
        author=outsider.device.subject,
        key=outsider.device.device_key(),
        roster=lab.roster_ref(state),
        published_at=pi.device.now(),
        updated_at=pi.device.now(),
    )
    sk = labkey.LabStoreKeys(keys[1], keys[1])
    doc = seal_record(sk, labitem.KIND_ITEM, value["item_id"], value, 1)
    real = pi.device.http.transport

    def inject(method, path, body, headers=None):
        out = real(method, path, body, headers)
        if method == "GET" and "/space/records?" in path:
            out = copy.deepcopy(out)
            out["records"].append({"author": outsider.device.subject, "change": 999, "record": doc})
            out["next"] = 999
        return out

    pi.device.http.transport = inject
    assert pi.labs.lab_sync(lab_id)["labs"][lab_id]["items"] == 0
    assert pi.lab_space.lab_items(lab_id) == []


def test_fork_detected_from_record_head(net, lab3):
    lab_id, pi, _, mem = lab3
    mem.lab_space.lab_publish(lab_id, note("A", "a"))
    keys = pi.lab_keys.lab_key(lab_id, 1)[1]
    sk = labkey.LabStoreKeys(keys, keys)
    state = mem.lab_roster.lab_state(lab_id)
    # A member item that names a roster head that is not in the chain.
    value = labitem.make_lab_item(
        lab_id=lab_id,
        item_id="cd" * 16,
        rev=1,
        kind="note",
        title="Fork",
        text="",
        author=mem.device.subject,
        key=mem.device.device_key(),
        roster={"head": "ee" * 32, "seq": state.seq},
        published_at=mem.device.now(),
        updated_at=mem.device.now(),
    )
    doc = seal_record(sk, labitem.KIND_ITEM, value["item_id"], value, 1)
    mem.device.http.call(
        "PUT", f"/labs/{lab_id}/space/records/{doc['record_id']}", {"record": doc}, auth=True
    )
    with pytest.raises(LogMisbehaved, match="fork"):
        pi.labs.lab_sync(lab_id)


def test_quota_and_non_member(net, lab3, tmp_path):
    lab_id, pi, _, mem = lab3
    net.labs.quota = 1000
    net.labs._db.execute("UPDATE lab_host SET quota = 1000 WHERE lab_id = ?", (lab_id,))
    with pytest.raises(LabError, match="lab space is full") as err:
        mem.lab_space.lab_publish(lab_id, note("Big", "x" * 5000))
    assert isinstance(err.value.__cause__, NodeHTTPError) and err.value.__cause__.status == 413
    outsider = net.join(tmp_path / "out2", "fake-sp-out2").client
    with pytest.raises(NodeHTTPError) as err:
        outsider.device.http.call("GET", f"/labs/{lab_id}/space/records?after=0", auth=True)
    assert err.value.status == 404


def test_removed_member_writes_no_new_records(net, lab3):
    lab_id, pi, _, mem = lab3
    mem.lab_keys.lab_key(lab_id)
    pi.labs.lab_remove(lab_id, mem.device.subject)
    with pytest.raises(LabError):
        mem.lab_space.lab_publish(lab_id, note("After", "text"))
    # New items use the new epoch: the old key does not open them.
    item_id = pi.lab_space.lab_publish(lab_id, note("New", "new text"))
    rows = net.labs._db.execute(
        "SELECT doc FROM lab_records WHERE lab_id = ?", (lab_id,)
    ).fetchall()
    old = labkey.LabStoreKeys(
        mem.lab_keys.epoch_keys(lab_id)[1], mem.lab_keys.epoch_keys(lab_id)[1]
    )
    assert item_id and all(old.key_id not in r[0] for r in rows)
