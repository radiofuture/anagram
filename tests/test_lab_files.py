"""Attachments of lab items (plan R2, step S10): encrypted blobs that only
lab members read, with no read receipt; a removed item deletes its blobs."""

from __future__ import annotations

import hashlib

import pytest

from anagram.core.nodeapi import NodeHTTPError
from anagram.network.groups.app.labrecords import LabItemDraft, SpaceRecord
from anagram.network.groups.app.labroster import LabError

ORIGIN = {"source_kind": "folder", "name": "gel.png", "media_type": "image/png"}


@pytest.fixture
def lab2(net, tmp_path):
    pi, mem, out = (
        net.join(tmp_path / n, f"fake-{n}").client for n in ("f-pi", "f-member", "f-outside")
    )
    lab_id = pi.labs.lab_create("Files Lab")["lab_id"]
    pi.labs.lab_add(lab_id, mem.device.subject)
    return lab_id, pi, mem, out


def _file(tmp_path, name: str, size: int):
    data = bytes((i * 7) % 251 for i in range(size))
    path = tmp_path / name
    path.write_bytes(data)
    return path, data


def test_member_downloads_and_the_digest_matches(net, lab2, tmp_path):
    lab_id, pi, mem, out = lab2
    path, data = _file(tmp_path, "gel.png", 2_500_000)  # three chunks
    item_id = pi.lab_space.lab_publish(
        lab_id, LabItemDraft("note", "Gel image", "Lane 3", ORIGIN, files=(path,))
    )
    mem.labs.lab_sync(lab_id)
    name, media, got = mem.lab_space.lab_file(lab_id, item_id, 0)  # no read receipt in a lab
    assert (name, media) == ("gel.png", "image/png")
    assert hashlib.sha256(got).digest() == hashlib.sha256(data).digest()
    # The node holds ciphertext only.
    [att] = mem.lab_space.lab_item(lab_id, item_id)["item"]["attachments"]
    stored = (net.vault.blob_dir / att["blob_id"]).read_bytes()
    assert data[:4096] not in stored
    # A revision with no files keeps the files.
    pi.lab_space.lab_publish(
        lab_id, LabItemDraft("note", "Gel image", "Lane 3 and 4", ORIGIN, item_id=item_id)
    )
    mem.labs.lab_sync(lab_id)
    assert mem.lab_space.lab_file(lab_id, item_id, 0)[2] == data
    with pytest.raises(LabError):
        mem.lab_space.lab_file(lab_id, item_id, 1)


def test_outsider_and_removed_member_get_404(net, lab2, tmp_path):
    lab_id, pi, mem, out = lab2
    path, _ = _file(tmp_path, "data.csv", 1000)
    item_id = pi.lab_space.lab_publish(
        lab_id, LabItemDraft("note", "Data", "", ORIGIN, files=(path,))
    )
    blob = pi.lab_space.lab_item(lab_id, item_id)["item"]["attachments"][0]["blob_id"]
    with pytest.raises(NodeHTTPError) as err:
        out.device.http.call("GET", f"/blobs/{blob}", auth=True)
    assert err.value.status == 404
    mem.labs.lab_sync(lab_id)
    assert mem.device.http.call("GET", f"/blobs/{blob}", auth=True)
    pi.labs.lab_remove(lab_id, mem.device.subject)
    with pytest.raises(NodeHTTPError) as err:
        mem.device.http.call("GET", f"/blobs/{blob}", auth=True)
    assert err.value.status == 404


def test_tombstone_deletes_the_blob(net, lab2, tmp_path):
    lab_id, pi, mem, _ = lab2
    path, _ = _file(tmp_path, "notes.txt", 100)
    item_id = mem.lab_space.lab_publish(
        lab_id, LabItemDraft("note", "Notes", "x", ORIGIN, files=(path,))
    )
    blob = mem.lab_space.lab_item(lab_id, item_id)["item"]["attachments"][0]["blob_id"]
    assert net.vault.blob_owner(blob) == mem.device.subject
    pi.labs.lab_sync(lab_id)
    pi.lab_space.lab_unpublish(lab_id, item_id)  # the PI removes an item of a member
    assert net.vault.blob_owner(blob) is None
    assert not (net.vault.blob_dir / blob).exists()


def test_a_record_cannot_list_the_blob_of_another_person(net, lab2, tmp_path):
    """A member must not open a private blob of another person by listing
    it in a lab record."""
    lab_id, pi, mem, out = lab2
    blob = "ab" * 16
    out.device.http.call("PUT", f"/blobs/{blob}", b"private ciphertext", auth=True)
    sk = mem.lab_space.writer(lab_id)[1]
    with pytest.raises(NodeHTTPError) as err:
        rec = SpaceRecord("lab_item_text", "x" * 32 + ":0", {"text": "t"}, 1, blobs=(blob,))
        mem.lab_space.put_record(lab_id, sk, rec)
    assert err.value.status in (400, 403)
    with pytest.raises(NodeHTTPError):
        mem.device.http.call("GET", f"/blobs/{blob}", auth=True)


def test_ui_route_gives_the_file(tmp_path):
    from conftest import make_net
    from test_ui_api import ORIGIN as UI_ORIGIN
    from test_ui_api import join_via_ui, launched, ui_client

    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "pi")
    launched(tc)
    join_via_ui(net, svc, tc, "fake-0000-0001-files", "Mei-Lin Chen")
    lab = tc.post("/api/labs", json={"name": "Chen Lab"}, headers=UI_ORIGIN).json()["id"]
    path, data = _file(tmp_path, 'odd "name";.txt', 300)
    with svc.session() as c:
        item_id = c.lab_space.lab_publish(
            lab, LabItemDraft("note", "Odd", "", ORIGIN, files=(path,))
        )
    detail = tc.get(f"/api/labs/{lab}/space/{item_id}").json()
    assert detail["attachments"] == [
        {"media_type": "text/plain", "n": 0, "name": 'odd "name";.txt', "size": 300}
    ]
    assert detail["item"]["attachments"] == 1
    assert "blob_id" not in str(detail) and "content_key" not in str(detail)
    r = tc.get(f"/api/labs/{lab}/space/{item_id}/files/0")
    assert r.status_code == 200 and r.content == data
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-disposition"].startswith('attachment; filename="odd name.txt"')
    assert tc.get(f"/api/labs/{lab}/space/{item_id}/files/3").status_code == 400
