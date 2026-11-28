"""v2 fix 1: the data that makes proofs work goes with the person.

A lost laptop must not make proofs worthless. The vault records and an index
snapshot go to the personal store on the node (ciphertext only). A recovery
(kit or guardians) restores the keys, then the store. A second device gets the
person keys by HPKE. No network.
"""

from __future__ import annotations

import base64
import copy
import shutil
from datetime import UTC, datetime

import pytest

from anagram.admission.app.join import node_of
from anagram.core.crypto import hpke
from anagram.core.crypto.chunked import ContentDigest, hash_file
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.app import guardians as g
from anagram.identity.app.kit import recover
from anagram.identity.formats.personal_store import (
    StoreKeys,
    make_person_keys,
    open_person_keys,
    open_record,
    seal_record,
    validate_record,
)
from anagram.identity.node.store import NodePersonalStore
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.proofs.proof import verify_bundle
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")

CLAIM = "CANARY-STORE-CLAIM-7731: NBT7 binds at 2.9 A"


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_lab(tmp_path):
    lab = tmp_path / "lab-files"  # outside the client home: the files survive
    lab.mkdir()
    (lab / "notes.md").write_text("# Notes\n\nCANARY-STORE-NOTE-4410 we need cryo-EM time.\n")
    (lab / "data.csv").write_text("a,b\n1,2\n")
    return lab


def device_a(net, tmp_path):
    """Device A: a finding, a second finding, and one source checkpoint."""
    r = net.join(tmp_path / "laptop", "fake-chen", "Mei Chen")
    a = r.client
    lab = make_lab(tmp_path)
    bundle = a.findings.commit_finding([lab / "notes.md"], claim=CLAIM)
    a.findings.commit_finding([lab / "data.csv"])
    idx = LocalIndex.for_client(a, clock=net.clock)
    sid = idx.add_source(FolderConnector(lab))
    idx.scan()
    assert idx.streams.checkpoint(a, sid) is not None
    idx.close()
    a.grants.ring_create("lab")
    out = a.personal.sync_store(snapshot=True)
    assert out["snapshots"]["index"] == "sent"
    return r, bundle.subject.root.hex(), sid, lab


def check_restored(net, b, root, sid, lab):
    """Old proofs work on the new device: the finding and a source item."""
    assert root in {f["root"] for f in b.findings.list_findings()}
    report = verify_bundle(b.findings.public_bundle(root, ["claim"]), b.device.trust())
    assert report.ok, report.summary()
    proof = b.findings.prove_file(root, lab / "notes.md")
    assert verify_bundle(proof, b.device.trust(), [lab / "notes.md"]).ok
    assert b.findings.opening(root).finding.fields["claim"] == CLAIM
    idx = LocalIndex.for_client(b, clock=net.clock)
    try:
        report, items_ok = idx.streams.verify_checkpoint(b, sid, 0)
        assert report.ok and items_ok, report.summary()
        item = next(i for i in idx.items(sid) if i.name == "notes.md")
        opening = idx.evidence_opening(sid, item.key)
        committed = ContentDigest.from_json(opening.fields["content"])
        assert hash_file(lab / "notes.md", committed.chunk_size).digest == committed.digest
        assert opening.root().hex() in idx.streams.checkpoints(sid)[0]["item_roots"]
    finally:
        idx.close()
    assert [r["name"] for r in b.grants.ring_list()] == ["lab"]


def test_lost_laptop_recovery_kit_restores_proofs(net, tmp_path):
    r, root, sid, lab = device_a(net, tmp_path)
    kit = r.kit_text
    subject = r.subject
    r.client.vault.close()
    shutil.rmtree(tmp_path / "laptop")  # the laptop is gone
    b = recover(
        tmp_path / "new-laptop",
        kit,
        transport=net.transport,
        clock=net.clock,
        open_home=Client.open,
    )
    assert b.device.subject == subject
    assert b.personal.last_restore["status"] == "restored"
    assert b.personal.last_restore["snapshots"]["index"] == "restored"
    assert b.account.orcid == "fake-chen"  # the ORCID opening came back from the store
    check_restored(net, b, root, sid, lab)
    # The restore needs no ORCID step: the restored device key signed in.
    assert b.account.whoami()["subject"] == subject


def test_lost_laptop_guardians_restore_proofs(net, tmp_path):
    guardians = [net.join(tmp_path / n, f"fake-{n}").client for n in ("okafor", "varga")]
    r, root, sid, lab = device_a(net, tmp_path)
    r.client.guardians.guardians_set([net.sid("fake-okafor"), net.sid("fake-varga")], threshold=2)
    r.client.vault.close()
    shutil.rmtree(tmp_path / "laptop")
    home = tmp_path / "new-laptop"
    rid = g.start_guardian_recovery(
        home,
        **node_of(net.invite()),
        transport=net.transport,
        browser=net.browser(),
        login_hint="fake-chen",
        clock=net.clock,
    )
    for guardian in guardians:
        guardian.guardians.guardian_approve(rid)
    b = g.finish_guardian_recovery(
        home, transport=net.transport, clock=net.clock, open_home=Client.open
    )
    assert b.personal.last_restore["status"] == "restored"
    check_restored(net, b, root, sid, lab)


def test_node_holds_only_ciphertext(net, tmp_path):
    r, root, sid, lab = device_a(net, tmp_path)
    a = r.client
    raw = (net.home.dir / "store.sqlite").read_bytes()
    doc = a.findings.opening(root)
    secrets_ = [
        CLAIM.encode(),
        b"CANARY-STORE-NOTE-4410",
        b"notes.md",
        str(lab).encode(),
        a.keystore.get("vault-key").hex().encode(),
        a.keystore.get("index-key").hex().encode(),
        b"fake-chen",
    ]
    for f in doc.finding.fields:
        secrets_.append(doc.finding.salts[f].hex().encode())
    for s in secrets_:
        assert s not in raw
    listing = a.device.http.call("GET", "/store/records", auth=True)
    assert listing["used"] > 0 and listing["records"]
    for item in listing["records"]:
        assert set(item) == {"record_id", "size", "version"}
    # Records are padded: the node sees sizes in steps only.
    for item in listing["records"]:
        assert (item["size"] - 16) % 512 == 0


def test_second_device_gets_person_keys_and_records(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two", invite=link).client
    lab = make_lab(tmp_path)
    root = first.findings.commit_finding([lab / "notes.md"], claim=CLAIM).subject.root.hex()
    r = net.join(tmp_path / "desktop", "fake-two", invite=link)
    assert r.status == "pending_device"
    assert r.client.keystore.get("vault-key") != first.keystore.get("vault-key")
    first.account.add_device(r.device_request)
    r2 = net.join(tmp_path / "desktop", "fake-two", invite=link)
    second = r2.client
    assert second.keystore.get("vault-key") == first.keystore.get("vault-key")
    assert second.keystore.get("index-key") == first.keystore.get("index-key")
    assert second.findings.opening(root).finding.fields["claim"] == CLAIM
    assert verify_bundle(second.findings.bundle(root), second.device.trust()).ok
    # The new kit of the second device holds the person keys too.
    assert "Recovery code" in r2.kit_text
    # A finding of the second device reaches the first device.
    root2 = second.findings.commit_finding([lab / "data.csv"]).subject.root.hex()
    assert first.personal.sync_store(snapshot=False)["pulled"] >= 1
    assert first.findings.bundle(root2).subject.root.hex() == root2


def test_person_keys_from_a_foreign_device_are_refused(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two", invite=link).client
    r = net.join(tmp_path / "desktop", "fake-two", invite=link)
    first.account.add_device(r.device_request)
    second = net.join(tmp_path / "desktop", "fake-two", invite=link).client
    # The node swaps in a package that a key it holds signed.
    evil_key = SigningKey.generate()
    me = second.device.my_device()
    evil = make_person_keys(
        subject=second.device.subject,
        recipient=me,
        keys={"index-key": b"\1" * 32, "vault-key": b"\2" * 32},
        created_at=second.device.now(),
        sender=evil_key,
    )

    def swap(method, path, body, headers=None):
        if method == "GET" and path.startswith("/store/person-keys/"):
            return {"package": evil}
        return net.transport(method, path, body, headers)

    second.device.http.transport = swap
    with pytest.raises(LogMisbehaved, match="not active"):
        second.personal.adopt_person_keys()


def test_person_keys_package_format():
    sender = SigningKey.generate()
    x = hpke.generate()
    me = {"ed25519": "ab" * 32, "x25519": hpke.public_bytes(x).hex()}
    subject = "pid:" + "cd" * 16
    keys = {"index-key": b"\1" * 32, "vault-key": b"\2" * 32}
    pkg = make_person_keys(
        subject=subject,
        recipient=me,
        keys=keys,
        created_at=datetime(2026, 10, 27, tzinfo=UTC),
        sender=sender,
    )
    assert open_person_keys(pkg, x, me["ed25519"], subject) == keys
    with pytest.raises(FormatError, match="another"):
        open_person_keys(pkg, x, "ef" * 32, subject)
    bad = copy.deepcopy(pkg)
    bad["created_at"] = "2030-01-01T00:00:00Z"
    with pytest.raises(FormatError, match="signature"):
        open_person_keys(bad, x, me["ed25519"], subject)
    with pytest.raises(FormatError):
        open_person_keys(pkg, hpke.generate(), me["ed25519"], subject)


def test_store_records_reject_changes():
    keys = StoreKeys(b"\7" * 32)
    doc = seal_record(keys, "finding", "r1", {"x": 1}, 3)
    assert open_record(keys, doc) == ("finding", "r1", {"x": 1})
    assert keys.record_id("finding", "r1") == doc["record_id"]
    assert keys.record_id("finding", "r2") != doc["record_id"]
    for field, value in (("version", 4), ("record_id", "00" * 16), ("key_id", "00" * 8)):
        bad = {**doc, field: value}
        with pytest.raises(FormatError):
            open_record(keys, bad)
    ct = bytearray(base64.b64decode(doc["ciphertext"]))
    ct[0] ^= 1
    with pytest.raises(FormatError):
        open_record(keys, {**doc, "ciphertext": base64.b64encode(bytes(ct)).decode()})
    with pytest.raises(FormatError):
        open_record(StoreKeys(b"\x09" * 32), doc)  # another vault key
    with pytest.raises(FormatError):
        validate_record({**doc, "extra": 1})
    with pytest.raises(FormatError):
        seal_record(keys, "finding", "r1", {"x": 1}, 0)


def test_store_node_rules(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    b = net.join(tmp_path / "b", "fake-bob").client
    keys = StoreKeys(a.keystore.get("vault-key"))
    doc = seal_record(keys, "ring", "x", {"members": []}, 2)
    rid = doc["record_id"]
    path = f"/store/records/{rid}"
    assert (
        net.tc.put(path, json={"record": doc}, headers=auth(a.device.http.token)).status_code == 200
    )
    # The same record again is fine; an older or equal version is refused.
    assert (
        net.tc.put(path, json={"record": doc}, headers=auth(a.device.http.token)).status_code == 200
    )
    older = seal_record(keys, "ring", "x", {"members": ["y"]}, 2)
    assert (
        net.tc.put(path, json={"record": older}, headers=auth(a.device.http.token)).status_code
        == 409
    )
    # A record ID in the path that differs from the record is refused.
    r = net.tc.put(
        "/store/records/" + "0" * 32, json={"record": doc}, headers=auth(a.device.http.token)
    )
    assert r.status_code == 400
    # Each person sees only their own records. No session: 401.
    assert net.tc.get(path, headers=auth(b.device.http.token)).status_code == 404
    assert net.tc.get(path).status_code == 401
    assert rid not in {
        x["record_id"] for x in b.device.http.call("GET", "/store/records", auth=True)["records"]
    }
    # A person who signed in but never claimed an invite is not a member.
    start = net.tc.post(
        "/auth/email/start",
        json={"device_key": "11" * 32, "email": "x@example.org", "nonce": "22" * 16},
    ).json()
    code = net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]
    outsider = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": code}
    ).json()["session"]["token"]
    assert net.tc.get("/store/records", headers=auth(outsider)).status_code == 403
    # Quota.
    small = NodePersonalStore(tmp_path / "small.sqlite", net.identity, quota=100)
    with pytest.raises(Exception, match="quota"):
        small.put(a.device.subject, rid, doc)
    # Delete.
    assert net.tc.delete(path, headers=auth(a.device.http.token)).status_code == 200
    assert net.tc.get(path, headers=auth(a.device.http.token)).status_code == 404


def test_sync_is_incremental_and_snapshot_replaces_old_chunks(net, tmp_path):
    r, root, sid, lab = device_a(net, tmp_path)
    a = r.client
    again = a.personal.sync_store(snapshot=True)
    assert again["pushed"] == 0 and again["snapshots"]["index"] == "unchanged"
    before = {
        x["record_id"] for x in a.device.http.call("GET", "/store/records", auth=True)["records"]
    }
    (lab / "more.txt").write_text("new item\n")
    idx = LocalIndex.for_client(a, clock=net.clock)
    idx.scan()
    idx.streams.checkpoint(a, sid)
    idx.close()
    out = a.personal.sync_store(snapshot=True)
    assert out["snapshots"]["index"] == "sent"
    after = {
        x["record_id"] for x in a.device.http.call("GET", "/store/records", auth=True)["records"]
    }
    # A new snapshot replaces the chunk record of the old snapshot.
    assert len(after) == len(before)


def test_commit_syncs_automatically(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    lab = make_lab(tmp_path)
    root = a.findings.commit_finding([lab / "notes.md"], claim=CLAIM).subject.root.hex()
    keys = StoreKeys(a.keystore.get("vault-key"))
    listing = a.device.http.call("GET", "/store/records", auth=True)["records"]
    assert keys.record_id("finding", root) in {x["record_id"] for x in listing}
    assert a.vault.kv_get("store/last_error") is None


def test_commit_works_when_the_node_has_no_store(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    lab = make_lab(tmp_path)

    def no_store(method, path, body, headers=None):
        if path.startswith("/store/"):
            raise NodeHTTPError(404, "Not Found")
        return net.transport(method, path, body, headers)

    a.device.http.transport = no_store
    a.findings.commit_finding([lab / "notes.md"])
    assert "404" in a.vault.kv_get("store/last_error")
    with pytest.raises(NodeHTTPError):
        a.personal.sync_store()


def test_local_mode_has_no_store(tmp_path):
    from anagram.shell.client import Client

    c = Client.init(tmp_path / "home")
    lab = make_lab(tmp_path)
    c.findings.commit_finding([lab / "notes.md"])
    with pytest.raises(ClientError, match="community node"):
        c.personal.sync_store()


def test_restore_does_not_overwrite_an_index(net, tmp_path):
    r, root, sid, lab = device_a(net, tmp_path)
    b = recover(
        tmp_path / "new",
        r.kit_text,
        transport=net.transport,
        clock=net.clock,
        open_home=Client.open,
    )
    index = tmp_path / "new" / "index.sqlite"
    before = index.read_bytes()
    out = b.personal.restore_personal_store()
    assert out["snapshots"]["index"] == "restored to index.sqlite.restored"
    assert index.read_bytes() == before
    assert (tmp_path / "new" / "index.sqlite.restored").exists()
    # A home with Anagram data is refused before anything is written.
    with pytest.raises(ClientError, match="already has Anagram data"):
        recover(tmp_path / "new", r.kit_text, transport=net.transport, open_home=Client.open)


def test_store_record_ids_do_not_show_kinds(net, tmp_path):
    """The node cannot tell a finding from a ring by its record ID."""
    keys = StoreKeys(b"\x05" * 32)
    ids = {keys.record_id(k, "x") for k in ("finding", "ring", "person", "snapshot")}
    assert len(ids) == 4 and all(len(i) == 32 for i in ids)
    other = StoreKeys(b"\x06" * 32)
    assert keys.record_id("finding", "x") != other.record_id("finding", "x")


def test_device_sign_in_rules(net, tmp_path):
    from anagram.identity.app.identity import device_sign_in
    from anagram.identity.formats.documents import sign_device_signin

    a = net.join(tmp_path / "a", "fake-alice").client
    node_key = a.config["identity"]["node_key"]
    session = device_sign_in(a.device.http, a.device.subject, a.device.device_key(), node_key)
    assert net.tc.get("/me", headers=auth(session["token"])).json()["subject"] == a.device.subject
    # A key that is not an active device of the person gets no session.
    stranger = SigningKey.generate()
    with pytest.raises(NodeHTTPError) as e:
        device_sign_in(a.device.http, a.device.subject, stranger, node_key)
    assert e.value.status == 401
    # A wrong signature (here: for another challenge) fails, and a challenge
    # is single use.
    start = net.tc.post(
        "/auth/device/start",
        json={
            "device_key": a.device.device_key().public_bytes().hex(),
            "subject": a.device.subject,
        },
    ).json()
    sig = sign_device_signin(a.device.subject, "00" * 32, node_key, a.device.device_key())
    r = net.tc.post(
        "/auth/device/verify", json={"challenge_id": start["challenge_id"], "signature": sig}
    )
    assert r.status_code == 401
    good = sign_device_signin(a.device.subject, start["challenge"], node_key, a.device.device_key())
    r = net.tc.post(
        "/auth/device/verify", json={"challenge_id": start["challenge_id"], "signature": good}
    )
    assert r.status_code == 401  # used
    bad = net.tc.post("/auth/device/start", json={"device_key": "zz", "subject": "x"})
    assert bad.status_code == 400


def test_pull_imports_large_vault_records_and_put_person_keys_verifies_sig(net, tmp_path):
    from datetime import UTC, datetime

    from anagram.identity.formats.personal_store import MAX_PERSON_KEYS_BYTES, make_person_keys

    a = net.join(tmp_path / "a", "fake-large").client
    keys = StoreKeys(a.keystore.get("vault-key"))
    # M12: a vault record >= 1 MiB (SNAPSHOT_CHUNK) must NOT be skipped during _pull().
    big_val = {"members": [], "name": "big-ring", "position": 99, "pad": "x" * (1 << 20)}
    doc = seal_record(keys, "ring", "big-ring", big_val, 1)
    assert len(base64.b64decode(doc["ciphertext"])) >= 1 << 20
    a.device.http.call("PUT", f"/store/records/{doc['record_id']}", {"record": doc}, auth=True)
    # Clear local tracking so pull fetches it.
    pulled = a.personal.pull_store()
    assert pulled >= 1
    assert any(r["name"] == "big-ring" for r in a.vault.rings())

    # M13: put_person_keys verifies signature and size cap.
    dev = a.device.my_device()
    pkg = make_person_keys(
        subject=a.device.subject,
        recipient=dev,
        keys={"index-key": b"\x01" * 32, "vault-key": b"\x02" * 32},
        created_at=datetime(2026, 10, 27, tzinfo=UTC),
        sender=a.device.device_key(),
    )
    bad_sig = {**pkg, "signature": "00" * 64}
    r = net.tc.put(
        f"/store/person-keys/{dev['ed25519']}",
        json={"package": bad_sig},
        headers=auth(a.device.http.token),
    )
    assert r.status_code == 400
    too_big = {
        **pkg,
        "ciphertext": base64.b64encode(b"z" * (MAX_PERSON_KEYS_BYTES + 1)).decode("ascii"),
    }
    r2 = net.tc.put(
        f"/store/person-keys/{dev['ed25519']}",
        json={"package": too_big},
        headers=auth(a.device.http.token),
    )
    assert r2.status_code == 400
