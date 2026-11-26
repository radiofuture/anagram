"""Migration of hex key files into the sealed keystore, and the client on a
migrated home. The slot is a `MemorySlot`: no real keychain. No network."""

from __future__ import annotations

import json
import os

import pytest

from anagram.admission.app.join import node_of
from anagram.core.nodeapi import HttpNode
from anagram.identity.app import guardians as g
from anagram.identity.app import keychain
from anagram.identity.app.keychain import (
    MARKER,
    MemorySlot,
    SealedKeystore,
    open_keystore,
    slots,
)
from anagram.identity.app.keychain.migrate import migrate_to_os, needs_migration
from anagram.identity.app.keystore import FileKeystore, KeystoreError
from anagram.identity.app.kit import recover
from anagram.proofs.proof import verify_bundle
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")

CLAIM = "CANARY-MIGRATE-CLAIM-5521: the keys moved"


@pytest.fixture(autouse=True)
def file_policy(monkeypatch):
    """Each home starts with hex key files. A test that needs the keychain
    from the start sets the policy itself."""
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "file")


@pytest.fixture
def slot(monkeypatch):
    """One memory slot in the place of the OS keychain."""
    s = MemorySlot()
    monkeypatch.setattr(slots, "os_slot", lambda: s)
    monkeypatch.setattr(keychain, "_masters", {})
    return s


def reopen(net, home):
    c = Client(home, clock=net.clock)
    c.device.node = HttpNode(c.config["node"]["url"], net.transport, token=c.device.session_token())
    return c


def hex_keys(home) -> dict[str, str]:
    return {p.name: p.read_text().strip() for p in (home / "keys").iterdir() if ".key" in p.name}


def names(home) -> list[str]:
    return sorted(p.name for p in (home / "keys").iterdir())


def keys_bytes(home) -> bytes:
    return b"".join(p.read_bytes() for p in sorted((home / "keys").iterdir()))


def joined(net, tmp_path):
    home = tmp_path / "laptop"
    r = net.join(home, "fake-chen", "Mei Chen")
    note = tmp_path / "notes.md"
    note.write_text("# Notes\n\nwe need cryo-EM time.\n")
    root = r.client.findings.commit_finding([note], claim=CLAIM).subject.root.hex()
    r.client.grants.ring_create("lab")
    r.client.vault.close()
    return home, r, root, note


def test_needs_migration_rules(tmp_path, monkeypatch):
    legacy, marked, empty = tmp_path / "legacy", tmp_path / "marked", tmp_path / "empty"
    FileKeystore(legacy / "keys").put("device", b"\x01" * 32)
    open_keystore(marked).put("device", b"\x01" * 32)  # policy file: marker "file"
    for policy, expect in (("file", False), ("auto", True), ("os", True)):
        monkeypatch.setenv("ANAGRAM_KEYSTORE", policy)
        assert needs_migration(legacy) is expect
        assert needs_migration(marked) is expect
        assert needs_migration(empty) is False
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    sealed_home = tmp_path / "sealed"
    open_keystore(sealed_home, slot=MemorySlot())
    assert needs_migration(sealed_home) is False


def test_migrate_a_joined_home_and_the_client_works(net, tmp_path, slot):
    home, r, root, note = joined(net, tmp_path)
    before = hex_keys(home)
    assert {"device-ed25519.key", "device-x25519.key", "vault-key.key"} <= set(before)

    out = migrate_to_os(home, slot)
    assert out["backend"] == "memory"
    assert out["moved"] == sorted(n[: -len(".key")] for n in before)

    # No hex key file stays, and no key value is in a file of the directory.
    assert not [n for n in names(home) if ".key" in n], names(home)
    assert names(home) == sorted([MARKER, *(n.replace(".key", ".skey") for n in before)])
    data = keys_bytes(home)
    for value in before.values():
        assert value.encode() not in data and bytes.fromhex(value) not in data
    marker = json.loads((home / "keys" / MARKER).read_text())
    assert marker["backend"] == "memory"
    assert list(slot.items) == [f"keystore-master:{marker['id']}"]

    # The client opens the home through the slot and does its work.
    c = reopen(net, home)
    assert type(c.keystore) is SealedKeystore
    for name, value in before.items():
        assert c.keystore.get(name[: -len(".key")]) == bytes.fromhex(value)
    assert c.account.whoami()["subject"] == r.subject
    assert c.findings.opening(root).finding.fields["claim"] == CLAIM
    assert verify_bundle(c.findings.bundle(root), c.device.trust()).ok
    assert verify_bundle(c.findings.prove_file(root, note), c.device.trust(), [note]).ok
    assert [x["name"] for x in c.grants.ring_list()] == ["lab"]
    other = tmp_path / "data.csv"
    other.write_text("a,b\n1,2\n")
    root2 = c.findings.commit_finding([other]).subject.root.hex()
    assert verify_bundle(c.findings.bundle(root2), c.device.trust()).ok
    assert c.personal.sync_store(snapshot=False) is not None
    c.vault.close()
    assert not [n for n in names(home) if n.endswith(".key")]


def test_migrate_keeps_the_copies_of_replaced_keys(tmp_path, slot):
    home = tmp_path / "home"
    ks = FileKeystore(home / "keys")
    ks.put("vault-key", b"\x01" * 32)
    ks.replace("vault-key", b"\x02" * 32)
    ks.replace("vault-key", b"\x03" * 32)
    out = migrate_to_os(home, slot)
    assert out["moved"] == ["vault-key"]
    assert names(home) == [
        MARKER,
        "vault-key.skey",
        "vault-key.skey.replaced-1",
        "vault-key.skey.replaced-2",
    ]
    sealed = open_keystore(home)
    assert sealed.get("vault-key") == b"\x03" * 32
    for n, value in ((1, b"\x01" * 32), (2, b"\x02" * 32)):
        p = home / "keys" / f"vault-key.skey.replaced-{n}"
        assert sealed.read_file("vault-key", p) == value
        assert os.stat(p).st_mode & 0o777 == 0o600


def test_migrate_a_home_with_a_file_marker(tmp_path, slot):
    home = tmp_path / "home"
    open_keystore(home).put("device", b"\x01" * 32)  # policy file writes the marker
    migrate_to_os(home, slot)
    assert json.loads((home / "keys" / MARKER).read_text())["backend"] == "memory"
    assert open_keystore(home).get("device") == b"\x01" * 32
    with pytest.raises(KeystoreError):
        migrate_to_os(home, slot)  # a second migration is refused


def test_stop_before_the_marker_keeps_the_hex_files(net, tmp_path, slot, monkeypatch):
    home, r, root, _ = joined(net, tmp_path)
    before = hex_keys(home)
    import anagram.identity.app.keychain.migrate as mod

    def stop(*a, **k):
        raise RuntimeError("the process stopped")

    monkeypatch.setattr(mod, "write_marker", stop)
    with pytest.raises(RuntimeError):
        migrate_to_os(home, slot)
    monkeypatch.undo()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)

    # The hex files are the truth: the home opens as a file keystore.
    assert hex_keys(home) == before
    assert json.loads((home / "keys" / MARKER).read_text())["backend"] == "file"
    c = reopen(net, home)
    assert type(c.keystore) is FileKeystore
    assert c.findings.opening(root).finding.fields["claim"] == CLAIM
    c.vault.close()
    stopped = list(slot.items)
    assert len(stopped) == 1

    # The next try removes the sealed files and the master key of the stopped try.
    migrate_to_os(home, slot)
    marker = json.loads((home / "keys" / MARKER).read_text())
    assert list(slot.items) == [f"keystore-master:{marker['id']}"]
    assert list(slot.items) != stopped
    assert not [n for n in names(home) if ".key" in n]
    assert names(home) == sorted([MARKER, *(n.replace(".key", ".skey") for n in before)])
    c = reopen(net, home)
    assert c.findings.opening(root).finding.fields["claim"] == CLAIM
    c.vault.close()


def test_stop_after_the_marker_erases_the_hex_files_at_the_next_open(tmp_path, slot, monkeypatch):
    home = tmp_path / "home"
    FileKeystore(home / "keys").put("device", b"\x01" * 32)
    import anagram.identity.app.keychain.migrate as mod

    def stop(path):
        raise RuntimeError("the process stopped")

    monkeypatch.setattr(mod, "erase_file", stop)
    with pytest.raises(RuntimeError):
        migrate_to_os(home, slot)
    monkeypatch.undo()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)
    assert "device.key" in names(home)  # the stop left the hex file
    ks = open_keystore(home)
    assert type(ks) is SealedKeystore and ks.get("device") == b"\x01" * 32
    assert names(home) == ["device.skey", MARKER]


def test_malformed_hex_file_stops_the_migration(tmp_path, slot):
    home = tmp_path / "home"
    FileKeystore(home / "keys").put("device", b"\x01" * 32)
    (home / "keys" / "vault-key.key").write_text("zz\n")
    with pytest.raises(KeystoreError):
        migrate_to_os(home, slot)
    assert not (home / "keys" / MARKER).exists()
    assert FileKeystore(home / "keys").get("device") == b"\x01" * 32


def test_locked_slot_stops_the_migration(tmp_path, slot):
    home = tmp_path / "home"
    FileKeystore(home / "keys").put("device", b"\x01" * 32)
    slot.locked = True
    with pytest.raises(keychain.SlotLocked):
        migrate_to_os(home, slot)
    slot.locked = False
    assert names(home) == [".migrate.json", "device.key"]
    assert FileKeystore(home / "keys").get("device") == b"\x01" * 32
    migrate_to_os(home, slot)
    assert names(home) == ["device.skey", MARKER]


# ---- the client with the policy `os` (a new home is sealed from the start)


def test_join_and_recover_with_a_sealed_keystore(net, tmp_path, slot, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    home = tmp_path / "laptop"
    r = net.join(home, "fake-chen", "Mei Chen")
    assert type(r.client.keystore) is SealedKeystore
    assert not [n for n in names(home) if n.endswith(".key")]
    note = tmp_path / "notes.md"
    note.write_text("# Notes\n")
    root = r.client.findings.commit_finding([note], claim=CLAIM).subject.root.hex()
    r.client.personal.sync_store(snapshot=False)
    vault_key = r.client.keystore.get("vault-key")
    assert vault_key.hex().encode() not in keys_bytes(home)
    kit = r.kit_text
    r.client.vault.close()

    new = tmp_path / "new-laptop"
    b = recover(new, kit, transport=net.transport, clock=net.clock, open_home=Client.open)
    assert type(b.keystore) is SealedKeystore
    assert b.keystore.get("vault-key") == vault_key
    assert b.findings.opening(root).finding.fields["claim"] == CLAIM
    assert not [n for n in names(new) if n.endswith(".key")]
    assert len(slot.items) == 2  # one master key for each home


def test_guardian_recovery_removes_its_temporary_master_key(net, tmp_path, slot, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    people = {
        name: net.join(tmp_path / name, f"fake-{name}", name.title()).client
        for name in ("chen", "okafor", "varga", "helix")
    }
    chen = people["chen"]
    chen.guardians.guardians_set(
        [net.sid("fake-okafor"), net.sid("fake-varga"), net.sid("fake-helix")], threshold=2
    )
    vault_key = chen.keystore.get("vault-key")
    assert len(slot.items) == 4

    new = tmp_path / "new"
    rid = g.start_guardian_recovery(
        new,
        **node_of(net.invite()),
        transport=net.transport,
        browser=net.browser(),
        login_hint="fake-chen",
        clock=net.clock,
    )
    assert len(slot.items) == 5  # the keystore of the temporary keys
    assert sorted(p.name for p in (new / g.PENDING_DIR / "keys").iterdir()) == [
        MARKER,
        "node-session.skey",  # the session of the request, sealed as the keys are
        "temp-ed25519.skey",
        "temp-x25519.skey",
    ]
    people["okafor"].guardians.guardian_approve(rid)
    people["helix"].guardians.guardian_approve(rid)
    restored = g.finish_guardian_recovery(
        new, transport=net.transport, clock=net.clock, open_home=Client.open
    )
    assert restored.keystore.get("vault-key") == vault_key
    assert not (new / g.PENDING_DIR).exists()
    assert len(slot.items) == 5  # the temporary master key is gone; the new home has one
