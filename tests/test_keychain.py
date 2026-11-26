"""The keystore of a client home: sealed key files, the marker, the policy.

These tests use `MemorySlot` or a fake `keyring` backend object. They never
use the real keychain of this computer. One opt-in test does
(`ANAGRAM_TEST_OS_KEYCHAIN=1`); it is not part of the offline suite.
"""

import json
import os
import secrets
import stat

import pytest
from keyring import errors as keyring_errors

from anagram.identity.app import keychain
from anagram.identity.app.keychain import (
    MARKER,
    KeyringSlot,
    MemorySlot,
    SealedKeystore,
    SlotLocked,
    SlotUnavailable,
    describe,
    destroy_keystore,
    open_keystore,
    slots,
)
from anagram.identity.app.keystore import FileKeystore, KeystoreError

MASTER = b"\x07" * 32
KID = "00112233445566ff"
SECRET = b"canary-secret-" + b"\x5a" * 18


def sealed(tmp_path, master=MASTER, kid=KID):
    return SealedKeystore(tmp_path / "keys", master, kid)


def no_keychain():
    raise SlotUnavailable("no keychain service on this computer")


# ---- sealed key files


def test_sealed_file_format_mode_and_no_plaintext(tmp_path):
    ks = sealed(tmp_path)
    ks.put("device-ed25519", SECRET)
    p = tmp_path / "keys" / "device-ed25519.skey"
    assert sorted(os.listdir(tmp_path / "keys")) == ["device-ed25519.skey"]
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "keys").st_mode) == 0o700
    text = p.read_text()
    assert text.endswith("\n") and text.count("\n") == 1
    doc = json.loads(text)
    assert sorted(doc) == ["ct", "nonce", "schema"]
    assert doc["schema"] == "anagram.sealed_key.v1"
    assert SECRET.hex() not in text and SECRET not in p.read_bytes()
    assert sealed(tmp_path).get("device-ed25519") == SECRET


def test_sealed_key_does_not_open_with_other_name(tmp_path):
    ks = sealed(tmp_path)
    ks.put("vault-key", SECRET)
    os.rename(tmp_path / "keys" / "vault-key.skey", tmp_path / "keys" / "index-key.skey")
    with pytest.raises(KeystoreError):
        ks.get("index-key")
    # A file that does not open is never replaced by a new key.
    with pytest.raises(KeystoreError):
        ks.get_or_create("index-key", lambda: b"\x01" * 32)


def test_sealed_key_does_not_open_in_other_keystore_or_with_other_master(tmp_path):
    sealed(tmp_path).put("vault-key", SECRET)
    with pytest.raises(KeystoreError):
        sealed(tmp_path, kid="ffffffffffffffff").get("vault-key")
    with pytest.raises(KeystoreError):
        sealed(tmp_path, master=b"\x08" * 32).get("vault-key")


@pytest.mark.parametrize("text", ["", "\n", "zz", "{}", '{"schema": "anagram.sealed_key.v1"}'])
def test_malformed_sealed_file_is_an_error(tmp_path, text):
    ks = sealed(tmp_path)
    (tmp_path / "keys" / "device.skey").write_text(text)
    with pytest.raises(KeystoreError):
        ks.get("device")
    with pytest.raises(KeystoreError):
        ks.get_or_create("device", lambda: b"\x03" * 32)


def test_changed_sealed_file_is_an_error(tmp_path):
    ks = sealed(tmp_path)
    ks.put("device", SECRET)
    p = tmp_path / "keys" / "device.skey"
    doc = json.loads(p.read_text())
    doc["ct"] = ("00" if doc["ct"][:2] != "00" else "01") + doc["ct"][2:]
    p.write_text(json.dumps(doc))
    with pytest.raises(KeystoreError):
        ks.get("device")


def test_sealed_replace_keeps_the_old_file(tmp_path):
    ks = sealed(tmp_path)
    ks.put("vault-key", SECRET)
    ks.replace("vault-key", b"\x02" * 32)
    assert ks.get("vault-key") == b"\x02" * 32
    assert sorted(os.listdir(tmp_path / "keys")) == [
        "vault-key.skey",
        "vault-key.skey.replaced-1",
    ]
    assert ks.list() == ["vault-key"]


def test_sealed_lost_race_does_not_overwrite(tmp_path, monkeypatch):
    ks = sealed(tmp_path)
    other = sealed(tmp_path)
    real_fsync = os.fsync
    done = []

    def other_writer_wins(fd):
        real_fsync(fd)
        if not done:
            done.append(1)
            other.put("device", b"\xaa" * 32)

    monkeypatch.setattr(os, "fsync", other_writer_wins)
    with pytest.raises(FileExistsError):
        ks.put("device", b"\x01" * 32)
    monkeypatch.undo()
    assert ks.get("device") == b"\xaa" * 32
    assert os.listdir(tmp_path / "keys") == ["device.skey"]


def test_master_key_length(tmp_path):
    with pytest.raises(KeystoreError):
        SealedKeystore(tmp_path / "keys", b"short", KID)


# ---- the marker and the policy


def marker(home):
    return json.loads((home / "keys" / MARKER).read_text())


def test_policy_default_and_values(monkeypatch):
    monkeypatch.delenv("ANAGRAM_KEYSTORE")
    assert keychain.policy() == "file"
    for value in ("file", "auto", "os"):
        monkeypatch.setenv("ANAGRAM_KEYSTORE", value)
        assert keychain.policy() == value
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "keychain")
    with pytest.raises(KeystoreError):
        keychain.policy()


def test_policy_file_makes_a_file_keystore_and_a_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "file")
    slot = MemorySlot()
    ks = open_keystore(tmp_path, slot=slot)  # the slot does not change the policy
    assert type(ks) is FileKeystore
    m = marker(tmp_path)
    assert m["backend"] == "file" and m["schema"] == "anagram.keystore.v2" and len(m["id"]) == 16
    assert stat.S_IMODE(os.stat(tmp_path / "keys" / MARKER).st_mode) == 0o600
    assert slot.items == {}
    assert describe(tmp_path) == {"backend": "file", "protected": False}
    ks.put("device", SECRET)
    assert ks.list() == ["device"]  # the marker is not a key
    assert open_keystore(tmp_path).get("device") == SECRET


def test_policy_os_makes_a_sealed_keystore(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    ks = open_keystore(tmp_path, slot=slot)
    assert type(ks) is SealedKeystore
    m = marker(tmp_path)
    assert m["backend"] == "memory"
    assert list(slot.items) == [f"keystore-master:{m['id']}"]
    master = slot.items[f"keystore-master:{m['id']}"]
    assert len(master) == 32
    assert describe(tmp_path) == {"backend": "memory", "protected": True}
    ks.put("device", SECRET)
    again = open_keystore(tmp_path, slot=slot)
    assert type(again) is SealedKeystore and again.get("device") == SECRET
    data = b"".join(p.read_bytes() for p in (tmp_path / "keys").iterdir())
    assert SECRET not in data and SECRET.hex().encode() not in data
    assert master not in data and master.hex().encode() not in data


def test_policy_os_with_no_keychain_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    monkeypatch.setattr(slots, "os_slot", no_keychain)
    with pytest.raises(SlotUnavailable):
        open_keystore(tmp_path)
    assert not (tmp_path / "keys" / MARKER).exists()


def test_policy_auto_uses_the_keychain_or_falls_back_to_files(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "auto")
    slot = MemorySlot()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)
    assert type(open_keystore(tmp_path / "a")) is SealedKeystore
    assert marker(tmp_path / "a")["backend"] == "memory"
    monkeypatch.setattr(slots, "os_slot", no_keychain)
    assert type(open_keystore(tmp_path / "b")) is FileKeystore
    assert marker(tmp_path / "b")["backend"] == "file"


def test_marker_wins_over_the_policy(tmp_path, monkeypatch):
    slot = MemorySlot()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "file")
    open_keystore(tmp_path / "f").put("device", SECRET)
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    open_keystore(tmp_path / "s").put("device", SECRET)
    assert type(open_keystore(tmp_path / "f")) is FileKeystore
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "file")
    ks = open_keystore(tmp_path / "s")
    assert type(ks) is SealedKeystore and ks.get("device") == SECRET


def test_legacy_hex_files_stay_a_file_keystore(tmp_path, monkeypatch):
    FileKeystore(tmp_path / "keys").put("device", SECRET)
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    ks = open_keystore(tmp_path, slot=slot)
    assert type(ks) is FileKeystore and ks.get("device") == SECRET
    assert not (tmp_path / "keys" / MARKER).exists()  # the migration is explicit
    assert slot.items == {}
    assert describe(tmp_path) == {"backend": "file", "protected": False}


def test_locked_slot_never_creates_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "auto")
    slot = MemorySlot()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)
    # A new home with a locked keychain: stop. No fallback to files.
    slot.locked = True
    with pytest.raises(SlotLocked):
        open_keystore(tmp_path / "new")
    assert not (tmp_path / "new" / "keys" / MARKER).exists()
    # A home with keys, then the keychain is locked: stop. No new keys.
    slot.locked = False
    home = tmp_path / "home"
    open_keystore(home).put("device", SECRET)
    before = sorted(p.name for p in (home / "keys").iterdir())
    monkeypatch.setattr(keychain, "_masters", {})
    slot.locked = True
    with pytest.raises(SlotLocked):
        open_keystore(home)
    assert sorted(p.name for p in (home / "keys").iterdir()) == before
    slot.locked = False
    assert open_keystore(home).get("device") == SECRET


def test_missing_master_key_is_an_error_and_makes_no_new_master(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    open_keystore(tmp_path, slot=slot).put("device", SECRET)
    slot.items.clear()
    with pytest.raises(KeystoreError, match="master key"):
        open_keystore(tmp_path, slot=slot)
    assert slot.items == {}


def test_other_backend_than_the_marker_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    open_keystore(tmp_path, slot=slot)
    other = MemorySlot()
    other.backend = "secret-service"
    other.items = dict(slot.items)
    with pytest.raises(KeystoreError, match="backend"):
        open_keystore(tmp_path, slot=other)


def test_malformed_marker_is_an_error(tmp_path):
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / MARKER).write_text("{}")
    with pytest.raises(KeystoreError):
        open_keystore(tmp_path)
    with pytest.raises(KeystoreError):
        describe(tmp_path)


def test_process_reads_the_os_keychain_one_time(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    monkeypatch.setattr(slots, "os_slot", lambda: slot)
    open_keystore(tmp_path).put("device", SECRET)
    monkeypatch.setattr(keychain, "_masters", {})
    slot.reads = 0
    for _ in range(3):
        assert open_keystore(tmp_path).get("device") == SECRET
    assert slot.reads == 1


def test_destroy_keystore_removes_the_files_and_the_master_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    slot = MemorySlot()
    open_keystore(tmp_path, slot=slot).put("temp-x25519", SECRET)
    destroy_keystore(tmp_path, slot=slot)
    assert slot.items == {}
    assert os.listdir(tmp_path / "keys") == []
    destroy_keystore(tmp_path, slot=slot)  # a second call is not an error


# ---- KeyringSlot with a fake backend object (no real keychain)


class FakeBackend:
    def __init__(self, fail=None):
        self.data = {}
        self.fail = fail

    def _check(self):
        if self.fail:
            raise self.fail

    def get_password(self, service, account):
        self._check()
        return self.data.get((service, account))

    def set_password(self, service, account, value):
        self._check()
        self.data[(service, account)] = value

    def delete_password(self, service, account):
        self._check()
        if (service, account) not in self.data:
            raise keyring_errors.PasswordDeleteError("not found")
        del self.data[(service, account)]


def test_keyring_slot_stores_hex_under_the_service():
    impl = FakeBackend()
    slot = KeyringSlot("macos-keychain", impl)
    assert slot.get("keystore-master:ab") is None
    slot.set("keystore-master:ab", MASTER)
    assert impl.data == {("org.radiofuture.anagram", "keystore-master:ab"): MASTER.hex()}
    assert slot.get("keystore-master:ab") == MASTER
    with pytest.raises(FileExistsError):
        slot.set("keystore-master:ab", b"\x09" * 32)
    slot.delete("keystore-master:ab")
    slot.delete("keystore-master:ab")  # an absent item is not an error
    assert impl.data == {}


@pytest.mark.parametrize(
    ("error", "expect"),
    [
        (keyring_errors.KeyringLocked("locked"), SlotLocked),
        (keyring_errors.KeyringError("access refused"), SlotLocked),
        (keyring_errors.PasswordSetError("refused"), SlotLocked),
        (keyring_errors.PasswordDeleteError("refused"), SlotLocked),
        (keyring_errors.NoKeyringError("none"), SlotUnavailable),
        (keyring_errors.InitError("none"), SlotUnavailable),
    ],
)
def test_keyring_slot_maps_errors(error, expect):
    slot = KeyringSlot("macos-keychain", FakeBackend(fail=error))
    with pytest.raises(expect):
        slot.get("a")
    with pytest.raises(expect):
        slot.set("a", MASTER)
    with pytest.raises(expect):
        slot.delete("a")


def test_keyring_slot_with_open_keystore(tmp_path, monkeypatch):
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    impl = FakeBackend()
    slot = KeyringSlot("macos-keychain", impl)
    open_keystore(tmp_path, slot=slot).put("device", SECRET)
    assert marker(tmp_path)["backend"] == "macos-keychain"
    assert open_keystore(tmp_path, slot=slot).get("device") == SECRET
    impl.fail = keyring_errors.KeyringLocked("locked")
    with pytest.raises(SlotLocked):
        open_keystore(tmp_path, slot=slot)


def test_suite_guard_refuses_the_real_keychain():
    if os.environ.get("ANAGRAM_TEST_KEYSTORE") == "os-memory":
        pytest.skip("the suite runs with a memory slot")
    with pytest.raises(AssertionError):
        slots.os_slot()


# ---- opt-in: the real keychain of this computer


@pytest.mark.skipif(
    os.environ.get("ANAGRAM_TEST_OS_KEYCHAIN") != "1",
    reason="uses the real OS keychain; set ANAGRAM_TEST_OS_KEYCHAIN=1",
)
def test_real_os_keychain_round_trip():
    from conftest import REAL_OS_SLOT

    slot = REAL_OS_SLOT()
    acct = "keystore-master:test-" + secrets.token_hex(8)
    value = secrets.token_bytes(32)
    try:
        assert slot.get(acct) is None
        slot.set(acct, value)
        assert slot.get(acct) == value
        with pytest.raises(FileExistsError):
            slot.set(acct, value)
    finally:
        slot.delete(acct)
    assert slot.get(acct) is None


# ---- the policy of the CLI (security review P2)


@pytest.mark.parametrize(
    ("argv", "want"),
    [
        ([], "auto"),  # `anagram` opens the UI
        (["ui", "--no-browser"], "auto"),
        (["--plain-key-files", "ui", "--no-browser"], "file"),
        (["--plain-key-files"], "file"),
    ],
)
def test_anagram_and_anagram_ui_default_to_the_os_keychain(monkeypatch, argv, want):
    from anagram.shell.cli import main as cli

    monkeypatch.delenv("ANAGRAM_KEYSTORE")
    seen = []
    monkeypatch.setattr(cli, "cmd_ui", lambda args: seen.append(keychain.policy()) or 0)
    assert cli.main(argv) == 0
    assert seen == [want]


def test_node_commands_keep_the_policy_of_the_environment(monkeypatch):
    from anagram.shell.cli import main as cli
    from anagram.shell.cli import node as cli_node

    monkeypatch.delenv("ANAGRAM_KEYSTORE")
    seen = []
    monkeypatch.setattr(
        cli_node, "cmd_node_serve", lambda args: seen.append(keychain.policy()) or 0
    )
    assert cli.main(["node", "serve"]) == 0
    assert seen == ["file"]
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "file")  # tests and headless hosts
    monkeypatch.setattr(cli, "cmd_ui", lambda args: seen.append(keychain.policy()) or 0)
    assert cli.main(["ui"]) == 0
    assert seen == ["file", "file"]
