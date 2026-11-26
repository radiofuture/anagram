"""The local vault file is encrypted (SQLCipher) with a device-local key. A
plain vault of an older version is encrypted in place. No network."""

from __future__ import annotations

import os
import sqlite3

import pytest
import sqlcipher3

from anagram.core.nodeapi import HttpNode
from anagram.identity.app.device import LOCAL_STORE_KEY
from anagram.identity.formats.backup import BACKUP_KEYS
from anagram.identity.formats.personal_store import PERSON_KEY_NAMES
from anagram.local import localdb
from anagram.local.vault import DB_KEY_INFO, SCHEMA, Vault
from anagram.network.sharing.app.tables import SCHEMA as SHARE_TABLES
from anagram.proofs.proof import verify_bundle
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")

KEY = b"\x21" * 32
RING = "CANARY-RING-8842"
RECIPIENT = "CANARY-RECIPIENT-1177"
PATH = "/Users/someone/CANARY-PATH-3391/notes.md"
SUBJECT = "CANARY-SUBJECT-6604"
CANARIES = (RING, RECIPIENT, "CANARY-PATH-3391", SUBJECT)


def fill(v) -> None:
    """Rows in each table. `v` is a Vault."""
    v.add_finding("aa" * 32, "bb" * 16, 1, "2026-10-15T12:00:00Z", {"ct": "00", "nonce": "11"})
    v.set_bundle("aa" * 32, {"schema": "bundle"})
    v.set_log_state("node.test/log", 3, "cc" * 32, "checkpoint text")
    v.expect_device({"ed25519": "dd" * 32, "x25519": "ee" * 32})
    v.add_directory_entry(0, SUBJECT, {"subject": SUBJECT})
    v.set_monitor_state("node.test/log", 3, [b"\x01" * 32])
    v.add_alert(2, "an alert")
    v.add_alert(None, "a second alert")
    v.set_evidence_meta("aa" * 32, 0, PATH, third_party=True)
    v.set_blob("aa" * 32, 0, "ff" * 16, 1024, 4096)
    v.put_sealed("content-key", "aa" * 32, b"\x02" * 12, b"\x03" * 40)
    v.create_ring(RING)
    v.set_ring_members(RING, [SUBJECT])
    v.add_grant_sent("99" * 16, "aa" * 32, RECIPIENT, ["dd" * 32], "2026-10-15T12:00:00Z")
    v.kv_set("store:cursor", "7")


def dump(db) -> dict:
    """All rows of all tables (also `sqlite_sequence`), and the schema text."""
    tables = sorted(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'"))
    out = {t: sorted(db.execute(f'SELECT * FROM "{t}"').fetchall(), key=repr) for t in tables}  # noqa: S608
    out["#schema"] = sorted(
        db.execute("SELECT type, name, sql FROM sqlite_master").fetchall(), key=repr
    )
    return out


def plain_vault(path) -> dict:
    """A vault as the older version wrote it: plain SQLite, same schema."""

    class Plain(Vault):
        def __init__(self, p):
            self._db = sqlite3.connect(str(p), isolation_level=None)
            self._db.executescript(SCHEMA)
            self._db.executescript(SHARE_TABLES)  # the Client gives them to Vault

    v = Plain(path)
    fill(v)
    rows = dump(v._db)
    v.close()
    assert localdb.is_plain_sqlite(path)
    assert RING.encode() in path.read_bytes()
    return rows


def siblings(path) -> list[str]:
    return sorted(p.name for p in path.parent.iterdir())


def test_vault_file_has_no_plaintext(tmp_path):
    path = tmp_path / "vault.sqlite"
    v = Vault(path, KEY)
    fill(v)
    assert v.ring(RING)["members"] == [SUBJECT]
    assert v.evidence_meta("aa" * 32)[0]["path"] == PATH
    with pytest.raises(KeyError):  # the unique rule still gives the same error
        v.create_ring(RING)
    v.close()
    data = path.read_bytes()
    assert not localdb.is_plain_sqlite(path)
    for canary in CANARIES:
        assert canary.encode() not in data
    assert b"CREATE TABLE" not in data and b"findings" not in data
    assert siblings(path) == ["vault.sqlite"]
    assert os.stat(path).st_mode & 0o777 == 0o600
    again = Vault(path, KEY)
    assert again.grants_sent()[0]["recipient"] == RECIPIENT
    again.close()


def test_wrong_key_fails(tmp_path):
    path = tmp_path / "vault.sqlite"
    v = Vault(path, KEY)
    fill(v)
    v.close()
    before = path.read_bytes()
    with pytest.raises(localdb.LocalDBError):
        Vault(path, b"\x22" * 32)
    with pytest.raises(localdb.LocalDBError):
        Vault(path, b"short")
    # The same key with another purpose (the index) does not open the vault.
    with pytest.raises(localdb.LocalDBError):
        localdb.connect(path, KEY, b"anagram.index.sqlcipher.v1")
    assert path.read_bytes() == before  # a failed open changes nothing
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(path).execute("SELECT count(*) FROM sqlite_master")


def test_changed_file_fails(tmp_path):
    path = tmp_path / "vault.sqlite"
    v = Vault(path, KEY)
    fill(v)
    v.close()
    data = bytearray(path.read_bytes())
    data[100] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises((localdb.LocalDBError, sqlcipher3.DatabaseError)):
        Vault(path, KEY).list()


def test_plain_vault_migrates_with_equal_rows(tmp_path):
    path = tmp_path / "vault.sqlite"
    rows = plain_vault(path)
    v = Vault(path, KEY)
    assert dump(v._db) == rows
    v.add_alert(None, "after")  # AUTOINCREMENT goes on from the old sequence
    assert v._db.execute("SELECT max(id) FROM alerts").fetchone()[0] == 3
    v.close()
    data = path.read_bytes()
    assert not localdb.is_plain_sqlite(path)
    for canary in CANARIES:
        assert canary.encode() not in data
    assert siblings(path) == ["vault.sqlite"]  # no `.plain-old`, no temp file
    assert os.stat(path).st_mode & 0o077 == 0


def test_plain_copy_gets_zeros_before_it_is_removed(tmp_path):
    path = tmp_path / "vault.sqlite"
    plain_vault(path)
    size = path.stat().st_size
    fd = os.open(path, os.O_RDONLY)  # keeps the plain file open across the migration
    try:
        Vault(path, KEY).close()
        assert os.pread(fd, size + 10, 0) == b"\x00" * size
    finally:
        os.close(fd)


def test_stop_before_the_rename_keeps_the_plain_vault(tmp_path, monkeypatch):
    path = tmp_path / "vault.sqlite"
    rows = plain_vault(path)

    def stop(src, dst):
        raise RuntimeError("the process stopped")

    monkeypatch.setattr(localdb.os, "replace", stop)
    with pytest.raises(RuntimeError):
        Vault(path, KEY)
    monkeypatch.undo()
    # The plain file is complete, with a second name from the stopped try.
    assert siblings(path) == ["vault.sqlite", "vault.sqlite.plain-old"]
    assert localdb.is_plain_sqlite(path)
    assert os.path.samefile(path, tmp_path / "vault.sqlite.plain-old")
    v = Vault(path, KEY)  # the next open does the migration
    assert dump(v._db) == rows
    v.close()
    assert siblings(path) == ["vault.sqlite"]
    assert RING.encode() not in path.read_bytes()


def test_stop_during_the_export_keeps_the_plain_vault(tmp_path, monkeypatch):
    path = tmp_path / "vault.sqlite"
    rows = plain_vault(path)
    monkeypatch.setattr(localdb, "_counts", lambda db, schema: {"x": 1 if schema == "main" else 2})
    with pytest.raises(localdb.LocalDBError, match="does not agree"):
        Vault(path, KEY)
    monkeypatch.undo()
    assert siblings(path) == ["vault.sqlite"]
    assert localdb.is_plain_sqlite(path)
    v = Vault(path, KEY)
    assert dump(v._db) == rows
    v.close()


def test_plain_old_copy_is_erased_at_the_next_open(tmp_path):
    """A stop after the rename and before the erase leaves `.plain-old`."""
    path = tmp_path / "vault.sqlite"
    Vault(path, KEY).close()
    old = tmp_path / "vault.sqlite.plain-old"
    old.write_bytes(localdb.PLAIN_MAGIC + RING.encode())
    with pytest.raises(localdb.LocalDBError):
        Vault(path, b"\x22" * 32)
    assert old.exists()  # a store that does not open: nothing is erased
    Vault(path, KEY).close()
    assert siblings(path) == ["vault.sqlite"]


def test_encrypt_in_place_refuses_a_file_that_is_not_plain(tmp_path):
    path = tmp_path / "vault.sqlite"
    Vault(path, KEY).close()
    with pytest.raises(localdb.LocalDBError):
        localdb.encrypt_in_place(path, KEY, DB_KEY_INFO)
    with pytest.raises(localdb.LocalDBError):
        localdb.encrypt_in_place(tmp_path / "absent.sqlite", KEY, DB_KEY_INFO)


def test_db_key_is_bound_to_the_purpose():
    a = localdb.db_key(KEY, b"anagram.vault.sqlcipher.v1")
    assert len(a) == 32 and a != KEY
    assert a != localdb.db_key(KEY, b"anagram.index.sqlcipher.v1")


def test_index_store_uses_the_same_key_scheme():
    from anagram.local.index import store

    assert store.db_key(KEY) == localdb.db_key(KEY, store.DB_KEY_INFO)


# ---- the client


def reopen(net, home):
    c = Client(home, clock=net.clock)
    c.device.node = HttpNode(c.config["node"]["url"], net.transport, token=c.device.session_token())
    return c


def test_client_vault_is_encrypted_with_a_device_local_key(net, tmp_path):
    home = tmp_path / "laptop"
    c = net.join(home, "fake-chen", "Mei Chen").client
    folder = tmp_path / "CANARY-PATH-3391"
    folder.mkdir()
    (folder / "notes.md").write_text("# Notes\n")
    root = c.findings.commit_finding([folder / "notes.md"], claim="a claim").subject.root.hex()
    c.grants.ring_create(RING)
    key = c.keystore.get(LOCAL_STORE_KEY)
    assert key is not None and len(key) == 32
    assert key not in (c.keystore.get("vault-key"), c.keystore.get("index-key"))
    # The key is device-local: not in the recovery backup, not a person key.
    assert LOCAL_STORE_KEY not in BACKUP_KEYS and LOCAL_STORE_KEY not in PERSON_KEY_NAMES
    c.vault.close()
    data = (home / "vault.sqlite").read_bytes()
    assert not localdb.is_plain_sqlite(home / "vault.sqlite")
    for canary in (RING, "CANARY-PATH-3391", root, c.device.subject):
        assert canary.encode() not in data
    c = reopen(net, home)
    assert c.keystore.get(LOCAL_STORE_KEY) == key
    assert [r["name"] for r in c.grants.ring_list()] == [RING]
    c.vault.close()


def test_client_migrates_a_plain_vault_of_an_older_version(net, tmp_path):
    home = tmp_path / "laptop"
    c = net.join(home, "fake-chen", "Mei Chen").client
    note = tmp_path / "notes.md"
    note.write_text("# Notes\n")
    root = c.findings.commit_finding([note], claim="a claim").subject.root.hex()
    c.grants.ring_create(RING)
    rows = dump(c.vault._db)
    # Make the home as the older version left it: a plain vault file.
    plain = tmp_path / "plain.sqlite"
    c.vault._db.execute("ATTACH DATABASE ? AS plain KEY ''", (str(plain),))
    c.vault._db.execute("SELECT sqlcipher_export('plain')")
    c.vault._db.execute("DETACH DATABASE plain")
    c.vault.close()
    os.replace(plain, home / "vault.sqlite")
    assert localdb.is_plain_sqlite(home / "vault.sqlite")
    assert RING.encode() in (home / "vault.sqlite").read_bytes()

    c = reopen(net, home)
    assert dump(c.vault._db) == rows
    assert c.findings.opening(root).finding.fields["claim"] == "a claim"
    assert verify_bundle(c.findings.bundle(root), c.device.trust()).ok
    assert verify_bundle(c.findings.prove_file(root, note), c.device.trust(), [note]).ok
    c.vault.close()
    assert not localdb.is_plain_sqlite(home / "vault.sqlite")
    assert RING.encode() not in (home / "vault.sqlite").read_bytes()
    assert not [p.name for p in home.iterdir() if p.name.startswith("vault.sqlite.")]


def test_adopt_person_keys_keeps_the_local_store_key(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two", invite=link).client
    note = tmp_path / "notes.md"
    note.write_text("# Notes\n")
    root = first.findings.commit_finding([note], claim="a claim").subject.root.hex()
    r = net.join(tmp_path / "desktop", "fake-two", invite=link)
    local = r.client.keystore.get(LOCAL_STORE_KEY)
    assert local != first.keystore.get(LOCAL_STORE_KEY)
    first.account.add_device(r.device_request)
    r.client.vault.close()
    second = net.join(tmp_path / "desktop", "fake-two", invite=link).client
    assert second.keystore.get("vault-key") == first.keystore.get("vault-key")
    assert second.keystore.get(LOCAL_STORE_KEY) == local  # no re-key of the vault file
    assert second.findings.opening(root).finding.fields["claim"] == "a claim"
    second.vault.close()
    again = reopen(net, tmp_path / "desktop")
    assert again.findings.opening(root).finding.fields["claim"] == "a claim"
    again.vault.close()
