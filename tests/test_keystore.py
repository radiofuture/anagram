import os
import stat

import pytest

from anagram.identity.app.keychain import SealedKeystore
from anagram.identity.app.keystore import FileKeystore, KeystoreError, MemoryKeystore


def test_put_get_mode_and_no_overwrite(tmp_path):
    ks = FileKeystore(tmp_path / "keys")
    ks.put("device", b"\x01" * 32)
    assert ks.get("device") == b"\x01" * 32
    assert stat.S_IMODE(os.stat(tmp_path / "keys" / "device.key").st_mode) == 0o600
    with pytest.raises(FileExistsError):
        ks.put("device", b"\x02" * 32)
    assert ks.get("device") == b"\x01" * 32
    assert sorted(os.listdir(tmp_path / "keys")) == ["device.key"]


@pytest.mark.parametrize("text", ["", "\n", "zz", "abc"])
def test_empty_or_malformed_key_file_is_an_error(tmp_path, text):
    ks = FileKeystore(tmp_path / "keys")
    (tmp_path / "keys" / "device.key").write_text(text)
    with pytest.raises(KeystoreError):
        ks.get("device")
    # get_or_create must not hide a broken key by making a new one.
    with pytest.raises(KeystoreError):
        ks.get_or_create("device", lambda: b"\x03" * 32)


def test_failed_write_leaves_no_key(tmp_path, monkeypatch):
    ks = FileKeystore(tmp_path / "keys")

    def broken_fsync(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken_fsync)
    with pytest.raises(OSError, match="disk full"):
        ks.put("device", b"\x01" * 32)
    monkeypatch.undo()
    assert ks.get("device") is None
    assert os.listdir(tmp_path / "keys") == []


def test_lost_race_does_not_overwrite(tmp_path, monkeypatch):
    ks = FileKeystore(tmp_path / "keys")
    final = tmp_path / "keys" / "device.key"
    real_fsync = os.fsync

    def other_writer_wins(fd):
        real_fsync(fd)
        if not final.exists():
            final.write_text("aa" * 32 + "\n")

    monkeypatch.setattr(os, "fsync", other_writer_wins)
    with pytest.raises(FileExistsError):
        ks.put("device", b"\x01" * 32)
    monkeypatch.undo()
    assert ks.get("device") == b"\xaa" * 32
    assert os.listdir(tmp_path / "keys") == ["device.key"]


# ---- the keystore API of the three keystores (integration contract 1.1)

OLD = b"old-token-" + b"\x11" * 22
NEW = b"new-token-" + b"\x22" * 22


def _file(tmp_path):
    return FileKeystore(tmp_path / "keys")


def _memory(tmp_path):
    return MemoryKeystore()


def _sealed(tmp_path):
    return SealedKeystore(tmp_path / "keys", b"\x07" * 32, "00112233445566ff")


@pytest.fixture(params=[_file, _memory, _sealed], ids=["file", "memory", "sealed"])
def ks(request, tmp_path):
    return request.param(tmp_path)


def _disk(tmp_path) -> bytes:
    d = tmp_path / "keys"
    if not d.exists():
        return b""
    return b"".join(p.read_bytes() for p in sorted(d.iterdir()))


def test_put_never_overwrites_by_default(ks):
    ks.put("device", OLD)
    with pytest.raises(FileExistsError):
        ks.put("device", NEW)
    assert ks.get("device") == OLD
    assert ks.get("other") is None


def test_put_overwrite_leaves_no_old_value(ks, tmp_path):
    ks.put("acct-1", OLD, overwrite=True)  # a new name is permitted
    assert ks.get("acct-1") == OLD
    ks.put("acct-1", NEW, overwrite=True)
    assert ks.get("acct-1") == NEW
    assert ks.list() == ["acct-1"]
    d = tmp_path / "keys"
    if d.exists():
        # One file: no `.replaced-<n>` copy, no temp file, no old copy.
        assert len(list(d.iterdir())) == 1
    # The old value is in no file of the directory (hex form and raw form).
    assert OLD.hex().encode() not in _disk(tmp_path)
    assert OLD not in _disk(tmp_path)


def test_overwrite_writes_zeros_on_the_old_file(tmp_path, monkeypatch):
    """The old file gets zeros before the unlink, not only an unlink."""
    ks = FileKeystore(tmp_path / "keys")
    ks.put("acct-1", OLD)
    old_fd = os.open(tmp_path / "keys" / "acct-1.key", os.O_RDONLY)  # keeps the old file open
    try:
        ks.put("acct-1", NEW, overwrite=True)
        data = os.pread(old_fd, 1000, 0)
    finally:
        os.close(old_fd)
    assert data == b"\x00" * (len(OLD.hex()) + 1)
    assert ks.get("acct-1") == NEW


def test_delete_writes_zeros_on_the_file(tmp_path):
    ks = FileKeystore(tmp_path / "keys")
    ks.put("acct-1", OLD)
    fd = os.open(tmp_path / "keys" / "acct-1.key", os.O_RDONLY)
    try:
        assert ks.delete("acct-1") is True
        data = os.pread(fd, 1000, 0)
    finally:
        os.close(fd)
    assert data == b"\x00" * (len(OLD.hex()) + 1)


def test_overwrite_cleans_the_copy_of_a_stopped_overwrite(tmp_path):
    ks = FileKeystore(tmp_path / "keys")
    ks.put("acct-1", OLD)
    stale = tmp_path / "keys" / ".acct-1.deadbeef.old"
    stale.write_text(OLD.hex() + "\n")
    ks.put("acct-1", NEW, overwrite=True)
    assert sorted(os.listdir(tmp_path / "keys")) == ["acct-1.key"]


def test_failed_overwrite_keeps_the_old_value(ks, tmp_path, monkeypatch):
    if isinstance(ks, MemoryKeystore):
        pytest.skip("no disk")
    ks.put("acct-1", OLD)

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken)
    with pytest.raises(OSError, match="disk full"):
        ks.put("acct-1", NEW, overwrite=True)
    monkeypatch.undo()
    assert ks.get("acct-1") == OLD
    assert len(os.listdir(tmp_path / "keys")) == 1


def test_delete(ks, tmp_path):
    ks.put("acct-1", OLD)
    assert ks.delete("acct-1") is True
    assert ks.get("acct-1") is None
    assert ks.delete("acct-1") is False
    assert ks.list() == []
    d = tmp_path / "keys"
    if d.exists():
        assert os.listdir(d) == []
    ks.put("acct-1", NEW)  # the name is free again
    assert ks.get("acct-1") == NEW


def test_list_by_prefix(ks):
    for name in ("acct-b", "acct-a", "model-key-x", "device-ed25519"):
        ks.put(name, OLD)
    ks.replace("device-ed25519", NEW)  # the kept copy is not a name
    assert ks.list() == ["acct-a", "acct-b", "device-ed25519", "model-key-x"]
    assert ks.list("acct-") == ["acct-a", "acct-b"]
    assert ks.list("none") == []


def test_replace_keeps_the_old_value_on_disk(tmp_path):
    ks = FileKeystore(tmp_path / "keys")
    ks.put("vault-key", OLD)
    ks.replace("vault-key", NEW)
    assert ks.get("vault-key") == NEW
    assert sorted(os.listdir(tmp_path / "keys")) == ["vault-key.key", "vault-key.key.replaced-1"]
    assert (tmp_path / "keys" / "vault-key.key.replaced-1").read_text().strip() == OLD.hex()


@pytest.mark.parametrize("name", ["", "A", "a_b", "../x", "-a", "a" * 64, "a.key"])
def test_bad_names_are_refused(ks, name):
    with pytest.raises(ValueError):
        ks.put(name, OLD)
    with pytest.raises(ValueError):
        ks.get(name)
    with pytest.raises(ValueError):
        ks.delete(name)


def test_empty_secret_is_refused(ks):
    with pytest.raises(ValueError):
        ks.put("device", b"")
    with pytest.raises(ValueError):
        ks.put("device", b"", overwrite=True)
    assert ks.get("device") is None


def test_get_or_create_uses_the_key_of_a_faster_writer(ks):
    def factory():
        ks.put("local-store-key", OLD)  # a second writer wins during the call
        return NEW

    assert ks.get_or_create("local-store-key", factory) == OLD
    assert ks.get_or_create("local-store-key", lambda: NEW) == OLD


def test_erase_old_does_not_zero_multi_linked_inode(tmp_path):
    ks = FileKeystore(tmp_path / "keys")
    ks.put("acct-1", OLD)
    live = tmp_path / "keys" / "acct-1.key"
    stale = tmp_path / "keys" / ".acct-1.deadbeef.old"
    os.link(live, stale)
    # Simulate a concurrent/stale .old link still pointing to the live inode.
    ks._erase_old("acct-1")
    assert ks.get("acct-1") == OLD
    assert stale.exists()
