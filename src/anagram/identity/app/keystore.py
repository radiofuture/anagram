"""Keystore interface, a file keystore, and a memory keystore.

`FileKeystore` holds each key as a hex file (mode 0600 in a 0700 directory).
`anagram.identity.app.keychain` adds a keystore whose files are sealed with a master key
from the OS keychain. Client code gets its keystore from
`anagram.identity.app.keychain.open_keystore`.

Rules of the interface:

- `put(name, secret)` never overwrites. Identity keys use it.
- `put(name, secret, overwrite=True)` replaces the value and keeps no copy of
  the old value. Tokens and API keys use it.
- `replace(name, secret)` keeps the old value in a second file. Identity keys
  only.
- `delete(name)` erases the value.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")


class KeystoreError(ValueError):
    """A key file is there but it is empty or malformed. Do not replace it."""


def check_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"bad key name: {name!r}")
    return name


def erase_file(path: str | Path) -> bool:
    """Write zeros on the file, fsync, then unlink it. Return True if the file
    was there. On an SSD or a copy-on-write file system the old blocks can stay;
    the erase is best effort."""
    try:
        fd = os.open(path, os.O_WRONLY)
    except FileNotFoundError:
        return False
    try:
        size = os.fstat(fd).st_size
        if size:
            os.write(fd, b"\x00" * size)
        os.fsync(fd)
    finally:
        os.close(fd)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    return True


class Keystore(ABC):
    @abstractmethod
    def get(self, name: str) -> bytes | None: ...

    @abstractmethod
    def put(self, name: str, secret: bytes, *, overwrite: bool = False) -> None:
        """Store a value. With `overwrite=False`, fail with `FileExistsError`
        if the name exists. With `overwrite=True`, replace the value; no copy
        of the old value stays."""

    @abstractmethod
    def replace(self, name: str, secret: bytes) -> None:
        """Replace a key on purpose (a new device takes the person keys). The
        old value stays in the keystore under a second name. Identity keys
        only. The caller must make sure that no data depends on the old key."""

    @abstractmethod
    def delete(self, name: str) -> bool:
        """Erase a value. Return True if the name was there."""

    @abstractmethod
    def list(self, prefix: str = "") -> list[str]:
        """The names that start with `prefix`, sorted."""

    def get_or_create(self, name: str, factory: Callable[[], bytes]) -> bytes:
        value = self.get(name)
        if value is None:
            with contextlib.suppress(FileExistsError):
                # If a second writer made the key first, use that key.
                self.put(name, factory())
            value = self.get(name)
            if value is None:
                raise KeystoreError(f"key {name} was removed during its creation")
        return value


class DirectoryKeystore(Keystore):
    """One file for each key in a 0700 directory. A subclass gives the file
    suffix and the text form of a value (`_encode`, `_decode`)."""

    suffix = ""

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)

    @abstractmethod
    def _encode(self, name: str, secret: bytes) -> str: ...

    @abstractmethod
    def _decode(self, name: str, text: str, path: Path) -> bytes: ...

    def _path(self, name: str) -> Path:
        return self.dir / f"{check_name(name)}{self.suffix}"

    def get(self, name: str) -> bytes | None:
        try:
            return self.read_file(name, self._path(name))
        except FileNotFoundError:
            return None

    def read_file(self, name: str, path: Path) -> bytes:
        """The value of key `name` in the file `path` (the key file or a copy
        of it, for example `.replaced-<n>`)."""
        text = path.read_text(encoding="ascii", errors="replace")
        return self._decode(name, text.strip(), path)

    def write_file(self, name: str, secret: bytes, path: Path) -> None:
        """Write the value of key `name` atomically to the file `path` in this
        directory (a copy beside the key file, for example `.replaced-<n>`)."""
        os.replace(self._write_tmp(name, secret), path)

    def _write_tmp(self, name: str, secret: bytes) -> str:
        """Write the value to a 0600 temp file in the same directory and fsync
        it. Return the path. The caller links or renames it and removes it."""
        if not secret:
            raise ValueError("empty secret")
        text = self._encode(name, secret)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{name}.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text + "\n")
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        return tmp

    def put(self, name: str, secret: bytes, *, overwrite: bool = False) -> None:
        """Write the key atomically.

        `overwrite=False`: hard-link a temp file to the final name. The link
        fails if the name exists, so two writers cannot both win.

        `overwrite=True`: rename a temp file onto the final name, then write
        zeros on the old file and remove it. A reader sees the old value or
        the new value, never a partial file."""
        p = self._path(name)
        if not overwrite:
            if p.exists():
                raise FileExistsError(f"key exists: {name}")
            tmp = self._write_tmp(name, secret)
            try:
                try:
                    os.link(tmp, p)
                except FileExistsError:
                    raise FileExistsError(f"key exists: {name}") from None
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
            self.fsync_dir()
            return
        tmp = self._write_tmp(name, secret)
        old = self.dir / f".{name}.{secrets.token_hex(4)}.old"
        try:
            # A second name for the old file, so that its bytes can be erased
            # after the rename took the file away from the final name.
            with contextlib.suppress(FileNotFoundError):
                os.link(p, old)
            os.replace(tmp, p)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(old)
            raise
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        self._erase_old(name)
        self.fsync_dir()

    def _erase_old(self, name: str) -> None:
        """Erase each old copy that an overwrite of this name left (also the
        copy of an overwrite that stopped before its erase)."""
        for stale in self.dir.glob(f".{name}.*.old"):
            erase_file(stale)

    def replace(self, name: str, secret: bytes) -> None:
        """Write the new key atomically. The old key file stays as
        `<name><suffix>.replaced-<n>` (it is not deleted)."""
        p = self._path(name)
        if not p.exists():
            self.put(name, secret)
            return
        n = 1
        while (keep := self.dir / f"{p.name}.replaced-{n}").exists():
            n += 1
        os.link(p, keep)
        tmp = self._write_tmp(name, secret)
        try:
            os.replace(tmp, p)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        self.fsync_dir()

    def delete(self, name: str) -> bool:
        """Write zeros on the key file, fsync, unlink. A `.replaced-<n>` copy
        from `replace` is not touched."""
        had = erase_file(self._path(name))
        self._erase_old(name)
        self.fsync_dir()
        return had

    def list(self, prefix: str = "") -> list[str]:
        out = []
        for p in self.dir.iterdir():
            if not p.name.endswith(self.suffix):
                continue
            name = p.name[: -len(self.suffix)]
            if _NAME.match(name) and name.startswith(prefix):
                out.append(name)
        return sorted(out)

    def fsync_dir(self) -> None:
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class FileKeystore(DirectoryKeystore):
    """Hex key files `<name>.key`. The files are not encrypted."""

    suffix = ".key"

    def _encode(self, name: str, secret: bytes) -> str:
        return secret.hex()

    def _decode(self, name: str, text: str, path: Path) -> bytes:
        if not _HEX.match(text):
            raise KeystoreError(f"key file {path} is empty or malformed")
        return bytes.fromhex(text)


class MemoryKeystore(Keystore):
    """For tests. Nothing goes to the disk."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    def get(self, name: str) -> bytes | None:
        return self._data.get(check_name(name))

    def put(self, name: str, secret: bytes, *, overwrite: bool = False) -> None:
        if not secret:
            raise ValueError("empty secret")
        if not overwrite and check_name(name) in self._data:
            raise FileExistsError(f"key exists: {name}")
        self._data[check_name(name)] = secret

    def replace(self, name: str, secret: bytes) -> None:
        self.put(name, secret, overwrite=True)

    def delete(self, name: str) -> bool:
        return self._data.pop(check_name(name), None) is not None

    def list(self, prefix: str = "") -> list[str]:
        return sorted(n for n in self._data if n.startswith(prefix))
