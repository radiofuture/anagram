"""The place of the master key: one item in the OS keychain.

A slot holds one secret for each account name. `KeyringSlot` wraps one
explicit backend object of the `keyring` library. The code never calls
`keyring.get_keyring()`, so a third-party backend is never found
automatically. `MemorySlot` is for tests.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from anagram.identity.app.keystore import KeystoreError

SERVICE = "org.radiofuture.anagram"
ACCOUNT_PREFIX = "keystore-master:"


class SlotUnavailable(KeystoreError):
    """This computer has no keychain service."""


class SlotLocked(KeystoreError):
    """The keychain is there, but it is locked or it refused the access. The
    caller must stop: no fallback to files, no new keys."""


def account(keystore_id: str) -> str:
    return ACCOUNT_PREFIX + keystore_id


class MasterSlot(ABC):
    backend: str  # "macos-keychain" | "secret-service" | "windows-credential" | "memory"

    @abstractmethod
    def get(self, account: str) -> bytes | None: ...

    @abstractmethod
    def set(self, account: str, secret: bytes) -> None:
        """Store a secret. Fail with `FileExistsError` if the account exists."""

    @abstractmethod
    def delete(self, account: str) -> None: ...


class KeyringSlot(MasterSlot):
    """Wraps one `keyring` backend object. The stored value is the hex text of
    the secret."""

    def __init__(self, backend: str, impl) -> None:
        self.backend = backend
        self._impl = impl

    def _call(self, fn, *args):
        from keyring import errors

        try:
            return fn(SERVICE, *args)
        except (errors.NoKeyringError, errors.InitError) as exc:
            raise SlotUnavailable("no keychain service on this computer") from exc
        except errors.KeyringError as exc:
            # Locked, access refused, or an error that we cannot tell from
            # these. The safe answer is the same: stop.
            raise SlotLocked("the keychain is locked or it refused the access") from exc

    def get(self, account: str) -> bytes | None:
        text = self._call(self._impl.get_password, account)
        if text is None:
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise KeystoreError("the keychain item of Anagram is malformed") from None

    def set(self, account: str, secret: bytes) -> None:
        if self.get(account) is not None:
            raise FileExistsError(f"keychain item exists: {account}")
        self._call(self._impl.set_password, account, secret.hex())

    def delete(self, account: str) -> None:
        from keyring import errors

        try:
            self._impl.delete_password(SERVICE, account)
        except errors.PasswordDeleteError:
            # The backends raise this error also for an item that is not there.
            if self.get(account) is not None:
                raise SlotLocked("the keychain refused the delete") from None
        except (errors.NoKeyringError, errors.InitError) as exc:
            raise SlotUnavailable("no keychain service on this computer") from exc
        except errors.KeyringError as exc:
            raise SlotLocked("the keychain is locked or it refused the access") from exc


class MemorySlot(MasterSlot):
    """For tests. `locked = True` makes each call fail as a locked keychain."""

    backend = "memory"

    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}
        self.locked = False
        self.reads = 0

    def _check(self) -> None:
        if self.locked:
            raise SlotLocked("the keychain is locked or it refused the access")

    def get(self, account: str) -> bytes | None:
        self._check()
        self.reads += 1
        return self.items.get(account)

    def set(self, account: str, secret: bytes) -> None:
        self._check()
        if account in self.items:
            raise FileExistsError(f"keychain item exists: {account}")
        self.items[account] = secret

    def delete(self, account: str) -> None:
        self._check()
        self.items.pop(account, None)


def _platform_backend() -> tuple[str, object]:
    """The name and the backend object for this system. Raise `SlotUnavailable`
    if there is none."""
    try:
        if sys.platform == "darwin":
            from keyring.backends import macOS

            name, cls = "macos-keychain", macOS.Keyring
        elif sys.platform.startswith("linux"):
            from keyring.backends import SecretService

            name, cls = "secret-service", SecretService.Keyring
        elif sys.platform == "win32":
            from keyring.backends import Windows

            name, cls = "windows-credential", Windows.WinVaultKeyring
        else:
            raise SlotUnavailable(f"no keychain support for {sys.platform}")
        cls.priority  # noqa: B018  (raises if the backend cannot work on this host)
    except SlotUnavailable:
        raise
    except Exception as exc:  # (import error, no D-Bus session, no library)
        raise SlotUnavailable("no keychain service on this computer") from exc
    return name, cls()


def os_slot() -> MasterSlot:
    """The keychain of this operating system. Raise `SlotUnavailable` if this
    computer has none. This function does not read or write an item."""
    name, impl = _platform_backend()
    return KeyringSlot(name, impl)
