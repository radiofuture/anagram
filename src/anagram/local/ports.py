"""Ports of the app (layers plan, section 4). The `Client`
composition root gives them; the app does not import the code that
gives them.

- `LabContext`: what the app reads about the labs of the person
  (L3 gives it: `Client.lab_context`).
- `Committer`: the client calls that commit a record to the log (stream
  checkpoints, findings).
- `LocalClient`: the app client as the app uses it (the index
  key, the source kinds of the higher layers, the labs)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from anagram.core.nodeapi import NodeAPI


class LabPolicy(Protocol):
    """The rules of one lab that the app applies."""

    oauth_clients: Any  # the `oauth_clients` section of the lab settings

    def allows_assistant(self) -> bool: ...

    def allows_cloud_assistant(self) -> bool: ...

    def allows_recipient(self, recipient_id: str | None) -> bool: ...


class LabContext(Protocol):
    """The labs of the person on this device. A method can raise when there
    is no session or no lab cache; the caller then uses the private space
    only."""

    def readable_labs(self) -> list[str]: ...

    def lab_list(self) -> list[dict]: ...

    def lab_policy(self, lab_id: str) -> LabPolicy: ...


class SecretKeys(Protocol):
    """The keystore of the device: named secrets."""

    def get(self, name: str) -> bytes | None: ...

    def get_or_create(self, name: str, make: Callable[[], bytes]) -> bytes: ...


class CommitDevice(Protocol):
    def device_key(self) -> Any: ...

    def now(self) -> datetime: ...

    def trust(self) -> Any: ...


class FindingCommits(Protocol):
    def check_submit(self, subject: Any, result: dict) -> None: ...

    def commit_finding(self, paths: list, **kw: Any) -> Any: ...


class Committer(Protocol):
    device: CommitDevice
    findings: FindingCommits

    @property
    def node(self) -> NodeAPI: ...


class LocalClient(Committer, Protocol):
    index_sources: tuple[type, ...]
    lab_context: LabContext

    @property
    def home(self) -> Path: ...

    @property
    def keystore(self) -> SecretKeys: ...
