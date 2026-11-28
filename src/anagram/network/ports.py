"""Ports of the network layer.

`AdmissionCheck`: the checks of the `invite` and `join` entries of a group
roster. L4 gives it; the roster (`network.formats.lab`) uses it. (What the
node groups and matching read from L1 is not a port here: L1 is below, so
they import `IdentityDirectory` from `identity.api`.)"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol


class AdmissionCheck(Protocol):
    """The admission checks of a group roster (the `invite` and `join`
    entries). `refusal` is the admission policy: None if a person can use the
    invite at `at`, else the reason (`revoked`, `used`, `expired`,
    `endorser`). `endorser_ok` is the rule of the group: the person who made
    the invite can still invite (a group narrows the node policy)."""

    def invite_id(self, auth: dict) -> str: ...

    def check_invite(self, auth: dict) -> dict: ...

    def check_request_form(self, request: dict) -> dict: ...

    def check_request(self, request: dict, auth: dict) -> dict: ...

    def request_hash(self, request: dict) -> str: ...

    def refusal(self, invite: dict, endorser_ok: bool, at: datetime) -> str | None: ...


class FindingVault(Protocol):
    """The calls of the local vault (L2, `anagram.local.vault.Vault`) that
    the network parts make: the finding rows, the evidence metadata and
    blobs, the sent grants, and the rings. The composition root gives the
    vault. The share tables are in `ShareStore`."""

    def find(self, ref: str) -> Any: ...

    def get(self, root: str) -> Any: ...

    def list(self) -> list: ...

    def evidence_meta(self, root: str) -> dict[int, dict]: ...

    def set_blob(self, root: str, slot: int | None, blob_id: str) -> None: ...

    def clear_blob(self, root: str, slot: int | None) -> None: ...

    def grants_sent(self, root: str | None = None) -> list[dict]: ...

    def add_grant_sent(self, *args: Any) -> None: ...

    def forget_grant_sent(self, grant_id: str) -> None: ...

    def ring(self, name: str) -> Any: ...

    def rings(self) -> list[dict]: ...

    def create_ring(self, name: str) -> Any: ...

    def set_ring_members(self, name: str, members: list[str]) -> None: ...
