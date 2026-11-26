"""Ports of the model part (layers plan, section 4): what the model profiles
need from a higher layer. The keystore of the device (L1) gives
`SecretStore`; models does not import it."""

from __future__ import annotations

from typing import Protocol


class SecretStore(Protocol):
    def get(self, name: str) -> bytes | None: ...

    def put(self, name: str, secret: bytes, *, overwrite: bool = False) -> None: ...

    def delete(self, name: str) -> bool: ...
