"""Ports of the proofs part (layers plan, section 4): what the certificate
and the preprint need from the app. The `Client` composition root
gives it; proofs does not import the code that gives it."""

from __future__ import annotations

from typing import Any, Protocol


class FindingReader(Protocol):
    """Own findings and their proofs: `opening`, `public_bundle`,
    `refresh_anchors` (the findings part of the app)."""

    def opening(self, ref: str) -> Any: ...

    def public_bundle(
        self, ref: str, finding_fields_to_open: Any = (), evidence_fields_to_open: Any = None
    ) -> Any: ...

    def refresh_anchors(self, ref: str | None = None) -> list[dict]: ...


class NodeCalls(Protocol):
    def call(self, method: str, path: str, body: Any = None, auth: bool = False) -> Any: ...


class ProofDevice(Protocol):
    """The device: calls to the node, and the pinned trust."""

    @property
    def http(self) -> NodeCalls: ...

    def trust(self) -> Any: ...


class FindingRows(Protocol):
    """The local vault: finding rows (`root`, `bundle`, ...) and the
    evidence metadata."""

    def get(self, root: str) -> Any: ...

    def find(self, ref: str) -> Any: ...

    def evidence_meta(self, root: str) -> dict[int, dict]: ...


class FindingSource(Protocol):
    """The client calls that read one's own findings and proofs."""

    device: ProofDevice
    findings: FindingReader

    @property
    def config(self) -> dict: ...

    @property
    def vault(self) -> FindingRows: ...
