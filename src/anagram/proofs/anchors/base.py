"""Anchor interface.

An anchor gets an independent time for a 32-byte digest. Anagram anchors the
SHA-256 of each checkpoint text. An anchor record is a JSON object with a
"type" key. Verification is offline and uses only the record, the digest, and
the trust inputs that the verifier pins (AnchorTrust).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509


@dataclass(frozen=True)
class AnchorCheck:
    type: str
    ok: bool
    time: datetime | None = None
    detail: str = ""
    pending: bool = False
    # Identity of the trust root that gave the time (for example a TSA signer
    # certificate fingerprint). Anchors with the same source count once.
    source: str = ""


@dataclass
class AnchorTrust:
    """Trust inputs for offline anchor checks. The verifier supplies them."""

    fake_keys: list[bytes] = field(default_factory=list)
    tsa_roots: list[x509.Certificate] = field(default_factory=list)
    # Bitcoin block height -> (merkle root, internal byte order; block time, unix).
    # Get these from a Bitcoin node or block explorer that you trust.
    bitcoin_headers: dict[int, tuple[bytes, int]] = field(default_factory=dict)


class Anchor(ABC):
    type: str

    @abstractmethod
    def stamp(self, digest: bytes) -> dict:
        """Return an anchor record for the digest."""


def verify_anchor(record: dict, digest: bytes, trust: AnchorTrust) -> AnchorCheck:
    kind = record.get("type") if isinstance(record, dict) else None
    try:
        if kind == "fake":
            from anagram.proofs.anchors.fake import verify_fake

            return verify_fake(record, digest, trust)
        if kind == "rfc3161":
            from anagram.proofs.anchors.rfc3161 import verify_record

            return verify_record(record, digest, trust)
        if kind == "opentimestamps":
            from anagram.proofs.anchors.ots import verify_record as verify_ots

            return verify_ots(record, digest, trust)
    except (KeyError, TypeError, ValueError) as exc:
        return AnchorCheck(str(kind), False, detail=f"malformed record: {exc}")
    return AnchorCheck(str(kind), False, detail="unknown anchor type")
