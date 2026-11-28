"""Proof bundle format `anagram.proof_bundle.v1` (JSON). See spec/proof-bundle.md."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from anagram.core.canonical import canonical_json, loads
from anagram.core.errors import FormatError
from anagram.core.validate import HEX32, hex_field, int_at_least
from anagram.proofs.records import FieldProof, SignedSubject

BUNDLE_SCHEMA = "anagram.proof_bundle.v1"


@dataclass(frozen=True)
class LogProof:
    entry: dict  # the log entry object; leaf data = canonical_json(entry)
    leaf_index: int
    tree_size: int
    inclusion: tuple[bytes, ...]
    checkpoint: str  # C2SP signed note, with log signature and cosignatures

    def to_json(self) -> dict:
        return {
            "checkpoint": self.checkpoint,
            "entry": self.entry,
            "inclusion": [h.hex() for h in self.inclusion],
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
        }

    @classmethod
    def from_json(cls, obj: dict) -> LogProof:
        if not isinstance(obj, dict) or not isinstance(obj.get("entry"), dict):
            raise FormatError("log proof: bad entry")
        if not isinstance(obj.get("checkpoint"), str):
            raise FormatError("log proof: bad checkpoint")
        inclusion = obj.get("inclusion")
        if not isinstance(inclusion, list):
            raise FormatError("log proof: inclusion must be a list")
        return cls(
            entry=dict(obj["entry"]),
            leaf_index=int_at_least(obj.get("leaf_index"), "log proof leaf_index", 0),
            tree_size=int_at_least(obj.get("tree_size"), "log proof tree_size", 0),
            inclusion=tuple(
                bytes.fromhex(hex_field(h, HEX32, "log proof inclusion")) for h in inclusion
            ),
            checkpoint=obj["checkpoint"],
        )


@dataclass(frozen=True)
class EvidenceOpening:
    """Opened fields of the evidence item in finding field `evidence.<slot>`."""

    slot: int
    fields: tuple[FieldProof, ...]

    def to_json(self) -> dict:
        return {"fields": [f.to_json() for f in self.fields], "slot": self.slot}

    @classmethod
    def from_json(cls, obj: dict) -> EvidenceOpening:
        return cls(
            slot=int(obj["slot"]),
            fields=tuple(FieldProof.from_json(f) for f in obj["fields"]),
        )


@dataclass(frozen=True)
class ProofBundle:
    subject: SignedSubject
    log: LogProof
    anchors: tuple[dict, ...] = ()
    finding_openings: tuple[FieldProof, ...] = ()
    evidence_openings: tuple[EvidenceOpening, ...] = ()
    sealed_opening: dict | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "anchors": list(self.anchors),
            "log": self.log.to_json(),
            "openings": {
                "evidence": [e.to_json() for e in self.evidence_openings],
                "finding": [f.to_json() for f in self.finding_openings],
            },
            "schema": BUNDLE_SCHEMA,
            "sealed_opening": self.sealed_opening,
            "subject": self.subject.to_json(),
        }

    def dumps(self) -> str:
        return canonical_json(self.to_json()).decode("utf-8")

    @classmethod
    def from_json(cls, obj: dict) -> ProofBundle:
        if not isinstance(obj, dict) or obj.get("schema") != BUNDLE_SCHEMA:
            raise FormatError("not an anagram.proof_bundle.v1 document")
        try:
            openings = obj.get("openings") or {}
            return cls(
                subject=SignedSubject.from_json(obj["subject"]),
                log=LogProof.from_json(obj["log"]),
                anchors=tuple(obj.get("anchors") or ()),
                finding_openings=tuple(
                    FieldProof.from_json(f) for f in openings.get("finding", [])
                ),
                evidence_openings=tuple(
                    EvidenceOpening.from_json(e) for e in openings.get("evidence", [])
                ),
                sealed_opening=obj.get("sealed_opening"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise FormatError(f"bad proof bundle: {exc}") from exc

    @classmethod
    def loads(cls, text: str | bytes) -> ProofBundle:
        return cls.from_json(loads(text))
