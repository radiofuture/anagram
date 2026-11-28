"""Proof bundles: build and verify offline.

verify_bundle() needs only the bundle, the pinned trust inputs, and (optional)
local copies of files to compare. It uses no network and no node.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from anagram.core.canonical import CanonicalError, canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import ContentDigest, hash_file
from anagram.core.crypto.hashing import TAG_EVIDENCE_ROOT, TAG_FINDING_ROOT
from anagram.core.errors import FormatError
from anagram.core.validate import HEX32, hex_field, int_at_least
from anagram.proofs.anchors.base import AnchorTrust, verify_anchor
from anagram.proofs.anchors.defaults import describe_record
from anagram.proofs.bundle import EvidenceOpening, LogProof, ProofBundle
from anagram.proofs.log.checkpoint import open_checkpoint
from anagram.proofs.log.note import NoteError, NoteVerifier
from anagram.proofs.records import FieldProof, SignedSubject, check_schema_layout, owner_json


@dataclass
class Trust:
    """What the verifier pins. Never take these from the bundle itself."""

    log_keys: list[NoteVerifier]
    witness_keys: list[NoteVerifier] = field(default_factory=list)
    witness_threshold: int | None = None  # default: 1 if witness keys are pinned, else 0
    anchors: AnchorTrust = field(default_factory=AnchorTrust)
    min_anchors: int = 1

    def threshold(self) -> int:
        if self.witness_threshold is not None:
            return self.witness_threshold
        return 1 if self.witness_keys else 0


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    required: bool = True


@dataclass
class VerifyReport:
    checks: list[Check] = field(default_factory=list)
    kind: str | None = None
    root: str | None = None
    owner_key: str | None = None
    # Proven time. witness_time is the k-th earliest valid cosignature time
    # (k = witness threshold). anchor_time is the m-th earliest time over
    # distinct anchor sources (m = min_anchors). not_after is the earlier one.
    not_after: datetime | None = None
    witness_time: datetime | None = None
    anchor_time: datetime | None = None
    opened: dict[str, Any] = field(default_factory=dict)
    evidence: dict[int, dict[str, Any]] = field(default_factory=dict)
    matched_files: dict[str, int] = field(default_factory=dict)
    # One line for each anchor record in the bundle: (label, state). The state
    # is "valid <time>", "pending", or "not counted: <reason>".
    anchor_notes: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks if c.required)

    def anchor_lines(self) -> list[str]:
        """Which anchors back this proof, in plain words."""
        if not self.anchor_notes:
            return ["anchors that back this proof: none (time comes from witnesses only)"]
        out = ["anchors that back this proof:"]
        out += [f"  - {label}: {state}" for label, state in self.anchor_notes]
        if any(label.startswith("fake") for label, _ in self.anchor_notes):
            out.append("  WARNING: a fake anchor is for local tests only. It proves no time.")
        return out

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, ok, detail))
        return ok

    def summary(self) -> str:
        lines = [f"{'VALID' if self.ok else 'INVALID'} {self.kind or '?'} {self.root or ''}"]
        if self.not_after:
            lines.append(f"existed no later than: {self.not_after.isoformat()}")
        if self.witness_time:
            lines.append(f"  from witnesses: {self.witness_time.isoformat()}")
        if self.anchor_time:
            lines.append(f"  from anchors: {self.anchor_time.isoformat()}")
        lines.extend(self.anchor_lines())
        for k, v in sorted(self.opened.items()):
            lines.append(f"opened {k}: {canonical_json(v).decode()}")
        for slot, fields in sorted(self.evidence.items()):
            for k, v in sorted(fields.items()):
                lines.append(f"opened evidence.{slot}.{k}: {canonical_json(v).decode()}")
        for path, slot in self.matched_files.items():
            lines.append(f"file {path} equals evidence.{slot}")
        for c in self.checks:
            mark = ("ok" if c.ok else "FAIL") if c.required else ("info" if c.ok else "skip")
            lines.append(f"  [{mark}] {c.name}{': ' + c.detail if c.detail else ''}")
        return "\n".join(lines)


def build_bundle(
    subject: SignedSubject,
    submitted: dict,
    finding_openings: list[FieldProof] | tuple = (),
    evidence_openings: list[EvidenceOpening] | tuple = (),
    sealed_opening: dict | None = None,
) -> ProofBundle:
    """Make a bundle from a subject and a node submit result."""
    log = LogProof(
        entry=subject.log_entry(),
        leaf_index=int_at_least(submitted["leaf_index"], "leaf_index", 0),
        tree_size=int_at_least(submitted["tree_size"], "tree_size", 0),
        inclusion=tuple(
            bytes.fromhex(hex_field(h, HEX32, "inclusion")) for h in submitted["inclusion"]
        ),
        checkpoint=submitted["checkpoint"],
    )
    return ProofBundle(
        subject=subject,
        log=log,
        anchors=tuple(submitted.get("anchors", ())),
        finding_openings=tuple(finding_openings),
        evidence_openings=tuple(evidence_openings),
        sealed_opening=sealed_opening,
    )


def _kth_earliest(times: list[datetime], k: int) -> datetime | None:
    """The k-th earliest time (k >= 1), or None if k < 1 or too few times.
    With k sources needed, fewer than k sources cannot move the time earlier."""
    if k < 1 or len(times) < k:
        return None
    return sorted(times)[k - 1]


def _cosign_time(ts: int) -> datetime | None:
    try:
        return datetime.fromtimestamp(ts, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _anchor_source(rec: dict, check_source: str) -> str:
    """Identity of the trust root behind an anchor. Two anchors from one source
    count once. If the anchor check gives no source, use the record bytes."""
    if check_source:
        return check_source
    try:
        return "record:" + hashlib.sha256(canonical_json(rec)).hexdigest()
    except (CanonicalError, TypeError, ValueError):
        return "record:" + repr(rec)


def verify_bundle(
    bundle: ProofBundle, trust: Trust, files: list[str | Path] | tuple = ()
) -> VerifyReport:
    r = VerifyReport()
    s = bundle.subject
    r.kind, r.root, r.owner_key = s.kind, s.root.hex(), s.owner_key.hex()

    r.add("owner signature", s.signature_ok())
    r.add("log entry matches subject", bundle.log.entry == s.log_entry())

    # Checkpoint and inclusion.
    try:
        vc = open_checkpoint(bundle.log.checkpoint, trust.log_keys, trust.witness_keys)
    except NoteError as exc:
        r.add("checkpoint signed by pinned log key", False, str(exc))
        return r
    cp = vc.checkpoint
    r.add("checkpoint signed by pinned log key", True, vc.log_key.name)
    r.add("tree size matches checkpoint", bundle.log.tree_size == cp.size)
    try:
        leaf = merkle.leaf_hash(canonical_json(bundle.log.entry))
    except CanonicalError as exc:
        r.add("log inclusion", False, str(exc))
        return r
    r.add(
        "log inclusion",
        merkle.verify_inclusion(
            leaf, bundle.log.leaf_index, cp.size, bundle.log.inclusion, cp.root
        ),
        f"leaf {bundle.log.leaf_index} of {cp.size}",
    )

    # Witnesses. Count each pinned witness once. A time that is out of range
    # makes the cosignature invalid.
    need = trust.threshold()
    w_times: dict[tuple[str, bytes], datetime] = {}
    for w, ts in vc.cosignatures:
        when = _cosign_time(ts)
        if when is not None:
            w_times.setdefault((w.name, w.public), when)
    r.add(
        "witness cosignatures",
        len(w_times) >= need,
        f"{len(w_times)} valid, {need} needed",
    )
    r.witness_time = _kth_earliest(list(w_times.values()), need)

    # Anchors. Count distinct sources (trust roots), not records.
    digest = cp.digest()
    a_times: dict[str, datetime] = {}
    for rec in bundle.anchors:
        check = verify_anchor(rec, digest, trust.anchors)
        if check.ok and check.time is not None:
            src = _anchor_source(rec, check.source)
            if src not in a_times or check.time < a_times[src]:
                a_times[src] = check.time
        # One anchor alone does not fail the bundle (the verifier may not pin its
        # trust root). The count below is the requirement.
        r.checks.append(Check(f"anchor {check.type}", check.ok, check.detail, required=False))
        if check.ok and check.time is not None:
            state = f"valid, {check.time.isoformat()}"
        elif check.pending:
            state = "pending (not usable yet; refresh the proof later)"
        else:
            state = f"not counted: {check.detail}"
        r.anchor_notes.append((describe_record(rec), state))
    r.add(
        "anchors",
        len(a_times) >= trust.min_anchors,
        f"{len(a_times)} valid distinct sources, {trust.min_anchors} needed",
    )
    r.anchor_time = _kth_earliest(list(a_times.values()), trust.min_anchors)
    derived = [t for t in (r.witness_time, r.anchor_time) if t is not None]
    r.not_after = min(derived) if derived else None

    # Selective openings.
    _verify_openings(bundle, r)

    # Files.
    for path in files:
        _match_file(Path(path), r)
    return r


def _open_field(fp: FieldProof, tag: str, root: bytes, label: str, r: VerifyReport) -> bool:
    try:
        check_schema_layout(tag, fp.layout)
    except FormatError as exc:
        return r.add(label, False, str(exc))
    return r.add(label, fp.verify(tag, root))


def _verify_openings(bundle: ProofBundle, r: VerifyReport) -> None:
    s = bundle.subject
    layout: tuple[str, ...] = ()
    for fp in bundle.finding_openings:
        if _open_field(fp, s.root_tag, s.root, f"opening {fp.name}", r):
            r.opened[fp.name] = fp.value
            if s.root_tag == TAG_FINDING_ROOT:
                layout = fp.layout
    if "owner" in r.opened:
        r.add("opened owner equals signer", r.opened["owner"] == owner_json(s.owner_key))
    if s.root_tag == TAG_FINDING_ROOT and r.opened:
        for count, prefix in (("evidence_count", "evidence."), ("link_count", "links.")):
            if count in r.opened:
                n = sum(1 for name in layout if name.startswith(prefix))
                r.add(f"opened {count} equals layout", r.opened[count] == n)
    for ev in bundle.evidence_openings:
        root_hex = r.opened.get(f"evidence.{ev.slot}")
        if not isinstance(root_hex, str) or not HEX32.match(root_hex):
            r.add(
                f"evidence.{ev.slot} opening",
                False,
                "bad root" if isinstance(root_hex, str) else "finding field not opened",
            )
            continue
        ev_root = bytes.fromhex(root_hex)
        fields: dict[str, Any] = {}
        for fp in ev.fields:
            label = f"opening evidence.{ev.slot}.{fp.name}"
            if _open_field(fp, TAG_EVIDENCE_ROOT, ev_root, label, r):
                fields[fp.name] = fp.value
        r.evidence[ev.slot] = fields


def _match_file(path: Path, r: VerifyReport) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        r.add(f"file {path.name} equals an opened evidence item", False, str(exc))
        return
    for slot, fields in r.evidence.items():
        content = fields.get("content")
        if not isinstance(content, dict):
            continue
        try:
            expected = ContentDigest.from_json(content)
        except (FormatError, ValueError, KeyError, TypeError):
            continue
        if size != expected.size:
            continue
        try:
            got = hash_file(path, expected.chunk_size)
        except (OSError, ValueError) as exc:
            r.add(f"file {path.name} equals evidence.{slot}", False, str(exc))
            return
        if got.digest == expected.digest:
            r.matched_files[str(path)] = slot
            r.add(f"file {path.name} equals evidence.{slot}", True)
            return
    r.add(f"file {path.name} equals an opened evidence item", False, "no opened content matches")
