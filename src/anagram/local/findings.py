"""Findings of this person: commit, anchors, and proofs (layer L2).

`Findings.commit_finding` seals the opening data in the vault before the node
sees anything (lost salts make a proof worthless), sends the signed subject to
the log, and checks the answer (`LogCheck`). The proof methods give a bundle
with selected openings.
"""

from __future__ import annotations

import mimetypes
import secrets
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import ContentDigest, hash_file
from anagram.core.errors import ClientError, LogMisbehaved
from anagram.identity.api import Device, LogCheck, PersonalStore
from anagram.local.vault import Vault
from anagram.proofs.anchors.ots import is_complete
from anagram.proofs.bundle import EvidenceOpening, LogProof, ProofBundle
from anagram.proofs.proof import build_bundle
from anagram.proofs.records import (
    KIND_FINDING,
    LINK_SUPERSEDES,
    Link,
    OpeningDocument,
    SignedSubject,
    evidence_fields,
    evidence_opening,
    finding_fields,
    finding_opening,
)
from anagram.proofs.sealed import seal_opening, unseal_opening


class Findings:
    def __init__(
        self, device: Device, log: LogCheck, personal: PersonalStore, vault: Vault
    ) -> None:
        self.device = device
        self.vault = vault
        self.log = log
        self.personal = personal

    # --------------------------------------------------------------- commit

    def commit_finding(
        self,
        paths: Sequence[str | Path],
        claim: str | None = None,
        links: Sequence[Link] = (),
        source: str = "file",
        third_party: Sequence[bool] | None = None,
    ) -> ProofBundle:
        """Commit files and a claim. `third_party[i]` marks evidence item i as
        holding other people's words (the index sets it; see `Vault.flag_third_party`)."""
        if not paths and claim is None:
            raise ClientError("a finding needs evidence or a claim")
        evidence = []
        for p in paths:
            p = Path(p)
            if not p.is_file():
                raise ClientError(f"not a file: {p}")
            media_type = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            fields = evidence_fields(hash_file(p), media_type, p.name, source)
            evidence.append(evidence_opening(fields))

        finding_id = secrets.token_bytes(16)
        version = 1
        for link in links:
            if link.type == LINK_SUPERSEDES:
                prev = self.vault.get(link.target.hex())
                if prev is None:
                    raise ClientError("supersedes target is not in this vault")
                finding_id = bytes.fromhex(prev.finding_id)
                version = prev.version + 1

        key = self.device.device_key()
        fields = finding_fields(
            finding_id=finding_id,
            version=version,
            owner_key=key.public_bytes(),
            created_at=self.device.now(),
            evidence_roots=[e.root() for e in evidence],
            claim=claim,
            links=list(links),
        )
        opening = finding_opening(fields)
        root = opening.root()
        subject = SignedSubject.sign(KIND_FINDING, root, key)
        sealed = seal_opening(self.device.vault_key(), root, OpeningDocument(opening, evidence))
        # Store the sealed opening before the node sees anything: lost salts
        # make a proof worthless.
        self.vault.add_finding(root.hex(), finding_id.hex(), version, fields["created_at"], sealed)
        flags = list(third_party or [])
        for slot, p in enumerate(paths):
            flag = bool(flags[slot]) if slot < len(flags) else False
            self.vault.set_evidence_meta(root.hex(), slot, str(Path(p).resolve()), flag)

        result = self.device.node.submit(subject.log_entry())
        self.check_submit(subject, result)
        bundle = build_bundle(subject, result, sealed_opening=sealed)
        self.vault.set_bundle(root.hex(), bundle.to_json())
        self.personal.auto_sync()  # the salts go to the personal store (best effort)
        return bundle

    def check_submit(self, subject: SignedSubject, result: dict) -> None:
        """Check the node's answer to a submitted signed subject before the client
        trusts it: checkpoint signatures and cosignatures, consistency with the
        last seen checkpoint, and the inclusion proof. Raise `LogMisbehaved`."""
        self.log.logged(subject.log_entry_bytes(), result)

    # -------------------------------------------------------------- anchors

    @staticmethod
    def _needs_anchor_refresh(bundle: ProofBundle) -> bool:
        real = [a for a in bundle.anchors if a.get("type") != "fake"]
        if not real:
            return True
        return any(a.get("type") == "opentimestamps" and not is_complete(a) for a in real)

    def refresh_anchors(self, ref: str | None = None) -> list[dict]:
        """Get background anchors for logged findings from the node.

        A node in background anchor mode stamps a later checkpoint some minutes
        after the commit. This method moves each bundle to the first anchored
        checkpoint that includes its entry, after it checks the checkpoint and
        the new inclusion proof. Result: one {"root", "status"} for each
        finding that needed anchors ("updated", "waiting", or "unchanged")."""
        rows = [self.vault.find(ref)] if ref else self.vault.list()
        out = []
        for row in rows:
            if row.bundle is None:
                continue
            bundle = ProofBundle.from_json(row.bundle)
            if not self._needs_anchor_refresh(bundle):
                continue
            found = self.device.node.anchored(bundle.log.tree_size)
            if not found or not found.get("anchors"):
                out.append({"root": row.root, "status": "waiting"})
                continue
            if found["checkpoint"] == bundle.log.checkpoint and list(bundle.anchors) == list(
                found["anchors"]
            ):
                out.append({"root": row.root, "status": "unchanged"})
                continue
            cp = self.log.old_checkpoint(found["checkpoint"])
            if cp.size != found["tree_size"] or cp.size < bundle.log.tree_size:
                raise LogMisbehaved("anchored checkpoint has a wrong size")
            path = [
                bytes.fromhex(h) for h in self.device.node.inclusion(bundle.log.leaf_index, cp.size)
            ]
            leaf = merkle.leaf_hash(canonical_json(bundle.log.entry))
            if not merkle.verify_inclusion(leaf, bundle.log.leaf_index, cp.size, path, cp.root):
                raise LogMisbehaved("entry is not included in the anchored checkpoint")
            log = LogProof(
                entry=bundle.log.entry,
                leaf_index=bundle.log.leaf_index,
                tree_size=cp.size,
                inclusion=tuple(path),
                checkpoint=found["checkpoint"],
            )
            new = replace(bundle, log=log, anchors=tuple(found["anchors"]))
            self.vault.set_bundle(row.root, new.to_json())
            out.append({"root": row.root, "status": "updated"})
        return out

    # --------------------------------------------------------------- proofs

    def opening(self, ref: str) -> OpeningDocument:
        row = self.vault.find(ref)
        return unseal_opening(self.device.vault_key(), row.sealed)

    def bundle(self, ref: str) -> ProofBundle:
        row = self.vault.find(ref)
        if row.bundle is None:
            raise ClientError("finding has no log proof yet")
        return ProofBundle.from_json(row.bundle)

    def public_bundle(
        self,
        ref: str,
        finding_fields_to_open: Sequence[str] = (),
        evidence_fields_to_open: dict[int, Sequence[str]] | None = None,
    ) -> ProofBundle:
        """A bundle with selected openings and no sealed opening."""
        base = self.bundle(ref)
        doc = self.opening(ref)
        names = list(finding_fields_to_open)
        ev_open = []
        for slot, ev_names in (evidence_fields_to_open or {}).items():
            names.append(f"evidence.{slot}")
            ev = doc.evidence[slot]
            ev_open.append(EvidenceOpening(slot, tuple(ev.prove(n) for n in ev_names)))
        f_open = tuple(doc.finding.prove(n) for n in dict.fromkeys(names))
        return ProofBundle(
            subject=base.subject,
            log=base.log,
            anchors=base.anchors,
            finding_openings=f_open,
            evidence_openings=tuple(ev_open),
            sealed_opening=None,
        )

    def prove_file(self, ref: str, path: str | Path) -> ProofBundle:
        """Open the salt of the evidence item that equals the file at `path`."""
        doc = self.opening(ref)
        path = Path(path)
        size = path.stat().st_size
        for slot, ev in enumerate(doc.evidence):
            expected = ContentDigest.from_json(ev.fields["content"])
            if expected.size != size:
                continue
            if hash_file(path, expected.chunk_size).digest == expected.digest:
                return self.public_bundle(ref, (), {slot: ["content"]})
        raise ClientError("the file does not equal any evidence item of this finding")

    def list_findings(self) -> list[dict]:
        return [
            {
                "created_at": r.created_at,
                "finding_id": r.finding_id,
                "logged": r.bundle is not None,
                "root": r.root,
                "version": r.version,
            }
            for r in self.vault.list()
        ]
