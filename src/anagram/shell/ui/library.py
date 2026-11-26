"""The findings of the local UI (layer L2): proposed findings from the
index, the timestamp (commit) of a finding, the finding views, and the proof
files.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError
from anagram.local.api import (
    LocalIndex,
    ProviderDrafter,
    approve_finding,
    draft_findings,
    proposals,
)
from anagram.network.api import PUBLIC
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.proof import verify_bundle
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.client import Client
    from anagram.shell.ui.service import UIService

CHANGED = "This proposed finding changed. Open the library again."


def day(ts: str | None) -> str | None:
    """'2026-10-15T12:00:00Z' -> '2026-10-15' (the UI formats it)."""
    return ts[:10] if ts else None


def label_kind(kind: str) -> str:
    return {
        "file": "File",
        "git_commit": "Git commit",
        "zotero_item": "Library item",
        "orcid_work": "Published work",
        "github_commit": "GitHub commit",
    }.get(kind, kind.replace("_", " ").capitalize())


def _draft_title(title: str) -> str:
    named = {"git_commit": "Git history", "github_commit": "GitHub history"}
    return named.get(title) or title.replace("/", " / ")


class LibraryUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self._proven: dict[str, str | None] = {}

    # -------------------------------------------------------------- drafts

    @staticmethod
    def _draft_list(idx: LocalIndex, drafter=None, select=None):
        if drafter is None:
            return draft_findings(idx)
        return draft_findings(idx, drafter=drafter, allow_external=True, select=select)

    @staticmethod
    def draft_json(d) -> dict:
        return {
            "claim_suggestion": d.claim_suggestion,
            "drafted_by": d.drafted_by,
            "end": day(d.end),
            "id": d.id,
            "polarity": d.polarity,
            "items": [
                {
                    "key": i.key,
                    "kind": label_kind(i.kind),
                    "name": i.name or i.ref,
                    "selectable": bool(i.path),
                    "third_party": i.key in d.third_party_keys,
                    "time": day(i.time),
                }
                for i in d.items
            ],
            "start": day(d.start),
            "third_party": d.third_party,
            "title": _draft_title(d.title),
            "topics": d.topics,
        }

    def drafts(self) -> list[dict]:
        used = set(self.ui.state.get("used_drafts") or [])
        with self.ui.session(index=True) as (_, idx):
            return [self.draft_json(d) for d in self._draft_list(idx) if d.id not in used]

    def model_draft(self, draft_id: str) -> dict:
        """A finding draft from a model. The model is the one of the task
        `draft` in the model profiles. An external model needs the
        opt-in of Settings, as before. `drafters` (old: a provider name in
        `ui.json`) is only used when no `draft` model is set."""
        ui = self.ui
        settings = ui.settings.view()
        provider = settings["model"]["provider"]
        enabled = settings["model"]["enabled"]
        with ui.session(index=True) as (c, idx):
            model, _ = ui.settings.draft_model(c, idx)
        if model is not None and (enabled or not model.external):
            drafter = ProviderDrafter(model)
        elif enabled and provider in ui.drafters:
            drafter = ui.drafters[provider]
        else:
            raise UIError(400, "Choose a model in Account first.")
        with ui.session(index=True) as (_, idx):
            for d in self._draft_list(idx, drafter, select=[draft_id]):
                if d.id == draft_id:
                    return self.draft_json(d)
        raise UIError(404, CHANGED)

    def timestamp(self, draft_id: str, claim: str | None, keys: list[str]) -> dict:
        """Commit a proposed finding. The new version then goes to the people
        and labs that have the finding (`SharingUI.follow`)."""
        ui = self.ui
        claim = (claim or "").strip() or None
        if claim and len(claim) > 500:
            raise UIError(400, "Keep the claim to one line (500 characters or fewer).")
        with ui.session(index=True) as (c, idx):
            draft = next((d for d in self._draft_list(idx) if d.id == draft_id), None)
            if draft is None:
                raise UIError(404, CHANGED)
            if not keys and claim is None:
                raise UIError(400, "Choose at least one file, or write a claim.")
            bundle = approve_finding(c, draft, claim=claim, keys=keys)
            # The proposal list leaves out a stamped proposal.
            proposals.set_state(idx, draft_id, "stamped")
        used = list(ui.state.get("used_drafts") or []) + [draft_id]
        ui.state.update(used_drafts=used)
        root = bundle.subject.root.hex()
        if draft.polarity:  # the screens show a negative result
            polarity = dict(ui.state.get("finding_polarity") or {})
            polarity[root] = draft.polarity
            ui.state.update(finding_polarity=polarity)
        view = self.finding(root)
        ui.publish("finding.changed")
        ui.publish("draft.changed")
        return {**view, "followed": ui.sharing.follow(view["root"])}

    # ------------------------------------------------------------ findings

    def _proven_by(self, c: Client, root: str, bundle: dict | None) -> str | None:
        if root in self._proven:
            return self._proven[root]
        if bundle is None:
            return None
        report = verify_bundle(ProofBundle.from_json(bundle), c.device.trust())
        value = (
            report.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
            if report.ok and report.not_after
            else None
        )
        self._proven[root] = value
        return value

    def _finding_view(self, c: Client, rows) -> dict:
        latest = rows[-1]
        label = self.ui.people.label
        versions = []
        for r in rows:
            sent = c.vault.grants_sent(r.root)
            versions.append(
                {
                    "created_at": r.created_at,
                    "proven_by": self._proven_by(c, r.root, r.bundle),
                    "root": r.root,
                    "shared_with": sorted(
                        {
                            "Everyone" if g["recipient"] == PUBLIC else label(g["recipient"])
                            for g in sent
                        }
                    ),
                    "version": r.version,
                }
            )
        doc = c.findings.opening(latest.root)
        meta = c.vault.evidence_meta(latest.root)
        evidence = []
        for slot, ev in enumerate(doc.evidence):
            m = meta.get(slot, {})
            evidence.append(
                {
                    "name": ev.fields.get("name") or f"File {slot + 1}",
                    "on_this_computer": bool(m.get("path")) and Path(m["path"]).is_file(),
                    "slot": slot,
                    "third_party": bool(m.get("third_party")),
                }
            )
        polarity = self.ui.state.get("finding_polarity") or {}
        return {
            "claim": doc.finding.fields.get("claim"),
            "polarity": next((polarity[r.root] for r in rows[::-1] if r.root in polarity), None),
            "details": {"finding_id": latest.finding_id, "root": latest.root},
            "evidence": evidence,
            "id": latest.finding_id,
            "root": latest.root,
            "versions": versions[::-1],
        }

    def findings(self) -> list[dict]:
        with self.ui.session() as c:
            groups: dict[str, list] = {}
            for r in c.vault.list():
                groups.setdefault(r.finding_id, []).append(r)
            out = [
                self._finding_view(c, sorted(rows, key=lambda r: r.version))
                for rows in groups.values()
            ]
        return sorted(out, key=lambda f: f["versions"][0]["created_at"], reverse=True)

    def finding(self, ref: str) -> dict:
        with self.ui.session() as c:
            row = c.vault.find(ref)
            rows = [r for r in c.vault.list() if r.finding_id == row.finding_id]
            return self._finding_view(c, sorted(rows, key=lambda r: r.version))

    # -------------------------------------------------------------- proofs

    def proof_file(self, root: str) -> tuple[str, str]:
        """Proof bundle that opens the claim and each file's fingerprint and name
        (not the files). Anyone can check it with `anagram verify`."""
        with self.ui.session() as c:
            row = c.vault.find(root)
            _refresh_anchors(c, row.root)
            doc = c.findings.opening(row.root)
            names = ["claim"] if doc.finding.fields.get("claim") is not None else []
            ev = {slot: list(e.names()) for slot, e in enumerate(doc.evidence)}
            bundle = c.findings.public_bundle(row.root, names, ev)
        return f"anagram-proof-{row.root[:12]}.json", bundle.dumps()

    def file_proof(self, root: str, slot: int) -> tuple[str, str]:
        with self.ui.session() as c:
            row = c.vault.find(root)
            m = c.vault.evidence_meta(row.root).get(slot) or {}
            path = m.get("path")
            if not path or not Path(path).is_file():
                raise UIError(404, "This file is not on this computer any more.")
            _refresh_anchors(c, row.root)
            try:
                bundle = c.findings.prove_file(row.root, path)
            except ClientError as exc:
                raise UIError(
                    409,
                    "This file changed after you made its proof. The proof covers the old version.",
                ) from exc
        return f"{Path(path).name}.anagram-proof.json", bundle.dumps()


def _refresh_anchors(c: Client, root: str) -> None:
    """Best effort: add background anchors (TSA, Bitcoin) before a download.
    A node that is down or has no anchor yet leaves the proof as it is."""
    try:
        c.findings.refresh_anchors(root)
    except Exception:  # noqa: S110 - the proof is valid without them
        pass
