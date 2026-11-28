"""Draft findings: proposals only; approval is explicit."""

from __future__ import annotations

import pytest
from indexkit import lab_index

from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.local.understanding.drafter import DrafterError, FakeModelDrafter
from anagram.local.understanding.drafts import approve_finding, draft_findings
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")


@pytest.fixture
def chen(sim_community, tmp_path):
    index, ids = lab_index(tmp_path / "chen.sqlite", sim_community.out_dir / "labs" / "chen")
    index.scan()
    return index


def test_draft_findings_group_by_folder(chen):
    drafts = draft_findings(chen)
    by_title = {d.where: d for d in drafts}  # the group (a folder), not the title
    assert "mei-lin-chen/notes" in by_title
    assert "git_commit" in by_title  # the repository history
    assert "zotero_item" not in by_title  # references are not findings
    assert "mei-lin-chen/library" not in by_title  # a Zotero export file is a reference
    notes = by_title["mei-lin-chen/notes"]
    assert notes.title == "Chen Lab: Q4 project plan"  # a phrase for people, not the folder
    assert by_title["git_commit"].title == "Nbt7 processing"
    assert notes.committable and notes.paths[0].endswith("2026-q4-project-plan.md")
    assert notes.claim_suggestion.startswith("We have three new experimental cryo-EM structures")
    assert notes.drafted_by == "deterministic"
    assert notes.topics  # plain labels, not IDs
    assert not any(t.startswith("openalex:") for t in notes.topics)
    # The draft ID depends only on the evidence roots.
    assert notes.id == {d.where: d for d in draft_findings(chen)}["mei-lin-chen/notes"].id


def test_third_party_flag_and_claim_from_own_text(chen, sim_community):
    mail = next(d for d in draft_findings(chen) if d.where == "mei-lin-chen/mail")
    assert mail.third_party
    assert mail.claim_suggestion == "We still have no way to predict affinity for the NbT7 pocket."
    third = [c["canary"] for c in sim_community.canaries if c["third_party"]]
    for d in draft_findings(chen):
        assert not any(c in (d.claim_suggestion or "") for c in third)


def test_external_drafter_needs_opt_in(chen):
    fake = FakeModelDrafter()
    with pytest.raises(DrafterError):
        draft_findings(chen, drafter=fake)
    assert fake.seen == []
    # Opt-in alone sends nothing: the provider reads only selected drafts.
    drafts = draft_findings(chen, drafter=fake, allow_external=True)
    assert fake.seen == [] and all(d.drafted_by == "deterministic" for d in drafts)
    mail_id = next(d.id for d in drafts if d.where == "mei-lin-chen/mail")
    drafts = draft_findings(chen, drafter=fake, allow_external=True, select=[mail_id])
    mail = next(d for d in drafts if d.where == "mei-lin-chen/mail")
    assert mail.drafted_by == "fake-model" and mail.claim_suggestion.startswith("Draft:")
    others = [d for d in drafts if d.id != mail_id]
    assert all(d.drafted_by == "deterministic" for d in others)
    assert not any("cryo-EM structures" in s for s in fake.seen)  # notes were not selected
    # The provider saw only the owner's text, never the quoted part.
    assert not any("Our docking runs" in s for s in fake.seen)
    assert any("predict affinity" in s for s in fake.seen)


def test_drafts_do_not_commit_and_approval_does(tmp_path):
    client = Client.init(tmp_path / "home")
    root = tmp_path / "lab"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "result.md").write_text("# Result\n\nWe found that X binds Y at pH 6.\n")
    index = LocalIndex.for_client(client)
    index.add_source(FolderConnector(root))
    index.scan()
    drafts = draft_findings(index)
    assert client.findings.list_findings() == []  # nothing committed by drafting
    (d,) = drafts
    assert d.claim_suggestion == "We found that X binds Y at pH 6."
    bundle = approve_finding(client, d, claim="X binds Y at pH 6.")
    rows = client.findings.list_findings()
    assert len(rows) == 1 and rows[0]["root"] == bundle.subject.root.hex()
    doc = client.findings.opening(rows[0]["root"])
    assert doc.finding.fields["claim"] == "X binds Y at pH 6."
    assert doc.evidence[0].fields["name"] == "result.md"
    # Approval without a claim does not use the suggestion.
    b2 = approve_finding(client, d, claim=None)
    assert client.findings.opening(b2.subject.root.hex()).finding.fields["claim"] is None


def test_approved_finding_flags_third_party_evidence(chen, tmp_path):
    """The index's third-party flag reaches the vault grant gate."""
    from anagram.network.sharing.app.grants import ThirdPartyWarning

    mail = next(d for d in draft_findings(chen) if d.where == "mei-lin-chen/mail")
    assert mail.third_party_keys
    client = Client.init(tmp_path / "home")
    bundle = approve_finding(client, mail, claim="Affinity is the open problem.")
    root = bundle.subject.root.hex()
    flagged = client.grants.third_party_items(root)
    assert flagged and all(name.endswith(".eml") for name in flagged)
    # Grant and publish stop at the gate before any network call.
    with pytest.raises(ThirdPartyWarning):
        client.grants.grant(root, recipients=["0000-0002-1825-0097"])
    with pytest.raises(ThirdPartyWarning):
        client.grants.publish(root)
    client.grants.third_party_gate(root, warnings_ack=True)  # acknowledged: no error
    notes = next(d for d in draft_findings(chen) if d.where == "mei-lin-chen/notes")
    plain = approve_finding(client, notes, claim=None)
    assert client.grants.third_party_items(plain.subject.root.hex()) == []


def test_approve_finding_uses_source_qualified_third_party_items(tmp_path):
    from anagram.local.understanding.drafts import FindingDraft

    client = Client.init(tmp_path / "home")
    r1, r2 = tmp_path / "src1", tmp_path / "src2"
    (r1 / "shared").mkdir(parents=True)
    (r2 / "shared").mkdir(parents=True)
    (r1 / "shared" / "note.md").write_text("# Own note\n\nOwn result.\n")
    (r2 / "shared" / "note.md").write_text("# Third party\n\nOther result.\n")
    index = LocalIndex.for_client(client)
    try:
        s1 = index.add_source(FolderConnector(r1))
        s2 = index.add_source(FolderConnector(r2))
        index.scan()
        it1 = next(i for i in index.items(s1) if i.key == "shared/note.md")
        it2 = next(i for i in index.items(s2) if i.key == "shared/note.md")
        draft = FindingDraft(
            id="d1",
            title="Mixed",
            claim_suggestion="Own result.",
            items=[it1, it2],
            start=None,
            end=None,
            topics=[],
            third_party=True,
            drafted_by="deterministic",
            third_party_keys=frozenset({"shared/note.md"}),
            third_party_items=frozenset({(s2, "shared/note.md")}),
            where="shared",
        )
        bundle = approve_finding(client, draft, claim="Own result.")
        flagged = client.grants.third_party_items(bundle.subject.root.hex())
        assert len(flagged) == 1
    finally:
        index.close()
        client.vault.close()
