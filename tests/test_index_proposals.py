"""Proposed findings from content (R4 step 9): links, groups, titles, state.

Review items V1 and V2: a draft title is a short clean phrase, with a model
and with no model. Fake models only; no network."""

from __future__ import annotations

import json
import re

import pytest
from indexkit import lab_index
from test_index_kinds import assert_clean_title

from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector, source_state
from anagram.local.understanding import links, proposals, understand
from anagram.local.understanding.drafter import DrafterError, FakeModelDrafter
from anagram.local.understanding.drafts import draft_findings, draft_findings_by_folder
from anagram.local.understanding.kinds import current_versions, kind_of
from anagram.models.providers.fake import FakeTextModel

pytestmark = pytest.mark.usefixtures("no_network")

LABS = ("chen", "okafor", "varga", "helix")
LAB = "lab:lab-0123456789abcdef"

GEL = (
    "# Band shift of NbT7 with LX-4\n\n"
    "We found that NbT7 binds LX-4 at pH 6. The gel band moved by 12 kDa in three runs.\n"
    "The control lane showed no shift, and the ligand-free sample stayed in place.\n"
    "All raw files of this work stay in the shared drive of the group for a later check.\n"
)
FOLLOW = (
    "# NbT7 and LX-4 again\n\n"
    "We found the same NbT7 shift with LX-4 in a second gel, two weeks later.\n"
    "This replicates the first run; the band moved by 11 kDa with the same buffer.\n"
    "All raw files of this work stay in the shared drive of the group for a later check.\n"
)
PROTOCOL = (
    "# Gel protocol for NbT7\n\n"
    "Protocol: mix NbT7 with LX-4, incubate 30 minutes, run the gel at 120 V for one hour.\n"
    "Stain with the usual dye, then image the gel on the scanner in room B12.\n"
    "All raw files of this work stay in the shared drive of the group for a later check.\n"
)
OTHER = (
    "# Mouse colonies\n\n"
    "We found that strain K7 takes over the gut in five days in all ten mice of the run.\n"
    "The share of K7 rose from 6 percent to 38 percent, measured by qPCR of stool.\n"
    "All raw files of this work stay in the shared drive of the group for a later check.\n"
)
ENTITIES = ("nbt7", "lx-4", "gel", "k7", "qpcr")


def item_of(request) -> dict:
    line = request.user.splitlines()[1]
    return json.loads(line)


def fake_reader(request):
    """A fake model that reads the item: a finding when the text says "We
    found", a method for a protocol, else a note. The title is candidate 1
    (the rules title: the first heading of the item)."""
    item = item_of(request)
    text = item.get("text") or item.get("start") or ""
    if request.purpose == "understand.verify":  # the finding check keeps the finding
        return {"in_paper": True, "result": 1, "role": "own_result", "whose": "own"}
    if request.purpose == "understand.extract":
        first = next((s.strip() for s in re.split(r"(?<=\.)\s|\n", text) if "found" in s), "")
        found = [e for e in ENTITIES if e in text.lower()]
        return {
            "claims": [{"quote": first[:60], "status": "observed", "text": first}] if first else [],
            "entities": [{"text": e, "type": "material"} for e in found],
            "people": [],
            "summary": "",
        }
    kind = "finding" if "We found" in text else "method" if "Protocol" in text else "note"
    return {
        "confidence": 0.9,
        "kind": kind,
        "second": "",
        "polarity": "",
        "stage": "observed",
        "title": 1,
    }


def make(tmp_path, files):
    root = tmp_path / "lab"
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    index = LocalIndex(tmp_path / "i.sqlite", bytes(32))
    sid = index.add_source(FolderConnector(root))
    index.scan()
    return index, sid


def understood(tmp_path, files):
    index, sid = make(tmp_path, files)
    report = understand.run(index, FakeTextModel(fake_reader), limit=50)
    assert report.failed == 0 and report.retry == 0
    return index, sid


def test_proposals_follow_content_across_two_folders(tmp_path):
    files = {
        "alpha/gel.md": GEL,
        "alpha/protocol.md": PROTOCOL,
        "beta/followup.md": FOLLOW,
        "gamma/mice.md": OTHER,
    }
    index, sid = understood(tmp_path, files)
    assert links.update(index) == {"related": 3, "supports": 1}  # the protocol shares 3 names
    drafts = draft_findings(index)
    by_keys = {frozenset(i.key for i in d.items): d for d in drafts}
    # The protocol (a method) is linked to the gel finding, but it is not evidence.
    nbt7 = by_keys[frozenset({"alpha/gel.md", "beta/followup.md"})]
    assert frozenset({"gamma/mice.md"}) in by_keys
    assert nbt7.title in ("Band shift of NbT7 with LX-4", "NbT7 and LX-4 again")
    assert nbt7.claim_suggestion.startswith("We found")
    assert nbt7.drafted_by == "model"
    assert nbt7.reason == "2 related findings with a claim"
    for d in drafts:
        assert_clean_title(d.title)
        assert d.state == "new" and not d.where.startswith("alpha")  # an item ref, not a path


def test_fallback_with_no_model(tmp_path):
    index, sid = make(tmp_path, {"alpha/notes.md": PROTOCOL.replace("Protocol", "Plan")})
    assert [d.where for d in draft_findings(index)] == ["alpha"]
    assert [d.title for d in draft_findings(index)] == ["Gel protocol for NbT7"]
    # A rules finding is a seed with no model.
    index2, _ = make(tmp_path / "2", {"alpha/gel.md": GEL, "beta/x.md": FOLLOW})
    assert kind_of(index2, current_versions(index2)["item:1"]).by == "rules"
    drafts = draft_findings(index2)
    assert drafts and all(d.reason.startswith(("A finding", "2 related")) for d in drafts)
    assert all(d.drafted_by == "deterministic" for d in drafts)


@pytest.fixture(scope="module")
def demo(sim_community, tmp_path_factory):
    out = {}
    for slug in LABS:
        db = tmp_path_factory.mktemp("prop") / f"{slug}.sqlite"
        index, _ = lab_index(db, sim_community.out_dir / "labs" / slug)
        index.scan()
        out[slug] = index
    yield out
    for index in out.values():
        index.close()


def _assert_clean_draft(d, canaries):
    assert_clean_title(d.title)
    claim = d.claim_suggestion or ""
    assert "<!--" not in claim and "internal ref" not in claim.lower()
    assert not any(c in claim or c in d.title for c in canaries)
    assert len(claim) <= 300


def test_demo_titles_are_clean_with_no_model(demo, sim_community):
    """V1 and V2: no joined slide text, no internal reference, no path."""
    canaries = [c["canary"] for c in sim_community.canaries]
    for slug, index in demo.items():
        drafts = draft_findings(index)
        assert drafts, slug
        for d in drafts:
            _assert_clean_draft(d, canaries)
        titles = [d.title for d in drafts]
        assert len(set(titles)) == len(titles), titles  # each title says which draft it is
    chen = {d.where: d for d in draft_findings(demo["chen"])}
    deck = chen["mei-lin-chen/decks"]
    assert deck.title == "Three states of NbT7" and deck.claim_suggestion is None
    assert chen["mei-lin-chen/notes"].claim_suggestion.endswith("(3.1 A).")
    assert "library" not in " ".join(chen)  # a Zotero export is a reference


def test_demo_titles_are_clean_with_a_model(sim_community, tmp_path):
    """With understanding on, the title is a short phrase in the words of the
    item. The model cannot give joined text or a reference as the title: it
    chooses a candidate by number (here the last one, or one out of range)."""
    canaries = [c["canary"] for c in sim_community.canaries]

    def sloppy(request):
        item = item_of(request)
        text = item.get("text") or item.get("start") or ""
        if request.purpose in ("understand.extract", "understand.verify"):
            return fake_reader(request)
        last = len(item.get("titles") or {}) + len(text) % 2  # sometimes out of range
        kind = "finding" if re.search(r"\b(?:We have|map at|RMSE|percent)\b", text) else "note"
        return {
            "confidence": 0.8,
            "kind": kind,
            "second": "",
            "polarity": "",
            "stage": "",
            "title": last,
        }

    for slug in LABS:
        index, _ = lab_index(tmp_path / f"{slug}.sqlite", sim_community.out_dir / "labs" / slug)
        index.scan()
        understand.run(index, FakeTextModel(sloppy), limit=100)
        drafts = draft_findings(index)
        assert any(d.reason for d in drafts), slug  # proposals from content, not folders
        for d in drafts:
            _assert_clean_draft(d, canaries)
            assert len(d.title.split()) <= 14
        index.close()


def test_state_later_dismiss_and_stamped(tmp_path):
    index, sid = understood(tmp_path, {"alpha/gel.md": GEL, "gamma/mice.md": OTHER})
    events = []
    drafts = proposals.propose_findings(index, publish=lambda t, d: events.append((t, d)))
    assert [t for t, _ in events] == ["suggestion.new", "suggestion.new"]
    events.clear()
    assert len(proposals.propose_findings(index, publish=lambda t, d: events.append(t))) == 2
    assert events == []  # known proposals are not new
    gel = next(d for d in drafts if d.items[0].key == "alpha/gel.md")
    mice = next(d for d in drafts if d.items[0].key == "gamma/mice.md")
    proposals.set_state(index, gel.id, "later")
    assert {d.id: d.state for d in draft_findings(index)}[gel.id] == "later"
    proposals.dismiss(index, mice, publish=lambda t, d: events.append((t, d)))
    assert [t for t, _ in events] == ["suggestion.changed", "item.kind"]
    assert mice.id not in {d.id for d in draft_findings(index)}
    ref = index.item_ref(sid, "gamma/mice.md")
    assert kind_of(index, current_versions(index)[ref]).kind == "note"
    proposals.set_state(index, gel.id, "stamped")
    assert draft_findings(index) == [] or gel.id not in {d.id for d in draft_findings(index)}
    assert proposals.import_used(index, ["abc", gel.id]) == 1
    with pytest.raises(ValueError):
        proposals.set_state(index, gel.id, "gone")


def test_scope_leaves_out_other_spaces(tmp_path):
    index, sid = understood(tmp_path, {"alpha/gel.md": GEL})
    assert len(proposals.propose_findings(index)) == 1
    source_state.set_space(index.store, sid, LAB, now=0)
    assert proposals.propose_findings(index) == []
    assert len(proposals.propose_findings(index, scope=frozenset({LAB}))) == 1


def test_external_drafter_reads_only_selected_seeds(tmp_path):
    index, sid = make(tmp_path, {"alpha/gel.md": GEL})
    fake = FakeModelDrafter()
    with pytest.raises(DrafterError):
        draft_findings(index, drafter=fake)
    drafts = draft_findings(index, drafter=fake, allow_external=True)
    assert fake.seen == [] and drafts[0].claim_suggestion.startswith("We found")
    drafts = draft_findings(index, drafter=fake, allow_external=True, select=[drafts[0].id])
    assert drafts[0].drafted_by == "fake-model" and fake.seen


def test_folder_drafts_keep_the_old_groups(sim_community, tmp_path):
    index, _ = lab_index(tmp_path / "c.sqlite", sim_community.out_dir / "labs" / "chen")
    index.scan()
    assert {d.where for d in draft_findings_by_folder(index)} == {
        d.where for d in draft_findings(index)
    }


def test_propose_findings_filters_scope_before_drafter_and_enforces_external_opt_in(tmp_path):
    from anagram.local.understanding.drafter import ProviderDrafter

    index, sid = make(tmp_path, {"alpha/gel.md": GEL})
    try:
        source_state.set_space(index.store, sid, LAB, now=0)
        fake = FakeModelDrafter()
        # Out-of-scope lab item must never reach the drafter even when select matches its id.
        all_ids = [d.id for d in proposals.propose_findings(index, scope=frozenset({LAB}))]
        out = proposals.propose_findings(index, drafter=fake, allow_external=True, select=all_ids)
        assert out == [] and fake.seen == []

        # ProviderDrafter requires source allow_external, lab_allow, and logs disclosure.
        ext_model = FakeTextModel(
            lambda req: {"claim": "NbT7 binds ligand X at pH 6."},
            external=True,
            profile_id="cloud-1234abcd",
            recipient="Cloud Co",
        )
        drafter = ProviderDrafter(ext_model)
        # Without source opt-in: falls back without calling external model.
        res = proposals.propose_findings(
            index,
            drafter=drafter,
            allow_external=True,
            select=all_ids,
            scope=frozenset({LAB}),
            lab_allow={LAB: frozenset({ext_model.recipient_id})},
        )
        assert ext_model.calls == [] and res[0].drafted_by == "deterministic"
        # With source opt-in but no lab_allow: still blocked.
        index.set_source_prefs(sid, allow_external=[ext_model.recipient_id])
        res = proposals.propose_findings(
            index, drafter=drafter, allow_external=True, select=all_ids, scope=frozenset({LAB})
        )
        assert ext_model.calls == [] and res[0].drafted_by == "deterministic"
        # With both source opt-in and lab_allow: runs and logs disclosure.
        res = proposals.propose_findings(
            index,
            drafter=drafter,
            allow_external=True,
            select=all_ids,
            scope=frozenset({LAB}),
            lab_allow={LAB: frozenset({ext_model.recipient_id})},
        )
        assert len(ext_model.calls) == 1 and res[0].drafted_by == drafter.name
        assert any(d["adapter"] == ext_model.recipient_id for d in index.disclosures())
    finally:
        index.close()
