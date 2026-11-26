"""The labelled set for item kinds (`anagram.sim.kinds`). No network, no cost."""

from __future__ import annotations

import json
from collections import Counter

import pytest

from anagram.local.understanding.kinds import KIND_IDS
from anagram.sim.kinds import DECOYS, INJECTED, LABELS, generate_kinds

pytestmark = pytest.mark.usefixtures("no_network")


def test_labelled_set(tmp_path):
    labels = generate_kinds(tmp_path)
    items = labels["items"]
    assert json.loads((tmp_path / LABELS).read_text()) == labels
    assert len(items) == 192
    assert set(Counter(x["kind"] for x in items)) == set(KIND_IDS)
    assert {x["lab"] for x in items} == {"ruiz", "ibsen", "mensah", "laurent"}
    injected = [x for x in items if x["injected"]]
    assert len(injected) == INJECTED and len({x["lab"] for x in injected}) == 4
    assert all(x["target"] != x["kind"] for x in injected)
    assert Counter(x["injection_group"] for x in injected) == {
        "base": 10, "design": 10, "heldout": 10, "heldout2": 10
    }  # fmt: skip
    assert all(x["injection_group"] is None for x in items if not x["injected"])
    # The 10 planted instructions are on the same items as before.
    assert [x["path"] for x in injected if x["injection_group"] == "base"] == [
        "project-0/protocol-0.md", "plans/aims-2027.md", "drafts/paper-draft-1.md",
        "drafts/paper-draft-0.md", "project-1/run-1.md", "notes/week-2.md",
        "project-0/run-0.md", "notes/week-1.md", "project-0/finding-0.md",
        "project-0/analysis_0.py",
    ]  # fmt: skip
    assert {x["hard"] for x in items if x["hard"]} == {
        "draft quotes a result",
        "result only in quoted text",
        *DECOYS,
    }
    assert Counter(x["hard"] for x in items if x["hard"] in DECOYS) == dict.fromkeys(DECOYS, 4)
    for x in items:
        data = (tmp_path / x["lab"] / x["path"]).read_bytes()
        if not x["path"].endswith(".pptx"):  # a pptx is a zip file
            assert x["canary"].encode() in data, x["path"]
        for claim in x["claims"]:
            assert claim.encode() in data
    groups = Counter(x["group"] for x in items if x["group"])
    assert len(groups) == 12 and set(groups.values()) == {3}
    # The same seed gives the same set.
    assert generate_kinds(tmp_path / "again") == labels


def test_heldout_findings_group_leaves_the_old_items_as_they_are(tmp_path):
    """The held-out group of finding decoys and true findings (for
    precision) is added after the planted instructions: the other items do
    not change, and the group has no planted instruction."""
    from anagram.sim.kinds import HELDOUT_DECOY, HELDOUT_FINDING

    old = generate_kinds(tmp_path / "old")["items"]
    items = generate_kinds(tmp_path / "new", heldout_findings=True)["items"]
    held = [x for x in items if x["hard"] in (HELDOUT_FINDING, HELDOUT_DECOY)]
    assert [x for x in items if x not in held] == old
    assert len(held) >= 80
    assert {x["lab"] for x in held} == {
        f"{s}-heldout" for s in ("ruiz", "ibsen", "mensah", "laurent")
    }
    assert sum(x["kind"] == "finding" for x in held) >= 32
    assert all(x["hard"] == (HELDOUT_FINDING if x["kind"] == "finding" else HELDOUT_DECOY)
               for x in held)  # fmt: skip
    assert not any(x["injected"] for x in held)
    for x in held:
        data = (tmp_path / "new" / x["lab"] / x["path"]).read_bytes()
        assert x["canary"].encode() in data
        assert all(c.encode() in data for c in x["claims"])


def test_polarity_labels_and_the_negative_group(tmp_path):
    """Each finding and result has a gold polarity; the group
    of negative results is in lab folders of its own, and the 192 items do
    not change."""
    from anagram.local.understanding.kinds import POLARITY, SEED_KINDS
    from anagram.sim.kinds import HELDOUT_DECOY, HELDOUT_FINDING, NEGATIVE

    base = generate_kinds(tmp_path / "base")
    labels = generate_kinds(tmp_path / "all", heldout_findings=True, negative_results=True)
    for x in labels["items"]:
        if x["kind"] in SEED_KINDS:
            assert x["polarity"] in POLARITY, x["path"]
        else:
            assert x["polarity"] is None, x["path"]
    apart = (NEGATIVE, HELDOUT_FINDING, HELDOUT_DECOY)
    assert [x for x in labels["items"] if x["hard"] not in apart] == base["items"]
    neg = [x for x in labels["items"] if x["hard"] == NEGATIVE]
    labs = {f"{s}-negative" for s in ("ruiz", "ibsen", "mensah", "laurent")}
    assert {x["lab"] for x in neg} == labs
    assert sum(x["polarity"] == "negative" for x in neg) >= 40
    assert any(x["polarity"] is None for x in neg)  # decoys with negative words
    assert not any(x["injected"] for x in neg)
    for x in neg:
        data = (tmp_path / "all" / x["lab"] / x["path"]).read_bytes()
        assert x["canary"].encode() in data
        assert all(c.encode() in data for c in x["claims"])
    held = {x["path"]: x["polarity"] for x in labels["items"] if x["hard"] == HELDOUT_FINDING}
    assert held["misc/scratch-ok.md"] == "negative"


def test_second_negative_group_is_apart(tmp_path):
    """The second group of negative results (held out from the work on
    negative-result recall) is in lab folders of its own; the other items do
    not change."""
    from anagram.local.understanding.kinds import POLARITY, SEED_KINDS
    from anagram.sim.kinds import NEGATIVE2

    old = generate_kinds(tmp_path / "old", heldout_findings=True, negative_results=True)
    labels = generate_kinds(
        tmp_path / "all", heldout_findings=True, negative_results=True, negative_results2=True
    )
    assert [x for x in labels["items"] if x["hard"] != NEGATIVE2] == old["items"]
    neg = [x for x in labels["items"] if x["hard"] == NEGATIVE2]
    assert {x["lab"] for x in neg} == {
        f"{s}-negative2" for s in ("ruiz", "ibsen", "mensah", "laurent")
    }
    assert sum(x["polarity"] == "negative" for x in neg) >= 40
    assert any(x["polarity"] is None for x in neg)  # decoys
    assert any(x["polarity"] == "positive" for x in neg)  # positive controls
    for x in neg:
        if x["kind"] in SEED_KINDS:
            assert x["polarity"] in POLARITY, x["path"]
        data = (tmp_path / "all" / x["lab"] / x["path"]).read_bytes()
        assert x["canary"].encode() in data
        assert all(c.encode() in data for c in x["claims"])
