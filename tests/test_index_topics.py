"""Topic chips: whole-word phrases, enough evidence, field agreement, and
weights from the vocabulary (generic words count less).

Regression for the demo: Chen's cryo-EM code got "Cryospheric studies and
observations" and "Arctic and Antarctic ice dynamics" (from "ice thickness"),
and a Git history got "Target Tracking and Data Fusion in Sensor Networks"
(from "particle filter").
"""

from __future__ import annotations

import pytest
from indexkit import lab_index

from anagram.local.understanding.chips import extract_chips, select_topics
from anagram.local.understanding.drafts import draft_findings
from anagram.local.understanding.vocabulary import default_vocabulary

pytestmark = pytest.mark.usefixtures("no_network")

EM = "openalex:t10857"  # Advanced Electron Microscopy Techniques and Applications
CRYOSPHERE = "openalex:t10644"
ICE = "openalex:t11459"
TRACKING = "openalex:t10711"
GUT = "openalex:t10066"

# Fields that a structural biology, computational chemistry, microbiome, or
# screening lab can plausibly have.
PLAUSIBLE_FIELDS = {
    "Biochemistry, Genetics and Molecular Biology",
    "Computer Science",
    "Chemistry",
    "Pharmacology, Toxicology and Pharmaceutics",
    "Immunology and Microbiology",
    "Agricultural and Biological Sciences",
    "Medicine",
}
WRONG_FIELDS = {"Earth and Planetary Sciences", "Environmental Science", "Engineering"}


def _topics(text: str) -> list[str]:
    v = default_vocabulary()
    return [t for t, _ in select_topics([extract_chips(text, v)], v, k=5, min_score=0)]


def test_cryo_em_code_gets_no_ice_topics():
    text = (
        "# filter_particles.py\n"
        "Filter cryo-EM particles by ice thickness and CTF fit.\n"
        "Input: 2D class averages from the Krios. Output: a particle stack for "
        "single-particle analysis.\n"
    )
    got = _topics(text)
    assert got[0] == EM
    assert CRYOSPHERE not in got and ICE not in got


def test_particle_filter_commit_is_not_target_tracking():
    got = _topics("Add a particle filter step before cryo-EM particle picking.")
    assert TRACKING not in got and EM in got


def test_phrases_match_whole_words_only():
    v = default_vocabulary()
    # "cryo" alone, or inside a longer word, is not "cryo-EM".
    for text in ("Cryoprotectant mix for the grids.", "The cryosphere team called."):
        assert EM not in extract_chips(text, v).topics, text
    # "cryo-EM" never brings an Earth science topic.
    fields = {v.topics[t].group for t in extract_chips("Cryo-EM and cryo-EM maps.", v).topics}
    assert not fields & WRONG_FIELDS


def test_generic_words_weigh_less():
    v = default_vocabulary()
    assert v.phrase_weight("data analysis") < v.phrase_weight("ice thickness")
    assert v.phrase_weight("ice thickness") < v.phrase_weight("cryo em")
    assert v.phrase_weight("neural network") < v.phrase_weight("gut microbiota")
    assert 0 < v.phrase_weight("data analysis") < 1


def test_a_topic_needs_enough_evidence():
    # One two-word keyword alone is not enough.
    assert _topics("We measured the ice thickness.") == []
    # A curated alias or the topic name is enough on its own.
    assert _topics("Notes on the gut microbiome.") == [GUT]
    # Two distinct keywords of one topic are enough.
    two = _topics("Ice thickness and sea ice extent from the radar survey.")
    assert set(two) & {CRYOSPHERE, ICE}


def test_old_stored_chips_have_no_phrase_hits():
    from anagram.local.understanding.chips import ItemChips

    old = ItemChips.from_json({"needs": {}, "offers": {}, "topics": {EM: 2}})
    assert old.topic_phrases is None  # LocalIndex.meaning derives the chips again
    new = extract_chips("Cryo-EM maps.", default_vocabulary())
    assert ItemChips.from_json(new.to_json()) == new and new.topic_phrases


def test_selection_is_deterministic():
    text = "Cryo-EM maps, ice thickness, and binding affinity of the ligand pocket."
    assert _topics(text) == _topics(text)


@pytest.fixture(scope="module")
def lab_topics(sim_community, tmp_path_factory):
    out = {}
    v = default_vocabulary()
    for lab in sim_community.ground_truth["labs"]:
        db = tmp_path_factory.mktemp("topics") / f"{lab['slug']}.sqlite"
        index, _ = lab_index(db, sim_community.out_dir / lab["path"])
        index.scan()
        labels = {t.label: t.id for t in v.topics.values()}
        findings = {
            f.title: [labels[x] for x in f.topics] for f in draft_findings(index) if f.topics
        }
        out[lab["slug"]] = findings
        index.close()
    return out


def test_sim_labs_get_topics_in_plausible_fields(lab_topics):
    v = default_vocabulary()
    for slug, findings in lab_topics.items():
        assert findings, slug
        for title, topics in findings.items():
            for t in topics:
                assert v.topics[t].group not in WRONG_FIELDS, (slug, title, v.topics[t].label)
                assert t not in (CRYOSPHERE, ICE, TRACKING), (slug, title)


def test_sim_lab_topics_name_the_lab_field(lab_topics):
    profile = {slug: {t for ts in f.values() for t in ts} for slug, f in lab_topics.items()}
    assert EM in profile["chen"]
    assert GUT in profile["varga"]
