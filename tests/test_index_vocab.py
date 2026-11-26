"""The bundled vocabulary: IDs fit the room, the version is stable."""

from __future__ import annotations

import re

from anagram.local.understanding.chips import extract_chips
from anagram.local.understanding.vocabulary import (
    VOCAB_VERSION,
    default_vocabulary,
    load_capabilities,
    normalise,
)

CHIP = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")  # the chip ID form


def test_snapshot_and_ids_fit_the_room():
    v = default_vocabulary()
    assert v.version == VOCAB_VERSION == "anagram-vocab.1.oa-20261015"
    assert CHIP.match(v.version)
    assert len(v.topics) == 4516  # full OpenAlex Topics list, 2026-10-15
    assert 40 <= len(v.capabilities) <= 80
    for tid in v.topics:
        assert CHIP.match(tid) and tid.startswith("openalex:t")
    for cid in v.capabilities:
        assert CHIP.match(cid) and cid.startswith("anagram:")
    assert v.label("openalex:t10066") == "Gut microbiota and health"


def test_capability_phrases_are_unique_to_one_id():
    caps = load_capabilities()
    seen: dict[str, str] = {}
    for term in caps.values():
        for p in term.phrases:
            assert seen.setdefault(p, term.id) == term.id, p


def test_generic_single_words_are_not_topic_phrases():
    v = default_vocabulary()
    for word in ("maps", "core", "real", "notes"):
        # Either not a phrase, or only in an exact form such as "Real" or "NOTES".
        assert word not in v.topic_index or word in v.topic_exact
    # An acronym matches only in its exact form: "NOTES" is a surgery method.
    assert "NOTES" in v.topic_exact["notes"]
    plain = extract_chips("Lab notes about the gut microbiome.", v).topics
    acronym = extract_chips("We trained surgeons in NOTES.", v).topics
    surgery = list(v.topic_index["notes"])
    assert not set(surgery) & set(plain)
    assert set(surgery) <= set(acronym)
    assert "bacteroides" in v.topic_index  # a name keeps its place
    assert normalise("Cryo-EM, 2.6 Å") == "cryo em 2 6"
