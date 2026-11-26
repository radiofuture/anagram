"""The app-side checks are total on untrusted input (review M1).

An attestation document, a release, a checkpoint or a handoff message of
any JSON form gives `Refused` with a spec code. No KeyError, TypeError,
ValueError or FormatError leaves the verifier, so a boundary catches
`Refused` only. The inputs are the vectors of spec/vectors/
enclave-trust.json with one field changed at a time.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from anagram.core.canonical import canonical_json
from anagram.core.crypto.hashing import tagged_hash
from anagram.network.formats import credential as cred
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust import handoff as ho
from anagram.network.matching.trust.attestation import verify_attestation, verify_successor
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.release import accept_release
from anagram.network.matching.trust.roots import Roots, Witness, quorum_times
from anagram.proofs.log.note import NoteVerifier

V = json.loads((Path(__file__).parent.parent / "spec/vectors/enclave-trust.json").read_text())
JUNK = [None, True, 0, -1, 2**70, 1.5, "", "zz", "ab" * 16, [], [1], {}, {"a": [None]}]


def _roots() -> Roots:
    r = V["roots"]
    return Roots(
        log_key=NoteVerifier.parse(r["log_key"]),
        witnesses=tuple(
            Witness(NoteVerifier.parse(w["cosign"]), w["entry_key"], w["independent"])
            for w in r["witnesses"]
        ),
        release_key=r["release_key"],
        rebuilders=tuple(r["rebuilders"]),
        dev_root=r["dev_root"],
    )


def _case() -> dict:
    return next(c for c in V["attestation_cases"] if c["expect"] == "ok")


def _view(case: dict) -> LogView:
    size = int(case["checkpoints"][-1].split("\n")[1])
    entries = (V["base_entries"] + case["extra_entries"])[:size]
    return LogView.from_checkpoints(entries, case["checkpoints"], _roots())


def _changes(doc: dict) -> list[dict]:
    """The document with one field (or one evidence report field) set to
    each junk value, and with one field removed."""
    out = []
    for name in doc:
        for junk in JUNK:
            out.append({**doc, name: junk})
        out.append({k: v for k, v in doc.items() if k != name})
    for side in ("platform_evidence", "gpu_evidence"):
        evidence = doc.get(side)
        if not isinstance(evidence, dict):
            continue
        for name in evidence["report"]:
            for junk in JUNK:
                changed = copy.deepcopy(doc)
                changed[side]["report"][name] = junk
                out.append(changed)
    return out


def _only_refused(fn, *args) -> None:
    try:
        fn(*args)
    except Refused:
        pass


def test_the_ok_case_passes():
    case = _case()
    rel = V["base_entries"][0]
    verify_attestation(case["doc"], rel, _view(case), _roots(), case["now"])


@pytest.mark.parametrize("check", [verify_attestation, verify_successor])
def test_a_document_of_any_form_is_refused(check):
    case = _case()
    rel, view, roots = V["base_entries"][0], _view(case), _roots()
    changes = _changes(case["doc"])
    assert len(changes) > 100
    for doc in changes:
        _only_refused(check, doc, rel, view, roots, case["now"])
    for junk in JUNK:
        _only_refused(check, junk, rel, view, roots, case["now"])


def test_a_release_of_any_form_is_refused():
    case = _case()
    rel, view, roots = V["base_entries"][0], _view(case), _roots()
    for junk in JUNK:
        _only_refused(accept_release, junk, view, roots, "1.2.0", case["now"])
        for name in rel:
            _only_refused(accept_release, {**rel, name: junk}, view, roots, "1.2.0", case["now"])


def test_a_checkpoint_of_any_form_is_refused():
    for junk in [*JUNK, "a\nb\nc\n", "origin\nNaN\nroot\n\n— x y\n"]:
        _only_refused(quorum_times, junk, _roots())


def test_a_handoff_message_of_any_form_is_refused():
    h = V["handoff_messages"]
    view = LogView.from_checkpoints(
        V["base_entries"] + h["extra_entries"], h["checkpoints"], _roots()
    )
    successor = tagged_hash(
        "anagram/v1/room/attestation", canonical_json(h["successor_attestation"])
    )
    key = bytes.fromhex(h["successor_intake_private_hex"])
    msg = next(c["msg"] for c in h["cases"] if c["expect"] == "ok")
    for name in msg:
        for junk in JUNK:
            _only_refused(ho.accept, {**msg, name: junk}, view, successor, key)
    for junk in JUNK:
        _only_refused(ho.accept, junk, view, successor, key)


@pytest.mark.parametrize("text", ["AQ=", "AQ==", "AR", "A", "A+8", "AQ\n", "A Q"])
def test_a_base64url_value_has_one_text(text: str) -> None:
    """Only the canonical unpadded form decodes (review low item)."""
    with pytest.raises(Refused):
        cred.unb64url(text)
    assert cred.unb64url("AQ") == b"\x01"
