"""The strict policy (spec/enclave-trust.md 4.9): rule 9 (only evidence
that names a pinned cloud passes) and the rule 3 bits of each profile.

Scenario 1 of the plan: real AMD evidence signed by a VCEK is refused with
`evidence_not_cloud_bound`, and so is a Google token from an unpinned
project. Scenario 2: each enforced bit, flipped alone, gives its own code."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import gcpkit
import pytest

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust import attestation
from anagram.network.matching.trust.attestation import POLICY_RULE_CODES
from anagram.network.matching.trust.entries import _profiles
from anagram.network.matching.trust.policy import check_cloud, check_policy
from anagram.network.matching.trust.profiles.gcp import gcp_claims
from anagram.network.matching.trust.profiles.snp import snp_claims
from anagram.network.matching.trust.roots import AMD_ARK_SHA256
from anagram.vectors import enclave_policy

FIX = Path(__file__).parent / "fixtures"
V = json.loads((Path(__file__).parent.parent / "spec/vectors/enclave-policy.json").read_text())
GCP_PINS = {"project_numbers": ["2"], "zones": ["z"]}  # gcpkit's good payload


def code(fn, *args) -> str:
    try:
        fn(*args)
    except Refused as exc:
        return exc.code
    return "ok"


# --- scenario 1: cloud binding on real verifier output ----------------------------


def real_snp_cpu() -> dict:
    f = FIX / "snp"
    ev = {
        name: base64.b64encode((f / file).read_bytes()).decode()
        for name, file in (
            ("ark", "milan_ark.der"),
            ("ask", "milan_ask.der"),
            ("crl", "milan_ark.crl"),
            ("leaf", "milan_vcek.der"),
            ("report", "milan_report.bin"),
        )
    }
    return snp_claims(ev, None, SimpleNamespace(amd_arks=AMD_ARK_SHA256)).cpu  # type: ignore[arg-type]


def test_real_vcek_report_is_not_cloud_bound() -> None:
    cpu = real_snp_cpu()
    assert cpu["signing_key"] == "vcek" and cpu["csp_id"] is None
    pins = {"csp_ids": ["AnyCloud"]}
    for production in (True, False):
        assert code(check_cloud, "raw-snp", pins, cpu, production) == "evidence_not_cloud_bound"


def gcp_cpu(**changes) -> dict:
    google = gcpkit.FakeGoogle()
    token = google.token(gcpkit.changed(**changes) if changes else None)
    roots = SimpleNamespace(gcp_cs_root=google.pin())
    return gcp_claims({"token": token}, None, roots).cpu  # type: ignore[arg-type]


def test_google_token_from_the_pinned_project_and_zone_passes() -> None:
    cpu = gcp_cpu()
    assert cpu["cloud"] == {"project_number": "2", "zone": "z"}
    assert code(check_cloud, "gcp-cs", GCP_PINS, cpu, True) == "ok"


@pytest.mark.parametrize(
    "changes",
    [
        {"submods__gce__project_number": "3"},
        {"submods__gce__zone": "elsewhere"},
        {"submods__gce": ...},
    ],
    ids=["project", "zone", "no_gce"],
)
def test_google_token_from_an_unpinned_place_is_refused(changes) -> None:
    assert code(check_cloud, "gcp-cs", GCP_PINS, gcp_cpu(**changes), True) == (
        "evidence_not_cloud_bound"
    )


def test_google_token_with_a_bad_gce_claim_is_a_bad_attestation() -> None:
    with pytest.raises(Refused) as exc:
        gcp_cpu(submods__gce__zone=7)
    assert exc.value.code == "bad_attestation"


def test_raw_tdx_only_in_development() -> None:
    cpu = {"debug": False, "migratable": False}
    assert code(check_cloud, "raw-tdx", {}, cpu, True) == "evidence_not_cloud_bound"
    assert code(check_cloud, "raw-tdx", {}, cpu, False) == "ok"


# --- scenario 2: each bit has its own code ----------------------------------------


def test_real_google_claims_pass_the_policy_and_each_flip_has_its_code() -> None:
    assert code(check_policy, "gcp-cs", gcp_cpu(), None) == "ok"
    flips = {
        "secure_boot_off": {"secboot": False},
        "image_not_stable": {"submods__confidential_space__support_attributes": ["USABLE"]},
        "launch_override": {"submods__container__cmd_override": ["/bin/sh"]},
        "policy_refused": {"dbgstat": "enabled"},
    }
    for want, changes in flips.items():
        assert code(check_policy, "gcp-cs", gcp_cpu(**changes), None) == want, want


def test_real_snp_report_policy_bits() -> None:
    """The fixture guest is a debug guest with SMT allowed and no
    ciphertext hiding or page swap lock: each fix moves to the next code."""
    cpu = real_snp_cpu()
    assert code(check_policy, "raw-snp", cpu, None) == "policy_refused"
    steps = [
        ("debug", False, "smt_allowed"),
        ("policy.smt", False, "ciphertext_hiding_off"),
        ("policy.ciphertext_hiding", True, "page_swap_allowed"),
        ("policy.page_swap_disable", True, "ok"),
    ]
    for path, value, want in steps:
        cpu = enclave_policy._with(cpu, path, value)
        assert code(check_policy, "raw-snp", cpu, None) == want, path


# --- the vector file ----------------------------------------------------------------


@pytest.mark.parametrize("case", V["cases"], ids=lambda c: c["name"])
def test_policy_vector(case) -> None:
    assert enclave_policy.outcome(case) == case["expect"]


def test_policy_vectors_are_current_and_cover_every_new_code() -> None:
    assert enclave_policy.build() == V
    seen = {c["expect"] for c in V["cases"]}
    for rule, codes in POLICY_RULE_CODES.items():
        assert set(codes) <= seen, rule


# --- the release form ----------------------------------------------------------------


def entry(profile: str, **extra) -> dict:
    return {
        profile: {"measurement": "00" * 32, "reference": {}, "tcb_floor": {}, **extra},
    }


def test_release_cloud_pins() -> None:
    assert _profiles(entry("simulated"))
    assert not _profiles(entry("simulated", cloud={}))  # simulated binds no cloud
    assert not _profiles(entry("raw-snp"))  # a real profile needs its pins
    assert _profiles(entry("raw-snp", cloud={"csp_ids": ["A", "B"]}))
    assert not _profiles(entry("raw-snp", cloud={"csp_ids": []}))
    assert not _profiles(entry("raw-snp", cloud={"csp_ids": ["B", "A"]}))  # sorted
    assert not _profiles(entry("raw-snp", cloud={"csp_ids": ["A", "A"]}))
    assert not _profiles(entry("raw-snp", cloud={"csp_ids": [""]}))
    assert not _profiles(entry("raw-snp", cloud={"csp_ids": ["A"], "zones": ["z"]}))
    assert _profiles(entry("gcp-cs", cloud={"project_numbers": ["1"], "zones": ["z"]}))
    assert not _profiles(entry("gcp-cs", cloud={"project_numbers": ["1"]}))
    assert _profiles(entry("raw-tdx", cloud={}))
    assert not _profiles(entry("raw-tdx", cloud={"csp_ids": ["A"]}))


# --- the wiring: rule 9 runs right after rule 8 ------------------------------------


def test_rule_9_runs_before_rule_4(monkeypatch) -> None:
    """A document that rule 4 refuses gives the rule 9 code when rule 9
    refuses: the order is 8, 9, 4, 3."""
    import test_enclave_trust as t

    (case,) = [c for c in t.V["attestation_cases"] if c["expect"] == "evidence_expired"][:1]
    rel = t.V["base_entries"][0]
    lv = t.view(case)
    t.accept_release(rel, lv, t.roots(), "1.2.0", t.now_of(case))

    def refuse(*_args, **_kw):
        raise Refused("evidence_not_cloud_bound")

    monkeypatch.setattr(attestation, "check_cloud", refuse)
    subject = bytes.fromhex(case["subject"])
    got = t.outcome(
        attestation.verify_attestation, case["doc"], rel, lv, t.roots(), t.now_of(case), subject
    )
    assert got == "evidence_not_cloud_bound"
