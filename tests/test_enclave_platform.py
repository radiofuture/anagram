"""The platform ports (review H4): one evidence verifier for each profile of
the spec; `simulated` and `raw-snp` available, and stubs that refuse clearly
for the profiles that this build does not verify yet."""

from __future__ import annotations

import pytest

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.entries import PROFILES
from anagram.network.matching.trust.pins import Pins
from anagram.network.matching.trust.platform import (
    VERIFIERS,
    available_profiles,
    evidence_verifier,
)
from anagram.network.matching.trust.profiles.simulated import SimulatedPlatform


def test_one_verifier_for_each_profile_of_the_spec() -> None:
    assert set(VERIFIERS) == set(PROFILES)
    assert available_profiles() == ("simulated", "raw-snp")


@pytest.mark.parametrize("profile", [p for p in PROFILES if p not in ("simulated", "raw-snp")])
def test_a_profile_with_no_verifier_is_unknown(profile: str) -> None:
    with pytest.raises(Refused) as exc:
        evidence_verifier(profile)
    assert exc.value.code == "unknown_profile"
    assert "no verifier" in exc.value.detail or "not yet" in exc.value.detail
    with pytest.raises(Refused, match="unknown_profile"):
        VERIFIERS[profile].claims({}, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("profile", [None, 3, ["simulated"], "other"])
def test_a_profile_of_another_form_is_unknown(profile: object) -> None:
    with pytest.raises(Refused, match="unknown_profile"):
        evidence_verifier(profile)


def test_the_simulated_platform_names_its_profile() -> None:
    from anagram.core.crypto.signing import SigningKey

    platform = SimulatedPlatform(SigningKey.generate(), {"gpu": False})
    assert platform.profile == "simulated"
    assert evidence_verifier(platform.profile).available


def test_pins_of_a_profile_that_this_build_does_not_verify_are_refused() -> None:
    doc = {"schema": "anagram.enclave.devnet.v1", "profile": "raw-tdx"}
    with pytest.raises(ValueError, match="verifies only"):
        Pins.from_json(doc)
