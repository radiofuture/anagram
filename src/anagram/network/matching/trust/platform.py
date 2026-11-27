"""The platform ports of the enclave (spec/enclave-trust.md 4).

- `Platform`: what an instance asks of its confidential VM: the evidence
  that carries a key binding (rule 5). The instance code does not know the
  profile; the host gives it a platform.
- `EvidenceVerifier`: what the app, the log and the witnesses ask of a
  profile: the evidence step (rule 8) and the claims that the other rules
  read. `evidence_verifier` finds it by profile name.

`simulated`, `raw-snp`, `raw-tdx` and `gcp-cs` are available in this build. Every other
profile of the spec has a stub that refuses with `unknown_profile`.
"""

from __future__ import annotations

from typing import Protocol

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import Claims, Unverified, gcp, snp, tdx
from anagram.network.matching.trust.profiles.simulated import SimulatedEvidence
from anagram.network.matching.trust.roots import Roots


class Platform(Protocol):
    """A confidential VM of one profile."""

    @property
    def profile(self) -> str: ...

    def evidence(self, binding: bytes) -> tuple[JsonObject, JsonObject | None]:
        """(platform_evidence, gpu_evidence) that carry this key binding."""
        ...


class EvidenceVerifier(Protocol):
    """The evidence step of one profile."""

    @property
    def profile(self) -> str: ...

    @property
    def available(self) -> bool: ...

    @property
    def reason(self) -> str: ...

    def claims(self, doc: JsonObject, roots: Roots) -> Claims:
        """Rule 8 (the roots of the evidence); then the claims, or Refused."""
        ...


_CLOUD = "a cloud profile; this build has no verifier for it"
VERIFIERS: dict[str, EvidenceVerifier] = {
    v.profile: v
    for v in (
        SimulatedEvidence(),
        snp.VERIFIER,
        tdx.VERIFIER,
        gcp.VERIFIER,
        Unverified("azure-cvm-gpu", _CLOUD),
    )
}


def evidence_verifier(profile: object) -> EvidenceVerifier:
    """The verifier of an available profile, else `unknown_profile`."""
    found = VERIFIERS.get(profile) if isinstance(profile, str) else None
    if found is None:
        raise Refused("unknown_profile", str(profile))
    if not found.available:
        raise Refused("unknown_profile", f"{profile}: {found.reason}")
    return found


def available_profiles() -> tuple[str, ...]:
    """The profiles whose evidence this build verifies."""
    return tuple(p for p, v in VERIFIERS.items() if v.available)
