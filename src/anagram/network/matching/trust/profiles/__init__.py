"""The attestation profiles (spec/enclave-trust.md 4).

Each profile gives the evidence step of the app's checks (rule 8: the
roots of the evidence) and turns its evidence into `Claims`; the other
rules are the same for every profile (`trust/attestation.py`). The
registry is in `trust/platform.py`.

- `simulated`: development and CI only; the development root signs the
  evidence (4.1, 4.2). It protects nothing.
- `snp`, `tdx`: pure parsers of the AMD SEV-SNP report and the Intel TDX
  quote. Their evidence verifiers are stubs that refuse: this build checks
  no vendor chain, so it claims no production profile.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.roots import Roots


@dataclass(frozen=True)
class Claims:
    """What the evidence of one instance says, after its roots passed.

    `cpu` keys: `debug`, `migratable` (rule 3), `tcb` (`{"svn"}`, rule 2),
    `reference` (rule 1) and `report_data` (rule 5). `gpu` keys: `ocsp`
    (rule 8), `dbgstat`, `cc_mode` (rule 3), `driver_version`,
    `vbios_version` (rule 2) and `nonce` (rule 6)."""

    cpu: JsonObject
    gpu: JsonObject | None


def evidence_object(value: object, what: str) -> JsonObject:
    """An object of evidence; any other form is `bad_attestation`."""
    if not isinstance(value, dict):
        raise Refused("bad_attestation", f"{what} form")
    return value


@dataclass(frozen=True)
class Unverified:
    """The evidence verifier of a profile that this build does not verify.
    The registry refuses its profile with `unknown_profile` and `reason`,
    at the same step as a profile that it does not know."""

    profile: str
    reason: str
    available: bool = False

    def claims(self, doc: JsonObject, roots: Roots) -> Claims:
        raise Refused("unknown_profile", f"{self.profile}: {self.reason}")
