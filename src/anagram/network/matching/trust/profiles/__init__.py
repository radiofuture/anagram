"""The attestation profiles (spec/enclave-trust.md 4).

Each profile gives the evidence step of the app's checks (rule 8: the
roots of the evidence) and turns its evidence into `Claims`; the other
rules are the same for every profile (`trust/attestation.py`). The
registry is in `trust/platform.py`.

- `simulated`: development and CI only; the development root signs the
  evidence (4.1, 4.2). It protects nothing.
- `snp` (`raw-snp`): the AMD SEV-SNP report and its AMD chain (`amd`).
- `tdx`: a pure parser of the Intel TDX quote. Its evidence verifier is a
  stub that refuses: this build checks no Intel chain.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.roots import Roots


@dataclass(frozen=True)
class Claims:
    """What the evidence of one instance says, after its roots passed.

    `cpu` keys: `debug`, `migratable` (rule 3), `tcb` (floor items,
    rule 2; optional `tcb_required` and `tcb_not_applicable`), `reference`
    (rule 1), `report_data` (rule 5) and optional `valid_until` (rule 4:
    the next update of the collateral, Unix seconds). `gpu` keys: `ocsp`
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
