"""The `simulated` profile: its platform and its evidence verifier
(spec/enclave-trust.md 4.1, 4.2).

Development and CI only: the development root signs the evidence, and
anyone with that key can make valid evidence for any code. A production
app pins no development root (`Roots.dev_root` is None), so the verifier
refuses the evidence with `untrusted_root`.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.signing import SigningKey, verify
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust.profiles import Claims, evidence_object
from anagram.network.matching.trust.roots import Roots

PROFILE = "simulated"
TAG_SIGN_SIM_EVIDENCE = "anagram/v1/enclave/sign/simulated-evidence"
TAG_SIGN_SIM_GPU = "anagram/v1/enclave/sign/simulated-gpu"
GPU_REPORT = {
    "cc_mode": "ON",
    "dbgstat": "disabled",
    "driver_version": "550.90.07",
    "ocsp": "good",
    "vbios_version": "96.00.9F.00.01",
}


def sign_simulated(report: JsonObject, key: SigningKey, tag: str) -> JsonObject:
    return {
        "report": report,
        "signature": key.sign(tag, canonical_json(report)).hex(),
        "signer": key.public_bytes().hex(),
    }


@dataclass(frozen=True)
class SimulatedPlatform:
    """A confidential VM that signs its evidence with the development root."""

    dev_root: SigningKey
    reference: JsonObject
    svn: int = 3
    profile: str = PROFILE

    @property
    def gpu(self) -> bool:
        return bool(self.reference.get("gpu"))

    def evidence(self, binding: bytes) -> tuple[JsonObject, JsonObject | None]:
        """(platform_evidence, gpu_evidence) that carry this key binding."""
        gpu = None
        if self.gpu:
            report = {**GPU_REPORT, "nonce": b.gpu_nonce(binding).hex()}
            gpu = sign_simulated(report, self.dev_root, TAG_SIGN_SIM_GPU)
        report_data = b.report_data(binding, canonical_json(gpu) if gpu else None)
        cpu = {
            "debug": False,
            "migratable": False,
            "reference": self.reference,
            "report_data": report_data.hex(),
            "tcb": {"svn": self.svn},
        }
        return sign_simulated(cpu, self.dev_root, TAG_SIGN_SIM_EVIDENCE), gpu


def _signed(obj: object, roots: Roots, tag: str) -> JsonObject:
    """Rule 8 for the simulated profile: the evidence is signed by the pinned
    development root."""
    if not isinstance(obj, dict) or set(obj) != {"report", "signature", "signer"}:
        raise Refused("bad_attestation", "bad evidence form")
    if roots.dev_root is None or obj["signer"] != roots.dev_root:
        raise Refused("untrusted_root")
    report = obj["report"]
    try:
        sig = bytes.fromhex(obj["signature"])
        body = canonical_json(report)
    except (TypeError, ValueError) as exc:  # CanonicalError is a ValueError
        raise Refused("bad_attestation", "bad evidence form") from exc
    if not verify(bytes.fromhex(roots.dev_root), tag, body, sig):
        raise Refused("untrusted_root", "evidence signature")
    return evidence_object(report, "evidence report")


@dataclass(frozen=True)
class SimulatedEvidence:
    """The evidence verifier of the `simulated` profile."""

    profile: str = PROFILE
    reason: str = "development and CI only; it protects nothing"
    available: bool = True

    def claims(self, doc: JsonObject, roots: Roots) -> Claims:
        """Rule 8: the roots of the CPU and GPU evidence, and the GPU OCSP
        status."""
        cpu = _signed(doc["platform_evidence"], roots, TAG_SIGN_SIM_EVIDENCE)
        gpu = None
        if doc["gpu_evidence"] is not None:
            gpu = _signed(doc["gpu_evidence"], roots, TAG_SIGN_SIM_GPU)
            if gpu.get("ocsp") != "good":
                raise Refused("cert_revoked", str(gpu.get("ocsp")))
        return Claims(cpu, gpu)
