"""What an app pins, and the witness quorum of a checkpoint
(spec/enclave-trust.md 2.6, 3.5).

Every other check of the app starts from these roots: a checkpoint counts
only with the signature of the pinned log key and the cosignatures of 2
distinct pinned witnesses, at least 1 of them independent.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.network.formats.strict import Refused
from anagram.proofs.log.checkpoint import open_checkpoint
from anagram.proofs.log.note import NoteVerifier

# SHA-256 of the DER of each product's ARK, as AMD KDS serves it
# (https://kdsintf.amd.com/{vcek,vlek}/v1/<Product>/cert_chain; the VCEK
# and VLEK chains share the ARK). Spec section 2.6.
AMD_ARK_SHA256: tuple[tuple[str, str], ...] = (
    ("genoa", "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1"),
    ("milan", "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"),
    ("turin", "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"),
)
# SHA-256 of the DER of the Intel SGX Root CA, as Intel serves it
# (https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer).
# Spec section 2.6.
INTEL_ROOT_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
# SHA-256 of the DER of the Confidential Space Root CA, as Google serves it
# (https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt,
# SHA-1 fingerprint B9:51:20:74:...:21:23:21 as Google's page gives it).
# Spec section 2.6.
GCP_CS_ROOT_SHA256 = "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39"


@dataclass(frozen=True)
class Witness:
    cosign: NoteVerifier  # C2SP cosignature/v1 key (log.md section 4)
    entry_key: str  # hex Ed25519 key for enclave_entry_cosign entries
    independent: bool  # not run by Radiofuture


@dataclass(frozen=True)
class Roots:
    """What the app pins (spec section 2.6)."""

    log_key: NoteVerifier
    witnesses: tuple[Witness, ...]
    release_key: str
    rebuilders: tuple[str, ...]
    dev_root: str | None = None  # `simulated` only; None in a production app
    amd_arks: tuple[tuple[str, str], ...] = AMD_ARK_SHA256  # product -> SHA-256 of the ARK DER
    intel_root: str = INTEL_ROOT_SHA256  # SHA-256 of the Intel SGX Root CA DER
    gcp_cs_root: str = GCP_CS_ROOT_SHA256  # SHA-256 of the Confidential Space Root CA DER


def quorum_times(note_text: str, roots: Roots) -> tuple[bytes, int, int, int, bytes]:
    """Open a checkpoint note. Return (anchor, size, signed_lower, signed_upper,
    root). The quorum is 2 distinct pinned witnesses, at least 1 independent."""
    if not isinstance(note_text, str):
        raise Refused("bad_attestation", "checkpoint form")
    try:
        vc = open_checkpoint(note_text, [roots.log_key], [w.cosign for w in roots.witnesses])
    except ValueError as exc:  # NoteError, or a size that is not a number
        raise Refused("bad_attestation", f"checkpoint: {exc}") from exc
    by_key = {w.cosign.vkey(): w for w in roots.witnesses}
    good = [(by_key[v.vkey()], t) for v, t in vc.cosignatures]
    if len(good) < 2 or not any(w.independent for w, _ in good):
        raise Refused("bad_attestation", "checkpoint has no witness quorum")
    times = [t for _, t in good]
    return vc.checkpoint.digest(), vc.checkpoint.size, min(times), max(times), vc.checkpoint.root


def app_now(clock: int, note_text: str, roots: Roots) -> int:
    """The app's "now" (section 3.5): its computer clock, but never before
    `lower` of its latest accepted checkpoint. Every rule of the app that
    says "now" (2.5 rule 6, 3.5 rules 4 and 7) uses this value."""
    return max(clock, quorum_times(note_text, roots)[2])
