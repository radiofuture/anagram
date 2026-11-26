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
