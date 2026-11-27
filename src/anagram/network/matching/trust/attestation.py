"""The attestation document and the app's checks of it (spec/enclave-trust.md
3.3 to 3.5, 5.3, 5.4).

The checks run in the fixed order of the spec; the first failed check gives
its error code. The evidence step (rule 8) is the profile's
(`trust/platform.py`); the other rules are the same for every profile.

Every check is total on untrusted input: a document of any JSON form gives
`Refused` with a spec code, never another exception. The release that a
document names is always one that the caller accepted (`accept_release`)
or read from its checked view, so its form is checked.
"""

from __future__ import annotations

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json
from anagram.core.crypto.signing import SigningKey, verify
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust.entries import entry_digest
from anagram.network.matching.trust.lines import (
    MAX_LEASE,
    latest_epoch,
    lease,
    line_authorised,
    line_forked,
    line_writer,
)
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.platform import evidence_verifier
from anagram.network.matching.trust.profiles import evidence_object
from anagram.network.matching.trust.release import effective_floor, meets
from anagram.network.matching.trust.roots import Roots, quorum_times

ATTESTATION_SCHEMA = "anagram.operator_attestation.v3"
TAG_SIGN_ATTESTATION = "anagram/v1/enclave/sign/attestation"

MAX_EVIDENCE_AGE = 86400
MAX_SKEW = 300
# TCB statuses that no floor can allow: a revoked platform, or no matching
# TCB level in the collateral (spec section 4.8).
NEVER_PASSES = ("Revoked", "Unsupported")

# Rule number -> error codes (spec section 3.5).
RULE_CODES = {
    1: ("measurement_mismatch",),
    2: ("tcb_below_floor",),
    3: ("policy_refused",),
    4: ("evidence_expired",),
    5: ("binding_mismatch",),
    6: ("gpu_binding_mismatch",),
    7: (
        "instance_not_logged",
        "line_not_authorised",
        "instance_revoked",
        "line_forked",
        "instance_not_writer",
        "instance_limit",
    ),
    8: ("untrusted_root", "cert_revoked"),
}
PRE_CODES = ("bad_attestation", "unknown_profile")

_DOC_FIELDS = {
    "checkpoint",
    "descriptor_hashes",
    "gpu_evidence",
    "instance_id",
    "intake_key",
    "key_epoch",
    "line_id",
    "log_proof",
    "output_key",
    "platform_evidence",
    "profile",
    "release",
    "schema",
    "signature",
}


def _doc_body(doc: JsonObject) -> bytes:
    return canonical_json({k: v for k, v in doc.items() if k != "signature"})


def sign_attestation(doc: JsonObject, output_key: SigningKey) -> JsonObject:
    out = {k: v for k, v in doc.items() if k != "signature"}
    out["signature"] = output_key.sign(TAG_SIGN_ATTESTATION, _doc_body(out)).hex()
    return out


def _bytes(doc: JsonObject, name: str, n: int) -> bytes:
    v = doc.get(name)
    try:
        raw = bytes.fromhex(v) if isinstance(v, str) else b""
    except ValueError:
        raw = b""
    if len(raw) != n:
        raise Refused("bad_attestation", f"bad {name}")
    return raw


def verify_attestation(
    doc: JsonObject,
    release: JsonObject,
    view: LogView,
    roots: Roots,
    now: int,
    subject: bytes | None = None,
) -> dict[str, object]:
    """Check an `anagram.operator_attestation.v3` document against an
    accepted release. Return the keys to seal to. Raise Refused with the
    code of the first failed check. With `subject`, the line must also be
    the one authorised for its shard."""
    issued = verify_evidence(doc, release, view, roots, now)
    _check_logged(doc, release, view, roots, now, subject)
    _check_writer(doc, release, view, roots)
    return {"intake_key": doc["intake_key"], "output_key": doc["output_key"], "issued": issued}


def verify_successor(
    doc: JsonObject, release: JsonObject, view: LogView, roots: Roots, now: int
) -> None:
    """The live instance's check of a successor's document (section 5.3
    step 2): the pre-checks, rules 1 to 6 and 8, and rule 7 (a) to (d). The
    successor is not yet a holder, so (e) and (f) do not apply."""
    verify_evidence(doc, release, view, roots, now)
    _check_logged(doc, release, view, roots, now, None)


def verify_evidence(
    doc: JsonObject, release: JsonObject, view: LogView, roots: Roots, now: int
) -> int:
    """The pre-checks and rules 8, 4, 3, 2, 1, 5 and 6, in that order: what
    the log and the witnesses check before they accept an instance key
    (section 5.4). Return the signed issue time of the evidence."""
    bind, issued = _pre_checks(doc, release, roots)
    ref = release["profiles"][doc["profile"]]

    # Rule 8: roots (and OCSP for the GPU), by the profile's verifier.
    claims = evidence_verifier(doc["profile"]).claims(doc, roots)
    cpu, gpu = claims.cpu, claims.gpu

    # Rule 4: age by signed time (the checkpoint that the evidence binds).
    if now - issued > MAX_EVIDENCE_AGE or issued > now + MAX_SKEW:
        raise Refused("evidence_expired")
    _check_collateral(cpu, now)

    # Rule 3: policy bits.
    if cpu.get("debug") is not False or cpu.get("migratable") is not False:
        raise Refused("policy_refused", "cpu")
    if gpu is not None and (gpu.get("dbgstat") != "disabled" or gpu.get("cc_mode") != "ON"):
        raise Refused("policy_refused", "gpu")

    # Rule 2: TCB floor (release floor, raised by enclave_floor entries).
    _check_floor(effective_floor(release, doc["profile"], view, roots), cpu, gpu)

    # Rule 1: evidence -> reference values -> measurement.
    reference = evidence_object(cpu.get("reference") or {}, "reference")
    try:
        measured = b.measurement(doc["profile"], reference).hex()
    except CanonicalError as exc:  # a reference with no canonical form
        raise Refused("bad_attestation", "reference form") from exc
    if measured != ref["measurement"]:
        raise Refused("measurement_mismatch")

    # Rules 5 and 6: key binding and GPU binding.
    _check_binding(doc, cpu, gpu, bind, bool(ref["reference"].get("gpu")))
    return issued


def _pre_checks(doc: JsonObject, release: JsonObject, roots: Roots) -> tuple[bytes, int]:
    """Form, release, possession of the output key, the checkpoint quorum,
    and then the profile (section 3.4 step 1: every `bad_attestation`
    check comes before `unknown_profile`, so the profile code is never
    given for a document that fails a check of its integrity). Return the
    binding value and the signed issue time."""
    if not isinstance(doc, dict) or set(doc) != _DOC_FIELDS or doc["schema"] != ATTESTATION_SCHEMA:
        raise Refused("bad_attestation", "fields or schema")
    try:
        body = _doc_body(doc)
    except CanonicalError as exc:
        raise Refused("bad_attestation", "no canonical form") from exc
    if doc["release"] != entry_digest(release).hex():
        raise Refused("bad_attestation", "release digest")
    key_epoch = doc["key_epoch"]
    if type(key_epoch) is not int or not 0 <= key_epoch < 2**64:
        raise Refused("bad_attestation", "key_epoch")
    if doc["descriptor_hashes"] != release["descriptor_hashes"]:
        raise Refused("bad_attestation", "descriptor set differs from the release")
    output_key = _bytes(doc, "output_key", 32)
    if not verify(output_key, TAG_SIGN_ATTESTATION, body, _bytes(doc, "signature", 64)):
        raise Refused("bad_attestation", "document signature")
    anchor, _, issued, _, _ = quorum_times(doc["checkpoint"], roots)
    profile = doc["profile"]
    if not isinstance(profile, str) or profile not in release["profiles"]:
        raise Refused("unknown_profile", str(profile))
    evidence_verifier(profile)  # an unknown profile, or one with no verifier in this build
    bind = b.Binding(
        line_id=_bytes(doc, "line_id", 16),
        instance_id=_bytes(doc, "instance_id", 16),
        key_epoch=key_epoch,
        intake_key=_bytes(doc, "intake_key", 32),
        output_key=output_key,
        descriptor_set=b.descriptor_set_hash([bytes.fromhex(h) for h in doc["descriptor_hashes"]]),
        release=entry_digest(release),
        checkpoint=anchor,
    )
    return bind.value(), issued


def _check_collateral(cpu: JsonObject, now: int) -> None:
    """Rule 4 for a profile with collateral (the AMD CRL): `now` is before
    its next update."""
    valid_until = cpu.get("valid_until")
    if valid_until is not None and (type(valid_until) is not int or now >= valid_until):
        raise Refused("evidence_expired", "collateral (CRL) is past its next update")
    valid_from = cpu.get("valid_from")
    if valid_from is not None and (type(valid_from) is not int or now + MAX_SKEW < valid_from):
        raise Refused("evidence_expired", "evidence (token) is not valid yet")


def _check_floor(floor: JsonObject, cpu: JsonObject, gpu: JsonObject | None) -> None:
    """Rule 2. The CPU claims give their floor items in `tcb`; a profile may
    name items that do not apply to this evidence (`tcb_not_applicable`:
    another product's items) and items that the floor must name
    (`tcb_required`), so a floor with no item for the evidence's hardware
    never passes it."""
    claims = dict(evidence_object(cpu.get("tcb") or {}, "tcb"))
    skip = cpu.get("tcb_not_applicable") or []
    required = cpu.get("tcb_required") or []
    if not isinstance(skip, list) or not isinstance(required, list):
        raise Refused("bad_attestation", "tcb claims form")
    if gpu is not None:
        claims["gpu_driver"] = gpu.get("driver_version")
        claims["gpu_vbios"] = gpu.get("vbios_version")
    for name, value in claims.items():
        if name.endswith("_status") and value in NEVER_PASSES:
            raise Refused("tcb_below_floor", name)  # whatever the floor lists
    for name in required:
        if name not in floor:
            raise Refused("tcb_below_floor", f"the floor has no {name}")
    for name, minimum in floor.items():
        if name.startswith("gpu_") and gpu is None:
            continue  # no GPU evidence: rule 6 refuses it if the release needs a GPU
        if name in skip:
            continue
        if name not in claims or not meets(name, claims[name], minimum):
            raise Refused("tcb_below_floor", name)


def _check_binding(
    doc: JsonObject, cpu: JsonObject, gpu: JsonObject | None, bind: bytes, gpu_required: bool
) -> None:
    got = cpu.get("report_data")
    plain = b.report_data(bind).hex()
    if gpu is None:
        if gpu_required:
            raise Refused("gpu_binding_mismatch", "no GPU evidence")
        if got != plain:
            raise Refused("binding_mismatch")
        return
    if gpu.get("bound_by_cpu_evidence") is True:
        # The CPU evidence itself names the GPU (gcp-cs, section 4.5): there is
        # no separate GPU evidence, and the binding is the plain form.
        if doc["gpu_evidence"] is not None or got != plain:
            raise Refused("binding_mismatch")
        return
    if got == plain:
        raise Refused("gpu_binding_mismatch", "CPU evidence does not cover the GPU")
    if got != b.report_data(bind, canonical_json(doc["gpu_evidence"])).hex():
        raise Refused("binding_mismatch")
    if gpu.get("nonce") != b.gpu_nonce(bind).hex():
        raise Refused("gpu_binding_mismatch", "GPU nonce")


def _check_logged(
    doc: JsonObject,
    release: JsonObject,
    view: LogView,
    roots: Roots,
    now: int,
    subject: bytes | None,
) -> None:
    """Rule 7 (a) to (d), in order."""
    digest = entry_digest(release).hex()
    match = [
        (i, e)
        for i, e in view.of_kind("enclave_instance_key")
        if e["release"] == digest
        and e["line_id"] == doc["line_id"]
        and e["instance_id"] == doc["instance_id"]
        and e["key_epoch"] == doc["key_epoch"]
        and e["intake_key"] == doc["intake_key"]
        and e["signer"] == doc["output_key"]
        and e["profile"] == doc["profile"]
    ]
    if not match:
        raise Refused("instance_not_logged")
    i, latest = match[-1]
    until = lease(latest)
    if until <= now or until > view.logged_by[i] + MAX_LEASE:
        raise Refused("instance_not_logged", "lease expired or longer than 24 h")
    line_authorised(view, doc["line_id"], roots, subject)
    if view.revoked({"instance_id": doc["instance_id"]}, roots) or view.revoked(
        {"line_id": doc["line_id"]}, roots
    ):
        raise Refused("instance_revoked")
    if line_forked(view, doc["line_id"], roots):
        raise Refused("line_forked")


def _check_writer(doc: JsonObject, release: JsonObject, view: LogView, roots: Roots) -> None:
    """Rule 7 (e) and (f)."""
    epoch = latest_epoch(view, doc["line_id"])
    if epoch is None or line_writer(view, doc["line_id"], roots) != doc["instance_id"]:
        raise Refused("instance_not_writer")
    if len(epoch["holders"]) > release["max_instances"]:
        raise Refused("instance_limit", f"{len(epoch['holders'])} > {release['max_instances']}")
