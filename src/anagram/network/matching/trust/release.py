"""The release rules of the app (spec/enclave-trust.md 2.5, 5.3, 7.2).

An app seals only to an instance of a release that is in its checked log
view, signed by the pinned release key, not revoked, rebuilt by every
pinned rebuilder, and logged at least 14 days before `not_before` (48
hours for a security fix that the independent witnesses cosigned). The TCB
floor of a release can only go up, by `enclave_floor` entries.
"""

from __future__ import annotations

from anagram.core.canonical import CanonicalError, JsonObject
from anagram.core.version import VERSION
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.trust.entries import entry_digest
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

APP_VERSION = VERSION  # the app's version, for `min_app_version` (2.5 rule 3)
NOTICE = 14 * 86400
FIX_NOTICE = 48 * 3600

RELEASE_CODES = (
    "release_not_logged",
    "release_revoked",
    "release_app_too_old",
    "release_rebuild_differs",
    "release_rebuilds_missing",
    "release_fix_not_cosigned",
    "release_notice_short",
    "release_not_yet",
)
HANDOFF_CODES = ("handoff_not_successor", "handoff_bad_sender", "handoff_bad_ciphertext")


def version_key(text: str, base: int) -> tuple[int, ...]:
    try:
        return tuple(int(p, base) for p in text.split("."))
    except ValueError as exc:
        raise Refused("bad_attestation", f"bad version {text!r}") from exc


_FLOOR_BASE = {"gpu_driver": 10, "gpu_vbios": 16, "min_app_version": 10}


def meets(name: str, value: object, floor: object) -> bool:
    """One floor item: an integer is a minimum; a list is a set of allowed
    values; a dotted string is a minimum version (decimal, or hex for VBIOS)."""
    if isinstance(floor, bool) or isinstance(value, bool):
        return value == floor
    if isinstance(floor, int):
        return isinstance(value, int) and value >= floor
    if isinstance(floor, list):
        return value in floor
    if isinstance(floor, str) and name in _FLOOR_BASE and isinstance(value, str):
        base = _FLOOR_BASE[name]
        return version_key(value, base) >= version_key(floor, base)
    return value == floor


def raise_floor(floor: JsonObject, raised: JsonObject) -> JsonObject:
    """Merge an enclave_floor entry. It may only narrow (spec section 7.2)."""
    out = dict(floor)
    for name, new in raised.items():
        old = out.get(name)
        if old is None:
            out[name] = new
        elif isinstance(old, list) and isinstance(new, list):
            out[name] = [v for v in old if v in new]
        elif not isinstance(old, list) and meets(name, new, old):
            out[name] = new
    return out


def effective_floor(release: JsonObject, profile: str, view: LogView, roots: Roots) -> JsonObject:
    digest = entry_digest(release).hex()
    floor = dict(release["profiles"][profile]["tcb_floor"])
    for _, e in view.of_kind("enclave_floor"):
        if e["release"] == digest and e["profile"] == profile and e["signer"] == roots.release_key:
            floor = raise_floor(floor, e["tcb_floor"])
    return floor


def _digest(entry: object) -> bytes:
    """The entry digest of an untrusted entry; a form that has no canonical
    JSON is `bad_attestation`."""
    if not isinstance(entry, dict):
        raise Refused("bad_attestation", "entry form")
    try:
        return entry_digest(entry)
    except CanonicalError as exc:
        raise Refused("bad_attestation", "entry form") from exc


def accept_release(
    release: JsonObject, view: LogView, roots: Roots, app_version: str, now: int
) -> None:
    """May the app seal to an instance of this release? (spec section 2.5)
    A release is used only when it is in the checked view, so every field
    read after `find` has the form that `check_entry` checked."""
    digest = _digest(release)
    index = view.find(digest)
    if index is None or release["signer"] != roots.release_key:
        raise Refused("release_not_logged")
    if view.revoked({"release": digest.hex()}, roots):
        raise Refused("release_revoked")
    if version_key(app_version, 10) < version_key(release["min_app_version"], 10):
        raise Refused("release_app_too_old")
    not_before = parse_time(release["not_before"], "not_before")
    want = {p: v["measurement"] for p, v in release["profiles"].items()}
    good = set()
    for i, e in view.of_kind("enclave_rebuild"):
        if e["signer"] not in roots.rebuilders or e["release"] != digest.hex():
            continue
        if not e["same"] or e["image_digest"] != release["image_digest"]:
            raise Refused("release_rebuild_differs", e["signer"])
        if e["measurements"] != want:
            raise Refused("release_rebuild_differs", e["signer"])
        if view.logged_by[i] <= not_before:
            good.add(e["signer"])
    if good != set(roots.rebuilders):
        raise Refused("release_rebuilds_missing")
    logged = view.logged_by[index]
    if logged + NOTICE > not_before:
        if not release["security_fix"]:
            raise Refused("release_notice_short")
        if not view.cosign_quorum(
            digest, roots, before=not_before - FIX_NOTICE, independent_only=True
        ):
            raise Refused("release_fix_not_cosigned")
        if logged + FIX_NOTICE > not_before:
            raise Refused("release_notice_short")
    if now < not_before:
        raise Refused("release_not_yet")


def check_successor(own_release: JsonObject, successor_release: JsonObject) -> None:
    """The old instance hands the state key only to the same release or to
    its named successor (spec section 5.3). The caller accepted
    `successor_release` first (`accept_release`), so its form is checked."""
    own = entry_digest(own_release).hex()
    if entry_digest(successor_release).hex() != own and successor_release["successor_of"] != own:
        raise Refused("handoff_not_successor")
