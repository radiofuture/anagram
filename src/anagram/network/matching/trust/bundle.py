"""The attestation bundle and its check (spec/enclave-trust.md 3.7).

    {"schema": "anagram.enclave.attestation_bundle.v1", "checkpoint",
     "descriptors": [...], "documents": [...]}

The enclave front end gives the bundle; the node relays it. An app checks
it before it seals (3.7 steps 1 to 4), and a node checks it the same way
for its operator (`anagram node enclave status`). `check_bundle` is a pure
function of the bundle, the reader of the log, the pins and the time, so
both parts use the same code and neither imports the other.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import tagged_hash
from anagram.network.formats.strict import HEX32, Refused
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.attestation import verify_attestation
from anagram.network.matching.trust.follow import LogFollower
from anagram.network.matching.trust.release import APP_VERSION, accept_release
from anagram.network.matching.trust.roots import Roots, app_now, quorum_times

SCHEMA = "anagram.enclave.attestation_bundle.v1"
# The domain tag of an attestation digest (3.4). The name is locked; the
# node-run matching room used it first.
TAG_ATTESTATION = "anagram/v1/room/attestation"


# The app seals only while its view of the log is fresh: every witness of
# the quorum cosigned the bundle's checkpoint at most this long ago (3.7).
MAX_VIEW_AGE = 3600


class StaleView(Refused):
    """The bundle's checkpoint is older than `MAX_VIEW_AGE`: the app's view
    of the log may miss a revoke or a newer release, so it sends nothing."""

    def __init__(self, detail: str) -> None:
        super().__init__("log_view_stale", detail)


class NotSealable(Refused):
    """No document of the bundle passes the checks; the app sends nothing
    and tries again in one hour (3.7)."""

    def __init__(self, detail: str) -> None:
        super().__init__("not_sealable", detail)


def attestation_digest(doc: JsonObject) -> bytes:
    """The digest that a sealed request names (enclave-messages.md 3)."""
    return tagged_hash(TAG_ATTESTATION, canonical_json(doc))


@dataclass(frozen=True)
class Target:
    """The instance to seal to, after the checks."""

    document: JsonObject
    release: JsonObject
    descriptors: dict[str, list[JsonObject]]
    output_keys: frozenset[str]
    checked_at: int = 0  # signed lower time of the checkpoint it was checked under

    def fresh(self, clock: int) -> bool:
        """The view that chose this target is still fresh (3.7)."""
        return clock - self.checked_at <= MAX_VIEW_AGE

    @property
    def digest(self) -> bytes:
        return attestation_digest(self.document)

    @property
    def intake(self) -> bytes:
        return bytes.fromhex(self.document["intake_key"])

    @property
    def matching(self) -> JsonObject:
        body: JsonObject = self.descriptors["matching"][0]["body"]  # checked descriptor
        return body


def _form(bundle: object) -> tuple[str, list[JsonObject], list[object]]:
    """(checkpoint, descriptors, documents) of a bundle of the right form."""
    if not isinstance(bundle, dict):
        raise NotSealable("bundle form")
    checkpoint, docs, descriptors = (
        bundle.get("checkpoint"),
        bundle.get("documents"),
        bundle.get("descriptors"),
    )
    if not (
        isinstance(checkpoint, str)
        and isinstance(docs, list)
        and isinstance(descriptors, list)
        and all(isinstance(d, dict) for d in descriptors)
    ):
        raise NotSealable("bundle form")
    return checkpoint, descriptors, docs


def check_bundle(
    bundle: object,
    follower: LogFollower,
    roots: Roots,
    clock: int,
    subject: bytes,
    app_version: str = APP_VERSION,
) -> Target:
    """3.7 steps 1 to 4: read the log under the bundle's checkpoint, then
    take the first document whose release, descriptors and attestation
    pass for `subject`. `clock` is the reader's computer clock. Raise
    `NotSealable` when no document passes."""
    checkpoint, descriptors, docs = _form(bundle)
    view = follower.follow(checkpoint)
    now = app_now(clock, checkpoint, roots)
    lower = quorum_times(checkpoint, roots)[2]
    if clock - lower > MAX_VIEW_AGE:
        raise StaleView(f"the newest checkpoint is {(clock - lower) // 60} minutes old")
    for doc in docs:
        release_hex = doc.get("release") if isinstance(doc, dict) else None
        if not (
            isinstance(doc, dict) and isinstance(release_hex, str) and HEX32.match(release_hex)
        ):
            continue
        index = view.find(bytes.fromhex(release_hex))
        if index is None:
            continue
        release = view.entries[index]
        try:
            accept_release(release, view, roots, app_version, now)
            by_kind = dsc.check_set(descriptors, release["descriptor_hashes"])
            verify_attestation(doc, release, view, roots, now, subject)
        except Refused:  # DescriptorError is a refusal too
            continue
        keys = frozenset(
            e["signer"]
            for _, e in view.of_kind("enclave_instance_key")
            if e["line_id"] == doc["line_id"]
        )
        return Target(doc, release, by_kind, keys, lower)
    raise NotSealable("no document passes")


def make_bundle(
    checkpoint: str, descriptors: list[JsonObject], docs: list[JsonObject]
) -> JsonObject:
    """The bundle of the front end: the latest checkpoint, the release's
    descriptors and the document of the writer of each line."""
    return {
        "checkpoint": checkpoint,
        "descriptors": descriptors,
        "documents": docs,
        "schema": SCHEMA,
    }
