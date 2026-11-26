"""A development network of the `simulated` profile, in one process: the
transparency log, its witnesses and the release key.

Development and CI only (spec/enclave-trust.md 4.1: it protects nothing; a
production app pins no development root and refuses it). It has every part
that a real network has, so the enclave service, the node relay and the
app run their real checks against it. The platform and its evidence are in
`profiles/simulated.py`.

- `SimulatedLog`: the transparency log of `translog.py` with its three
  witnesses in the same process. The two Anagram witnesses read new
  entries and refuse a checkpoint that forks a line or logs a line ID twice
  (2.4); the public witness checks only consistency;
- `DevTrust`: the pinned keys of a development network (log, witnesses,
  release key, rebuilders, development root) and the operator steps that
  log a release and authorise a line.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats.strict import fmt_time
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust.entries import entry_digest, sign_entry
from anagram.network.matching.trust.profiles.simulated import PROFILE, SimulatedPlatform
from anagram.network.matching.trust.roots import Roots, Witness
from anagram.network.matching.trust.translog import (
    EntryWitness,
    LogStore,
    TransparencyLog,
    check_failover,
)
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner


@dataclass
class WitnessKeys:
    name: str
    cosign: SigningKey  # cosignature/v1 key
    entry: SigningKey  # entry key for enclave_entry_cosign
    independent: bool  # not run by Radiofuture
    reads_entries: bool  # an Anagram witness (Radiofuture, university)

    @property
    def signer(self) -> NoteSigner:
        return NoteSigner(self.name, self.cosign, ALG_COSIGNATURE_V1)


class SimulatedLog(TransparencyLog):
    """The enclave transparency log and its three witnesses, in memory (or
    with a `LogStore`)."""

    def __init__(
        self,
        origin: str,
        log_key: SigningKey,
        witnesses: list[WitnessKeys],
        roots: Roots,
        clock: Callable[[], int],
        store: LogStore | None = None,
    ) -> None:
        verifier = NoteSigner(origin, log_key).verifier
        self.witness_keys = witnesses
        self.witnesses = [
            EntryWitness(w.name, w.cosign, w.entry, w.reads_entries, verifier, roots, clock)
            for w in witnesses
        ]
        super().__init__(origin, log_key, roots, clock, list(self.witnesses), store)

    def cosign_entry(self, entry: JsonObject, witnesses: tuple[str, ...]) -> None:
        """Witnesses log `enclave_entry_cosign` entries on an entry."""
        by_name = {w.name: w for w in self.witnesses}
        for name in witnesses:
            self.append(by_name[name].sign_entry_cosign(entry))


@dataclass(frozen=True)
class ReleasePlan:
    """The values of one `enclave_release` entry that an operator chooses."""

    descriptor_hashes: list[str]
    reference: JsonObject
    tcb_floor: JsonObject
    not_before: int
    successor_of: str | None = None
    max_instances: int = 2
    weights: list[JsonObject] = field(default_factory=list)
    commit: str = "0" * 40


def release_entry(release_key: SigningKey, plan: ReleasePlan) -> JsonObject:
    """An `enclave_release` of the `simulated` profile (section 2.3)."""
    image = "sha256:" + hashlib.sha256(canonical_json(plan.reference)).hexdigest()
    return sign_entry(
        "enclave_release",
        {
            "build": {
                "builder": "sha256:" + "0" * 64,
                "lock_sha256": "0" * 64,
                "source_date_epoch": plan.not_before,
            },
            "descriptor_hashes": sorted(plan.descriptor_hashes),
            "image_digest": image,
            "max_instances": plan.max_instances,
            "min_app_version": "0.0.0",
            "not_before": fmt_time(plan.not_before),
            "profiles": {
                PROFILE: {
                    "measurement": b.measurement(PROFILE, plan.reference).hex(),
                    "reference": plan.reference,
                    "tcb_floor": plan.tcb_floor,
                }
            },
            "security_fix": False,
            "source_commit": plan.commit,
            "successor_of": plan.successor_of,
            "vendor_digests": [],
            "weights": plan.weights,
        },
        release_key,
    )


def rebuild_entries(release: JsonObject, rebuilders: tuple[SigningKey, ...]) -> list[JsonObject]:
    """One `enclave_rebuild` of each rebuilder that found the same image (2.5)."""
    return [
        sign_entry(
            "enclave_rebuild",
            {
                "image_digest": release["image_digest"],
                "measurements": {PROFILE: release["profiles"][PROFILE]["measurement"]},
                "release": entry_digest(release).hex(),
                "same": True,
            },
            key,
        )
        for key in rebuilders
    ]


def line_entry(release_key: SigningKey, release: JsonObject, line_id: str) -> JsonObject:
    """The `enclave_line` of the first line of a release (5.6). Both
    independent witnesses must cosign it before it holds."""
    fields = {
        "line_id": line_id,
        "reason": "first",
        "release": entry_digest(release).hex(),
        "replaces": None,
        "shard": {"k": 0, "n": 1},
    }
    return sign_entry("enclave_line", fields, release_key)


def writer_entry(
    release_key: SigningKey, line_id: str, writer: str, latest: JsonObject
) -> JsonObject:
    """The `enclave_writer` of a failover (5.7) that names the latest state
    epoch `latest` of the line. Both independent witnesses must cosign it."""
    fields = {
        "counter": latest["counter"],
        "epoch": entry_digest(latest).hex(),
        "line_id": line_id,
        "writer": writer,
    }
    return sign_entry("enclave_writer", fields, release_key)


def _random_key(_label: str) -> SigningKey:
    return SigningKey.generate()


@dataclass
class DevTrust:
    """The pinned keys of a development network and the operator steps of a
    release. `key` makes each key from its label (random by default; tests
    pass a seeded function)."""

    clock: Callable[[], int]
    origin: str = "enclave.anagram.example/log"
    key: Callable[[str], SigningKey] = _random_key
    log: SimulatedLog = field(init=False)
    release_key: SigningKey = field(init=False)
    rebuilders: tuple[SigningKey, SigningKey] = field(init=False)
    dev_root: SigningKey = field(init=False)

    def __post_init__(self) -> None:
        self.release_key = self.key("release")
        self.rebuilders = (self.key("rebuild-ci"), self.key("rebuild-ext"))
        self.dev_root = self.key("dev-root")
        witnesses = [
            WitnessKeys(name, self.key(f"w-{name}"), self.key(f"w-{name}-entry"), ind, reads)
            for name, ind, reads in (
                ("witness.radiofuture.example", False, True),
                ("witness.uni.example", True, True),
                ("witness.public.example", True, False),
            )
        ]
        roots = Roots(
            log_key=NoteSigner(self.origin, self.key("log")).verifier,
            witnesses=tuple(
                Witness(w.signer.verifier, w.entry.public_bytes().hex(), w.independent)
                for w in witnesses
            ),
            release_key=self.release_key.public_bytes().hex(),
            rebuilders=tuple(sorted(k.public_bytes().hex() for k in self.rebuilders)),
            dev_root=self.dev_root.public_bytes().hex(),
        )
        self.log = SimulatedLog(self.origin, self.key("log"), witnesses, roots, self.clock)

    @property
    def roots(self) -> Roots:
        return self.log.roots

    def platform(self, reference: JsonObject, svn: int = 3) -> SimulatedPlatform:
        return SimulatedPlatform(self.dev_root, reference, svn)

    def release(
        self,
        descriptor_hashes: list[str],
        reference: JsonObject,
        tcb_floor: JsonObject,
        not_before: int,
        successor_of: str | None = None,
        max_instances: int = 2,
        weights: list[JsonObject] | None = None,
        commit: str = "0" * 40,
    ) -> JsonObject:
        """Log a release and both rebuild records (sections 2.3, 2.5)."""
        rel = release_entry(
            self.release_key,
            ReleasePlan(
                descriptor_hashes, reference, tcb_floor, not_before, successor_of,
                max_instances, weights or [], commit,
            ),
        )  # fmt: skip
        self.log.append(rel)
        for entry in rebuild_entries(rel, self.rebuilders):
            self.log.append(entry)
        return rel

    def authorise_line(self, release: JsonObject, line_id: str) -> JsonObject:
        """The first line of a release: signed by the release key and
        cosigned by both independent witnesses (section 5.6)."""
        entry = line_entry(self.release_key, release, line_id)
        self.log.append(entry)
        self.log.cosign_entry(entry, self.independent)
        return entry

    @property
    def independent(self) -> tuple[str, ...]:
        return tuple(w.name for w in self.log.witness_keys if w.independent)

    def fail_over(self, line_id: str, writer: str) -> JsonObject:
        """Name a live holder the writer of a line whose writer stopped
        (section 5.7): signed by the release key and cosigned by both
        independent witnesses. Each witness first checks, at its own time,
        that the entry names the latest state epoch and one of its holders,
        and that every lease of the current writer ended."""
        latest = check_failover(self.log.view(), line_id, writer, self.roots, self.clock())
        entry = writer_entry(self.release_key, line_id, writer, latest)
        self.log.append(entry)
        self.log.cosign_entry(entry, self.independent)
        return entry
