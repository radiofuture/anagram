"""The operator's release-key steps for a development network.

    anagram enclave release   log a release, its two rebuild records, and write release.json
    anagram enclave line      authorise the first line of the release (5.6)
    anagram enclave failover  name a live holder the writer of a line (5.7)

Each step signs with the release key (or a rebuilder key) and writes to the
log's write API. A line and a failover hold only with an
`enclave_entry_cosign` of both independent witnesses: the operator asks
each witness (`POST /witness/entry-cosign`), which checks the entry at its
own time, and appends the cosign entries it gets back.

`release.json` is what each enclave process runs: the release entry, its
descriptors and the line ID. It holds no secret.

The engines of the `simulated` profile are the deterministic test
embedder and judge (`enclave/simulated_engines.py`): they prove the plumbing,
not the quality of matches.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from anagram.core.canonical import JsonObject
from anagram.core.files import atomic_write
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.simulated_engines import model_descriptors
from anagram.network.matching.hosting.clients import HttpLog
from anagram.network.matching.hosting.tools.devnet import DevNet
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.devtrust import (
    ReleasePlan,
    line_entry,
    rebuild_entries,
    release_entry,
    writer_entry,
)
from anagram.network.matching.trust.release import NOTICE
from anagram.network.matching.trust.translog import check_failover

HOUR = 3_600
REFERENCE = {"gpu": False, "image_digest": "sha256:" + "1" * 64}
TCB_FLOOR = {"svn": 3}
STATEMENT = "Anagram matches you inside a sealed service; names go out only after two yes answers."
RELEASE_SCHEMA = "anagram.enclave.devnet_release.v1"


def simulated_descriptors(
    network: str,
    roster_key: str,
    answer_day: int = 2,
    min_people: int = 2,
    min_nodes: int = 1,
    statement: str = STATEMENT,
) -> list[JsonObject]:
    """The descriptor set of a `simulated` release (spec/enclave-trust.md
    3.6): the matching rules, the vocabulary, and the two test engines."""
    docs = [
        {
            "body": {
                "accepted_schemas": ["anagram.known.v1", "anagram.pack.v1"],
                "anonymity_min_nodes": min_nodes,
                "anonymity_min_people": min_people,
                "answer_day": answer_day,
                "card_option": "a",
                "consent_statement": statement,
                "network": network,
                "roster_key": roster_key,
                "weekly_cap_max": 3,
            },
            "kind": "matching",
        },
        {
            "body": {"concepts": 1_000, "id": "anagram-vocab-test", "sha256": "0" * 64},
            "kind": "vocabulary",
        },
    ]
    return [{**d, "schema": dsc.SCHEMA} for d in docs] + model_descriptors()


def model_weights(descriptors: list[JsonObject]) -> list[JsonObject]:
    """The `weights` of a release: the name and digest of each model."""
    return sorted(
        (
            {"digest": d["body"]["digest"], "name": d["body"]["name"]}
            for d in descriptors
            if d["kind"] == "model"
        ),
        key=lambda w: w["name"],
    )


@dataclass(frozen=True)
class ReleaseFile:
    """`release.json`: what an enclave process runs."""

    release: JsonObject
    descriptors: list[JsonObject]
    line_id: str

    def to_json(self) -> JsonObject:
        return {
            "descriptors": self.descriptors,
            "line_id": self.line_id,
            "release": self.release,
            "schema": RELEASE_SCHEMA,
        }

    @classmethod
    def read(cls, path: str | Path) -> ReleaseFile:
        doc = json.loads(Path(path).read_text())
        if doc.get("schema") != RELEASE_SCHEMA:
            raise ValueError(f"{path} is not a release file")
        return cls(doc["release"], doc["descriptors"], doc["line_id"])

    def write(self, path: str | Path) -> None:
        text = json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n"
        atomic_write(path, text.encode(), mode=0o644)  # public: a release


@dataclass
class Operator:
    net: DevNet
    log: HttpLog
    witnesses: list[httpx.Client]  # the two independent witnesses
    clock: Callable[[], int]

    def release(self, answer_day: int, min_people: int, min_nodes: int) -> ReleaseFile:
        """Log a release that apps accept after the notice period (2.5),
        and both rebuild records. The line ID is new."""
        pins = self.net.pins()
        descriptors = simulated_descriptors(
            pins.network, pins.roster_key, answer_day, min_people, min_nodes
        )
        hashes = sorted(dsc.descriptor_hash(d).hex() for d in descriptors)
        not_before = self.clock() + NOTICE + HOUR
        plan = ReleasePlan(
            hashes, REFERENCE, TCB_FLOOR, not_before, weights=model_weights(descriptors)
        )
        rel = release_entry(self.net.key("release"), plan)
        self.log.append(rel)
        rebuilders = (self.net.key("rebuild-ci"), self.net.key("rebuild-ext"))
        for entry in rebuild_entries(rel, rebuilders):
            self.log.append(entry)
        return ReleaseFile(rel, descriptors, secrets.token_hex(16))

    def authorise_line(self, release: ReleaseFile) -> JsonObject:
        entry = line_entry(self.net.key("release"), release.release, release.line_id)
        self._cosigned(entry)
        return entry

    def fail_over(self, line_id: str, writer: str) -> JsonObject:
        """The operator checks rules 3 to 5 first; each witness checks them
        again at its own time before it cosigns."""
        latest = check_failover(self.log.view(), line_id, writer, self.log.roots, self.clock())
        entry = writer_entry(self.net.key("release"), line_id, writer, latest)
        self._cosigned(entry)
        return entry

    def _cosigned(self, entry: JsonObject) -> None:
        index = self.log.append(entry)
        self.log.wait_cosigned(index)
        for w in self.witnesses:
            r = w.post("/witness/entry-cosign", json={"entry": entry})
            if r.status_code != 200:
                raise Refused("bad_entry", f"a witness refused to cosign ({r.status_code})")
            self.log.append(r.json()["entry"])
