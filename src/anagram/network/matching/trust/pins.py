"""The public pins of a network: what a node and an app pin
(spec/enclave-trust.md 2.6; spec/network.md 1).

    {"schema": "anagram.enclave.devnet.v1", "profile", "network",
     "roster_key", "origin", "log_key", "witnesses": [{"name", "cosign",
     "entry_key", "independent", "reads_entries"}], "release_key",
     "rebuilders", "dev_root"}

The file name and the schema name come from the first networks, which were
development networks (`devnet.json`); the format is the same for any
profile. The pins name their profile; a profile whose evidence this build
does not verify is refused (`trust/platform.py`). `dev_root` is the
development root of the `simulated` profile, or null.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from anagram.core.canonical import JsonObject
from anagram.network.matching.trust.platform import available_profiles
from anagram.network.matching.trust.roots import Roots, Witness
from anagram.proofs.log.note import NoteVerifier

SCHEMA = "anagram.enclave.devnet.v1"


@dataclass(frozen=True)
class WitnessPin:
    name: str
    cosign: str  # vkey of the cosignature/v1 key
    entry_key: str  # hex Ed25519 key of enclave_entry_cosign entries
    independent: bool
    reads_entries: bool


@dataclass(frozen=True)
class Pins:
    """The pins of one network."""

    profile: str
    network: str
    roster_key: str
    origin: str
    log_key: str  # vkey
    witnesses: tuple[WitnessPin, ...]
    release_key: str
    rebuilders: tuple[str, ...]
    dev_root: str | None

    @property
    def roots(self) -> Roots:
        return Roots(
            log_key=NoteVerifier.parse(self.log_key),
            witnesses=tuple(
                Witness(NoteVerifier.parse(w.cosign), w.entry_key, w.independent)
                for w in self.witnesses
            ),
            release_key=self.release_key,
            rebuilders=self.rebuilders,
            dev_root=self.dev_root,
            roster_key=self.roster_key,
        )

    def to_json(self) -> JsonObject:
        return {
            "dev_root": self.dev_root,
            "log_key": self.log_key,
            "network": self.network,
            "origin": self.origin,
            "profile": self.profile,
            "rebuilders": list(self.rebuilders),
            "release_key": self.release_key,
            "roster_key": self.roster_key,
            "schema": SCHEMA,
            "witnesses": [
                {
                    "cosign": w.cosign,
                    "entry_key": w.entry_key,
                    "independent": w.independent,
                    "name": w.name,
                    "reads_entries": w.reads_entries,
                }
                for w in self.witnesses
            ],
        }

    @classmethod
    def from_json(cls, doc: JsonObject) -> Pins:
        if doc.get("schema") != SCHEMA:
            raise ValueError("not the pins of a network")
        if doc.get("profile") not in available_profiles():
            raise ValueError(f"this build verifies only the profiles {available_profiles()}")
        pins = cls(
            profile=doc["profile"],
            network=doc["network"],
            roster_key=doc["roster_key"],
            origin=doc["origin"],
            log_key=doc["log_key"],
            witnesses=tuple(
                WitnessPin(
                    w["name"], w["cosign"], w["entry_key"], w["independent"], w["reads_entries"]
                )
                for w in doc["witnesses"]
            ),
            release_key=doc["release_key"],
            rebuilders=tuple(doc["rebuilders"]),
            dev_root=doc["dev_root"],
        )
        if pins.roots.log_key.name != pins.origin:
            raise ValueError("the log key name is not the origin")
        return pins

    @classmethod
    def read(cls, path: str | Path) -> Pins:
        return cls.from_json(json.loads(Path(path).read_text()))
