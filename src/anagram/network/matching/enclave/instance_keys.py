"""The keys of one enclave instance, its attestation document and its lease
(spec/enclave-trust.md 3.3, 5.4).

The keys come from inside the instance and never leave it: the output key
signs receipts, slots and log entries; the intake key opens requests. The
instance logs its instance key with a lease of at most 24 hours and makes a
new document every 12 hours.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats.strict import Refused, fmt_time
from anagram.network.matching.enclave.state import LogPort, Release
from anagram.network.matching.trust import binding as b
from anagram.network.matching.trust.attestation import ATTESTATION_SCHEMA, sign_attestation
from anagram.network.matching.trust.bundle import attestation_digest
from anagram.network.matching.trust.entries import sign_entry
from anagram.network.matching.trust.lines import MAX_LEASE
from anagram.network.matching.trust.platform import Platform
from anagram.network.matching.trust.roots import Roots, quorum_times


def evidence_digest(doc: JsonObject) -> str:
    """Section 2.2: SHA-256 of `canonical_json(platform_evidence)`."""
    return hashlib.sha256(canonical_json(doc["platform_evidence"])).hexdigest()


@dataclass
class InstanceKeys:
    """The keys, the document and the lease of one instance. The sealed
    record keeps them (`record`), so a restart keeps the instance ID."""

    output: SigningKey = field(default_factory=SigningKey.generate)
    intake: X25519PrivateKey = field(default_factory=hpke.generate)
    instance_id: str = field(default_factory=lambda: secrets.token_hex(16))
    key_epoch: int = 0
    document: JsonObject | None = None
    lease_until: int = 0

    @property
    def intake_public(self) -> bytes:
        return hpke.public_bytes(self.intake)

    @property
    def output_hex(self) -> str:
        return self.output.public_bytes().hex()

    def attestation_digest(self) -> bytes:
        if self.document is None:
            raise Refused("unavailable", "no attestation document yet")
        return attestation_digest(self.document)

    def register(
        self,
        line_id: str,
        release: Release,
        platform: Platform,
        roots: Roots,
        log: LogPort,
        note: str,
        now: int,
    ) -> None:
        """Make a new attestation document that binds the checkpoint of
        `note`, and log the instance key with a lease of 24 hours from the
        host time `now`."""
        binding = b.Binding(
            line_id=bytes.fromhex(line_id),
            instance_id=bytes.fromhex(self.instance_id),
            key_epoch=self.key_epoch,
            intake_key=self.intake_public,
            output_key=self.output.public_bytes(),
            descriptor_set=release.descriptor_set,
            release=release.digest,
            checkpoint=quorum_times(note, roots)[0],
        ).value()
        cpu, gpu = platform.evidence(binding)
        doc = sign_attestation(
            {
                "checkpoint": note,
                "descriptor_hashes": release.entry["descriptor_hashes"],
                "gpu_evidence": gpu,
                "instance_id": self.instance_id,
                "intake_key": self.intake_public.hex(),
                "key_epoch": self.key_epoch,
                "line_id": line_id,
                "log_proof": None,
                "output_key": self.output_hex,
                "platform_evidence": cpu,
                "profile": platform.profile,
                "release": release.digest.hex(),
                "schema": ATTESTATION_SCHEMA,
            },
            self.output,
        )
        self.lease_until = now + MAX_LEASE
        fields = {
            "evidence_digest": evidence_digest(doc),
            "instance_id": self.instance_id,
            "intake_key": self.intake_public.hex(),
            "key_epoch": self.key_epoch,
            "lease_until": fmt_time(self.lease_until),
            "line_id": line_id,
            "profile": platform.profile,
            "release": release.digest.hex(),
        }
        log.append_instance_key(sign_entry("enclave_instance_key", fields, self.output), doc)
        self.document = doc

    def record(self) -> JsonObject:
        return {
            "document": self.document,
            "instance_id": self.instance_id,
            "intake_key": hpke.private_bytes(self.intake).hex(),
            "key_epoch": self.key_epoch,
            "lease_until": self.lease_until,
            "output": self.output.seed().hex(),
        }

    @classmethod
    def from_record(cls, record: JsonObject) -> InstanceKeys:
        return cls(
            output=SigningKey.from_seed(bytes.fromhex(record["output"])),
            intake=hpke.private_from_bytes(bytes.fromhex(record["intake_key"])),
            instance_id=record["instance_id"],
            key_epoch=record["key_epoch"],
            document=record["document"],
            lease_until=record["lease_until"],
        )
