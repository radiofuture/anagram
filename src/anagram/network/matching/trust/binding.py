"""Measurement, report-data binding and GPU nonce (spec/enclave-trust.md
section 4)."""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import lp, sha256, tagged_hash, u32, u64

TAG_MEASUREMENT = "anagram/v1/enclave/measurement"
TAG_DESCRIPTOR_SET = "anagram/v1/enclave/descriptor-set"
TAG_REPORT_DATA = "anagram/v1/enclave/report-data"
TAG_REPORT_DATA_GPU = "anagram/v1/enclave/report-data-gpu"
TAG_GPU_NONCE = "anagram/v1/enclave/gpu-nonce"


def measurement(profile: str, reference: JsonObject) -> bytes:
    """The logged measurement of one profile: a hash of its reference values."""
    return tagged_hash(TAG_MEASUREMENT, lp(profile.encode("utf-8")), canonical_json(reference))


def descriptor_set_hash(descriptor_hashes: list[bytes]) -> bytes:
    if any(len(h) != 32 for h in descriptor_hashes) or len(set(descriptor_hashes)) != len(
        descriptor_hashes
    ):
        raise ValueError("descriptor hashes must be distinct 32-byte values")
    return tagged_hash(TAG_DESCRIPTOR_SET, u32(len(descriptor_hashes)), *sorted(descriptor_hashes))


@dataclass(frozen=True)
class Binding:
    """The values that one piece of evidence must bind (rule 5)."""

    line_id: bytes  # 16
    instance_id: bytes  # 16
    key_epoch: int
    intake_key: bytes  # 32, X25519
    output_key: bytes  # 32, Ed25519
    descriptor_set: bytes  # 32
    release: bytes  # 32, digest of the enclave_release entry
    checkpoint: bytes  # 32, anchor digest of a cosigned checkpoint

    def value(self) -> bytes:
        sizes = (
            (self.line_id, 16),
            (self.instance_id, 16),
            (self.intake_key, 32),
            (self.output_key, 32),
            (self.descriptor_set, 32),
            (self.release, 32),
            (self.checkpoint, 32),
        )
        if any(len(v) != n for v, n in sizes) or not 0 <= self.key_epoch < 2**64:
            raise ValueError("bad binding field size")
        return tagged_hash(
            TAG_REPORT_DATA,
            self.line_id,
            self.instance_id,
            u64(self.key_epoch),
            self.intake_key,
            self.output_key,
            self.descriptor_set,
            self.release,
            self.checkpoint,
        )


def gpu_nonce(binding_value: bytes) -> bytes:
    """The 32-byte nonce that the enclave gives to the GPU (rule 6)."""
    return tagged_hash(TAG_GPU_NONCE, binding_value)


def report_data(binding_value: bytes, gpu_evidence: bytes | None = None) -> bytes:
    """The 32 bytes that the CPU evidence carries. With a GPU, they also
    cover the SHA-256 of the GPU evidence bytes."""
    if gpu_evidence is None:
        return binding_value
    return tagged_hash(TAG_REPORT_DATA_GPU, binding_value, sha256(gpu_evidence))


def report_data_field(value: bytes) -> bytes:
    """The 64-byte REPORT_DATA (SEV-SNP) or REPORTDATA (TDX) field."""
    return value + bytes(32)
