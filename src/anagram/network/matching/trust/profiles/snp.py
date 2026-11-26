"""Pure parser of the AMD SEV-SNP attestation report (spec/enclave-trust.md
section 4.3).

Source: AMD, "SEV Secure Nested Paging Firmware ABI Specification",
publication 56860, the ATTESTATION_REPORT structure table and the guest
policy table; the TCB_VERSION layouts (Milan/Genoa and Turin). Offsets
agree with google/go-sev-guest `abi/abi.go`. Integers are little-endian.

This module checks the layout and the must-be-zero fields only. It does not
check the signature, the certificate chain or any policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import Unverified

REPORT_SIZE = 0x4A0
SIGNATURE_OFFSET = 0x2A0
ECDSA_P384_SHA384 = 1

POLICY_SMT = 16
POLICY_RESERVED_ONE = 17
POLICY_MIGRATE_MA = 18
POLICY_DEBUG = 19
POLICY_SINGLE_SOCKET = 20
POLICY_CXL_ALLOW = 21
POLICY_MEM_AES_256_XTS = 22
POLICY_RAPL_DIS = 23
POLICY_CIPHERTEXT_HIDING = 24
POLICY_PAGE_SWAP_DISABLE = 25

# (CPUID family, model) -> product. Other values are `unknown`.
PRODUCTS = {(0x19, 0x01): "milan", (0x19, 0x11): "genoa", (0x1A, 0x02): "turin"}


class SnpFormatError(Refused):
    """A report that does not follow the layout: `bad_attestation`."""

    def __init__(self, detail: str) -> None:
        super().__init__("bad_attestation", detail)


def _u32(d: bytes, o: int) -> int:
    return int.from_bytes(d[o : o + 4], "little")


def _u64(d: bytes, o: int) -> int:
    return int.from_bytes(d[o : o + 8], "little")


def _mbz(d: bytes, lo: int, hi: int) -> None:
    if any(d[lo:hi]):
        raise SnpFormatError(f"reserved bytes 0x{lo:x}..0x{hi:x} are not zero")


def decode_policy(policy: int) -> JsonObject:
    if not policy >> POLICY_RESERVED_ONE & 1:
        raise SnpFormatError("policy bit 17 must be 1")
    if policy >> 26:
        raise SnpFormatError("policy bits 63:26 must be 0")

    def bit(n: int) -> bool:
        return bool(policy >> n & 1)

    return {
        "abi_major": policy >> 8 & 0xFF,
        "abi_minor": policy & 0xFF,
        "ciphertext_hiding": bit(POLICY_CIPHERTEXT_HIDING),
        "cxl_allow": bit(POLICY_CXL_ALLOW),
        "debug": bit(POLICY_DEBUG),
        "mem_aes_256_xts": bit(POLICY_MEM_AES_256_XTS),
        "migrate_ma": bit(POLICY_MIGRATE_MA),
        "page_swap_disable": bit(POLICY_PAGE_SWAP_DISABLE),
        "rapl_dis": bit(POLICY_RAPL_DIS),
        "single_socket": bit(POLICY_SINGLE_SOCKET),
        "smt": bit(POLICY_SMT),
    }


def decode_tcb(raw: int, product: str) -> JsonObject:
    """TCB_VERSION: Milan and Genoa use bytes 0, 1, 6, 7; Turin adds FMC at
    byte 0 and moves the others."""
    b = raw.to_bytes(8, "little")
    if product in ("milan", "genoa"):
        return {"boot_loader": b[0], "microcode": b[7], "snp": b[6], "tee": b[1]}
    if product == "turin":
        return {"boot_loader": b[1], "fmc": b[0], "microcode": b[7], "snp": b[3], "tee": b[2]}
    raise SnpFormatError(f"unknown product {product!r}")


@dataclass(frozen=True)
class SnpReport:
    version: int
    guest_svn: int
    policy: JsonObject
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: int
    platform_info: int
    author_key_en: bool
    mask_chip_key: bool
    signing_key: int  # 0 = VCEK, 1 = VLEK, 7 = none
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: int
    cpuid: tuple[int, int, int] | None  # (family, model, stepping), version >= 3
    chip_id: bytes
    committed_tcb: int
    current_version: tuple[int, int, int]  # (major, minor, build)
    committed_version: tuple[int, int, int]
    launch_tcb: int
    mit_vectors: tuple[int, int] | None  # (launch, current), version >= 5
    signature_r: bytes  # 72 bytes, little-endian
    signature_s: bytes
    signed_bytes: bytes  # bytes 0x000..0x29F, the signed part

    @property
    def product(self) -> str:
        if self.cpuid is None:
            return "unknown"
        return PRODUCTS.get(self.cpuid[:2], "unknown")


def parse_report(data: bytes) -> SnpReport:
    if len(data) != REPORT_SIZE:
        raise SnpFormatError(f"report size {len(data)}, want {REPORT_SIZE}")
    version = _u32(data, 0x00)
    if version < 2:
        raise SnpFormatError(f"report version {version} is not supported")
    algo = _u32(data, 0x34)
    if algo != ECDSA_P384_SHA384:
        raise SnpFormatError(f"signature algorithm {algo} is not supported")
    signer = _u32(data, 0x48)
    if signer >> 5:
        raise SnpFormatError("bits 31:5 at 0x48 must be 0")
    _mbz(data, 0x4C, 0x50)
    cpuid = None
    if version >= 3:
        fam, mod, step = data[0x188], data[0x189], data[0x18A]
        cpuid = (fam, mod, step)
        _mbz(data, 0x18B, 0x1A0)
    else:
        _mbz(data, 0x188, 0x1A0)
    _mbz(data, 0x1EB, 0x1EC)
    _mbz(data, 0x1EF, 0x1F0)
    mit = None
    if version >= 5:
        mit = (_u64(data, 0x1F8), _u64(data, 0x200))
        _mbz(data, 0x208, SIGNATURE_OFFSET)
    else:
        _mbz(data, 0x1F8, SIGNATURE_OFFSET)
    _mbz(data, SIGNATURE_OFFSET + 144, REPORT_SIZE)
    return SnpReport(
        version=version,
        guest_svn=_u32(data, 0x04),
        policy=decode_policy(_u64(data, 0x08)),
        family_id=data[0x10:0x20],
        image_id=data[0x20:0x30],
        vmpl=_u32(data, 0x30),
        signature_algo=algo,
        current_tcb=_u64(data, 0x38),
        platform_info=_u64(data, 0x40),
        author_key_en=bool(signer & 1),
        mask_chip_key=bool(signer >> 1 & 1),
        signing_key=signer >> 2 & 0x7,
        report_data=data[0x50:0x90],
        measurement=data[0x90:0xC0],
        host_data=data[0xC0:0xE0],
        id_key_digest=data[0xE0:0x110],
        author_key_digest=data[0x110:0x140],
        report_id=data[0x140:0x160],
        report_id_ma=data[0x160:0x180],
        reported_tcb=_u64(data, 0x180),
        cpuid=cpuid,
        chip_id=data[0x1A0:0x1E0],
        committed_tcb=_u64(data, 0x1E0),
        current_version=(data[0x1EA], data[0x1E9], data[0x1E8]),
        committed_version=(data[0x1EE], data[0x1ED], data[0x1EC]),
        launch_tcb=_u64(data, 0x1F0),
        mit_vectors=mit,
        signature_r=data[SIGNATURE_OFFSET : SIGNATURE_OFFSET + 72],
        signature_s=data[SIGNATURE_OFFSET + 72 : SIGNATURE_OFFSET + 144],
        signed_bytes=data[:SIGNATURE_OFFSET],
    )


def claims(report: SnpReport) -> JsonObject:
    """The claims of the `raw-snp` profile (spec section 4.3), as JSON."""
    product = report.product
    return {
        "family_id": report.family_id.hex(),
        "guest_svn": report.guest_svn,
        "host_data": report.host_data.hex(),
        "image_id": report.image_id.hex(),
        "measurement": report.measurement.hex(),
        "policy": report.policy,
        "product": product,
        "report_data": report.report_data.hex(),
        "reported_tcb": decode_tcb(report.reported_tcb, product) if product != "unknown" else None,
        "signing_key": report.signing_key,
        "mask_chip_key": report.mask_chip_key,
        "version": report.version,
        "vmpl": report.vmpl,
    }


# The evidence verifier of the profile: a stub that refuses, so this build
# claims no production profile.
VERIFIER = Unverified(
    "raw-snp",
    "the report parser is here; the VCEK chain, the TCB and the policy checks are not yet",
)
