"""Pure parser of the Intel TDX quote, version 4 (spec/enclave-trust.md
section 4.4).

Source: Intel, "Intel TDX DCAP Quoting Library API", the Quote Format
(version 4) appendix: the 48-byte header, the 584-byte TD quote body
(TD10_REPORT fields), and the signature data. The TD attribute bits follow
the Intel TDX module ABI specification (DEBUG bit 0, SEPT_VE_DISABLE bit
28, MIGRATABLE bit 29, PKS bit 30, KL bit 31, PERFMON bit 63). Offsets
agree with google/go-tdx-guest `abi/abi.go`. Integers are little-endian.

This module checks the layout only. It does not check the ECDSA signature,
the QE report, the PCK certificate chain, or any policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import Unverified

HEADER_SIZE = 0x30
BODY_SIZE = 0x248
QUOTE_VERSION = 4
ATT_KEY_ECDSA_P256 = 2
TEE_TDX = 0x00000081
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")

ATTR_DEBUG = 0
ATTR_SEPT_VE_DISABLE = 28
ATTR_MIGRATABLE = 29
ATTR_PKS = 30
ATTR_KL = 31
ATTR_PERFMON = 63

BODY_FIELDS = (  # name, size; in order from offset 0 of the body
    ("tee_tcb_svn", 16),
    ("mr_seam", 48),
    ("mr_signer_seam", 48),
    ("seam_attributes", 8),
    ("td_attributes", 8),
    ("xfam", 8),
    ("mr_td", 48),
    ("mr_config_id", 48),
    ("mr_owner", 48),
    ("mr_owner_config", 48),
    ("rtmr0", 48),
    ("rtmr1", 48),
    ("rtmr2", 48),
    ("rtmr3", 48),
    ("report_data", 64),
)


class TdxFormatError(Refused):
    """A report that does not follow the layout: `bad_attestation`."""

    def __init__(self, detail: str) -> None:
        super().__init__("bad_attestation", detail)


def decode_attributes(raw: bytes) -> JsonObject:
    v = int.from_bytes(raw, "little")

    def bit(n: int) -> bool:
        return bool(v >> n & 1)

    return {
        "debug": bit(ATTR_DEBUG),
        "kl": bit(ATTR_KL),
        "migratable": bit(ATTR_MIGRATABLE),
        "perfmon": bit(ATTR_PERFMON),
        "pks": bit(ATTR_PKS),
        "sept_ve_disable": bit(ATTR_SEPT_VE_DISABLE),
    }


@dataclass(frozen=True)
class TdxQuote:
    version: int
    att_key_type: int
    tee_type: int
    qe_vendor_id: bytes
    user_data: bytes
    body: dict[str, bytes]
    signature: bytes  # 64 bytes, ECDSA P-256 r || s
    attestation_key: bytes  # 64 bytes, P-256 x || y
    cert_data_type: int
    cert_data: bytes
    signed_bytes: bytes  # header || body: the bytes the attestation key signs


def parse_quote(data: bytes) -> TdxQuote:
    if len(data) < HEADER_SIZE + BODY_SIZE + 4 + 128 + 6:
        raise TdxFormatError("quote is too short")
    version = int.from_bytes(data[0:2], "little")
    key_type = int.from_bytes(data[2:4], "little")
    tee_type = int.from_bytes(data[4:8], "little")
    if version != QUOTE_VERSION:
        raise TdxFormatError(f"quote version {version} is not supported")
    if key_type != ATT_KEY_ECDSA_P256:
        raise TdxFormatError(f"attestation key type {key_type} is not supported")
    if tee_type != TEE_TDX:
        raise TdxFormatError(f"TEE type 0x{tee_type:x} is not TDX")
    body: dict[str, bytes] = {}
    o = HEADER_SIZE
    for name, size in BODY_FIELDS:
        body[name] = data[o : o + size]
        o += size
    sig_len = int.from_bytes(data[o : o + 4], "little")
    sig = data[o + 4 :]
    if len(sig) != sig_len or sig_len < 128 + 6:
        raise TdxFormatError("signature data length does not match")
    cert_type = int.from_bytes(sig[128:130], "little")
    cert_size = int.from_bytes(sig[130:134], "little")
    if 134 + cert_size != sig_len:
        raise TdxFormatError("certification data length does not match")
    return TdxQuote(
        version=version,
        att_key_type=key_type,
        tee_type=tee_type,
        qe_vendor_id=data[12:28],
        user_data=data[28:48],
        body=body,
        signature=sig[0:64],
        attestation_key=sig[64:128],
        cert_data_type=cert_type,
        cert_data=sig[134:],
        signed_bytes=data[: HEADER_SIZE + BODY_SIZE],
    )


def claims(quote: TdxQuote) -> JsonObject:
    """The claims of the `raw-tdx` profile (spec section 4.4), as JSON."""
    out: JsonObject = {name: value.hex() for name, value in quote.body.items()}
    out["td_attributes_bits"] = decode_attributes(quote.body["td_attributes"])
    out["qe_vendor_id"] = quote.qe_vendor_id.hex()
    out["cert_data_type"] = quote.cert_data_type
    return out


# The evidence verifier of the profile: a stub that refuses, so this build
# claims no production profile.
VERIFIER = Unverified(
    "raw-tdx",
    "the quote parser is here; the PCK chain, the QE report and the policy checks are not yet",
)
