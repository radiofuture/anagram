"""Pure parser of the Intel TDX quote, version 4 (spec/enclave-trust.md
section 4.4).

Source: Intel, "Intel TDX DCAP Quoting Library API", the Quote Format
(version 4) appendix: the 48-byte header, the 584-byte TD quote body
(TD10_REPORT fields), and the signature data. The TD attribute bits follow
the Intel TDX module ABI specification (DEBUG bit 0, SEPT_VE_DISABLE bit
28, MIGRATABLE bit 29, PKS bit 30, KL bit 31, PERFMON bit 63). Offsets
agree with google/go-tdx-guest `abi/abi.go`. Integers are little-endian.

`parse_quote` and `claims` check the layout only. `tdx_claims` is the
evidence step of the `raw-tdx` profile (rule 8): the quote and QE report
signatures, the PCK chain to the pinned Intel root, the CRLs and Intel's
collateral (`profiles/intel.py`).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles import Claims, evidence_object, intel
from anagram.network.matching.trust.roots import Roots

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


CERT_DATA_PCK_CHAIN = 5
CERT_DATA_QE_REPORT = 6
EVIDENCE_FIELDS = frozenset(
    {"pck_crl", "qe_identity", "quote", "root_crl", "tcb_info", "tcb_signing"}
)
TCB_REQUIRED = (
    "qe_tcb_status",
    "tcb_evaluation_data_number",
    "tcb_status",
    "tdx_module_tcb_status",
)
REFERENCE_FIELDS = (
    "mr_config_id",
    "mr_owner",
    "mr_owner_config",
    "mr_td",
    "rtmr0",
    "rtmr1",
    "rtmr2",
    "rtmr3",
    "xfam",
)


@dataclass(frozen=True)
class QeCertData:
    """Certification data type 6: the QE report, its signature by the PCK
    key, the QE authentication data and the PCK chain (type 5)."""

    qe_report: bytes
    qe_report_signature: bytes
    auth_data: bytes
    pck_chain: bytes


def parse_qe_cert_data(quote: TdxQuote) -> QeCertData:
    if quote.cert_data_type != CERT_DATA_QE_REPORT:
        raise TdxFormatError(f"certification data type {quote.cert_data_type} is not 6")
    raw = quote.cert_data
    if len(raw) < 384 + 64 + 2:
        raise TdxFormatError("QE certification data is too short")
    auth_len = int.from_bytes(raw[448:450], "little")
    at = 450 + auth_len
    if len(raw) < at + 6:
        raise TdxFormatError("QE authentication data length does not match")
    inner_type = int.from_bytes(raw[at : at + 2], "little")
    inner_size = int.from_bytes(raw[at + 2 : at + 6], "little")
    if inner_type != CERT_DATA_PCK_CHAIN:
        raise TdxFormatError(f"inner certification data type {inner_type} is not 5")
    if at + 6 + inner_size != len(raw):
        raise TdxFormatError("PCK chain length does not match")
    return QeCertData(raw[0:384], raw[384:448], raw[450:at], raw[at + 6 :])


def _decode(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise Refused("bad_attestation", f"{what} form")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise Refused("bad_attestation", f"{what} is not base64") from exc


def tdx_claims(platform_evidence: object, gpu_evidence: object, roots: Roots) -> Claims:
    """Rule 8 of the `raw-tdx` profile (spec section 4.4, steps 1 to 9),
    then the claims that the other rules check."""
    ev = evidence_object(platform_evidence, "platform_evidence")
    if set(ev) != EVIDENCE_FIELDS:
        raise Refused("bad_attestation", "platform_evidence fields")
    if gpu_evidence is not None:
        raise Refused("bad_attestation", "raw-tdx has no GPU evidence")
    raw = {name: _decode(ev[name], name) for name in sorted(EVIDENCE_FIELDS)}
    # Step 1: the quote and its certification data.
    quote = parse_quote(raw["quote"])
    if quote.qe_vendor_id != INTEL_QE_VENDOR_ID:
        raise TdxFormatError("QE vendor is not Intel")
    qe = parse_qe_cert_data(quote)
    # Steps 2 to 5: the certificates, the PCK's platform and the CRLs.
    chain = intel.verify_chain(
        intel.pem_chain(qe.pck_chain),
        raw["tcb_signing"],
        raw["root_crl"],
        raw["pck_crl"],
        roots.intel_root,
    )
    # Step 6: the PCK key signs the QE report.
    if not intel.raw_signed(chain.leaf_key, qe.qe_report_signature, qe.qe_report):
        raise Refused("untrusted_root", "QE report signature")
    report = intel.QeReport.parse(qe.qe_report)
    # Step 7: the quoting enclave is Intel's (QE Identity), and its level.
    qe_tcb = intel.td_qe(raw["qe_identity"], chain.tcb_signing_key, report)
    # Step 8: the QE report binds the attestation key.
    bound = hashlib.sha256(quote.attestation_key + qe.auth_data).digest() + bytes(32)
    if report.report_data != bound:
        raise Refused("untrusted_root", "QE report does not bind the attestation key")
    # Step 9: the attestation key signs the header and the body.
    att_key = intel.point_key(quote.attestation_key, "attestation key")
    if not intel.raw_signed(att_key, quote.signature, quote.signed_bytes):
        raise Refused("untrusted_root", "quote signature")
    # Step 10: TCB Info for this platform, the TDX module, the TCB level.
    body = quote.body
    tcb = intel.tdx_tcb(
        raw["tcb_info"],
        chain.tcb_signing_key,
        chain.pck,
        body["tee_tcb_svn"],
        body["mr_signer_seam"],
        body["seam_attributes"],
    )
    attrs = decode_attributes(body["td_attributes"])
    data = body["report_data"]
    cpu: JsonObject = {
        "advisory_ids": sorted(set(tcb.advisory_ids) | set(qe_tcb.advisory_ids)),
        "debug": attrs["debug"],
        "fmspc": chain.pck.fmspc.hex(),
        "migratable": attrs["migratable"],
        "mr_seam": body["mr_seam"].hex(),
        "reference": {name: body[name].hex() for name in REFERENCE_FIELDS},
        "report_data": data[:32].hex() if data[32:] == bytes(32) else data.hex(),
        "tcb": {
            "qe_tcb_status": qe_tcb.status,
            "tcb_evaluation_data_number": min(
                tcb.evaluation_data_number, qe_tcb.evaluation_data_number
            ),
            "tcb_status": tcb.tcb_status,
            "tdx_module_tcb_status": tcb.tdx_module_status,
        },
        "tcb_required": list(TCB_REQUIRED),
        "td_attributes": attrs,
        "tee_tcb_svn": body["tee_tcb_svn"].hex(),
        "valid_from": chain.valid_from,
        "valid_until": min(chain.valid_until, tcb.next_update, qe_tcb.next_update),
    }
    return Claims(cpu=cpu, gpu=None)


@dataclass(frozen=True)
class TdxEvidence:
    """The evidence verifier of the `raw-tdx` profile."""

    profile: str = "raw-tdx"
    reason: str = "Intel TDX: the quote, the PCK chain to the pinned Intel root, its CRLs and Intel's collateral"
    available: bool = True

    def claims(self, doc: JsonObject, roots: Roots) -> Claims:
        return tdx_claims(doc["platform_evidence"], doc["gpu_evidence"], roots)


VERIFIER = TdxEvidence()
