"""The Intel roots and collateral of TDX evidence (spec/enclave-trust.md
2.6, 4.4, rule 8).

Sources: Intel, "Intel SGX PCK Certificate and Certificate Revocation List
Profile Specification" (the chain, the SGX extensions of the PCK
certificate, the CRLs); Intel, "Intel SGX and TDX PCS API" version 4 and
the "TCB Info" and "Enclave Identity" formats (TDX TCB Info version 3, TD
QE Identity version 2). The TCB level and module identity rules agree with
google/go-tdx-guest `verify/verify.go`.

    Intel SGX Root CA (self-signed, pinned)
     ├─ Intel SGX PCK Platform CA  or  Intel SGX PCK Processor CA
     │   └─ Intel SGX PCK Certificate (one platform at one TCB; signs the QE report)
     └─ Intel SGX TCB Signing (signs TCB Info and QE Identity)

Every certificate and CRL is ECDSA P-256 with SHA-256. The collateral is
JSON that Intel signs over the exact bytes of its body.

Every check is total on untrusted input: it gives `Refused` with a spec
code, never another exception.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import SignatureAlgorithmOID

from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.profiles.amd import (
    _bit_string_unused,
    _cn,
    _ext,
    _load_cert,
    _load_crl,
    untrusted,
)

ROOT_CN = "Intel SGX Root CA"
PCK_CA_CNS = ("Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA")
PCK_CN = "Intel SGX PCK Certificate"
TCB_SIGNING_CN = "Intel SGX TCB Signing"

_SGX = "1.2.840.113741.1.13.1"
OID_SGX_EXTENSIONS = x509.ObjectIdentifier(_SGX)
# The DER AlgorithmIdentifier of ecdsa-with-SHA256 (no parameters). The
# outer copy is outside the signature, so only these exact bytes pass.
_ECDSA_SHA256_ALG = bytes.fromhex("300a06082a8648ce3d040302")

TCB_COMPONENTS = 16
# Intel's TCB status names (TCB Info format). A status outside this list is
# a collateral that this build does not understand.
STATUSES = (
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "Revoked",
)
# No TCB level of the collateral matches the platform.
UNSUPPORTED = "Unsupported"


# --- signatures -------------------------------------------------------------


def _p256(key: object, what: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise Refused("untrusted_root", f"{what}: not a P-256 key")
    return key


def _ecdsa_signed(
    oid: x509.ObjectIdentifier, sig: bytes, tbs: bytes, key: object, what: str, der: bytes
) -> None:
    """ECDSA P-256 SHA-256 by `key` over `tbs`. The outer and inner
    algorithm identifiers must be `_ECDSA_SHA256_ALG` exactly (`der` is the
    whole object: the outer identifier follows `tbs` in it)."""
    if oid != SignatureAlgorithmOID.ECDSA_WITH_SHA256:
        raise Refused("untrusted_root", f"{what}: not ECDSA with SHA-256")
    pub = _p256(key, what)
    at = der.find(tbs)
    outer = der[at + len(tbs) :] if at >= 0 else b""
    if not outer.startswith(_ECDSA_SHA256_ALG + b"\x03") or _ECDSA_SHA256_ALG not in tbs:
        raise Refused("untrusted_root", f"{what}: algorithm identifier")
    if _bit_string_unused(outer[len(_ECDSA_SHA256_ALG) :]) != 0:
        raise Refused("untrusted_root", f"{what}: signature has unused bits")
    try:
        pub.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise Refused("untrusted_root", f"{what}: signature") from exc


def raw_signed(key: ec.EllipticCurvePublicKey, sig: bytes, data: bytes) -> bool:
    """ECDSA P-256 SHA-256 with the signature as 32-byte big-endian r || s
    (the quote, the QE report and the collateral)."""
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def point_key(raw: bytes, what: str) -> ec.EllipticCurvePublicKey:
    """A P-256 key given as 64 bytes x || y."""
    if len(raw) != 64:
        raise Refused("bad_attestation", f"{what} length")
    with untrusted(f"{what} is not a P-256 point"):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw)


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    if cert.issuer != issuer.subject:
        raise Refused("untrusted_root", f"{what}: issuer name")
    _ecdsa_signed(
        cert.signature_algorithm_oid,
        cert.signature,
        cert.tbs_certificate_bytes,
        issuer.public_key(),
        what,
        cert.public_bytes(serialization.Encoding.DER),
    )


# --- DER of the SGX extensions ----------------------------------------------


def _tlv(buf: bytes, at: int) -> tuple[int, bytes, int]:
    """One DER element at `at`: (tag, value, end). Single-byte tags and
    minimal definite lengths only."""
    if at + 2 > len(buf) or buf[at] & 0x1F == 0x1F:
        raise Refused("untrusted_root", "PCK SGX extensions: DER")
    tag, n = buf[at], buf[at + 1]
    head = at + 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 2 or head + k > len(buf) or buf[head] == 0:
            raise Refused("untrusted_root", "PCK SGX extensions: DER length")
        n = int.from_bytes(buf[head : head + k], "big")
        if n < 0x80:
            raise Refused("untrusted_root", "PCK SGX extensions: DER length")
        head += k
    end = head + n
    if end > len(buf):
        raise Refused("untrusted_root", "PCK SGX extensions: DER length")
    return tag, buf[head:end], end


def _items(buf: bytes, tag: int = 0x30) -> list[tuple[int, bytes]]:
    """The elements of a whole DER value of `tag`; nothing may follow."""
    t, value, end = _tlv(buf, 0)
    if t != tag or end != len(buf):
        raise Refused("untrusted_root", "PCK SGX extensions: structure")
    out, at = [], 0
    while at < len(value):
        t, v, at = _tlv(value, at)
        out.append((t, v))
    return out


def _oid(value: bytes) -> str:
    if not value or value[-1] & 0x80:
        raise Refused("untrusted_root", "PCK SGX extensions: OID")
    arcs, n = [], 0
    for i, byte in enumerate(value):
        if n == 0 and byte == 0x80 and (i == 0 or not value[i - 1] & 0x80):
            raise Refused("untrusted_root", "PCK SGX extensions: OID")
        n = n << 7 | byte & 0x7F
        if not byte & 0x80:
            arcs.append(n)
            n = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first, *arcs[1:]])


def _uint(tag: int, value: bytes, hi: int, what: str) -> int:
    if (
        tag not in (0x02, 0x0A)
        or not value
        or value[0] & 0x80
        or (len(value) > 1 and value[0] == 0 and not value[1] & 0x80)
    ):
        raise Refused("untrusted_root", f"PCK {what}")
    v = int.from_bytes(value, "big")
    if v > hi:
        raise Refused("untrusted_root", f"PCK {what}")
    return v


def _pairs(items: list[tuple[int, bytes]], prefix: str, what: str) -> dict[str, tuple[int, bytes]]:
    """`SEQUENCE { OID, value }` items keyed by the OID's last arcs; each
    OID once, and each under `prefix`."""
    out: dict[str, tuple[int, bytes]] = {}
    for tag, body in items:
        if tag != 0x30:
            raise Refused("untrusted_root", f"PCK {what}: structure")
        pair = _items(bytes([0x30, *_der_len(len(body))]) + body)
        if len(pair) != 2 or pair[0][0] != 0x06:
            raise Refused("untrusted_root", f"PCK {what}: structure")
        oid = _oid(pair[0][1])
        name = oid[len(prefix) + 1 :]
        if not oid.startswith(prefix + ".") or name in out:
            raise Refused("untrusted_root", f"PCK {what}: OID {oid}")
        out[name] = pair[1]
    return out


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body), *body])


@dataclass(frozen=True)
class Pck:
    """What the PCK certificate says about its platform."""

    cpu_svn: tuple[int, ...]  # the 16 SGX TCB component SVNs
    pce_svn: int
    pce_id: bytes
    fmspc: bytes


def pck_extensions(leaf: x509.Certificate) -> Pck:
    """The SGX extensions of the PCK certificate (Intel's PCK profile)."""
    raw = _ext(leaf, OID_SGX_EXTENSIONS)
    if raw is None:
        raise Refused("untrusted_root", "PCK has no SGX extensions")
    top = _pairs(_items(raw), _SGX, "SGX extensions")
    allowed = {"1", "2", "3", "4", "5", "6", "7"}
    if not {"1", "2", "3", "4", "5"} <= set(top) <= allowed:
        raise Refused("untrusted_root", "PCK SGX extensions: fields")

    def octets(name: str, n: int, what: str) -> bytes:
        tag, value = top[name]
        if tag != 0x04 or len(value) != n:
            raise Refused("untrusted_root", f"PCK {what}")
        return value

    octets("1", 16, "PPID")
    tag, body = top["2"]
    if tag != 0x30:
        raise Refused("untrusted_root", "PCK TCB: structure")
    tcb = _pairs(_items(bytes([0x30, *_der_len(len(body))]) + body), _SGX + ".2", "TCB")
    if set(tcb) != {str(i) for i in range(1, 19)}:
        raise Refused("untrusted_root", "PCK TCB: fields")
    comps = tuple(_uint(*tcb[str(i)], 255, f"TCB component {i}") for i in range(1, 17))
    pce_svn = _uint(*tcb["17"], 0xFFFF, "PCESVN")
    cpu_tag, cpu = tcb["18"]
    if cpu_tag != 0x04 or len(cpu) != 16 or tuple(cpu) != comps:
        raise Refused("untrusted_root", "PCK CPUSVN")
    _uint(*top["5"], 2, "SGX type")  # Standard, Scalable, ScalableWithIntegrity
    return Pck(
        cpu_svn=comps,
        pce_svn=pce_svn,
        pce_id=octets("3", 2, "PCE-ID"),
        fmspc=octets("4", 6, "FMSPC"),
    )


# --- the chain and the CRLs ---------------------------------------------------


@dataclass(frozen=True)
class Chain:
    leaf_key: ec.EllipticCurvePublicKey
    tcb_signing_key: ec.EllipticCurvePublicKey
    pck: Pck
    valid_until: int  # the earliest next update or expiry of the chain and CRLs


_PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+?)\n-----END CERTIFICATE-----\n"
)


def pem_chain(data: bytes) -> list[bytes]:
    """The DER certificates of the PCK chain in the quote (certification
    data type 5): PEM blocks back to back, and at most one NUL after them."""
    if data.endswith(b"\x00"):
        data = data[:-1]
    out, at = [], 0
    while at < len(data):
        m = _PEM.match(data, at)
        if m is None:
            raise Refused("bad_attestation", "PCK chain is not PEM")
        with untrusted("PCK chain base64"):
            out.append(base64.b64decode(m[1].replace(b"\n", b""), validate=True))
        at = m.end()
    return out


def _unix(t: dt.datetime | None, what: str) -> int:
    if t is None:
        raise Refused("bad_attestation", f"{what} has no next update")
    return int(t.timestamp())


def _check_crl(crl_der: bytes, issuer: x509.Certificate, serials: dict[str, int], what: str) -> int:
    """`crl_der` is signed by `issuer` and revokes none of `serials`.
    Return its next update."""
    crl = _load_crl(crl_der)
    if crl.issuer != issuer.subject:
        raise Refused("untrusted_root", f"{what}: issuer name")
    _ecdsa_signed(
        crl.signature_algorithm_oid,
        crl.signature,
        crl.tbs_certlist_bytes,
        issuer.public_key(),
        what,
        crl.public_bytes(serialization.Encoding.DER),
    )
    next_update = _unix(crl.next_update_utc, what)
    for name, serial in serials.items():
        if crl.get_revoked_certificate_by_serial_number(serial) is not None:
            raise Refused("cert_revoked", f"{name} is on the {what}")
    return next_update


def verify_chain(
    chain_der: list[bytes],
    tcb_signing_der: bytes,
    root_crl_der: bytes,
    pck_crl_der: bytes,
    pin: str,
) -> Chain:
    """Rule 8, the certificates (spec section 4.4, steps 2 to 5)."""
    with untrusted("intel chain"):
        if len(chain_der) != 3:
            raise Refused("untrusted_root", "PCK chain is not leaf, CA, root")
        leaf_der, ca_der, root_der = chain_der
        # Step 2: the root is the pinned Intel SGX Root CA.
        if hashlib.sha256(root_der).hexdigest() != pin:
            raise Refused("untrusted_root", "root is not the pinned Intel SGX Root CA")
        root = _load_cert(root_der, "root")
        ca = _load_cert(ca_der, "PCK CA")
        leaf = _load_cert(leaf_der, "PCK")
        signer = _load_cert(tcb_signing_der, "TCB signing certificate")
        # Step 3: names and signatures.
        if _cn(root.subject) != ROOT_CN or _cn(ca.subject) not in PCK_CA_CNS:
            raise Refused("untrusted_root", "chain names")
        if _cn(leaf.subject) != PCK_CN or _cn(signer.subject) != TCB_SIGNING_CN:
            raise Refused("untrusted_root", "leaf or TCB signing name")
        _issued_by(root, root, "root")
        _issued_by(ca, root, "PCK CA")
        _issued_by(leaf, ca, "PCK")
        _issued_by(signer, root, "TCB signing certificate")
        leaf_key = _p256(leaf.public_key(), "PCK")
        signer_key = _p256(signer.public_key(), "TCB signing certificate")
        # Step 4: the platform the PCK certifies.
        pck = pck_extensions(leaf)
        # Step 5: revocation (the root's CRL for the CAs, the CA's for the PCK).
        until = [
            _check_crl(
                root_crl_der,
                root,
                {"PCK CA": ca.serial_number, "TCB signing certificate": signer.serial_number},
                "root CRL",
            ),
            _check_crl(pck_crl_der, ca, {"PCK": leaf.serial_number}, "PCK CRL"),
        ]
        until += [int(c.not_valid_after_utc.timestamp()) for c in (root, ca, leaf, signer)]
        return Chain(leaf_key, signer_key, pck, min(until))


# --- signed collateral --------------------------------------------------------

_SIGNED = re.compile(
    rb'\A\{"(tcbInfo|enclaveIdentity)":(\{.*\}),"signature":"([0-9a-f]{128})"\}\Z', re.S
)
_TIME = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise Refused("bad_attestation", "collateral has a duplicate name")
    return out


def _no_constant(name: str) -> None:
    raise Refused("bad_attestation", f"collateral has {name}")


def signed_json(
    raw: bytes, field: str, key: ec.EllipticCurvePublicKey, what: str
) -> dict[str, Any]:
    """Intel's `{"<field>": {...}, "signature": "<r || s hex>"}` as PCS
    serves it: the signature is over the exact bytes of the body."""
    m = _SIGNED.match(raw)
    if m is None or m[1].decode() != field:
        raise Refused("bad_attestation", f"{what} form")
    if not raw_signed(key, bytes.fromhex(m[3].decode()), m[2]):
        raise Refused("untrusted_root", f"{what} signature")
    try:
        body = json.loads(m[2], object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        raise Refused("bad_attestation", f"{what} is not JSON") from exc
    if not isinstance(body, dict):
        raise Refused("bad_attestation", f"{what} form")
    return body


def _field(obj: object, name: str, kind: type, what: str) -> Any:
    value = obj.get(name) if isinstance(obj, dict) else None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise Refused("bad_attestation", f"{what}.{name}")
    return value


def _hex(obj: object, name: str, n: int, what: str) -> bytes:
    value = _field(obj, name, str, what)
    if not re.fullmatch(r"[0-9a-fA-F]*", value) or len(value) != 2 * n:
        raise Refused("bad_attestation", f"{what}.{name}")
    return bytes.fromhex(value)


def _time(obj: object, name: str, what: str) -> int:
    value = _field(obj, name, str, what)
    if not _TIME.match(value):
        raise Refused("bad_attestation", f"{what}.{name}")
    try:
        return int(
            dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC).timestamp()
        )
    except ValueError as exc:
        raise Refused("bad_attestation", f"{what}.{name}") from exc


def _svn(obj: object, name: str, hi: int, what: str) -> int:
    value: int = _field(obj, name, int, what)
    if not 0 <= value <= hi:
        raise Refused("bad_attestation", f"{what}.{name}")
    return value


def _status(level: object, what: str) -> str:
    value: str = _field(level, "tcbStatus", str, what)
    if value not in STATUSES:
        raise Refused("bad_attestation", f"{what}.tcbStatus {value!r}")
    return value


def _advisories(level: object, what: str) -> list[str]:
    value = level.get("advisoryIDs", []) if isinstance(level, dict) else None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise Refused("bad_attestation", f"{what}.advisoryIDs")
    return sorted(value)


@dataclass(frozen=True)
class Identity:
    """An identity (TDX module or quoting enclave) to match against."""

    mrsigner: bytes
    attributes: bytes
    attributes_mask: bytes


def _identity(obj: object, size: int, what: str) -> Identity:
    return Identity(
        mrsigner=_hex(obj, "mrsigner", 48, what),
        attributes=_hex(obj, "attributes", size, what),
        attributes_mask=_hex(obj, "attributesMask", size, what),
    )


def masked_equal(value: bytes, ident: Identity) -> bool:
    got = bytes(a & b for a, b in zip(value, ident.attributes_mask, strict=True))
    want = bytes(a & b for a, b in zip(ident.attributes, ident.attributes_mask, strict=True))
    return got == want


@dataclass(frozen=True)
class TcbResult:
    tcb_status: str
    tdx_module_status: str
    advisory_ids: list[str]
    evaluation_data_number: int
    next_update: int


def tdx_tcb(
    raw: bytes,
    key: ec.EllipticCurvePublicKey,
    pck: Pck,
    tee_tcb_svn: bytes,
    mr_signer_seam: bytes,
    seam_attributes: bytes,
) -> TcbResult:
    """TDX TCB Info version 3 (rule 8: signed by Intel, for this platform,
    and the TDX module is Intel's; rule 2: the matching TCB level)."""
    w = "tcb_info"
    info = signed_json(raw, "tcbInfo", key, w)
    if _field(info, "id", str, w) != "TDX" or _field(info, "version", int, w) != 3:
        raise Refused("bad_attestation", "tcb_info is not TDX TCB Info version 3")
    if _field(info, "tcbType", int, w) != 0:
        raise Refused("bad_attestation", "tcb_info.tcbType")
    if _hex(info, "fmspc", 6, w) != pck.fmspc or _hex(info, "pceId", 2, w) != pck.pce_id:
        raise Refused("untrusted_root", "tcb_info is for another platform")
    number = _svn(info, "tcbEvaluationDataNumber", 2**32 - 1, w)
    next_update = _time(info, "nextUpdate", w)
    _time(info, "issueDate", w)
    # The TDX module is Intel's (MRSIGNERSEAM and SEAMATTRIBUTES).
    module = _identity(_field(info, "tdxModule", dict, w), 8, f"{w}.tdxModule")
    if module.mrsigner != mr_signer_seam or not masked_equal(seam_attributes, module):
        raise Refused("untrusted_root", "the TDX module is not the one in tcb_info")
    levels = _field(info, "tcbLevels", list, w)
    if not levels:
        raise Refused("bad_attestation", "tcb_info.tcbLevels")
    tcb_status, advisories = UNSUPPORTED, []
    for i, level in enumerate(levels):
        lw = f"{w}.tcbLevels[{i}]"
        tcb = _field(level, "tcb", dict, lw)
        sgx = _components(tcb, "sgxtcbcomponents", lw)
        tdx = _components(tcb, "tdxtcbcomponents", lw)
        pce = _svn(tcb, "pcesvn", 0xFFFF, lw)
        status = _status(level, lw)
        found = _advisories(level, lw)
        if tcb_status != UNSUPPORTED:
            continue  # the rest is checked for form only
        start = 2 if tee_tcb_svn[1] > 0 else 0
        if (
            all(a >= b for a, b in zip(pck.cpu_svn, sgx, strict=True))
            and pck.pce_svn >= pce
            and all(tee_tcb_svn[j] >= tdx[j] for j in range(start, TCB_COMPONENTS))
        ):
            tcb_status, advisories = status, found
    module_status = "UpToDate"
    if tee_tcb_svn[1] > 0:
        module_status, more = _module_status(info, tee_tcb_svn, mr_signer_seam, seam_attributes)
        advisories = sorted(set(advisories) | set(more))
    return TcbResult(tcb_status, module_status, advisories, number, next_update)


def _components(tcb: object, name: str, what: str) -> tuple[int, ...]:
    comps = _field(tcb, name, list, what)
    if len(comps) != TCB_COMPONENTS:
        raise Refused("bad_attestation", f"{what}.{name}")
    return tuple(_svn(c, "svn", 255, f"{what}.{name}") for c in comps)


def _module_status(
    info: dict[str, Any], tee_tcb_svn: bytes, mr_signer_seam: bytes, seam_attributes: bytes
) -> tuple[str, list[str]]:
    """The TDX module identity `TDX_<TEE_TCB_SVN[1] as 2 hex>` and its
    first TCB level with `isvsvn <= TEE_TCB_SVN[0]`."""
    w = "tcb_info.tdxModuleIdentities"
    want = f"TDX_{tee_tcb_svn[1]:02X}"
    found = [
        m
        for m in _field(info, "tdxModuleIdentities", list, "tcb_info")
        if isinstance(m, dict) and isinstance(m.get("id"), str) and m["id"].upper() == want
    ]
    if len(found) != 1:
        return UNSUPPORTED, []
    ident = _identity(found[0], 8, f"{w}[{want}]")
    if ident.mrsigner != mr_signer_seam or not masked_equal(seam_attributes, ident):
        raise Refused("untrusted_root", f"the TDX module is not {want} of tcb_info")
    for i, level in enumerate(_field(found[0], "tcbLevels", list, f"{w}[{want}]")):
        lw = f"{w}[{want}].tcbLevels[{i}]"
        if tee_tcb_svn[0] >= _svn(_field(level, "tcb", dict, lw), "isvsvn", 255, lw):
            return _status(level, lw), _advisories(level, lw)
    return UNSUPPORTED, []


# --- the TD quoting enclave ---------------------------------------------------


@dataclass(frozen=True)
class QeReport:
    """The SGX report of the quoting enclave (384 bytes)."""

    miscselect: bytes
    attributes: bytes
    mrsigner: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes

    @classmethod
    def parse(cls, raw: bytes) -> QeReport:
        if len(raw) != 384:
            raise Refused("bad_attestation", "QE report length")
        return cls(
            miscselect=raw[16:20],
            attributes=raw[48:64],
            mrsigner=raw[128:160],
            isv_prod_id=int.from_bytes(raw[256:258], "little"),
            isv_svn=int.from_bytes(raw[258:260], "little"),
            report_data=raw[320:384],
        )


@dataclass(frozen=True)
class QeResult:
    status: str
    advisory_ids: list[str]
    evaluation_data_number: int
    next_update: int


def td_qe(raw: bytes, key: ec.EllipticCurvePublicKey, report: QeReport) -> QeResult:
    """TD QE Identity version 2 (rule 8: signed by Intel, and the quoting
    enclave is Intel's; rule 2: its TCB level)."""
    w = "qe_identity"
    ident = signed_json(raw, "enclaveIdentity", key, w)
    if _field(ident, "id", str, w) != "TD_QE" or _field(ident, "version", int, w) != 2:
        raise Refused("bad_attestation", "qe_identity is not TD QE Identity version 2")
    number = _svn(ident, "tcbEvaluationDataNumber", 2**32 - 1, w)
    next_update = _time(ident, "nextUpdate", w)
    _time(ident, "issueDate", w)
    misc = Identity(b"", _hex(ident, "miscselect", 4, w), _hex(ident, "miscselectMask", 4, w))
    attrs = Identity(b"", _hex(ident, "attributes", 16, w), _hex(ident, "attributesMask", 16, w))
    if (
        report.mrsigner != _hex(ident, "mrsigner", 32, w)
        or report.isv_prod_id != _svn(ident, "isvprodid", 0xFFFF, w)
        or not masked_equal(report.miscselect, misc)
        or not masked_equal(report.attributes, attrs)
    ):
        raise Refused("untrusted_root", "the quoting enclave is not the one in qe_identity")
    status, advisories = UNSUPPORTED, []
    for i, level in enumerate(_field(ident, "tcbLevels", list, w)):
        lw = f"{w}.tcbLevels[{i}]"
        isvsvn = _svn(_field(level, "tcb", dict, lw), "isvsvn", 0xFFFF, lw)
        got, found = _status(level, lw), _advisories(level, lw)
        if status == UNSUPPORTED and report.isv_svn >= isvsvn:
            status, advisories = got, found
    return QeResult(status, advisories, number, next_update)
