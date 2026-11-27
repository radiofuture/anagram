"""The AMD certificate chain of SEV-SNP evidence (spec/enclave-trust.md 2.6,
4.3, rule 8).

Source: AMD, "Versioned Chip Endorsement Key (VCEK) Certificate and KDS
Interface Specification", publication 57230; the certificates and CRLs
that AMD's Key Distribution Service (kdsintf.amd.com) serves. Extension
OIDs agree with google/go-sev-guest `kds/kds.go`.

    ARK (AMD Root Key, self-signed, pinned)
     └─ ASK  (VCEK chain: CN "SEV-<Product>")       or ASVK (VLEK chain: CN "SEV-VLEK-<Product>")
         └─ VCEK (one chip at one TCB; hwID = CHIP_ID)  or VLEK (one cloud provider; csp_id)

Every certificate and the CRL are RSASSA-PSS with SHA-384 (MGF1 SHA-384,
salt 48). The leaf key is ECDSA P-384; it signs the report.

Every check is total on untrusted input: it gives `Refused` with a spec
code, never another exception.
"""

from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

from anagram.network.formats.strict import Refused

_AMD = "1.3.6.1.4.1.3704.1."
OID_PRODUCT_NAME = x509.ObjectIdentifier(_AMD + "2")
OID_HWID = x509.ObjectIdentifier(_AMD + "4")
OID_CSP_ID = x509.ObjectIdentifier(_AMD + "5")
# TCB component -> SPL extension of the leaf (publication 57230).
SPL_OIDS: dict[str, x509.ObjectIdentifier] = {
    "boot_loader": x509.ObjectIdentifier(_AMD + "3.1"),
    "tee": x509.ObjectIdentifier(_AMD + "3.2"),
    "snp": x509.ObjectIdentifier(_AMD + "3.3"),
    "microcode": x509.ObjectIdentifier(_AMD + "3.8"),
}
# The FMC SPL extension of a Turin leaf is not confirmed (spec section 10,
# item 1). Until it is, a Turin leaf is refused: without it, a leaf for a
# lower FMC could sign a report that claims a higher one.
TURIN_FMC_OID: x509.ObjectIdentifier | None = None

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
PRODUCTS = ("milan", "genoa", "turin")
VCEK, VLEK = 0, 1


def _load_cert(der: bytes, what: str) -> x509.Certificate:
    try:
        with warnings.catch_warnings():
            # AMD issues VCEKs with serial 0, which cryptography warns about.
            warnings.simplefilter("ignore")
            return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise Refused("bad_attestation", f"{what} is not a DER certificate") from exc


def _load_crl(der: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_der_x509_crl(der)
    except ValueError as exc:
        raise Refused("bad_attestation", "crl is not a DER CRL") from exc


def _cn(name: x509.Name) -> str:
    got = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(got[0].value) if len(got) == 1 else ""


def _pss_signed(oid: x509.ObjectIdentifier, sig: bytes, tbs: bytes, key: object, what: str) -> None:
    """RSASSA-PSS SHA-384 by `key`, whatever parameters the object claims."""
    if oid != SignatureAlgorithmOID.RSASSA_PSS or not isinstance(key, rsa.RSAPublicKey):
        raise Refused("untrusted_root", f"{what}: not RSASSA-PSS")
    try:
        key.verify(sig, tbs, _PSS, hashes.SHA384())
    except InvalidSignature as exc:
        raise Refused("untrusted_root", f"{what}: signature") from exc


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    if cert.issuer != issuer.subject:
        raise Refused("untrusted_root", f"{what}: issuer name")
    _pss_signed(
        cert.signature_algorithm_oid,
        cert.signature,
        cert.tbs_certificate_bytes,
        issuer.public_key(),
        what,
    )


def _ext(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bytes | None:
    try:
        value = cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    raw = getattr(value, "value", None)
    return raw if isinstance(raw, bytes) else None


def _der_small_int(raw: bytes | None, what: str) -> int:
    """A DER INTEGER of 0 to 255 (the SPL extensions)."""
    if raw is None or len(raw) < 3 or raw[0] != 0x02 or raw[1] != len(raw) - 2 or raw[1] > 2:
        raise Refused("untrusted_root", f"leaf {what} extension")
    value = int.from_bytes(raw[2:], "big", signed=True)
    if not 0 <= value <= 255:
        raise Refused("untrusted_root", f"leaf {what} extension")
    return value


def _der_string(raw: bytes | None, what: str) -> str:
    """A short DER IA5String or UTF8String (product name, csp_id)."""
    if raw is None or len(raw) < 2 or raw[0] not in (0x0C, 0x16) or raw[1] != len(raw) - 2:
        raise Refused("untrusted_root", f"leaf {what} extension")
    try:
        return raw[2:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("untrusted_root", f"leaf {what} extension") from exc


def leaf_product(leaf_der: bytes) -> str:
    """The product that the leaf names (`Milan-B0` gives `milan`), or ""."""
    name = _der_string(_ext(_load_cert(leaf_der, "leaf"), OID_PRODUCT_NAME), "product name")
    product = name.split("-", 1)[0].lower()
    return product if product in PRODUCTS else ""


@dataclass(frozen=True)
class Chain:
    """A chain that passed: the leaf key, its TCB, and what the CRL says."""

    leaf_key: ec.EllipticCurvePublicKey
    spl: dict[str, int]  # TCB component -> SPL of the leaf
    hwid: bytes | None  # VCEK only
    csp_id: str | None  # VLEK only
    crl_next_update: int  # Unix seconds


def verify_chain(
    product: str,
    signing_key: int,
    ark_der: bytes,
    ask_der: bytes,
    leaf_der: bytes,
    crl_der: bytes,
    pins: tuple[tuple[str, str], ...],
) -> Chain:
    """Rule 8 for an AMD chain: the pinned ARK, ARK -> ASK (or ASVK) ->
    leaf, the leaf kind that `signing_key` names, and the ARK's CRL."""
    pinned = dict(pins).get(product)
    if pinned is None or hashlib.sha256(ark_der).hexdigest() != pinned:
        raise Refused("untrusted_root", f"ARK is not the pinned ARK of {product}")
    ark = _load_cert(ark_der, "ark")
    ask = _load_cert(ask_der, "ask")
    leaf = _load_cert(leaf_der, "leaf")
    title = product.capitalize()
    if signing_key == VCEK:
        want_ask = f"SEV-{title}"
    elif signing_key == VLEK:
        want_ask = f"SEV-VLEK-{title}"
    else:
        raise Refused("untrusted_root", f"report signing key {signing_key} is not VCEK or VLEK")
    if _cn(ark.subject) != f"ARK-{title}" or _cn(ask.subject) != want_ask:
        raise Refused("untrusted_root", "chain names")
    _issued_by(ark, ark, "ark")
    _issued_by(ask, ark, "ask")
    _issued_by(leaf, ask, "leaf")
    leaf_key = leaf.public_key()
    if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or leaf_key.curve.name != "secp384r1":
        raise Refused("untrusted_root", "leaf key is not P-384")
    if leaf_product(leaf_der) != product:
        raise Refused("untrusted_root", "leaf product name")

    components = dict(SPL_OIDS)
    if product == "turin":
        if TURIN_FMC_OID is None:
            raise Refused("untrusted_root", "Turin FMC SPL extension is not confirmed")
        components["fmc"] = TURIN_FMC_OID
    spl = {name: _der_small_int(_ext(leaf, oid), name) for name, oid in components.items()}

    hwid = _ext(leaf, OID_HWID)
    csp = _ext(leaf, OID_CSP_ID)
    if signing_key == VCEK and (hwid is None or len(hwid) != 64):
        raise Refused("untrusted_root", "VCEK has no hwID")
    if signing_key == VLEK and csp is None:
        raise Refused("untrusted_root", "VLEK has no csp_id")

    crl = _load_crl(crl_der)
    if crl.issuer != ark.subject:
        raise Refused("untrusted_root", "crl issuer")
    _pss_signed(
        crl.signature_algorithm_oid, crl.signature, crl.tbs_certlist_bytes, ark.public_key(), "crl"
    )
    next_update = crl.next_update_utc
    if next_update is None:
        raise Refused("untrusted_root", "crl has no next update")
    for cert, what in ((ask, "ask"), (leaf, "leaf")):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # VCEK serial 0, as in _load_cert
            serial = cert.serial_number
        if crl.get_revoked_certificate_by_serial_number(serial) is not None:
            raise Refused("cert_revoked", what)

    return Chain(
        leaf_key=leaf_key,
        spl=spl,
        hwid=hwid if signing_key == VCEK else None,
        csp_id=_der_string(csp, "csp_id") if signing_key == VLEK else None,
        crl_next_update=int(next_update.timestamp()),
    )


def verify_report_signature(
    key: ec.EllipticCurvePublicKey, signed: bytes, r: bytes, s: bytes
) -> None:
    """The report signature: ECDSA P-384 SHA-384; R and S are 72-byte
    little-endian fields (only the low 48 bytes may be non-zero)."""
    if any(r[48:]) or any(s[48:]):
        raise Refused("untrusted_root", "report signature form")
    sig = encode_dss_signature(int.from_bytes(r, "little"), int.from_bytes(s, "little"))
    try:
        key.verify(sig, signed, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise Refused("untrusted_root", "report signature") from exc
