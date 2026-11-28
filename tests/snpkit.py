"""A test AMD: a fake ARK, ASK (or ASVK) and VCEK (or VLEK) with AMD's
extensions, a CRL, and SEV-SNP reports signed by the leaf. Tests pin the
fake ARK through `Roots.amd_arks`; production pins AMD's real ARKs."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import struct
from dataclasses import dataclass, field, replace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from anagram.network.matching.trust.profiles import amd

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
NOW = dt.datetime(2026, 11, 27, tzinfo=dt.UTC)
CPUID = {"milan": (0x19, 0x01, 1), "genoa": (0x19, 0x11, 1), "turin": (0x1A, 0x02, 0)}
POLICY_GOOD = (1 << 17) | (1 << 25)  # reserved bit, PAGE_SWAP_DISABLE; SMT off, debug off


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _der_int(v: int) -> bytes:
    body = v.to_bytes(2, "big", signed=True).lstrip(b"\x00") if v else b"\x00"
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([0x02, len(body)]) + body


def _der_ia5(s: str) -> bytes:
    return bytes([0x16, len(s)]) + s.encode()


_RSA_CACHE: dict[str, rsa.RSAPrivateKey] = {}


def _rsa(label: str) -> rsa.RSAPrivateKey:
    if label not in _RSA_CACHE:
        _RSA_CACHE[label] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _RSA_CACHE[label]


@dataclass
class FakeAmd:
    """One product's fake chain. Change a field, then call `chain()`."""

    product: str = "milan"
    signing_key: int = amd.VCEK
    chip_id: bytes = bytes(range(64))
    tcb: dict[str, int] = field(
        default_factory=lambda: {"boot_loader": 4, "tee": 0, "snp": 22, "microcode": 219}
    )
    spl: dict[str, int] | None = None  # leaf extensions; default: equal to tcb
    hwid: bytes | None = None  # default: chip_id
    csp_id: str = "Amazon Web Services"
    ask_cn: str | None = None
    leaf_product: str | None = None
    revoke: tuple[str, ...] = ()  # "ask", "leaf"
    leaf_ec: bool = True
    extra_exts: tuple[tuple[str, bytes], ...] = ()  # (OID, raw) added to the leaf as is

    def __post_init__(self) -> None:
        self.ark_key = _rsa(f"ark-{self.product}")
        self.ask_key = _rsa(f"ask-{self.product}")
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        self._chain: dict[str, bytes] | None = None

    def _cert(
        self, subject: str, issuer: str, key: object, signer: rsa.RSAPrivateKey, serial: int,
        exts: list[tuple[x509.ObjectIdentifier, bytes]] = (),  # type: ignore[assignment]
        *, ca: bool | None = None, crl_sign: bool = False,
        not_before: dt.datetime | None = None, not_after: dt.datetime | None = None,
    ) -> x509.Certificate:  # fmt: skip
        b = (
            x509.CertificateBuilder()
            .subject_name(_name(subject))
            .issuer_name(_name(issuer))
            .public_key(key)  # type: ignore[arg-type]
            .serial_number(serial)
            .not_valid_before(not_before or (NOW - dt.timedelta(days=1)))
            .not_valid_after(not_after or (NOW + dt.timedelta(days=3650)))
        )
        if ca is not None:
            b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            if ca:
                b = b.add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=crl_sign,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
        for oid, raw in exts:
            b = b.add_extension(x509.UnrecognizedExtension(oid, raw), critical=False)
        return b.sign(signer, hashes.SHA384(), rsa_padding=PSS)

    def chain(self) -> dict[str, bytes]:
        """The DER of the chain and the CRL (made once: PSS signatures are
        randomised, and the pin is a hash of the ARK bytes)."""
        if self._chain is None:
            self._chain = self._make_chain()
        return self._chain

    def _make_chain(self) -> dict[str, bytes]:
        t = self.product.capitalize()
        ark_cn = f"ARK-{t}"
        ask_cn = self.ask_cn or (f"SEV-{t}" if self.signing_key == amd.VCEK else f"SEV-VLEK-{t}")
        ark = self._cert(
            ark_cn, ark_cn, self.ark_key.public_key(), self.ark_key, 0x10000, ca=True, crl_sign=True
        )
        ask = self._cert(ask_cn, ark_cn, self.ask_key.public_key(), self.ark_key, 0x10001, ca=True)
        spl = self.spl if self.spl is not None else self.tcb
        exts = [(amd.OID_PRODUCT_NAME, _der_ia5(f"{self.leaf_product or t}-B0"))]
        exts += [(amd.SPL_OIDS[n], _der_int(v)) for n, v in spl.items() if n in amd.SPL_OIDS]
        if self.signing_key == amd.VCEK:
            exts.append((amd.OID_HWID, self.hwid if self.hwid is not None else self.chip_id))
        else:
            exts.append((amd.OID_CSP_ID, _der_ia5(self.csp_id)))
        exts += [(x509.ObjectIdentifier(oid), raw) for oid, raw in self.extra_exts]
        leaf_pub = self.leaf_key.public_key() if self.leaf_ec else _rsa("leaf-rsa").public_key()
        leaf = self._cert("SEV-VCEK", ask_cn, leaf_pub, self.ask_key, 0x20000, exts)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(_name(ark_cn))
            .last_update(NOW - dt.timedelta(days=1))
            .next_update(NOW + dt.timedelta(days=45))
        )
        for what, cert in (("ask", ask), ("leaf", leaf)):
            if what in self.revoke:
                crl = crl.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(cert.serial_number)
                    .revocation_date(NOW - dt.timedelta(hours=1))
                    .build()
                )
        der = serialization.Encoding.DER
        return {
            "ark": ark.public_bytes(der),
            "ask": ask.public_bytes(der),
            "leaf": leaf.public_bytes(der),
            "crl": crl.sign(self.ark_key, hashes.SHA384(), rsa_padding=PSS).public_bytes(der),
        }

    def pins(self) -> tuple[tuple[str, str], ...]:
        return ((self.product, hashlib.sha256(self.chain()["ark"]).hexdigest()),)

    def report(
        self,
        report_data: bytes = bytes(64),
        policy: int = POLICY_GOOD,
        measurement: bytes = b"\x11" * 48,
        version: int = 3,
        mask_chip_key: bool = False,
        cpuid: tuple[int, int, int] | None = None,
        tcb: dict[str, int] | None = None,
        launch_tcb: dict[str, int] | None = None,
    ) -> bytes:
        """A signed report of the given values; the rest are zero."""
        r = bytearray(0x4A0)
        struct.pack_into("<I", r, 0x00, version)
        struct.pack_into("<Q", r, 0x08, policy)
        struct.pack_into("<I", r, 0x34, 1)
        struct.pack_into("<I", r, 0x48, (self.signing_key << 2) | (int(mask_chip_key) << 1))
        r[0x50:0x90] = report_data.ljust(64, b"\x00")
        r[0x90:0xC0] = measurement
        t = tcb or self.tcb

        def pack_tcb(vals: dict[str, int]) -> bytearray:
            buf = bytearray(8)
            if self.product == "turin":
                buf[0], buf[1], buf[2], buf[3], buf[7] = (
                    vals.get("fmc", 0), vals["boot_loader"], vals["tee"], vals["snp"], vals["microcode"],
                )  # fmt: skip
            else:
                buf[0], buf[1], buf[6], buf[7] = (
                    vals["boot_loader"], vals["tee"], vals["snp"], vals["microcode"],
                )  # fmt: skip
            return buf

        raw = pack_tcb(t)
        r[0x180:0x188] = raw
        r[0x38:0x40] = raw
        r[0x1E0:0x1E8] = raw
        r[0x1F0:0x1F8] = pack_tcb(launch_tcb) if launch_tcb is not None else raw
        if version >= 3:
            r[0x188:0x18B] = bytes(cpuid or CPUID[self.product])
        r[0x1A0:0x1E0] = self.chip_id
        sig = self.leaf_key.sign(bytes(r[:0x2A0]), ec.ECDSA(hashes.SHA384()))
        rr, ss = decode_dss_signature(sig)
        r[0x2A0:0x2E8] = rr.to_bytes(72, "little")
        r[0x2E8:0x330] = ss.to_bytes(72, "little")
        return bytes(r)

    def evidence(self, report: bytes, **override: bytes) -> dict[str, str]:
        parts = {**self.chain(), "report": report, **override}
        return {k: base64.b64encode(v).decode() for k, v in parts.items()}


def variant(base: FakeAmd, **changes: object) -> FakeAmd:
    """A copy with the same keys and some fields changed."""
    out = replace(base, **changes)  # type: ignore[arg-type]
    out.ark_key, out.ask_key, out.leaf_key = base.ark_key, base.ask_key, base.leaf_key
    out._chain = None
    return out
