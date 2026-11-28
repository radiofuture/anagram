"""A test Intel: a fake SGX Root CA, PCK CA, PCK certificate (with the SGX
extensions), TCB signing certificate, CRLs, signed TCB Info and QE Identity,
and TDX quotes signed by a quoting enclave. Tests pin the fake root through
`Roots.intel_root`; production pins Intel's real root."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import struct
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from anagram.network.matching.trust.profiles import tdx

NOW = dt.datetime(2026, 11, 27, tzinfo=dt.UTC)
SGX = "1.2.840.113741.1.13.1"
QE_MRSIGNER = bytes.fromhex("DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5")
GOOD_ATTRS = 1 << tdx.ATTR_SEPT_VE_DISABLE

_KEYS: dict[str, ec.EllipticCurvePrivateKey] = {}


def key(label: str) -> ec.EllipticCurvePrivateKey:
    if label not in _KEYS:
        _KEYS[label] = ec.generate_private_key(ec.SECP256R1())
    return _KEYS[label]


def der(tag: int, body: bytes) -> bytes:
    n = len(body)
    head = (
        bytes([n])
        if n < 0x80
        else bytes([0x80 | ((n.bit_length() + 7) // 8)])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + head + body


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, bytes(out))


def der_uint(v: int) -> bytes:
    body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return der(0x02, body)


def seq(*items: bytes) -> bytes:
    return der(0x30, b"".join(items))


def pair(oid: str, value: bytes) -> bytes:
    return seq(der_oid(oid), value)


def sgx_extensions(
    comps: tuple[int, ...], pce_svn: int, pce_id: bytes, fmspc: bytes, cpusvn: bytes | None = None
) -> bytes:
    tcb = [pair(f"{SGX}.2.{i + 1}", der_uint(c)) for i, c in enumerate(comps)]
    tcb += [pair(f"{SGX}.2.17", der_uint(pce_svn))]
    tcb += [pair(f"{SGX}.2.18", der(0x04, cpusvn if cpusvn is not None else bytes(comps)))]
    return seq(
        pair(f"{SGX}.1", der(0x04, bytes(range(16)))),
        pair(f"{SGX}.2", seq(*tcb)),
        pair(f"{SGX}.3", der(0x04, pce_id)),
        pair(f"{SGX}.4", der(0x04, fmspc)),
        pair(f"{SGX}.5", der(0x0A, b"\x00")),
    )


def raw_sig(k: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    r, s = decode_dss_signature(k.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def point(k: ec.EllipticCurvePrivateKey) -> bytes:
    return k.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )[1:]


def signed_body(field_name: str, body: dict[str, Any], k: ec.EllipticCurvePrivateKey) -> bytes:
    raw = json.dumps(body, separators=(",", ":")).encode()
    return b'{"%s":%s,"signature":"%s"}' % (
        field_name.encode(),
        raw,
        raw_sig(k, raw).hex().encode(),
    )


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intel Corporation"),
        ]
    )


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FakeIntel:
    """One platform's fake chain and collateral. Change a field, then build."""

    comps: tuple[int, ...] = (9, 9, 2, 2, 4, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0)
    pce_svn: int = 11
    pce_id: bytes = b"\x00\x00"
    fmspc: bytes = bytes.fromhex("50806f000000")
    cpusvn: bytes | None = None  # default: comps
    tee_tcb_svn: bytes = bytes([5, 0, 9] + [0] * 13)
    ca_cn: str = "Intel SGX PCK Platform CA"
    revoke: tuple[str, ...] = ()  # "ca", "leaf", "signer"
    qe_isvsvn: int = 4
    qe_mrsigner: bytes = QE_MRSIGNER
    mr_signer_seam: bytes = bytes(48)
    tcb_levels: list[dict[str, Any]] | None = None  # default: one UpToDate level at the platform
    module_identities: list[dict[str, Any]] = field(default_factory=list)
    tcb_info_changes: dict[str, Any] = field(default_factory=dict)
    qe_identity_changes: dict[str, Any] = field(default_factory=dict)
    extra_leaf_exts: tuple[tuple[str, bytes], ...] = ()
    sgx_ext: bytes | None = None  # the raw SGX extension value; default: built from the fields

    def __post_init__(self) -> None:
        self.root_key, self.ca_key = key("root"), key("ca")
        self.leaf_key, self.signer_key = key("pck"), key("tcb-signing")
        self.att_key = key("attestation")
        self._chain: dict[str, bytes] | None = None

    def _cert(
        self, subject: str, issuer: str, pub: object, signer: ec.EllipticCurvePrivateKey,
        serial: int, exts: list[tuple[str, bytes]] = (),  # type: ignore[assignment]
        *, ca: bool | None = None, crl_sign: bool = False,
        not_before: dt.datetime | None = None, not_after: dt.datetime | None = None,
    ) -> x509.Certificate:  # fmt: skip
        b = (
            x509.CertificateBuilder()
            .subject_name(_name(subject))
            .issuer_name(_name(issuer))
            .public_key(pub)  # type: ignore[arg-type]
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
            b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), raw), False)
        return b.sign(signer, hashes.SHA256())

    def chain(self) -> dict[str, bytes]:
        """DER of the root, CA, PCK, TCB signer and the two CRLs (made once:
        ECDSA signatures are randomised, and the pin is a hash of the root)."""
        if self._chain is None:
            self._chain = self._make_chain()
        return self._chain

    def _make_chain(self) -> dict[str, bytes]:
        root_cn = "Intel SGX Root CA"
        root = self._cert(
            root_cn, root_cn, self.root_key.public_key(), self.root_key, 0x100,
            ca=True, crl_sign=True,
        )  # fmt: skip
        ca = self._cert(
            self.ca_cn, root_cn, self.ca_key.public_key(), self.root_key, 0x101,
            ca=True, crl_sign=True,
        )  # fmt: skip
        signer = self._cert(
            "Intel SGX TCB Signing", root_cn, self.signer_key.public_key(), self.root_key, 0x102,
            ca=False,
        )  # fmt: skip
        ext = self.sgx_ext
        if ext is None:
            ext = sgx_extensions(self.comps, self.pce_svn, self.pce_id, self.fmspc, self.cpusvn)
        exts = [(SGX, ext), *self.extra_leaf_exts] if ext else list(self.extra_leaf_exts)
        leaf = self._cert(
            "Intel SGX PCK Certificate", self.ca_cn, self.leaf_key.public_key(), self.ca_key,
            0x200, exts, ca=False,
        )  # fmt: skip

        def crl(issuer_cn: str, k: ec.EllipticCurvePrivateKey, revoked: list[int]) -> bytes:
            b = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(_name(issuer_cn))
                .last_update(NOW - dt.timedelta(days=1))
                .next_update(NOW + dt.timedelta(days=30))
            )
            for serial in revoked:
                b = b.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial)
                    .revocation_date(NOW - dt.timedelta(hours=1))
                    .build()
                )
            return b.sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

        serials = {"ca": ca.serial_number, "signer": signer.serial_number}
        root_revoked = [s for name, s in serials.items() if name in self.revoke]
        leaf_revoked = [leaf.serial_number] if "leaf" in self.revoke else []
        d = serialization.Encoding.DER
        return {
            "root": root.public_bytes(d),
            "ca": ca.public_bytes(d),
            "leaf": leaf.public_bytes(d),
            "tcb_signing": signer.public_bytes(d),
            "root_crl": crl(root_cn, self.root_key, root_revoked),
            "pck_crl": crl(self.ca_cn, self.ca_key, leaf_revoked),
        }

    def pin(self) -> str:
        return hashlib.sha256(self.chain()["root"]).hexdigest()

    def tcb_info(self) -> bytes:
        level = {
            "tcb": {
                "sgxtcbcomponents": [{"svn": c} for c in self.comps],
                "pcesvn": self.pce_svn,
                "tdxtcbcomponents": [{"svn": c} for c in self.tee_tcb_svn],
            },
            "tcbDate": "2025-08-13T00:00:00Z",
            "tcbStatus": "UpToDate",
        }
        body: dict[str, Any] = {
            "id": "TDX",
            "version": 3,
            "issueDate": _iso(NOW - dt.timedelta(days=1)),
            "nextUpdate": _iso(NOW + dt.timedelta(days=29)),
            "fmspc": self.fmspc.hex(),
            "pceId": self.pce_id.hex(),
            "tcbType": 0,
            "tcbEvaluationDataNumber": 20,
            "tdxModule": {
                "mrsigner": "00" * 48,
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
            },
            "tdxModuleIdentities": self.module_identities,
            "tcbLevels": self.tcb_levels if self.tcb_levels is not None else [level],
        }
        body.update(self.tcb_info_changes)
        return signed_body("tcbInfo", body, self.signer_key)

    def qe_identity(self) -> bytes:
        body: dict[str, Any] = {
            "id": "TD_QE",
            "version": 2,
            "issueDate": _iso(NOW - dt.timedelta(days=1)),
            "nextUpdate": _iso(NOW + dt.timedelta(days=28)),
            "tcbEvaluationDataNumber": 19,
            "miscselect": "00000000",
            "miscselectMask": "FFFFFFFF",
            "attributes": "11000000000000000000000000000000",
            "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
            "mrsigner": QE_MRSIGNER.hex().upper(),
            "isvprodid": 2,
            "tcbLevels": [
                {"tcb": {"isvsvn": 4}, "tcbDate": "2025-08-13T00:00:00Z", "tcbStatus": "UpToDate"},
                {
                    "tcb": {"isvsvn": 2},
                    "tcbDate": "2024-03-13T00:00:00Z",
                    "tcbStatus": "OutOfDate",
                    "advisoryIDs": ["INTEL-SA-00000"],
                },
            ],
        }
        body.update(self.qe_identity_changes)
        return signed_body("enclaveIdentity", body, self.signer_key)

    def qe_report(self, report_data: bytes) -> bytes:
        r = bytearray(384)
        r[48] = 0x11
        r[128:160] = self.qe_mrsigner
        struct.pack_into("<HH", r, 256, 2, self.qe_isvsvn)
        r[320:384] = report_data
        return bytes(r)

    def quote(
        self,
        report_data: bytes = bytes(64),
        attrs: int = GOOD_ATTRS,
        mr_td: bytes = b"\x22" * 48,
        auth: bytes = bytes(range(32)),
        qe_report_data: bytes | None = None,
        cert_data_type: int = 6,
        inner_type: int = 5,
        pem: bytes | None = None,
    ) -> bytes:
        """A quote signed by the attestation key, with a QE report signed by
        the PCK key; the rest of the body is fixed."""
        header = (
            struct.pack("<HHI", 4, 2, tdx.TEE_TDX) + bytes(4) + tdx.INTEL_QE_VENDOR_ID + bytes(20)
        )
        fields = {
            "tee_tcb_svn": self.tee_tcb_svn,
            "mr_signer_seam": self.mr_signer_seam,
            "td_attributes": attrs.to_bytes(8, "little"),
            "mr_td": mr_td,
            "report_data": report_data,
        }
        body = b"".join(fields.get(n, bytes(s)) for n, s in tdx.BODY_FIELDS)
        ak = point(self.att_key)
        if qe_report_data is None:
            qe_report_data = hashlib.sha256(ak + auth).digest() + bytes(32)
        qe = self.qe_report(qe_report_data)
        c = self.chain()
        if pem is None:
            pem = (
                b"".join(
                    x509.load_der_x509_certificate(c[n]).public_bytes(serialization.Encoding.PEM)
                    for n in ("leaf", "ca", "root")
                )
                + b"\x00"
            )
        cd = qe + raw_sig(self.leaf_key, qe) + struct.pack("<H", len(auth)) + auth
        cd += struct.pack("<HI", inner_type, len(pem)) + pem
        sig = (
            raw_sig(self.att_key, header + body) + ak + struct.pack("<HI", cert_data_type, len(cd))
        )
        sig += cd
        return header + body + struct.pack("<I", len(sig)) + sig

    def evidence(self, quote: bytes, **override: bytes) -> dict[str, str]:
        c = self.chain()
        parts = {
            "quote": quote,
            "tcb_info": self.tcb_info(),
            "qe_identity": self.qe_identity(),
            "tcb_signing": c["tcb_signing"],
            "root_crl": c["root_crl"],
            "pck_crl": c["pck_crl"],
            **override,
        }
        return {k: base64.b64encode(v).decode() for k, v in parts.items()}


def variant(base: FakeIntel, **changes: object) -> FakeIntel:
    """A copy with the same keys and some fields changed."""
    out = replace(base, **changes)  # type: ignore[arg-type]
    out._chain = None
    return out
