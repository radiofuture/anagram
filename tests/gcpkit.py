"""A test Google: a fake Confidential Space root, intermediate and leaf, and
PKI attestation tokens signed by the leaf. Tests pin the fake root through
`Roots.gcp_cs_root`; production pins Google's real root."""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

NOW = dt.datetime(2026, 11, 27, tzinfo=dt.UTC)
T0 = int(NOW.timestamp())
REPORT_DATA = "ab" * 32

_KEYS: dict[str, rsa.RSAPrivateKey] = {}


def key(label: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    if (label, bits) not in _KEYS:
        _KEYS[(label, bits)] = rsa.generate_private_key(public_exponent=65537, key_size=bits)  # type: ignore[index]
    return _KEYS[(label, bits)]  # type: ignore[index]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google LLC"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def good_payload() -> dict[str, Any]:
    return {
        "aud": "anagram/v1/enclave",
        "dbgstat": "disabled-since-boot",
        "eat_nonce": [REPORT_DATA],
        "eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
        "exp": T0 + 3600,
        "google_service_accounts": ["enclave@example.iam.gserviceaccount.com"],
        "hwmodel": "GCP_INTEL_TDX",
        "iat": T0,
        "iss": "https://confidentialcomputing.googleapis.com",
        "nbf": T0,
        "oemid": 11129,
        "secboot": True,
        "sub": "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/1",
        "submods": {
            "confidential_space": {
                "monitoring_enabled": {"memory": False},
                "support_attributes": ["LATEST", "STABLE", "USABLE"],
            },
            "container": {
                "args": ["/anagram-enclave"],
                "env": {"HOSTNAME": "enclave"},
                "image_digest": "sha256:" + "12" * 32,
                "image_id": "sha256:" + "34" * 32,
                "image_reference": "us-docker.pkg.dev/p/r/enclave@sha256:" + "12" * 32,
                "restart_policy": "Never",
            },
            "gce": {
                "instance_id": "1",
                "instance_name": "e",
                "project_id": "p",
                "project_number": "2",
                "zone": "z",
            },
        },
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["251100"],
        "tdx": [
            {
                "gcp_attester_tcb_date": "2025-08-13T00:00:00Z",
                "gcp_attester_tcb_status": "UpToDate",
                "tcb_evaluation_data_number": 20,
            }
        ],
        "attester_tcb": ["INTEL"],
    }


def gpu_submod(*versions: tuple[str, str], cc_mode: str = "ON") -> dict[str, Any]:
    return {
        "cc_feature": "SPT",
        "cc_mode": cc_mode,
        "gpus": [
            {
                "driver_version": d,
                "hwmodel": "GCP_NVIDIA_H100",
                "l4_serial_number": "00",
                "ueid": "01",
                "vbios_version": v,
            }
            for d, v in versions
        ],
    }


@dataclass
class FakeGoogle:
    root_cn: str = "Confidential Space Root CA"
    leaf_bits: int = 2048
    leaf_days: int = 30
    _chain: list[bytes] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.root_key, self.mid_key = key("root"), key("mid")
        self.leaf_key = key("leaf", self.leaf_bits)

    def chain(self) -> list[bytes]:
        if self._chain is None:

            def cert(
                subject: str,
                issuer: str,
                pub: object,
                signer: rsa.RSAPrivateKey,
                days: int,
                *,
                ca: bool = False,
                crl_sign: bool = False,
            ) -> bytes:
                b = (
                    x509.CertificateBuilder()
                    .subject_name(_name(subject))
                    .issuer_name(_name(issuer))
                    .public_key(pub)  # type: ignore[arg-type]
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(NOW - dt.timedelta(days=1))
                    .not_valid_after(NOW + dt.timedelta(days=days))
                    .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                )
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
                c = b.sign(signer, hashes.SHA256())
                return c.public_bytes(serialization.Encoding.DER)

            root = cert(
                self.root_cn,
                self.root_cn,
                self.root_key.public_key(),
                self.root_key,
                3650,
                ca=True,
                crl_sign=True,
            )
            mid = cert(
                "Confidential Space Intermediate",
                self.root_cn,
                self.mid_key.public_key(),
                self.root_key,
                365,
                ca=True,
            )
            leaf = cert(
                "Confidential Space Signer",
                "Confidential Space Intermediate",
                self.leaf_key.public_key(),
                self.mid_key,
                self.leaf_days,
                ca=False,
            )
            self._chain = [leaf, mid, root]
        return self._chain

    def pin(self) -> str:
        return hashlib.sha256(self.chain()[2]).hexdigest()

    def token(
        self,
        payload: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
        signer: rsa.RSAPrivateKey | None = None,
        x5c: list[bytes] | None = None,
    ) -> str:
        h = (
            header
            if header is not None
            else {
                "alg": "RS256",
                "kid": "1",
                "typ": "JWT",
                "x5c": [
                    base64.b64encode(c).decode() for c in (x5c if x5c is not None else self.chain())
                ],
            }
        )
        p = payload if payload is not None else good_payload()
        signing = b64url(json.dumps(h).encode()) + "." + b64url(json.dumps(p).encode())
        sig = (signer or self.leaf_key).sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        return signing + "." + b64url(sig)


def changed(**changes: Any) -> dict[str, Any]:
    """The good payload with dotted paths set (a value of `...` deletes)."""
    p = copy.deepcopy(good_payload())
    for path, value in changes.items():
        cur = p
        *head, last = path.split("__")
        for name in head:
            cur = cur[name]
        if value is ...:
            del cur[last]
        else:
            cur[last] = value
    return p
