"""A local RFC 3161 TSA for tests and the synthetic community.

It makes real RFC 3161 responses (CMS SignedData over TSTInfo) with a local
test CA. It gives NO independent time. Use it as the transport of an
RFC3161Anchor so the real request and verification code runs with no network.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class LocalTSA:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        start = datetime(2000, 1, 1, tzinfo=UTC)
        end = start + timedelta(days=365 * 100)
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Anagram Local Test Root"))
            .issuer_name(_name("Anagram Local Test Root"))
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.root_key, hashes.SHA256())
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Anagram Local Test TSA"))
            .issuer_name(self.root_cert.subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .sign(self.root_key, hashes.SHA256())
        )

    def respond(self, request_der: bytes) -> bytes:
        req = tsp.TimeStampReq.load(request_der)
        gen_time = datetime.fromtimestamp(int(self.clock()), UTC)
        tst_fields = {
            "version": "v1",
            "policy": "1.3.6.1.4.1.99999.1",
            "message_imprint": req["message_imprint"],
            "serial_number": secrets.randbits(63),
            "gen_time": gen_time,
        }
        if req["nonce"].native is not None:
            tst_fields["nonce"] = req["nonce"].native
        tst = tsp.TSTInfo(tst_fields)
        tst_der = tst.dump()
        cert_der = self.cert.public_bytes(Encoding.DER)
        asn1_cert = asn1_x509.Certificate.load(cert_der)
        signed_attrs = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["tst_info"]},
                {"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]},
                {
                    "type": "signing_certificate_v2",
                    "values": [
                        {
                            "certs": [
                                {
                                    "hash_algorithm": {"algorithm": "sha256"},
                                    "cert_hash": hashlib.sha256(cert_der).digest(),
                                }
                            ]
                        }
                    ],
                },
            ]
        )
        signature = self.key.sign(signed_attrs.dump(), ec.ECDSA(hashes.SHA256()))
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": {
                            "issuer": asn1_cert.issuer,
                            "serial_number": asn1_cert.serial_number,
                        }
                    }
                ),
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": signed_attrs,
                "signature_algorithm": {"algorithm": "sha256_ecdsa"},
                "signature": signature,
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": cms.ParsableOctetString(tst_der),
                },
                "certificates": [asn1_cert] if req["cert_req"].native else [],
                "signer_infos": [signer_info],
            }
        )
        resp = tsp.TimeStampResp(
            {
                "status": {"status": "granted"},
                "time_stamp_token": {"content_type": "signed_data", "content": signed_data},
            }
        )
        return resp.dump()

    def transport(self, url: str, body: bytes) -> bytes:
        return self.respond(body)
