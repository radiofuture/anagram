import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from asn1crypto import tsp
from cryptography import x509
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256

from anagram.core.crypto.signing import SigningKey
from anagram.proofs.anchors import AnchorTrust, verify_anchor
from anagram.proofs.anchors.fake import FakeAnchor
from anagram.proofs.anchors.local_tsa import LocalTSA
from anagram.proofs.anchors.ots import new_detached, record_from_detached
from anagram.proofs.anchors.rfc3161 import (
    RFC3161Anchor,
    TSAError,
    build_request,
    token_from_response,
    verify_token,
)

FIX = Path(__file__).parent / "fixtures" / "rfc3161"
DIGEST = hashlib.sha256(b"checkpoint text").digest()
T = 1_760_000_000


def test_fake_anchor():
    key = SigningKey.from_seed(b"\x07" * 32)
    rec = FakeAnchor(key, clock=lambda: T).stamp(DIGEST)
    trust = AnchorTrust(fake_keys=[key.public_bytes()])
    check = verify_anchor(rec, DIGEST, trust)
    assert check.ok and check.time == datetime.fromtimestamp(T, UTC)
    assert not verify_anchor(rec, DIGEST, AnchorTrust()).ok
    assert not verify_anchor(rec, hashlib.sha256(b"x").digest(), trust).ok
    backdated = {**rec, "time": "2020-01-01T00:00:00Z"}
    assert not verify_anchor(backdated, DIGEST, trust).ok


def test_request_building():
    der = build_request(DIGEST, nonce=42)
    req = tsp.TimeStampReq.load(der)
    assert req["version"].native == "v1"
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert req["message_imprint"]["hashed_message"].native == DIGEST
    assert req["nonce"].native == 42
    assert req["cert_req"].native is True
    with pytest.raises(TSAError):
        build_request(b"short")


def test_openssl_fixture_verifies():
    # Token made by the OpenSSL `ts` command (see fixtures/rfc3161/make_fixture.sh).
    digest = bytes.fromhex((FIX / "digest.hex").read_text().strip())
    assert digest == hashlib.sha256(b"anagram rfc3161 fixture").digest()
    root = x509.load_pem_x509_certificate((FIX / "root.pem").read_bytes())
    tsq = tsp.TimeStampReq.load((FIX / "request.tsq").read_bytes())
    token = token_from_response((FIX / "response.tsr").read_bytes(), digest, tsq["nonce"].native)
    check = verify_token(token, digest, [root])
    assert check.ok, check.detail
    assert check.time.year >= 2026
    # Wrong digest, no pinned root, wrong root: all fail.
    assert not verify_token(token, DIGEST, [root]).ok
    assert not verify_token(token, digest, []).ok
    other = LocalTSA()
    assert not verify_token(token, digest, [other.root_cert]).ok
    # One changed byte in the signature fails.
    bad = bytearray(token)
    bad[-5] ^= 1
    assert not verify_token(bytes(bad), digest, [root]).ok


def test_local_tsa_round_trip():
    tsa = LocalTSA(clock=lambda: T)
    anchor = RFC3161Anchor("https://tsa.invalid/", transport=tsa.transport)
    rec = anchor.stamp(DIGEST)
    trust = AnchorTrust(tsa_roots=[tsa.root_cert])
    check = verify_anchor(rec, DIGEST, trust)
    assert check.ok, check.detail
    assert check.time == datetime.fromtimestamp(T, UTC)
    assert check.source.startswith("rfc3161:") and len(check.source) == 8 + 64
    assert not verify_anchor(rec, hashlib.sha256(b"other").digest(), trust).ok
    # A different pinned root (another TSA) fails.
    assert not verify_anchor(rec, DIGEST, AnchorTrust(tsa_roots=[LocalTSA().root_cert])).ok


def test_rfc3161_rejects_response_for_other_digest():
    tsa = LocalTSA(clock=lambda: T)
    resp = tsa.respond(build_request(DIGEST, nonce=5))
    with pytest.raises(TSAError):
        token_from_response(resp, hashlib.sha256(b"x").digest(), 5)
    with pytest.raises(TSAError):
        token_from_response(resp, DIGEST, 6)


def test_ots_offline_verify():
    detached, leaf = new_detached(DIGEST)
    # Simulate what a calendar returns after Bitcoin confirmation.
    block_root = leaf.ops.add(OpSHA256())
    block_root.attestations.add(BitcoinBlockHeaderAttestation(900_000))
    leaf.attestations.add(PendingAttestation("https://calendar.invalid"))
    rec = record_from_detached(detached)

    pending_only = AnchorTrust()
    check = verify_anchor(rec, DIGEST, pending_only)
    assert not check.ok and "900000" in check.detail

    trust = AnchorTrust(bitcoin_headers={900_000: (block_root.msg, T)})
    check = verify_anchor(rec, DIGEST, trust)
    assert check.ok and check.time == datetime.fromtimestamp(T, UTC)
    assert check.source == "opentimestamps:bitcoin"

    wrong = AnchorTrust(bitcoin_headers={900_000: (bytes(32), T)})
    assert not verify_anchor(rec, DIGEST, wrong).ok
    assert not verify_anchor(rec, hashlib.sha256(b"x").digest(), trust).ok


def test_ots_pending_only():
    detached, leaf = new_detached(DIGEST)
    leaf.attestations.add(PendingAttestation("https://calendar.invalid"))
    check = verify_anchor(record_from_detached(detached), DIGEST, AnchorTrust())
    assert not check.ok and check.pending


def test_unknown_and_malformed():
    assert not verify_anchor({"type": "nope"}, DIGEST, AnchorTrust()).ok
    assert not verify_anchor({"type": "fake"}, DIGEST, AnchorTrust()).ok
    bad = {"type": "rfc3161", "token": base64.b64encode(b"junk").decode()}
    assert not verify_anchor(bad, DIGEST, AnchorTrust()).ok


def _build_tsa_chain_token(
    *,
    root_path_len: int | None = 1,
    inter_ca: bool | None = True,
    inter_path_len: int | None = 0,
    inter_key_cert_sign: bool | None = True,
    inter_eku: list | None = None,
    leaf_ca: bool = False,
):
    from datetime import timedelta

    from asn1crypto import cms
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    start = datetime(2000, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=365 * 50)
    gen_time = datetime.fromtimestamp(T, UTC)

    def nm(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(nm("Test Root"))
        .issuer_name(nm("Test Root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=root_path_len), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    inter_key = ec.generate_private_key(ec.SECP256R1())
    ib = (
        x509.CertificateBuilder()
        .subject_name(nm("Test Inter"))
        .issuer_name(root.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if inter_ca is not None:
        ib = ib.add_extension(
            x509.BasicConstraints(ca=inter_ca, path_length=inter_path_len if inter_ca else None),
            critical=True,
        )
    if inter_key_cert_sign is not None:
        ib = ib.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=inter_key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if inter_eku is not None:
        ib = ib.add_extension(x509.ExtendedKeyUsage(inter_eku), critical=False)
    inter = ib.sign(root_key, hashes.SHA256())

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(nm("Test Leaf"))
        .issuer_name(inter.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=leaf_ca, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(inter_key, hashes.SHA256())
    )
    tst = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.3.6.1.4.1.99999.1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": DIGEST,
            },
            "serial_number": 1,
            "gen_time": gen_time,
        }
    )
    tst_der = tst.dump()
    leaf_der = leaf.public_bytes(Encoding.DER)
    asn1_leaf = asn1_x509.Certificate.load(leaf_der)
    asn1_inter = asn1_x509.Certificate.load(inter.public_bytes(Encoding.DER))
    attrs = cms.CMSAttributes(
        [
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]},
        ]
    )
    sig = leaf_key.sign(attrs.dump(), ec.ECDSA(hashes.SHA256()))
    si = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": {
                        "issuer": asn1_leaf.issuer,
                        "serial_number": asn1_leaf.serial_number,
                    }
                }
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "sha256_ecdsa"},
            "signature": sig,
        }
    )
    sd = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {
                "content_type": "tst_info",
                "content": cms.ParsableOctetString(tst_der),
            },
            "certificates": [asn1_leaf, asn1_inter],
            "signer_infos": [si],
        }
    )
    ci = cms.ContentInfo({"content_type": "signed_data", "content": sd})
    return ci.dump(), root


def test_rfc3161_rfc5280_chain_validation_and_root_source():
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID

    # Valid intermediate chain: source is keyed on the pinned ROOT fingerprint.
    tok, root = _build_tsa_chain_token(inter_eku=[ExtendedKeyUsageOID.TIME_STAMPING])
    check = verify_token(tok, DIGEST, [root])
    assert check.ok, check.detail
    assert check.source == f"rfc3161:{root.fingerprint(hashes.SHA256()).hex()}"

    # Intermediate with anyExtendedKeyUsage is accepted.
    tok_any, root_any = _build_tsa_chain_token(
        inter_eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]
    )
    assert verify_token(tok_any, DIGEST, [root_any]).ok

    # Non-CA intermediate, missing BasicConstraints, pathLen violation, missing
    # keyCertSign, wrong EKU, and CA leaf must all fail.
    for kwargs in (
        {"inter_ca": False},
        {"inter_ca": None},
        {"root_path_len": 0},
        {"inter_key_cert_sign": False},
        {"inter_eku": [ExtendedKeyUsageOID.SERVER_AUTH]},
        {"leaf_ca": True},
    ):
        bad_tok, bad_root = _build_tsa_chain_token(**kwargs)
        assert not verify_token(bad_tok, DIGEST, [bad_root]).ok, kwargs


def test_ots_source_deduplicates_heights_and_upgrade_allowlists(monkeypatch):
    from anagram.proofs.anchors.ots import OpenTimestampsAnchor

    def _make_ots(height: int):
        det, leaf = new_detached(DIGEST)
        mr = leaf.ops.add(OpSHA256())
        mr.attestations.add(BitcoinBlockHeaderAttestation(height))
        return record_from_detached(det), mr.msg

    rec1, m1 = _make_ots(900_000)
    rec2, m2 = _make_ots(900_001)
    trust = AnchorTrust(bitcoin_headers={900_000: (m1, T), 900_001: (m2, T + 600)})
    c1 = verify_anchor(rec1, DIGEST, trust)
    c2 = verify_anchor(rec2, DIGEST, trust)
    assert c1.ok and c2.ok and c1.source == c2.source == "opentimestamps:bitcoin"

    # Overflowing block_time must not raise OverflowError.
    bad_trust = AnchorTrust(bitcoin_headers={900_000: (m1, 10**20)})
    assert not verify_anchor(rec1, DIGEST, bad_trust).ok

    # Upgrade must ignore untrusted or non-https calendar URIs (SSRF defense).
    det, leaf = new_detached(DIGEST)
    leaf.attestations.add(PendingAttestation("http://127.0.0.1:8080/evil"))
    leaf.attestations.add(PendingAttestation("https://evil.example/cal"))
    called = []

    class FakeCal:
        def __init__(self, uri):
            called.append(uri)

        def get_timestamp(self, msg, timeout=10):
            raise AssertionError("should not contact untrusted calendar")

    import opentimestamps.calendar as ots_cal

    monkeypatch.setattr(ots_cal, "RemoteCalendar", FakeCal)
    OpenTimestampsAnchor(calendars=("https://trusted.example",)).upgrade(record_from_detached(det))
    assert called == []
