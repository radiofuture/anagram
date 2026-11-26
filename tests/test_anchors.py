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
    assert check.source == "opentimestamps:bitcoin:900000"

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
