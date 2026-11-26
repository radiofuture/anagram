"""The vault vectors (spec/vectors/vault.json) check out on their own."""

import json
from itertools import combinations
from pathlib import Path

from anagram.core.crypto import shamir
from anagram.core.crypto.blob import blob_key, chunk_aad, chunk_nonce, decrypt_bytes
from anagram.identity.formats.backup import backup_id
from anagram.identity.formats.recovery import (
    guardian_info,
    recovery_info,
    recovery_request_id,
    validate_share,
)
from anagram.network.formats.vault import (
    grant_info,
    receipt_commitment,
    receipt_log_entry,
    verify_grant_receipt,
)

V = json.loads((Path(__file__).parent.parent / "spec" / "vectors" / "vault.json").read_text())


def test_blob_vector():
    b = V["blob"]
    key, root, ev = (bytes.fromhex(b[k]) for k in ("content_key", "finding_root", "evidence_root"))
    assert blob_key(key, root, b["slot"]).hex() == b["blob_key"]
    for c in b["chunks"]:
        final = c["index"] == len(b["chunks"]) - 1
        assert chunk_aad(root, ev, b["slot"], c["index"], final).hex() == c["aad"]
        assert chunk_nonce(c["index"]).hex() == c["nonce"]
    plain = decrypt_bytes(
        bytes.fromhex(b["ciphertext_hex"]),
        content_key=key,
        finding_root=root,
        evidence_root=ev,
        slot=b["slot"],
        chunk_size=b["chunk_size"],
    )
    assert plain.hex() == b["plaintext_hex"]


def test_grant_receipt_vector():
    g = V["grant_receipt"]
    verify_grant_receipt(g["receipt"])
    assert receipt_commitment(g["receipt"]).hex() == g["commitment"]
    assert receipt_log_entry(g["receipt"]) == g["log_entry"]


def test_hpke_info_vectors():
    h = V["hpke_info"]
    g = h["grant"]
    assert (
        grant_info(bytes.fromhex(g["grant_id"]), bytes.fromhex(g["device"])).hex() == g["info_hex"]
    )
    s = h["guardian_share"]
    info = guardian_info(bytes.fromhex(s["set_id"]), s["index"], bytes.fromhex(s["device"]))
    assert info.hex() == s["info_hex"]
    r = h["recovery_share"]
    assert recovery_info(bytes.fromhex(r["request_id"]), r["index"]).hex() == r["info_hex"]


def test_guardian_vectors():
    g = V["guardians"]
    shares = [(s["index"], bytes.fromhex(s["share"])) for s in g["shares"]]
    for pair in combinations(shares, g["threshold"]):
        assert shamir.combine(list(pair), g["threshold"]).hex() == g["secret"]
    assert backup_id(bytes.fromhex(g["secret"])) == g["backup_id"]
    validate_share(g["share_document"])
    r = V["recovery_request"]
    assert recovery_request_id(r["request"]) == r["request_id"]
