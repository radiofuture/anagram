"""Identity formats: vectors verify on their own, and changed documents fail."""

import copy
import json
from pathlib import Path

import pytest

from anagram.admission.formats import parse_invite_url, verify_invite, verify_receipt
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok
from anagram.identity.formats.backup import decode_secret, encode_secret, open_backup, seal_backup
from anagram.identity.formats.documents import (
    BindingError,
    SubjectKeys,
    binding_entry_hash,
    check_orcid_opening,
    is_subject,
    new_pid,
    orcid_commitment,
    sign_device_signin,
    validate_orcid,
    validate_ror,
    verify_assertion,
    verify_device_signin,
    verify_identity_record,
    verify_node_trust,
)
from anagram.identity.formats.personal_store import StoreKeys, open_record

V = json.loads((Path(__file__).parent.parent / "spec/vectors/identity.json").read_text())
FP = V["node_key_fingerprint"]
AKEY = bytes.fromhex(V["node_trust"]["assertion_key"])


def chain(entries):
    s = SubjectKeys(entries[0]["subject"])
    for e in entries:
        s.apply(e, assertion_key=AKEY, node_key=FP)
    return s


def test_vectors_verify():
    trust = verify_node_trust(V["node_trust"], FP)
    invite = parse_invite_url(V["invite_url"])
    assert invite == V["invite"]
    verify_invite(invite, trust)
    verify_receipt(V["receipt"], AKEY, V["subject"])
    verify_assertion(V["assertion"], assertion_key=AKEY, node_key=FP)
    state = chain(V["bindings"])
    assert sorted(state.devices) == V["active_devices_after"]
    assert [binding_entry_hash(e).hex() for e in V["bindings"]] == V["binding_hashes"]
    verify_identity_record(V["identity_record"], state)
    keys = open_backup(decode_secret(V["recovery"]["code"]), V["recovery"]["backup"])
    assert keys["device-ed25519"].hex() == V["seeds"]["device_1"]
    assert "index-key" in keys  # backup v2
    c = V["orcid_commitment"]
    assert orcid_commitment(c["orcid"], bytes.fromhex(c["salt"])) == c["commitment"]
    assert V["assertion"]["orcid_commitment"] == c["commitment"]
    assert all(e["orcid_commitment"] == c["commitment"] for e in V["bindings"])
    assert state.orcid_commitment == c["commitment"]
    sig = V["device_signin"]
    dev2 = SigningKey.from_seed(bytes.fromhex(V["seeds"]["device_2"]))
    assert verify_device_signin(
        V["subject"], dev2.public_bytes().hex(), sig["challenge"], FP, sig["signature"]
    )
    ps = V["personal_store"]
    keys = StoreKeys(bytes.fromhex(ps["vault_key"]))
    assert keys.key_id == ps["key_id"]
    assert open_record(keys, ps["record"]) == ("finding", "00" * 32, {"example": True})


def test_invite_join_vector_has_no_orcid():
    """v3: a person who joins with an invite and no ORCID iD."""
    j = V["invite_join"]
    a = verify_assertion(j["assertion"], assertion_key=AKEY, node_key=FP)
    assert a["method"] == "invite" and a["orcid_commitment"] is None
    state = chain([j["binding"]])
    assert state.orcid_commitment is None and len(state.devices) == 1
    verify_identity_record(j["identity_record"], state)
    # The method `invite` carries no commitment; an ORCID method needs one.
    bad = copy.deepcopy(j["assertion"])
    bad["orcid_commitment"] = V["orcid_commitment"]["commitment"]
    with pytest.raises(FormatError):
        verify_assertion(bad, assertion_key=AKEY, node_key=FP)
    bad = copy.deepcopy(j["assertion"])
    bad["method"] = "orcid"
    with pytest.raises(FormatError):
        verify_assertion(bad, assertion_key=AKEY, node_key=FP)


def test_no_orcid_in_public_identity_documents():
    """Fix 2: the log and the public directory show a pid and a commitment."""
    orcid = V["orcid_commitment"]["orcid"]
    public = [V["assertion"], V["receipt"], *V["bindings"], V["identity_record"]]
    for doc in public:
        assert orcid not in json.dumps(doc)
        assert "Josiah" not in json.dumps(doc) or doc is V["identity_record"]
    assert is_subject(V["subject"]) and not is_subject("orcid:" + orcid)
    assert new_pid() != new_pid() and is_subject(new_pid())


def test_orcid_commitment_hides_and_binds():
    c = V["orcid_commitment"]
    salt = bytes.fromhex(c["salt"])
    assert check_orcid_opening(c["commitment"], c["orcid"], salt)
    assert not check_orcid_opening(c["commitment"], "0000-0001-5109-3700", salt)
    assert not check_orcid_opening(c["commitment"], c["orcid"], bytes(32))
    assert orcid_commitment(c["orcid"], bytes(32)) != c["commitment"]
    with pytest.raises(FormatError):
        orcid_commitment(c["orcid"], b"short")


def test_commitment_must_stay_the_same_in_the_chain():
    first, second, _ = V["bindings"]
    bad = copy.deepcopy(second)
    bad["orcid_commitment"] = "ee" * 32
    with pytest.raises(FormatError):
        chain([first, bad])
    rec = copy.deepcopy(V["identity_record"])
    rec["orcid_commitment"] = "ee" * 32
    with pytest.raises(FormatError):
        verify_identity_record(rec, chain(V["bindings"]))


def test_old_backup_v1_still_opens():
    secret = b"\7" * 20
    subject = V["subject"]
    old = {"device-ed25519": b"\1" * 32, "device-x25519": b"\2" * 32, "vault-key": b"\3" * 32}
    doc = seal_backup(secret, subject, old, schema="anagram.key_backup.v1")
    assert doc["schema"] == "anagram.key_backup.v1"
    assert open_backup(secret, doc) == old
    new = seal_backup(secret, subject, {**old, "index-key": b"\4" * 32})
    assert new["schema"] == "anagram.key_backup.v2"
    assert open_backup(secret, new)["index-key"] == b"\4" * 32
    with pytest.raises(FormatError):
        seal_backup(secret, subject, old)  # v2 needs the index key


def test_device_signin_binds_challenge_node_and_subject():
    k = SigningKey.generate()
    dev = k.public_bytes().hex()
    sig = sign_device_signin(V["subject"], "ab" * 32, FP, k)
    assert verify_device_signin(V["subject"], dev, "ab" * 32, FP, sig)
    assert not verify_device_signin(V["subject"], dev, "ac" * 32, FP, sig)
    assert not verify_device_signin(V["subject"], dev, "ab" * 32, "00" * 32, sig)
    assert not verify_device_signin("pid:" + "11" * 16, dev, "ab" * 32, FP, sig)
    assert not verify_device_signin(V["subject"], dev, "ab" * 32, FP, "zz")


def test_wrong_pinned_fingerprint_rejected():
    with pytest.raises(FormatError, match="pinned"):
        verify_node_trust(V["node_trust"], "00" * 32)


def test_changed_trust_document_rejected():
    t = copy.deepcopy(V["node_trust"])
    t["assertion_key"] = SigningKey.generate().public_bytes().hex()
    with pytest.raises(FormatError, match="signature"):
        verify_node_trust(t, FP)


@pytest.mark.parametrize(
    "field,value", [("community", "Other"), ("expires_at", "2030-01-01T00:00:00Z")]
)
def test_tampered_invite_rejected(field, value):
    inv = copy.deepcopy(V["invite"])
    inv[field] = value
    with pytest.raises(FormatError, match="signature"):
        verify_invite(inv, V["node_trust"])


def test_damaged_invite_link():
    with pytest.raises(FormatError):
        parse_invite_url(V["invite_url"][:-5])


def test_forged_assertion_rejected():
    a = copy.deepcopy(V["assertion"])
    a["subject"] = "pid:" + "12" * 16
    with pytest.raises(FormatError, match="signature"):
        verify_assertion(a, assertion_key=AKEY, node_key=FP)
    with pytest.raises(FormatError, match="different device"):
        verify_assertion(V["assertion"], assertion_key=AKEY, node_key=FP, audience=b"\1" * 32)


def test_chain_rules():
    first, second, third = V["bindings"]
    with pytest.raises(BindingError, match="seq"):
        chain([second])
    with pytest.raises(BindingError):
        chain([first, third])  # skips seq 1
    bad = copy.deepcopy(second)
    bad["device"]["x25519"] = "11" * 32  # authority signature no longer matches
    with pytest.raises(BindingError):
        chain([first, bad])
    other_node = SubjectKeys(first["subject"])
    with pytest.raises(FormatError):
        other_node.apply(first, assertion_key=SigningKey.generate().public_bytes(), node_key=FP)


def test_orcid_and_ror():
    assert validate_orcid("0000-0002-1825-0097")
    assert validate_orcid("0000-0002-1694-233X") is not None
    assert validate_orcid("fake-chen-pi")
    for bad in ("0000-0002-1825-0098", "0000-0002-1825-009", "orcid", "FAKE-x"):
        with pytest.raises(FormatError):
            validate_orcid(bad)
    assert validate_ror("05dxps055") and validate_ror("fake-northbridge")
    with pytest.raises(FormatError):
        validate_ror("https://ror.org/05dxps055")


def test_wrong_recovery_code_fails():
    secret = decode_secret(V["recovery"]["code"])
    wrong = bytes([secret[0] ^ 1]) + secret[1:]
    with pytest.raises(FormatError):
        open_backup(wrong, V["recovery"]["backup"])
    assert decode_secret(encode_secret(secret).lower().replace("-", " ")) == secret


def test_signature_helper_rejects_garbage():
    assert not doc_signature_ok({"signature": "zz"}, "t", b"\0" * 32)
