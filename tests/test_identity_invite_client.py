"""R8: join, sign in again, and recover with no ORCID iD;
link an ORCID iD later (optional)."""

import json
import secrets

import pytest

from anagram.admission.formats import parse_invite_url
from anagram.admission.node.reader import ReaderInvites
from anagram.admission.node.store import AdmissionStore
from anagram.core.crypto.x25519 import X25519Key
from anagram.core.errors import ClientError, NodeError
from anagram.identity.app.identity import login
from anagram.identity.app.keychain import open_keystore
from anagram.identity.app.kit import recover
from anagram.identity.app.session import clear_session, read_session
from anagram.shell.client import Client


def test_join_with_invite_only(net, tmp_path):
    link = net.invite()
    r = net.join_invite(tmp_path / "ada", "Ada Lovelace", stated_email="ada@lab.org", invite=link)
    c = r.client
    assert r.status == "joined" and r.recovery_code and r.receipt["subject"] == c.device.subject
    cfg = json.loads((tmp_path / "ada" / "config.json").read_text())["identity"]
    assert cfg["orcid"] is None and cfg["orcid_commitment"] is None
    assert c.account.orcid is None
    me = c.account.whoami()
    assert me["identity"]["display_name"] == "Ada Lovelace"
    assert me["identity"]["orcid_commitment"] is None
    assert me["email"] == "ada@lab.org" and me["invited_by"] == {"by": None, "via": "node"}
    assert c.directory.lookup(c.device.subject).orcid_commitment is None
    # Join again on the same home is safe.
    again = net.join_invite(tmp_path / "ada", "Ada Lovelace", invite=link)
    assert again.subject == c.device.subject


def test_sign_in_again_with_the_device_key(net, tmp_path):
    c = net.join_invite(tmp_path / "ada").client
    home = tmp_path / "ada"
    clear_session(c.keystore)
    assert read_session(c.keystore) is None
    r = login(home, transport=net.transport, clock=net.clock, open_home=Client.open)
    assert r.status == "signed_in" and r.subject == c.device.subject
    assert read_session(r.client.keystore) is not None
    r.client.vault.close()


def test_device_login_refused_for_a_removed_device(net, tmp_path):
    first = net.join_invite(tmp_path / "one").client
    two = net.join_invite(tmp_path / "two", invite=net.invite())
    assert two.subject != first.device.subject  # a second invite is a second person
    # Copy the config of person one to a new home: its device key is not active.
    home = tmp_path / "copy"
    home.mkdir()
    (home / "config.json").write_text((tmp_path / "one" / "config.json").read_text())
    ks = open_keystore(home)
    ks.put("device-ed25519", secrets.token_bytes(32))
    ks.put("device-x25519", X25519Key.generate().private_bytes())
    ks.put("vault-key", secrets.token_bytes(32))
    with pytest.raises(ClientError, match="recovery kit"):
        login(home, transport=net.transport, clock=net.clock, open_home=Client.open)


def test_recover_with_no_orcid(net, tmp_path):
    r = net.join_invite(tmp_path / "ada", "Ada")
    kit = r.kit_text
    new = recover(
        tmp_path / "new", kit, transport=net.transport, clock=net.clock, open_home=Client.open
    )
    assert new.device.subject == r.subject and new.account.orcid is None
    new.vault.close()


def test_join_with_a_lab_invite_only(net, tmp_path):
    pi = net.join_invite(tmp_path / "pi", "Pi").client
    net.identity.db.execute(
        "UPDATE members SET role = 'organizer' WHERE subject = ?", (pi.device.subject,)
    )  # P11: on the default node a lab needs an organizer invite
    lab_id = pi.labs.lab_create("Chen Lab")["lab_id"]
    inv = pi.admission.lab_invite(lab_id)
    r = net.join_invite(tmp_path / "new", "New Member", invite=inv["url"])
    assert r.status == "joined" and r.receipt is None
    assert r.client.lab_roster.lab_state(lab_id).members[r.subject] == "member"
    assert net.admission.invited_by(r.subject) == {"by": pi.device.subject, "via": "lab"}
    # The link was for one person: the node refuses a second sign-in with it.
    with pytest.raises(Exception, match="no longer valid"):
        net.join_invite(tmp_path / "third", invite=inv["url"])


def test_reader_invite_to_an_email_asks_for_the_code(net, tmp_path):
    readers = ReaderInvites(net.identity, AdmissionStore(net.identity.db, net.identity.lock))
    owner = net.join_invite(tmp_path / "owner").client
    made = readers.create(owner.device.subject, {"kind": "email", "value": "r@uni.edu"}, None)
    codes = []

    def code():
        codes.append(net.mailer.outbox[-1][0])
        return net.mailer.outbox[-1][2].split("code is ")[1][:8]

    r = net.join_invite(tmp_path / "reader", "Reader", invite=made["invite_url"], email_code=code)
    assert r.status == "joined" and codes == ["r@uni.edu"]
    assert net.admission.invited_by(r.subject) == {"by": owner.device.subject, "via": "reader"}
    # With no code the join stops before an account.
    other = readers.create(owner.device.subject, {"kind": "email", "value": "x@uni.edu"}, None)
    with pytest.raises(ClientError, match="code"):
        net.join_invite(tmp_path / "x", invite=other["invite_url"])


def test_link_orcid_is_optional_and_survives_a_restore(net, tmp_path):
    r = net.join_invite(tmp_path / "ada", "Ada")
    c = r.client
    assert c.account.link_orcid(net.browser(), login_hint="fake-ada-linked") == "fake-ada-linked"
    # S4: a linked iD is not a room key; the room key stays the pid.
    assert c.account.orcid == "fake-ada-linked"
    assert c.account.whoami()["orcid_linked"]
    assert (
        c.directory.lookup(c.device.subject).orcid_commitment is None
    )  # the key directory does not change
    c.personal.sync_store()
    kit = c.account.make_recovery_kit().text
    new = recover(
        tmp_path / "new", kit, transport=net.transport, clock=net.clock, open_home=Client.open
    )
    assert new.account.orcid == "fake-ada-linked"
    new.vault.close()
    # Another member cannot link the same iD.
    b = net.join_invite(tmp_path / "bea", invite=net.invite()).client
    with pytest.raises(Exception, match="another member"):
        b.account.link_orcid(net.browser(), login_hint="fake-ada-linked")


def test_orcid_join_still_works(net, tmp_path):
    """Migration (R8-13): a person who joins with ORCID keeps the commitment."""
    r = net.join(tmp_path / "old", "fake-old-person")
    assert r.client.account.orcid == "fake-old-person"
    assert r.client.directory.lookup(r.subject).orcid_commitment == net.commitment(
        "fake-old-person"
    )
    assert parse_invite_url(net.invite())["token"]
    assert NodeError  # imported for symmetry with the node tests


def test_join_subject_mismatch_preserves_existing_session_and_private_modes(net, tmp_path):
    import os
    import stat

    from anagram.identity.app.kit import write_kit_file

    home = tmp_path / "ada"
    r = net.join_invite(home, "Ada")
    old_session = read_session(r.client.keystore)
    assert old_session is not None
    # M12: config.json and kit files are written with 0600 permissions.
    assert stat.S_IMODE(os.stat(home / "config.json").st_mode) == 0o600
    kit_file = write_kit_file(home, tmp_path / "kit.md", r.kit_text)
    assert stat.S_IMODE(os.stat(kit_file).st_mode) == 0o600
    r.client.vault.close()

    # M11: joining with another person's ORCID on an existing home must not
    # overwrite the existing session and must log out the mismatched session.
    with pytest.raises(ClientError, match="another person"):
        net.join(home, "fake-different-person", "Other")
    ks = open_keystore(home)
    assert read_session(ks) == old_session
