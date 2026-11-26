"""What a copy of the data directory shows (R1 plan, section 12).

The keystore is the sealed keystore with a `MemorySlot` in the place of the
OS keychain: the master key is not on the disk, as with a real keychain. The
tests scan each file of a joined home for secrets and canary strings.
No real keychain. No network.
"""

from __future__ import annotations

import json

import pytest
from conftest import make_net
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client

from anagram.core.errors import ClientError
from anagram.identity.app import keychain
from anagram.identity.app.keychain import MemorySlot, SealedKeystore, open_keystore, slots
from anagram.identity.app.keystore import KeystoreError, MemoryKeystore
from anagram.identity.app.kit import KIT_FILE, parse_kit
from anagram.identity.app.session import (
    SESSION_KEY,
    clear_session,
    read_session,
    session_token,
    write_session,
)
from anagram.shell.ui.state import UIState

pytestmark = pytest.mark.usefixtures("no_network")

BLOCK = "CANARY-BLOCK-3391"
RING = "CANARY-RING-8842"


@pytest.fixture
def slot(monkeypatch):
    """The policy `os`, with one memory slot in the place of the OS keychain."""
    s = MemorySlot()
    monkeypatch.setenv("ANAGRAM_KEYSTORE", "os")
    monkeypatch.setattr(slots, "os_slot", lambda: s)
    monkeypatch.setattr(keychain, "_masters", {})
    return s


def files(home) -> dict[str, bytes]:
    return {str(p.relative_to(home)): p.read_bytes() for p in home.rglob("*") if p.is_file()}


def assert_absent(home, secrets: dict[str, str | bytes]) -> None:
    """No file of the home holds a secret: as text, as bytes, or as hex."""
    for name, data in files(home).items():
        for label, secret in secrets.items():
            raw = secret.encode() if isinstance(secret, str) else secret
            assert raw not in data, f"{label} is in {name}"
            assert raw.hex().encode() not in data, f"{label} (hex) is in {name}"


def joined_ui(tmp_path):
    net = make_net(tmp_path)
    home = tmp_path / "me"
    svc, tc = ui_client(net, home)
    launched(tc)
    invite = net.invite()
    svc.join.prepare(invite, login_hint="fake-at-rest", name="Rest Person")
    join_via_ui(net, svc, tc, None, None, prepare=False)
    return net, home, svc, tc, invite


def test_home_has_no_plaintext_secrets(tmp_path, slot):
    net, home, svc, tc, invite = joined_ui(tmp_path)
    assert type(svc.keystore()) is SealedKeystore
    svc.state.update(blocked=[{"id": BLOCK}])
    assert tc.post("/api/rings", json={"name": RING}, headers=ORIGIN).status_code == 200

    token = session_token(svc.keystore())
    assert token and svc.state.get("invite") == invite
    ks = svc.keystore()
    secrets = {
        "session token": token,
        "invite link": invite,
        "invite fragment": invite.split("#", 1)[1],
        "block list": BLOCK,
        "ring name": RING,
        "master key": next(iter(slot.items.values())),
        **{name: ks.get(name) for name in ks.list()},
    }
    assert {"node-session", "ui-state-key", "local-store-key", "vault-key"} <= set(ks.list())
    assert_absent(home, secrets)

    names = set(files(home))
    assert "session.json" not in names and "ui.json" not in names
    assert "ui.sealed" in names and "keys/node-session.skey" in names
    # config.json stays plain (the claim text names what it shows).
    assert json.loads((home / "config.json").read_text())["identity"]["subject"]


def test_sign_out_removes_the_session(tmp_path, slot):
    _, home, svc, tc, _ = joined_ui(tmp_path)
    assert svc.joined()
    assert tc.post("/api/logout", headers=ORIGIN).json() == {"signed_out": True}
    assert SESSION_KEY not in svc.keystore().list()
    assert not svc.joined()
    assert tc.get("/api/overview").json()["signed_in_before"]


def test_session_rules():
    ks = MemoryKeystore()
    assert read_session(ks) is None and session_token(ks) is None
    write_session(ks, {"token": "first"})
    write_session(ks, {"token": "second"})
    assert session_token(ks) == "second"
    # A value that is not a session document is no session.
    ks.put(SESSION_KEY, b"not json", overwrite=True)
    assert read_session(ks) is None
    clear_session(ks)
    assert SESSION_KEY not in ks.list()


def test_old_ui_state_file_is_sealed_and_erased(tmp_path, slot):
    home = tmp_path / "old"
    home.mkdir()
    (home / "ui.json").write_text(json.dumps({"blocked": [{"id": BLOCK}], "kit_saved": True}))
    ks = open_keystore(home)
    state = UIState(home, ks)
    assert state.load() == {"blocked": [{"id": BLOCK}], "kit_saved": True}
    assert not (home / "ui.json").exists()
    assert_absent(home, {"block list": BLOCK})
    state.update(invite="https://node.test/join#CANARY-INVITE")
    assert_absent(home, {"invite": "CANARY-INVITE"})
    # A second object reads the same state; the sealed state wins over a plain file.
    (home / "ui.json").write_text(json.dumps({"kit_saved": False}))
    again = UIState(home, lambda: ks)
    assert again.get("kit_saved") is True and again.get("invite").endswith("CANARY-INVITE")
    assert not (home / "ui.json").exists()


def test_ui_state_that_does_not_open_is_not_replaced(tmp_path, slot):
    home = tmp_path / "h"
    state = UIState(home, open_keystore(home))
    state.update(kit_saved=True)
    before = (home / "ui.sealed").read_bytes()
    assert (home / "ui.sealed").stat().st_mode & 0o777 == 0o600

    other = UIState(home, MemoryKeystore())  # another key
    with pytest.raises(KeystoreError):
        other.load()
    with pytest.raises(KeystoreError):
        other.update(kit_saved=False)
    assert (home / "ui.sealed").read_bytes() == before


def test_ui_state_with_no_keystore_is_the_plain_file(tmp_path):
    state = UIState(tmp_path)
    assert state.load() == {}
    state.update(a=1)
    assert json.loads((tmp_path / "ui.json").read_text()) == {"a": 1}


# ------------------------------------------------------------ recovery kit


def kit_names(home) -> list[str]:
    return [n for n in files(home) if "kit" in n.lower()]


def test_join_writes_no_kit_file(tmp_path, slot):
    _, home, svc, tc, _ = joined_ui(tmp_path)
    assert kit_names(home) == []
    kit = tc.get("/api/recovery-kit").json()
    assert kit["pending"] and kit["available"] and not kit["saved"]
    text = tc.get("/api/recovery-kit/file").text
    code = parse_kit(text)["recovery code"]
    assert code == kit["code"]
    # The kit is only in the encrypted local vault.
    assert_absent(home, {"recovery code": code, "kit text": text})

    # A sign-out does not lose a kit that the person did not save.
    tc.post("/api/logout", headers=ORIGIN)
    assert tc.get("/api/recovery-kit").json()["code"] == code

    assert tc.post("/api/recovery-kit/saved", headers=ORIGIN).json() == {"saved": True}
    assert tc.get("/api/recovery-kit").json() == {
        "available": False,
        "pending": False,
        "saved": True,
    }
    assert tc.get("/api/recovery-kit/file").status_code == 404
    assert kit_names(home) == []


def test_new_kit_is_pending_and_not_a_file(tmp_path, slot):
    _, home, svc, tc, _ = joined_ui(tmp_path)
    tc.post("/api/recovery-kit/saved", headers=ORIGIN)
    code = tc.post("/api/recovery-kit/new", headers=ORIGIN).json()["code"]
    kit = tc.get("/api/recovery-kit").json()
    assert kit["pending"] and kit["code"] == code and not kit["saved"]
    assert kit_names(home) == []
    assert_absent(home, {"recovery code": code})


def test_old_kit_file_moves_into_the_vault(tmp_path, slot):
    _, home, svc, tc, _ = joined_ui(tmp_path)
    text = tc.get("/api/recovery-kit/file").text
    code = parse_kit(text)["recovery code"]
    with svc.session() as c:
        c.account.drop_pending_kit()
    (home / KIT_FILE).write_text(text)  # as an older home has it

    kit = tc.get("/api/recovery-kit").json()
    assert kit["pending"] and kit["code"] == code
    assert not (home / KIT_FILE).exists()
    assert tc.get("/api/recovery-kit/file").text == text
    assert_absent(home, {"recovery code": code})

    # After the person saved a kit, an old file is erased and is not offered again.
    tc.post("/api/recovery-kit/saved", headers=ORIGIN)
    (home / KIT_FILE).write_text(text)
    assert not tc.get("/api/recovery-kit").json()["pending"]
    assert not (home / KIT_FILE).exists()


def test_kit_file_is_refused_in_the_data_directory(net, tmp_path):
    r = net.join(tmp_path / "a", "fake-kit", "Kit Person")
    c = r.client
    assert kit_names(tmp_path / "a") == []
    for inside in (tmp_path / "a" / "kit.md", tmp_path / "a" / "keys" / ".." / "sub" / "kit.md"):
        with pytest.raises(ClientError, match="outside the Anagram data directory"):
            c.account.write_recovery_kit(inside)
    with pytest.raises(ClientError, match="directory"):
        c.account.write_recovery_kit(tmp_path)
    out, code = c.account.write_recovery_kit(tmp_path / "my-kit.md")
    assert out == (tmp_path / "my-kit.md").resolve() and out.stat().st_mode & 0o777 == 0o600
    assert parse_kit(out.read_text())["recovery code"] == code
    c.vault.close()
