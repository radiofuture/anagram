"""The credential store: accounts, token refresh, the host allow-list,
revoke, and redaction. Tokens are only in the keystore entry
`acct-<account id>`. All calls go to `FakeGoogle`. No network."""

from __future__ import annotations

import logging

import pytest
from indexkit import KEY
from sourcekit import creds_for, fake_client, google_grant, tokens

from anagram.identity.app.keystore import FileKeystore
from anagram.local.index.store import IndexStore
from anagram.local.sources import source_state as ss
from anagram.local.sources.credentials import TokenSet, key_name
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.google import classify_google, google_error
from anagram.local.sources.http import HttpResponse, SourceFault
from anagram.local.sources.oauth import DRIVE_SCOPE, GMAIL_SCOPE

pytestmark = pytest.mark.usefixtures("no_network")

DRIVE_LIST = "https://www.googleapis.com/drive/v3/files"


class Clock:
    def __init__(self, now: float = 10_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Api(FakeGoogle):
    """FakeGoogle with one API path that answers 200 to a valid token."""

    def api(self, method, parts, headers, body, grant):
        return HttpResponse(200, {}, b'{"files": []}')


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    fake = Api(expires_in=3600)
    keystore = FileKeystore(tmp_path / "keys")
    store = IndexStore(tmp_path / "index.sqlite", KEY)
    events: list[tuple[str, dict]] = []
    creds = creds_for(
        keystore,
        store,
        fake,
        clock,
        publish=lambda t, d: events.append((t, d)),
        google=fake_client(fake),
    )
    yield fake, creds, keystore, store, clock, events
    store.close()


def grant(fake: FakeGoogle, creds, clock, scopes=(DRIVE_SCOPE,)) -> TokenSet:
    """A grant at the fake, as a complete flow gives it (no browser)."""
    return google_grant(fake, clock(), scopes)


def test_save_keeps_the_token_in_the_keystore_only(env):
    fake, creds, keystore, store, clock, events = env
    t = grant(fake, creds, clock)
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, t)
    assert keystore.list("acct-") == [key_name(acct.id)]
    assert len(acct.id) == 32
    row = dict(store.one("SELECT * FROM account WHERE id = ?", (acct.id,)))
    assert t.access_token not in str(row) and t.refresh_token not in str(row)
    assert acct.status == "ok" and DRIVE_SCOPE in acct.scopes
    assert events == [("account.state", acct.view())]
    assert "ya29" not in repr(t) and "1//" not in repr(t)


def test_same_person_and_client_gives_one_account_with_joined_scopes(env):
    fake, creds, _, _, clock, _ = env
    a = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))
    b = creds.save(
        "google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock, (GMAIL_SCOPE,))
    )
    assert a.id == b.id
    assert {DRIVE_SCOPE, GMAIL_SCOPE} <= set(b.scopes)
    assert len(creds.accounts()) == 1


def test_access_token_refreshes_near_expiry_and_erases_the_old_token(env, tmp_path):
    fake, creds, keystore, _, clock, _ = env
    t = grant(fake, creds, clock)
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, t)
    assert creds.access_token(acct.id) == t.access_token
    clock.now += 3600 - 60  # less than 120 seconds remain
    new = creds.access_token(acct.id)
    assert new != t.access_token and new in fake.tokens_issued()
    assert creds.tokens(acct.id).refresh_token == t.refresh_token  # Google keeps it
    # No file of the keystore directory holds the old access token.
    for p in (tmp_path / "keys").iterdir():
        raw = p.read_bytes()
        assert t.access_token.encode() not in raw
        assert t.access_token.encode().hex().encode() not in raw
    assert [p.name for p in (tmp_path / "keys").iterdir()] == [f"{key_name(acct.id)}.key"]


def test_invalid_grant_marks_the_account_expired(env):
    fake, creds, _, _, clock, events = env
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))
    fake.revoke_grant()
    with pytest.raises(SourceFault) as exc:
        creds.access_token(acct.id, force_refresh=True)
    assert exc.value.code == "auth_expired"
    assert creds.account(acct.id).status == "expired"
    assert events[-1] == ("account.state", {**acct.view(), "status": "expired"})
    with pytest.raises(SourceFault) as exc:
        creds.access_token(acct.id)
    assert exc.value.code == "auth_expired"


def test_request_refreshes_one_time_on_401(env):
    fake, creds, _, _, clock, _ = env
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))
    fake.expire_access()  # the token stopped working before its time
    resp = creds.request(acct.id, "GET", DRIVE_LIST, classify=classify_google, sleep=lambda s: None)
    assert resp.status == 200
    assert [c[1] for c in fake.calls[-3:]] == [
        DRIVE_LIST,
        "https://oauth2.googleapis.com/token",
        DRIVE_LIST,
    ]
    # Two 401s in sequence: the account needs a sign-in.
    fake.fail_next(401, times=2, body=google_error(401, "authError"))
    with pytest.raises(SourceFault) as exc:
        creds.request(acct.id, "GET", DRIVE_LIST, classify=classify_google)
    assert exc.value.code == "auth_expired"
    assert creds.account(acct.id).status == "expired"


def test_token_host_allow_list(env):
    fake, creds, _, _, clock, _ = env
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))
    n = len(fake.calls)
    for url in (
        "https://evil.example.org/drive/v3/files",
        "http://www.googleapis.com/drive/v3/files",
        "https://www.googleapis.com.evil.example.org/x",
        "https://api.notion.com/v1/search",
    ):
        with pytest.raises(SourceFault):
            creds.request(acct.id, "GET", url)
        with pytest.raises(SourceFault):
            creds.auth_headers(acct.id, url)
    assert len(fake.calls) == n
    assert creds.auth_headers(acct.id, "https://gmail.googleapis.com/gmail/v1/users/me/profile")


def test_revoke_deletes_the_token_also_when_the_provider_is_offline(env):
    fake, creds, keystore, store, clock, _ = env
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))
    t = creds.tokens(acct.id)
    assert creds.revoke(acct.id) is True
    assert fake.revoked == [t.refresh_token]
    assert keystore.list("acct-") == [] and creds.accounts() == []

    acct = creds.save("google", fake.sub, fake.email, fake.client_id, grant(fake, creds, clock))

    def offline(*a):
        raise SourceFault("offline", "URLError")

    creds.http = offline
    assert creds.revoke(acct.id) is False
    assert keystore.list("acct-") == [] and creds.accounts() == []


def test_client_missing_gives_its_own_fault(env):
    fake, creds, _, _, clock, _ = env
    acct = creds.save("google", fake.sub, fake.email, "another-client", grant(fake, creds, clock))
    with pytest.raises(SourceFault) as exc:
        creds.access_token(acct.id, force_refresh=True)
    assert exc.value.code == "client_missing"


def test_token_never_leaves_keystore(env, caplog, tmp_path):
    """Tokens are in no log record, no event, no error text, no account row."""
    caplog.set_level(logging.DEBUG)
    fake, creds, _, store, clock, events = env
    t = grant(fake, creds, clock)
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, t)
    ss.append_event(store, "account.state", acct.view(), clock())
    clock.now += 4000
    creds.access_token(acct.id)
    fake.revoke_grant()
    errors = []
    for fn in (
        lambda: creds.access_token(acct.id, force_refresh=True),
        lambda: creds.request(acct.id, "GET", DRIVE_LIST),
    ):
        try:
            fn()
        except SourceFault as exc:
            errors.append(str(exc) + repr(exc) + exc.detail)
    secrets = [t.access_token, t.refresh_token, *fake.tokens_issued(), fake.client_secret]
    texts = [
        caplog.text,
        str(events),
        " ".join(errors),
        str([dict(r) for r in store.q("SELECT * FROM account")]),
        str([dict(r) for r in store.q("SELECT * FROM source_event")]),
    ]
    for s in secrets:
        for text in texts:
            assert s not in text


def test_api_key_account(env):
    _, creds, _, _, _, _ = env
    acct = creds.save("zotero", "12345", "Zotero 12345", "", tokens("zkey", None, None))
    assert creds.access_token(acct.id) == "zkey"
    assert creds.auth_headers(acct.id, "https://api.zotero.org/users/12345/items")
    with pytest.raises(SourceFault):
        creds.auth_headers(acct.id, "https://www.googleapis.com/drive/v3/files")
    assert creds.revoke(acct.id) is False  # Zotero has no revoke call; the key is deleted
    assert creds.accounts() == []


def test_save_preserves_existing_refresh_token_when_regrant_omits_it(env):
    fake, creds, _, _, clock, _ = env
    initial = grant(fake, creds, clock)
    assert initial.refresh_token is not None
    acct = creds.save("google", fake.sub, fake.email, fake.client_id, initial)
    new_access = grant(fake, creds, clock, (DRIVE_SCOPE, GMAIL_SCOPE)).access_token
    regrant = TokenSet(
        access_token=new_access,
        refresh_token=None,
        expires_at=clock() + 3600,
        scopes=(DRIVE_SCOPE, GMAIL_SCOPE),
    )
    again = creds.save("google", fake.sub, fake.email, fake.client_id, regrant)
    assert again.id == acct.id
    stored = creds.tokens(acct.id)
    assert stored.access_token == new_access
    assert stored.refresh_token == initial.refresh_token
