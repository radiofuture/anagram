"""OAuth for an installed app: PKCE, the loopback receiver, the flow against
`FakeGoogle`, and the order of OAuth client resolution.

The receiver tests use `loopback_only` (a socket connect to 127.0.0.1 only),
not `no_network`, which refuses loopback too (integration I21). No test calls
Google or Notion."""

from __future__ import annotations

import json
import socket
import threading
import urllib.parse

import pytest
from sourcekit import browse, fake_client, loopback_only  # noqa: F401 - fixture

from anagram.core.errors import ClientError
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.oauth import (
    DRIVE_SCOPE,
    NOTION,
    PROVIDERS,
    LoopbackReceiver,
    OAuthClient,
    OAuthError,
    OAuthFlow,
    candidate_clients,
    client_resolver,
    pkce_challenge,
)

pytestmark = pytest.mark.usefixtures("loopback_only")


def test_pkce_vector():
    # RFC 7636 appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_loopback_only_refuses_other_addresses():
    s = socket.socket()
    try:
        with pytest.raises(AssertionError):
            s.connect(("203.0.113.5", 443))
    finally:
        s.close()


# ----------------------------------------------------------------- receiver


def test_oauth_receiver_binds_loopback_only():
    r = LoopbackReceiver(state="s")
    try:
        assert r.server.server_address[0] == "127.0.0.1"
        assert r.redirect_uri == f"http://127.0.0.1:{r.port}/oauth/callback"
    finally:
        r.close()
    with pytest.raises(TypeError):
        LoopbackReceiver(host="0.0.0.0")  # noqa: S104 - the parameter does not exist


def test_oauth_receiver_wrong_state_refused():
    r = LoopbackReceiver(state="right-state")
    try:
        status, page = browse(r.redirect_uri + "?code=abc&state=wrong")
        assert status == 400
        assert "did not accept" in page
        status, _ = browse(r.redirect_uri + "?code=abc")
        assert status == 400
        status, _ = browse(f"http://127.0.0.1:{r.port}/other?code=abc&state=right-state")
        assert status == 400
        # The flow still waits for the correct callback.
        status, page = browse(r.redirect_uri + "?code=abc&state=right-state")
        assert status == 200
        assert "close this tab" in page
        assert r.wait(timeout_s=2) == {"code": "abc"}
    finally:
        r.close()


def test_oauth_receiver_second_request_refused():
    r = LoopbackReceiver(state="st")
    uri = r.redirect_uri
    assert browse(uri + "?code=one&state=st")[0] == 200
    assert r.wait(timeout_s=2) == {"code": "one"}
    with pytest.raises(OSError):
        browse(uri + "?code=two&state=st")


def test_oauth_receiver_timeout_and_cancel():
    r = LoopbackReceiver(state="st")
    assert r.wait(timeout_s=0.05) == {"error": "timeout"}
    r2 = LoopbackReceiver(state="st")
    threading.Timer(0.05, r2.cancel).start()
    assert r2.wait(timeout_s=5) == {"error": "cancelled"}


def test_oauth_receiver_gives_the_provider_error():
    r = LoopbackReceiver(state="st")
    assert browse(r.redirect_uri + "?error=access_denied&state=st")[0] == 200
    assert r.wait(timeout_s=2) == {"error": "access_denied"}


def test_oauth_receiver_fixed_ports_take_the_first_free_one():
    blocker = LoopbackReceiver()
    try:
        port = blocker.port
        r = LoopbackReceiver((port, 0), host_name="localhost")
        try:
            assert r.port != port
            assert r.redirect_uri.startswith("http://localhost:")
        finally:
            r.close()
        with pytest.raises(OAuthError):
            LoopbackReceiver((port,))
    finally:
        blocker.close()


# --------------------------------------------------------------------- flow


def _flow(fake: FakeGoogle, scopes=(DRIVE_SCOPE,), **kw) -> OAuthFlow:
    return OAuthFlow(
        PROVIDERS["google"], fake_client(fake), list(scopes), fake, clock=lambda: 1000.0, **kw
    )


def test_complete_flow_through_the_loopback_receiver():
    fake = FakeGoogle()
    flow = _flow(fake, login_hint="member@example.org")
    url = flow.start()
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["code_challenge_method"] == "S256"
    assert len(q["code_challenge"]) == 43
    assert q["access_type"] == "offline"
    assert q["include_granted_scopes"] == "true"
    assert q["prompt"] == "consent"
    assert q["login_hint"] == "member@example.org"
    assert set(q["scope"].split()) == {"openid", "email", DRIVE_SCOPE}
    assert q["redirect_uri"].startswith("http://127.0.0.1:")
    assert "client_secret" not in url
    status, _ = browse(fake.authorize(url))
    assert status == 200
    tokens, ident = flow.finish(timeout_s=5)
    assert ident == {"external_id": fake.sub, "label": fake.email}
    assert tokens.access_token in fake.tokens_issued()
    assert tokens.refresh_token and tokens.expires_at == 1000.0 + fake.expires_in
    assert DRIVE_SCOPE in tokens.scopes
    # The token exchange sent the verifier; the fake checked it.
    assert [c for c in fake.calls if c[0] == "POST"] == [
        ("POST", "https://oauth2.googleapis.com/token")
    ]


def test_flow_denied():
    fake = FakeGoogle()
    flow = _flow(fake)
    browse(fake.authorize(flow.start(), deny=True))
    with pytest.raises(OAuthError) as exc:
        flow.finish(timeout_s=5)
    assert exc.value.code == "denied"
    assert fake.calls == []


def test_flow_with_a_scope_cleared_in_the_consent():
    fake = FakeGoogle()
    flow = _flow(fake)
    browse(fake.authorize(flow.start(), drop=(DRIVE_SCOPE,)))
    with pytest.raises(OAuthError) as exc:
        flow.finish(timeout_s=5)
    assert exc.value.code == "scope_missing"


def test_flow_with_a_stolen_code_and_no_verifier_fails():
    fake = FakeGoogle()
    flow = _flow(fake)
    redirect = fake.authorize(flow.start())
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect).query))["code"]
    body = urllib.parse.urlencode(
        {
            "client_id": fake.client_id,
            "client_secret": fake.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": flow.receiver.redirect_uri,
            "code_verifier": "a" * 64,
        }
    ).encode()
    assert fake("POST", "https://oauth2.googleapis.com/token", {}, body).status == 400
    flow.cancel()


def test_flow_timeout_and_cancel():
    fake = FakeGoogle()
    flow = _flow(fake)
    flow.start()
    with pytest.raises(OAuthError) as exc:
        flow.finish(timeout_s=0.05)
    assert exc.value.code == "expired"
    flow2 = _flow(fake)
    flow2.start()
    flow2.cancel()
    with pytest.raises(OAuthError) as exc:
        flow2.finish(timeout_s=5)
    assert exc.value.code == "cancelled"


def test_notion_authorize_url():
    flow = OAuthFlow(NOTION, OAuthClient("notion-client", "notion-secret", "build"), [], None)
    try:
        url = flow.start()
    except OAuthError:
        pytest.skip("the registered Notion ports are in use on this computer")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert url.startswith("https://api.notion.com/v1/oauth/authorize?")
    assert q["owner"] == "user"
    assert "code_challenge" not in q and "scope" not in q
    port = urllib.parse.urlsplit(q["redirect_uri"]).port
    assert q["redirect_uri"] == f"http://localhost:{port}/oauth/callback"
    assert port in (53682, 53683, 53684)
    flow.cancel()


# ------------------------------------------------------- client resolution


class _Policy:
    def __init__(self, oauth_clients):
        self.oauth_clients = oauth_clients


class _Labs:
    def __init__(self, settings: dict[str, dict]):
        self.settings = settings

    def lab_list(self):
        return [{"lab_id": k} for k in self.settings]

    def lab_policy(self, lab_id):
        if self.settings[lab_id] is None:  # the person left this lab
            raise ClientError("not in the lab")
        return _Policy(self.settings[lab_id])


def test_client_resolution_order(tmp_path):
    build = tmp_path / "build.json"
    home = tmp_path / "home"
    home.mkdir()
    assert candidate_clients("google", home=home, build_file=build) == []
    (home / "oauth-clients.json").write_text(json.dumps({"google": {"client_id": "user-id"}}))
    assert client_resolver(None, home, build)("google").origin == "user"
    build.write_text(json.dumps({"google": {"client_id": "build-id", "client_secret": "x"}}))
    assert client_resolver(None, home, build)("google").client_id == "build-id"
    # A lab with no client, and a lab with no policy on this computer: no
    # lab client from them, and no failure.
    assert client_resolver(_Labs({"a": {}, "b": None}), home, build)("google").origin == "build"
    lab = _Labs(
        {
            "lab-a": {},
            "lab-x": None,
            "lab-b": {"google": {"client_id": "lab-id", "client_secret": "y"}},
        }
    )
    found = client_resolver(lab, home, build)("google")
    assert (found.client_id, found.origin) == ("lab-id", "lab")
    # The client of an existing grant: found by its ID in each origin.
    assert client_resolver(lab, home, build)("google", "user-id").origin == "user"
    assert client_resolver(lab, home, build)("google", "gone") is None
    assert client_resolver(lab, home, build)("notion") is None
    # The secret is never in the text form of a client.
    lab_secret = _Labs({"l": {"google": {"client_id": "c", "client_secret": "s3cr3t"}}})
    assert "s3cr3t" not in repr(client_resolver(lab_secret, home, build)("google"))


def test_loopback_receiver_auto_closes_after_timeout():
    import time

    from anagram.local.sources.oauth import LoopbackReceiver

    rec = LoopbackReceiver(state="st", timeout_s=0.05)
    try:
        deadline = time.monotonic() + 2.0
        while not rec._closed and time.monotonic() < deadline:
            time.sleep(0.02)
        assert rec._closed is True
    finally:
        rec.close()
