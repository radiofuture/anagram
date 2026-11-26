"""Test helpers for connected sources: the `loopback_only` socket guard, a
browser that follows the OAuth redirect to the loopback receiver, and a
credential store on a fake provider. No test uses the network."""

from __future__ import annotations

import socket
import urllib.request

import pytest

from anagram.local.sources.credentials import CredentialStore, TokenSet
from anagram.local.sources.oauth import OAuthClient


@pytest.fixture
def loopback_only(monkeypatch):
    """Permit a socket connect to 127.0.0.1 only (the OAuth receiver). Each
    other address is a bug. `no_network` refuses loopback too, so the
    receiver tests use this fixture in its place (integration I21)."""
    real = socket.socket.connect

    def connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else address
        if host != "127.0.0.1":
            raise AssertionError(f"network use in a test: {host}")
        return real(self, address, *args, **kwargs)

    def create_connection(address, *args, **kwargs):
        if address[0] not in ("127.0.0.1", "localhost"):
            raise AssertionError(f"network use in a test: {address[0]}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(kwargs.get("timeout") or (args[0] if args else 5))
        connect(sock, ("127.0.0.1", address[1]))
        return sock

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", create_connection)


def browse(url: str) -> tuple[int, str]:
    """The browser follows a redirect to the loopback receiver. A
    `localhost` URL goes to 127.0.0.1 (the receiver binds that address)."""
    url = url.replace("http://localhost:", "http://127.0.0.1:", 1)
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - loopback only
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def fake_client(fake) -> OAuthClient:
    return OAuthClient(fake.client_id, fake.client_secret, "user")


def resolver(**by_provider: OAuthClient):
    """A client resolver with one client for each provider."""

    def resolve(provider: str, client_id: str | None = None):
        c = by_provider.get(provider)
        if c is None or (client_id is not None and c.client_id != client_id):
            return None
        return c

    return resolve


def creds_for(keystore, store, http, clock, publish=None, **clients) -> CredentialStore:
    return CredentialStore(keystore, store, http, resolver(**clients), clock=clock, publish=publish)


def tokens(access: str, refresh: str | None, expires_at: float | None, *scopes: str) -> TokenSet:
    return TokenSet(access, expires_at, refresh, tuple(scopes))


REDIRECT = "http://127.0.0.1:1/oauth/callback"


def google_grant(fake, now: float, scopes=()) -> TokenSet:
    """A grant at `FakeGoogle` as a complete sign-in gives it, with no
    browser and no receiver (the receiver has its own tests)."""
    import urllib.parse

    from anagram.local.sources.oauth import parse_tokens

    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(
        {
            "client_id": fake.client_id,
            "include_granted_scopes": "true",
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "scope": " ".join(sorted({"openid", "email", *scopes})),
            "state": "st",
        }
    )
    redirect = fake.authorize(url)
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirect).query))["code"]
    body = urllib.parse.urlencode(
        {
            "client_id": fake.client_id,
            "client_secret": fake.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT,
        }
    ).encode()
    resp = fake("POST", "https://oauth2.googleapis.com/token", {}, body)
    return parse_tokens(resp.json(), now)


def google_account(creds: CredentialStore, fake, now: float, *scopes: str):
    """Save a Google account with a grant of `scopes`."""
    t = google_grant(fake, now, scopes)
    return creds.save("google", fake.sub, fake.email, fake.client_id, t)
