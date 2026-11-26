"""ORCID sign-in adapters (OAuth 2.0 authorization code, scope `/authenticate`).

ORCID accepts only exact, registered HTTPS redirect URIs. So the redirect target
is always the node (`<public_url>/auth/orcid/callback`), never a local client.

- `OrcidOAuth`: real ORCID (production or sandbox). Not run in tests.
- `FakeOrcid`: deterministic local fake for tests and local development. The
  node serves its authorize page at `/fake-orcid/authorize`.
"""

from __future__ import annotations

import json
import secrets
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

from anagram.identity.formats.documents import validate_orcid

ORCID_BASES = {"production": "https://orcid.org", "sandbox": "https://sandbox.orcid.org"}
SCOPE = "/authenticate"
REGISTER_URL = "https://orcid.org/developer-tools"

# post(url, form fields) -> JSON response
FormPost = Callable[[str, dict[str, str]], dict]


class OrcidError(Exception):
    pass


@dataclass(frozen=True)
class OrcidUser:
    orcid: str
    name: str | None


class OrcidAdapter(ABC):
    mode: str

    @abstractmethod
    def authorize_url(self, state: str, redirect_uri: str, login_hint: str | None = None) -> str:
        """The URL that the user's browser opens."""

    @abstractmethod
    def exchange(self, code: str, redirect_uri: str) -> OrcidUser:
        """Exchange the authorization code for the user's ORCID iD."""


def urllib_form_post(url: str, fields: dict[str, str]) -> dict:  # pragma: no cover - network
    if not url.startswith("https://"):
        raise OrcidError("ORCID token URL must be https")
    req = urllib.request.Request(  # noqa: S310 - https checked above
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read())


class OrcidOAuth(OrcidAdapter):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        mode: str = "production",
        post: FormPost = urllib_form_post,
    ) -> None:
        if mode not in ORCID_BASES:
            raise ValueError(f"unknown ORCID mode: {mode}")
        if not client_id or not client_secret:
            raise ValueError("ORCID needs a client ID and a client secret")
        self.mode = mode
        self.base = ORCID_BASES[mode]
        self.client_id = client_id
        self.client_secret = client_secret
        self.post = post

    def authorize_url(self, state: str, redirect_uri: str, login_hint: str | None = None) -> str:
        q = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": SCOPE,
            "state": state,
        }
        return f"{self.base}/oauth/authorize?{urllib.parse.urlencode(q)}"

    def exchange(self, code: str, redirect_uri: str) -> OrcidUser:
        try:
            data = self.post(
                f"{self.base}/oauth/token",
                {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
        except Exception as exc:  # network or HTTP error
            raise OrcidError(f"ORCID token exchange failed: {exc}") from exc
        orcid = data.get("orcid")
        try:
            validate_orcid(orcid)
        except ValueError as exc:
            raise OrcidError("ORCID returned no valid iD") from exc
        name = data.get("name") or None
        return OrcidUser(orcid, name if isinstance(name, str) else None)


class FakeOrcid(OrcidAdapter):
    """A local stand-in for ORCID. Use only for tests and local development."""

    mode = "fake"

    def __init__(self, public_url: str) -> None:
        self.public_url = public_url.rstrip("/")
        self._codes: dict[str, tuple[OrcidUser, str]] = {}

    def authorize_url(self, state: str, redirect_uri: str, login_hint: str | None = None) -> str:
        q = {"redirect_uri": redirect_uri, "state": state}
        if login_hint:
            q["orcid"] = login_hint
        return f"{self.public_url}/fake-orcid/authorize?{urllib.parse.urlencode(q)}"

    def approve(self, orcid: str, name: str | None, redirect_uri: str) -> str:
        """The fake 'user signed in' step. Returns an authorization code."""
        validate_orcid(orcid)
        code = secrets.token_urlsafe(16)
        self._codes[code] = (OrcidUser(orcid, name), redirect_uri)
        return code

    def exchange(self, code: str, redirect_uri: str) -> OrcidUser:
        item = self._codes.pop(code, None)
        if item is None or item[1] != redirect_uri:
            raise OrcidError("unknown or used authorization code")
        return item[0]
