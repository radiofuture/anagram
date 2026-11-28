"""Organizer page (/admin): organizers only, no user content."""

from __future__ import annotations

import re

import pytest
from conftest import NODE_URL, Clock
from fastapi.testclient import TestClient
from softauthn import SoftAuthenticator

from anagram.identity.node.mailer import FakeMailer
from anagram.shell.client import Client
from anagram.shell.node.app import create_app
from anagram.shell.node.home import NodeHome

ORG = "0000-0002-1825-0097"
MEMBER = "0000-0001-5109-3700"
CANARY = "CANARY-admin-claim-7f3a"


class Site:
    def __init__(self, tmp_path):
        from anagram.admission.app.join import join
        from anagram.core.nodeapi import NodeHTTPError
        from anagram.identity.app.browsers import HeadlessBrowser

        nh = NodeHome(tmp_path / "node")
        nh.create(
            origin="node.test/log",
            public_url=NODE_URL,
            community="Test community",
        )
        self.clock = Clock()
        service = nh.service()
        self.identity = nh.identity(service, mailer=FakeMailer(), clock=self.clock)
        labs = nh.labs(self.identity)
        self.admission = nh.admission(self.identity, labs)
        admin = nh.admin(self.identity, self.admission, None, service, self.clock)
        app = create_app(
            service,
            nh.trust_info(),
            self.identity,
            admin=admin,
            labs=labs,
            admission=self.admission,
        )
        self.tc = TestClient(app, base_url=NODE_URL)

        def transport(method, path, body, headers=None):
            r = self.tc.request(method, path, json=body, headers=headers or {})
            if r.status_code >= 400:
                raise NodeHTTPError(r.status_code, r.json().get("detail", ""))
            return r.json()

        def fetch(url):
            r = TestClient(app, base_url=NODE_URL).get(url, follow_redirects=False)
            return r.status_code, r.headers.get("location")

        def member(name, orcid, organizer=False):
            url = self.admission.create_invite(None, 7, organizer=organizer)["invite_url"]
            return join(
                tmp_path / name,
                url,
                transport=transport,
                browser=HeadlessBrowser(fetch),
                login_hint=orcid,
                display_name=name,
                clock=self.clock,
                open_home=Client.open,
            ).client

        self.org = member("org", ORG, organizer=True)
        self.member = member("member", MEMBER)
        self.member.labs.lab_create("Varga Lab")
        (tmp_path / "f.txt").write_text(CANARY)
        self.member.findings.commit_finding([tmp_path / "f.txt"], claim=CANARY)

    def orcid_login(self, orcid: str):
        """Browser steps: POST /admin/login, fake ORCID page, callback."""
        r = self.tc.post("/admin/login", headers={"Origin": NODE_URL}, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers["location"]
        assert "/fake-orcid/authorize" in loc and "state=" in loc
        r = self.tc.get(loc + f"&orcid={orcid}", follow_redirects=False)
        assert r.status_code == 303  # to /auth/orcid/callback
        return self.tc.get(r.headers["location"], follow_redirects=False)


@pytest.fixture
def site(tmp_path):
    return Site(tmp_path)


def csrf_of(page: str) -> str:
    return re.search(r"name=csrf value='([^']+)'", page).group(1)


def test_app_with_identity_needs_explicit_admission(tmp_path):
    """The composition root gives the admission service; the app does not
    make one (no hidden default)."""
    nh = NodeHome(tmp_path / "node")
    nh.create(origin="node.test/log", public_url=NODE_URL, community="Test community")
    service = nh.service()
    identity = nh.identity(service, mailer=FakeMailer(), clock=Clock())
    with pytest.raises(TypeError, match="admission"):
        create_app(service, nh.trust_info(), identity)
    with pytest.raises(TypeError, match="admission"):
        nh.admin(identity)
    assert create_app(service, nh.trust_info()) is not None  # a read-only log needs none


def test_login_page_shows_no_data(site):
    r = site.tc.get("/admin")
    assert r.status_code == 200 and "Sign in with ORCID" in r.text
    assert "Varga Lab" not in r.text and "Members" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_organizer_orcid_login_and_invite(site):
    r = site.orcid_login(ORG)
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    page = site.tc.get("/admin").text
    assert "Members</th><td>2" in page and "Organizers</th><td>1" in page
    assert "Varga Lab" in page and "1 member" in page
    assert "matching enclave of the network" in page  # no matching on the node
    assert "Rounds closed" not in page and "Current round" not in page
    # Never user content: no claim text, no member iD, no evidence.
    assert CANARY not in page and MEMBER not in page
    r = site.tc.post(
        "/admin/invites",
        data={"csrf": csrf_of(page), "days": "3"},
        headers={"Origin": NODE_URL},
    )
    assert r.status_code == 200 and f"{NODE_URL}/join#" in r.text
    assert CANARY not in r.text
    # Without the CSRF token, or from another origin: refused.
    assert site.tc.post("/admin/invites", data={"csrf": "x"}).status_code == 403
    bad = site.tc.post(
        "/admin/invites",
        data={"csrf": csrf_of(page)},
        headers={"Origin": "https://evil.example"},
    )
    assert bad.status_code == 403
    # Sign out ends the session.
    site.tc.post("/admin/logout", data={"csrf": csrf_of(page)}, headers={"Origin": NODE_URL})
    assert "Sign in with ORCID" in site.tc.get("/admin").text


def test_non_organizer_refused(site):
    r = site.orcid_login(MEMBER)
    assert r.status_code == 403 and "Only an organizer" in r.text
    assert "anagram_admin=" not in r.headers.get("set-cookie", "").replace("anagram_admin_flow", "")
    assert "Sign in with ORCID" in site.tc.get("/admin").text
    # A person who is not a member at all.
    r = site.orcid_login("0000-0003-1415-9269")
    assert r.status_code == 403


def test_callback_needs_the_flow_cookie(site):
    r = site.tc.post("/admin/login", headers={"Origin": NODE_URL}, follow_redirects=False)
    loc = r.headers["location"]
    r = site.tc.get(loc + f"&orcid={ORG}", follow_redirects=False)
    callback = r.headers["location"]
    site.tc.cookies.clear()  # another browser (login CSRF)
    r = site.tc.get(callback, follow_redirects=False)
    assert r.status_code == 403 and "Start again" in r.text
    assert (
        site.tc.post("/admin/login", headers={"Origin": "https://evil.example"}).status_code == 403
    )


def test_organizer_passkey_login(site):
    tok = site.org.node.token
    authn = SoftAuthenticator("node.test", NODE_URL)
    opts = site.tc.post(
        "/auth/passkeys/register/options", headers={"Authorization": f"Bearer {tok}"}
    ).json()
    r = site.tc.post(
        "/auth/passkeys/register/verify",
        json={"challenge_id": opts["challenge_id"], "credential": authn.register(opts["options"])},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    h = {"Origin": NODE_URL}
    assert site.tc.post("/admin/passkey/options", json={"orcid": ORG}).status_code == 403
    lo = site.tc.post("/admin/passkey/options", json={"orcid": ORG}, headers=h).json()
    r = site.tc.post(
        "/admin/passkey/verify",
        json={"challenge_id": lo["challenge_id"], "credential": authn.login(lo["options"])},
        headers=h,
    )
    assert r.status_code == 200
    assert "Members</th>" in site.tc.get("/admin").text
    assert "javascript" in site.tc.get("/admin/passkey.js").headers["content-type"]


def test_admin_without_orcid_hides_form_and_keeps_enter_link(tmp_path):
    nh = NodeHome(tmp_path / "node")
    nh.create(
        origin="real.example.org/log-v2",
        public_url="https://real.example.org",
        community="No ORCID Community",
        orcid_mode="production",
        orcid_client_id="",
        orcid_client_secret="",
        anchor_mode="background",
    )
    app, identity = nh.app_parts()
    tc = TestClient(app, base_url="https://real.example.org")
    r = tc.get("/admin")
    assert r.status_code == 200
    assert "Sign in with ORCID" not in r.text
    assert "Sign in with a passkey" in r.text
    r_login = tc.post(
        "/admin/login", headers={"Origin": "https://real.example.org"}, follow_redirects=False
    )
    assert r_login.status_code == 503
    # One-time enter link still works for an organizer without ORCID.
    from anagram.admission.app.join import join
    from anagram.core.nodeapi import NodeHTTPError

    def transport(method, path, body, headers=None):
        resp = tc.request(method, path, json=body, headers=headers or {})
        if resp.status_code >= 400:
            raise NodeHTTPError(resp.status_code, resp.json().get("detail", ""))
        return resp.json()

    invite_url = app.state.admission.create_invite(None, 7, organizer=True)["invite_url"]
    org = join(
        tmp_path / "org",
        invite_url,
        transport=transport,
        display_name="Org Person",
        method="invite",
        open_home=Client.open,
    ).client
    try:
        link = tc.post(
            "/admin/enter-link", headers={"Authorization": f"Bearer {org.node.token}"}
        ).json()["url"]
        enter = tc.get(link, follow_redirects=False)
        assert enter.status_code == 303 and enter.headers["location"] == "/admin"
        assert "Members</th><td>1" in tc.get("/admin").text
    finally:
        org.close()


def test_admin_passkey_options_no_enumeration_and_origin_and_logout_csrf(site):
    h = {"Origin": NODE_URL}
    # Unknown and non-organizer ORCIDs get a stable decoy allowCredentials entry.
    unknown1 = site.tc.post(
        "/admin/passkey/options", json={"orcid": "0000-0003-1415-9269"}, headers=h
    ).json()
    unknown2 = site.tc.post(
        "/admin/passkey/options", json={"orcid": "0000-0003-1415-9269"}, headers=h
    ).json()
    non_org = site.tc.post("/admin/passkey/options", json={"orcid": MEMBER}, headers=h).json()
    assert len(unknown1["options"]["allowCredentials"]) == 1
    assert unknown1["options"]["allowCredentials"] == unknown2["options"]["allowCredentials"]
    assert len(non_org["options"]["allowCredentials"]) == 1
    assert unknown1["options"]["allowCredentials"] != non_org["options"]["allowCredentials"]
    # POST /admin/login requires Origin header.
    assert site.tc.post("/admin/login", follow_redirects=False).status_code == 403
    # Failed logout CSRF returns 403 and does NOT clear the session cookie.
    site.orcid_login(ORG)
    page = site.tc.get("/admin").text
    assert "Members</th>" in page
    bad_logout = site.tc.post(
        "/admin/logout", data={"csrf": "wrong-token"}, headers=h, follow_redirects=False
    )
    assert bad_logout.status_code == 403
    assert "anagram_admin=" not in bad_logout.headers.get("set-cookie", "")
    assert "Members</th>" in site.tc.get("/admin").text


def test_orcid_callback_redirect_sets_security_headers(site):
    from anagram.shell import pages

    r = site.tc.post(
        "/auth/orcid/start",
        json={
            "code_challenge": "a" * 43,
            "device_key": "00" * 32,
            "nonce": "11" * 16,
            "return_to": "http://127.0.0.1:9999/auth/callback",
        },
    )
    assert r.status_code == 200
    auth_url = r.json()["authorize_url"]
    r2 = site.tc.get(auth_url + f"&orcid={MEMBER}", follow_redirects=False)
    assert r2.status_code == 303
    r3 = site.tc.get(r2.headers["location"], follow_redirects=False)
    assert r3.status_code == 303
    for k, v in pages.HEADERS.items():
        assert r3.headers.get(k.lower()) == v
