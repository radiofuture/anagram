"""Browser walk of the Sources screens (plan R3 step S15; Playwright,
headless Chromium).

One joined member who is PI of a lab, a real `UIServer` on 127.0.0.1, and
`FakeGoogle` as the transport of connected sources. The "system browser" of
a sign-in is a thread that gives the authorize URL to `FakeGoogle` and
follows the redirect to the real loopback receiver. No call leaves the
computer (fixture `loopback_only`).

The walk (in file order, one page): the kind grid says "Not set up for this
lab" one time for each kind; the lab admin adds the Google client on select;
sign in; choose a Drive folder in the tree; live counts with no reload; the
detail with pause and resume; a sign-in that expired (one sentence, one
button); remove. Then the slot view of Lab settings, and each screen at
390 px in light and dark with no horizontal scroll.

Set ANAGRAM_UI_SHOTS=DIR to save screenshots.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from conftest import make_net
from sourcekit import browse
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client
from uikit import clean, copy, ready, until

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.local.sources import http as http_mod  # noqa: E402
from anagram.local.sources.fake_google import FakeGoogle  # noqa: E402
from anagram.local.sources.gdrive import GDOC, GoogleDriveConnector  # noqa: E402
from anagram.shell.ui.server import UIServer  # noqa: E402

STORY = True  # the tests share one page, in file order (conftest.keep_story_order)
SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
expect = sync_api.expect
ORCID = "0000-0002-1825-0097"


class Member:
    def __init__(self, root: Path) -> None:
        self.fake = FakeGoogle()
        self.mp = pytest.MonkeyPatch()
        self.mp.setattr(http_mod, "default_http", lambda: self.fake)
        self.mp.setattr(GoogleDriveConnector, "rate", 1e9)
        net = make_net(root)
        self.svc, self.tc = ui_client(net, root / "me")
        launched(self.tc)
        join_via_ui(net, self.svc, self.tc, ORCID, "Ana Lee")
        assert self.tc.post("/api/recovery-kit/saved", headers=ORIGIN).status_code == 200
        body = {"name": "Ana Lee", "ror": "05dxps055", "institution_name": "Test University"}
        assert self.tc.put("/api/identity", json=body, headers=ORIGIN).json()["setup_done"]
        with self.svc.session() as c:
            self.lab = c.labs.lab_create("Lee Lab")["lab_id"]
        self.lab_folder = self.fake.add_folder("Lab notes")
        self.fake.add_file("Plan", b"# Plan\n\nNanodiscs.", parent=self.lab_folder, mime=GDOC)
        self.fake.add_folder("Teaching")
        self.denied = False
        # The system browser: the person agrees at Google, and Google sends
        # the browser back to the loopback receiver.
        self.svc.connections.open_browser = self._consent
        self.server = UIServer(self.svc).start()
        self.base = f"http://127.0.0.1:{self.server.port}"

    def _consent(self, url: str) -> None:
        threading.Thread(target=lambda: browse(self.fake.authorize(url)), daemon=True).start()

    def stop(self) -> None:
        self.server.stop()
        self.mp.undo()


@pytest.fixture(scope="module")
def member(tmp_path_factory, request):
    # `loopback_only` is a function fixture; this module guard does the same.
    import socket

    real = socket.socket.connect

    def connect(sock, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"network use in a test: {host}")
        return real(sock, address, *args, **kwargs)

    guard = pytest.MonkeyPatch()
    guard.setattr(socket.socket, "connect", connect)
    m = Member(tmp_path_factory.mktemp("sources"))
    yield m
    m.stop()
    guard.undo()


class Walk:
    def __init__(self, browser, member, width=1440, scheme="light") -> None:
        self.m = member
        self.ctx = browser.new_context(
            viewport={"width": width, "height": 900}, color_scheme=scheme
        )
        self.page = self.ctx.new_page()
        self.faults = clean(self.page)
        self.page.goto(member.server.url)

    def go(self, route: str, screen: str) -> None:
        self.page.goto(f"{self.m.base}/#/{route}")
        ready(self.page, screen)


@pytest.fixture(scope="module")
def walk(browser, member):
    w = Walk(browser, member)
    yield w
    w.ctx.close()


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True)


def no_scroll(page) -> bool:
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def tile(page, label: str):
    return page.get_by_role("list", name=copy("sources.kinds")).get_by_role(
        "button", name=label, exact=True
    )


def test_1_not_set_up_is_said_once_and_the_admin_adds_the_client(walk):
    page, m = walk.page, walk.m
    walk.go("sources", "sources")
    not_set = page.get_by_text(copy("sources.not_set_up"), exact=True)
    expect(not_set).to_have_count(3)  # Google Drive, Gmail, Notion: on the tile only
    expect(page.get_by_text(copy("sources.ask_admin", provider="Google"))).to_have_count(0)
    shot(page, "sources-01-grid")
    tile(page, "Google Drive").click()
    lead = copy("sources.client_lead", provider="Google", lab="Lee Lab")
    expect(page.get_by_text(lead)).to_be_visible()
    expect(page.get_by_text(copy("sources.not_set_up"), exact=True)).to_have_count(3)
    page.get_by_label(copy("sources.client_id")).fill("GOCSPX-a-secret-by-mistake")
    page.get_by_label(copy("sources.client_secret")).fill(m.fake.client_secret)
    page.get_by_role("button", name=copy("sources.client_save", provider="Google")).click()
    expect(page.get_by_role("alert")).to_contain_text("apps.googleusercontent.com")
    page.get_by_label(copy("sources.client_id")).fill(m.fake.client_id)
    shot(page, "sources-02-client-form")
    page.get_by_role("button", name=copy("sources.client_save", provider="Google")).click()
    # The kinds reload: Google Drive and Gmail are available now.
    expect(page.get_by_text(copy("sources.not_set_up"), exact=True)).to_have_count(1)
    expect(page.get_by_text(copy("sources.about_gdrive"))).to_be_visible()
    assert walk.faults == []


def test_2_sign_in_and_choose_a_drive_folder(walk):
    page, m = walk.page, walk.m
    # The setup of Google Drive stays open after the client is saved.
    page.get_by_role("button", name=copy("sources.signin", provider="Google")).click()
    tree = page.get_by_role("list", name=copy("sources.drive_choose"))
    expect(tree).to_be_visible()
    expect(page.get_by_text(copy("sources.signed_in", account=m.fake.email))).to_be_visible()
    # Nothing is chosen at the start.
    expect(tree.get_by_role("checkbox", checked=True)).to_have_count(0)
    page.get_by_role("button", name=copy("sources.drive_open", name="My Drive")).click()
    page.get_by_role("checkbox", name="Lab notes").check()
    shot(page, "sources-03-drive-tree")
    page.get_by_role("button", name=copy("sources.add_kind", kind="Google Drive")).click()
    rows = page.get_by_role("list", name=copy("sources.list"))
    row = rows.get_by_role("link", name=f"Google Drive ({m.fake.email})")
    expect(row).to_be_visible()
    expect(rows).to_contain_text(copy("sources.items", n=1))
    # W5: "Checked 15 October"; the label already names the kind.
    expect(rows).to_contain_text(copy("sources.state_checked", date="").strip().capitalize())
    assert walk.faults == []


def test_3_counts_are_live_with_no_reload(walk):
    page, m = walk.page, walk.m
    page.evaluate("window.__same_page = true")
    m.fake.add_file("Results", b"# Results\n\nKd 4 nM.", parent=m.lab_folder, mime=GDOC)
    sid = m.tc.get("/api/sources").json()["sources"][0]["id"]
    m.svc.sources.sync(sid)
    rows = page.get_by_role("list", name=copy("sources.list"))
    expect(rows).to_contain_text(copy("sources.items", n=2))
    assert page.evaluate("window.__same_page === true")
    shot(page, "sources-04-list")


def test_4_detail_pause_resume(walk):
    page, m = walk.page, walk.m
    page.get_by_role("link", name=f"Google Drive ({m.fake.email})").click()
    ready(page, "sources")
    expect(page.get_by_role("heading", level=1)).to_have_text(f"Google Drive ({m.fake.email})")
    expect(page.locator(".ag-facts")).to_contain_text(m.fake.email)
    page.get_by_role("button", name=copy("sources.pause")).click()
    expect(page.get_by_text(copy("sources.paused_text"))).to_be_visible()
    shot(page, "sources-05-paused")
    page.get_by_role("button", name=copy("sources.resume")).click()
    expect(page.get_by_text(copy("sources.paused_text"))).to_have_count(0)
    # What Anagram reads: the tree opens with the chosen folder.
    page.get_by_role("button", name=copy("sources.include_change")).click()
    page.get_by_role("button", name=copy("sources.drive_open", name="My Drive")).click()
    expect(page.get_by_role("checkbox", name="Lab notes")).to_be_checked()
    shot(page, "sources-06-detail")
    assert walk.faults == []


def test_5_an_expired_sign_in_has_one_sentence_and_one_button(walk):
    page, m = walk.page, walk.m
    sid = m.tc.get("/api/sources").json()["sources"][0]["id"]
    m.fake.revoke_grant()
    m.fake.expire_access()
    m.svc.sources.sync(sid)
    sentence = page.get_by_text("Your Google sign-in has ended.", exact=True)  # the server sentence
    expect(sentence).to_be_visible()
    fault = page.locator(".ag-source-fault")
    expect(fault.get_by_role("button")).to_have_count(1)
    expect(page.get_by_role("button", name=copy("sources.pause"))).to_have_count(0)
    shot(page, "sources-07-fault")
    fault.get_by_role("button", name=copy("sources.signin_again", provider="Google")).click()
    expect(page.locator(".ag-source-fault")).to_have_count(0)
    expect(page.get_by_role("button", name=copy("sources.pause"))).to_be_visible()
    assert walk.faults == []


def test_6_remove_deletes_and_goes_back(walk):
    page = walk.page
    page.get_by_role("button", name=copy("sources.remove")).click()
    sheet = page.get_by_role("dialog")
    expect(sheet).to_contain_text(copy("sources.remove_confirm_title"))
    shot(page, "sources-08-remove")
    sheet.get_by_role("button", name=copy("sources.remove_confirm_action")).click()
    ready(page, "sources")
    expect(page.get_by_text(copy("sources.empty"))).to_be_visible()
    assert walk.m.tc.get("/api/sources").json()["sources"] == []
    assert walk.faults == []


def test_7_lab_settings_slot(walk):
    """The lab screen (R2 S12) hosts the slot; here the test mounts it."""
    page, m = walk.page, walk.m
    page.evaluate(
        """async (lab) => {
          const { html, render } = await import('/static/js/core/html.js');
          const { Slot } = await import('/static/js/components/index.js');
          const main = document.getElementById('main');
          main.replaceChildren();
          const box = document.createElement('div');
          main.appendChild(box);
          render(html`<${Slot} name="lab.settings" props=${{ lab }} />`, box);
        }""",
        m.lab,
    )
    google = page.get_by_role("region", name=copy("labsources.client_title", provider="Google"))
    expect(google.get_by_label(copy("sources.client_id"))).to_have_value(m.fake.client_id)
    expect(google).to_contain_text(copy("sources.client_secret_set"))
    rules = page.get_by_role("region", name=copy("labsources.rules_title"))
    rules.get_by_role("checkbox", name="Folder").uncheck()
    rules.locator("input[name=lab-default][value=lab]").check()
    rules.get_by_role("button", name=copy("labsources.save")).click()
    expect(rules).to_contain_text(copy("labsources.saved"))
    with m.svc.session() as c:
        policy = c.lab_space.lab_policy(m.lab)
    assert "folder" not in policy.sources["allowed_kinds"] and policy.lab_default() == "lab"
    # W4: a chosen card has no second mark.
    assert page.locator(".rf-ui-choice-mark").count() == 0
    shot(page, "sources-09-lab-settings")
    assert walk.faults == []


@pytest.mark.parametrize(("width", "scheme"), [(390, "light"), (390, "dark"), (1440, "dark")])
def test_8_each_screen_at_each_width(browser, member, tmp_path, width, scheme):
    m = member
    if not m.tc.get("/api/sources").json()["sources"]:
        notes = tmp_path / "Lab notes"
        notes.mkdir()
        (notes / "plan.md").write_text("# Plan\n\nA plan about nanodiscs.\n")
        r = m.tc.post("/api/sources", json={"kind": "folder", "path": str(notes)}, headers=ORIGIN)
        assert r.status_code == 200, r.text
    sid = m.tc.get("/api/sources").json()["sources"][0]["id"]
    w = Walk(browser, member, width=width, scheme=scheme)
    try:
        w.go("sources", "sources")
        expect(w.page.get_by_role("link", name="Lab notes")).to_be_visible()
        expect(w.page.get_by_role("list", name=copy("sources.list"))).to_contain_text(
            "Folder, checked "
        )
        assert no_scroll(w.page)
        shot(w.page, f"sources-10-list-{width}-{scheme}")
        w.page.get_by_text(copy("sources.add"), exact=True).click()
        tile(w.page, "Notion").click()
        expect(w.page.get_by_text(copy("sources.client_how", provider="Notion"))).to_be_visible()
        until(w.page, "document.documentElement.scrollWidth <= window.innerWidth")
        shot(w.page, f"sources-11-add-{width}-{scheme}")
        w.go(f"sources/{sid}", "sources")
        expect(w.page.get_by_role("heading", level=1)).to_have_text("Lab notes")
        assert no_scroll(w.page)
        shot(w.page, f"sources-12-detail-{width}-{scheme}")
        assert w.faults == []
    finally:
        w.ctx.close()
