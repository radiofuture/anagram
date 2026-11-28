"""From an invite link to the app, in a browser, with no terminal and no
paste (R1 plan, step S9; integration 1.5).

A real node (uvicorn) and a real app (`AppRuntime`) run on
loopback ports. The test plays the operating system in one place: it gives
the `anagram://join/...` link of the node page to `anagram open-url`
(`launcher.open_url`), because no URL scheme handler is registered on the
test computer. Each other step is a click in Chromium.

Skipped when Playwright or its Chromium is not installed. Set
ANAGRAM_UI_SHOTS=DIR to save a screenshot of each step.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

import pytest
from test_app_runtime import FakeIndexer
from uikit import clean, copy, ready

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.admission.app.join import join  # noqa: E402
from anagram.identity.app.browsers import HeadlessBrowser, urllib_fetch  # noqa: E402
from anagram.shell import pages  # noqa: E402
from anagram.shell.app import launcher  # noqa: E402
from anagram.shell.app.runtime import AppRuntime  # noqa: E402
from anagram.shell.client import Client  # noqa: E402
from anagram.shell.ui.institutions import StaticInstitutions  # noqa: E402
from anagram.shell.ui.server import bind_local  # noqa: E402
from anagram.shell.ui.service import UIService  # noqa: E402

SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
COMMUNITY = "Northbridge Biology"
INSTITUTIONS = StaticInstitutions(
    [{"id": "fake-ror-northbridge", "label": "Northbridge University"}]
)
expect = sync_api.expect


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(
            path=str(Path(SHOTS) / f"join-{name}.png"), full_page=True, animations="disabled"
        )


class Site:
    """A node on a loopback port with one member (a PI) and one lab."""

    def __init__(self, root: Path) -> None:
        import uvicorn

        from anagram.shell.node.home import NodeHome

        sock = bind_local()
        port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        nh = NodeHome(root / "node")
        nh.create(
            origin="join.test/log",
            community=COMMUNITY,
            public_url=self.url,
            orcid_mode="fake",
        )
        app, self.identity = nh.app_parts()
        self.admission = app.state.admission
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True).start()
        end = time.monotonic() + 15
        while not self.server.started:
            assert time.monotonic() < end, "the node did not start"
            time.sleep(0.02)
        self.pi = join(
            root / "pi",
            self.invite(),
            browser=HeadlessBrowser(urllib_fetch),
            login_hint="fake-0000-0001-join-pi",
            display_name="Mei-Lin Chen",
            open_home=Client.open,
        ).client
        self.lab_id = self.pi.labs.lab_create("Chen Lab")["lab_id"]

    def invite(self) -> str:
        return self.admission.create_invite(None, 7)["invite_url"]

    def lab_invite(self) -> str:
        return self.pi.admission.lab_invite(self.lab_id)["url"]

    def stop(self) -> None:
        self.pi.vault.close()
        self.server.should_exit = True


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    s = Site(tmp_path_factory.mktemp("join-site"))
    yield s
    s.stop()


@pytest.fixture
def app_of(tmp_path):
    made: list[AppRuntime] = []

    def start(home: Path) -> AppRuntime:
        rt = AppRuntime(
            home,
            embed=False,
            tick_s=0.05,
            service=UIService(home, institutions=INSTITUTIONS),
            make_indexer=lambda s: FakeIndexer(),
        )
        rt.start()
        made.append(rt)
        return rt

    yield start
    for rt in made:
        rt.stop()


def no_start(home):
    raise AssertionError("the app runs; the launcher must not start it")


def open_from_node_page(page, invite: str, home: Path) -> None:
    """The person opens the invite link and selects "Open Anagram". The
    browser hands `anagram://join/...` to the operating system, which runs
    `anagram open-url`; the app opens in the browser."""
    page.goto(invite)
    title = pages.WORDS["join_title"].format(community=COMMUNITY)
    expect(page.get_by_role("heading", name=title)).to_be_visible()
    shot(page, "1-node-page")
    # Fallback for a computer where Anagram does not open: the full link.
    page.get_by_text(pages.WORDS["join_fallback"]).click()
    expect(page.get_by_label(pages.WORDS["join_link_label"])).to_have_value(invite)
    button = page.get_by_role("link", name=pages.WORDS["join_open"])
    href = button.get_attribute("href")
    assert href == "anagram://join/" + invite.split("#", 1)[1]
    opened: list[str] = []
    launcher.open_url(home, [href], start=no_start, browser=opened.append)
    page.goto(opened[0])


def fill_name(page, name: str, email: str | None = None) -> None:
    """R8: the invite is the proof. The person types a name,
    and an email address if they want; there is no ORCID step."""
    page.get_by_label(copy("welcome.name_label")).fill(name)
    if email:
        page.get_by_label(copy("welcome.email_label")).fill(email)
    shot(page, "3-name")


def sign_in_at_fake_orcid(page, orcid: str, name: str) -> None:
    """Only a reader invite to an ORCID iD goes to ORCID."""
    expect(page.get_by_role("heading", name=pages.WORDS["fake_title"])).to_be_visible()
    page.get_by_label(pages.WORDS["fake_orcid"]).fill(orcid)
    page.get_by_label(pages.WORDS["fake_name"]).fill(name)
    page.get_by_role("button", name=pages.WORDS["fake_action"]).click()


def subject_named(site, name: str) -> str:
    return next(r["subject"] for r in site.admission.invite_chain() if r["name"] == name)


def test_node_page_without_a_fragment_opens_the_app_only(browser, site):
    page = browser.new_page()
    faults = clean(page)
    page.goto(f"{site.url}/join")
    link = page.get_by_role("link", name=pages.WORDS["join_open"])
    assert link.get_attribute("href") == "anagram://open"
    assert page.locator("#join-link-field").is_hidden()
    page.goto(f"{site.url}/join#not*base64")
    assert link.get_attribute("href") == "anagram://open"
    assert faults == []
    page.close()


def test_new_person_joins_a_lab_from_the_link(browser, site, app_of, tmp_path):
    home = tmp_path / "new"
    rt = app_of(home)
    page = browser.new_page()
    faults = clean(page)
    lab = site.lab_invite()
    open_from_node_page(page, lab, home)
    ready(page, "welcome")
    expect(
        page.get_by_role("heading", name=copy("welcome.join_title", name="Chen Lab"))
    ).to_be_visible()
    expect(page.get_by_text(f"A lab in {COMMUNITY}.", exact=False)).to_be_visible()
    expect(page.get_by_label(copy("welcome.invite_label"))).to_be_hidden()  # no paste
    shot(page, "2-welcome")
    fill_name(page, "Ada Okafor")
    page.get_by_role("button", name=copy("welcome.join_action")).click()
    expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_visible(timeout=60000)
    expect(page.locator(".ag-kit-code")).to_be_visible()  # the new kit, not "gone"
    # A selection of the code copies it on one line, exactly (parse_kit reads one line).
    selected = page.locator(".ag-kit-code").evaluate(
        "el => { const r = document.createRange(); r.selectNodeContents(el);"
        " const s = getSelection(); s.removeAllRanges(); s.addRange(r); return s.toString(); }"
    )
    assert re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4})+", selected.strip()), selected
    shot(page, "4-kit")
    page.get_by_label(copy("welcome.kit_check")).check()
    page.get_by_role("button", name=copy("welcome.kit_continue")).click()
    expect(page.get_by_role("heading", name=copy("details.setup_title"))).to_be_visible()
    expect(page.get_by_label(copy("details.name"))).to_have_count(0)  # the first step had the name
    expect(page.get_by_role("radio", name="Chen Lab")).to_be_checked()  # the lab of the invite
    page.get_by_label(copy("details.institution")).fill("Northbridge")
    page.get_by_text("Northbridge University").click()
    shot(page, "5-details")
    page.get_by_role("button", name=copy("details.save_setup")).click()

    # The first Home: what Anagram does now, and one next action.
    ready(page, "home")
    expect(page.get_by_role("heading", level=1)).to_have_text(copy("home.first_title"))
    expect(page.get_by_text(copy("home.first_propose"))).to_be_visible()
    shot(page, "6-first-home")
    page.get_by_role("link", name=copy("home.connect")).click()
    ready(page, "sources")
    subject = subject_named(site, "Ada Okafor")
    assert site.pi.lab_roster.lab_state(site.lab_id).members.get(subject) == "member"
    assert site.identity.orcid_of(subject) is None  # no ORCID iD needed
    assert rt.service.state.get("pending_invite") is None
    assert faults == [], faults
    page.close()


def test_new_person_joins_the_node_from_the_link(browser, site, app_of, tmp_path):
    home = tmp_path / "node-only"
    app_of(home)
    page = browser.new_page()
    faults = clean(page)
    open_from_node_page(page, site.invite(), home)
    ready(page, "welcome")
    expect(
        page.get_by_role("heading", name=copy("welcome.join_title", name=COMMUNITY))
    ).to_be_visible()
    expect(page.get_by_text("Your invite is from 127.0.0.1.", exact=False)).to_be_visible()
    fill_name(page, "Lena Varga", "lena@northbridge.example")
    page.get_by_role("button", name=copy("welcome.join_action")).click()
    expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_visible(timeout=60000)
    subject = subject_named(site, "Lena Varga")
    assert site.identity.email_of(subject) == "lena@northbridge.example"
    assert subject_named(site, "Lena Varga") == subject
    assert faults == [], faults
    page.close()


def test_fallback_paste_in_the_disclosure(browser, site, app_of, tmp_path):
    """No pending invite (the link did not open Anagram): the welcome screen
    shows the invite link field expanded first, with one primary Join button."""
    home = tmp_path / "paste"
    rt = app_of(home)
    page = browser.new_page()
    faults = clean(page)
    page.goto(f"http://127.0.0.1:{rt.port}/open/{rt.tokens.mint()}")
    ready(page, "welcome")
    expect(page.get_by_text(copy("welcome.invite_open"))).to_be_visible()
    expect(page.get_by_label(copy("welcome.invite_label"))).to_be_visible()
    shot(page, "7-no-invite")
    page.get_by_label(copy("welcome.invite_label")).fill(site.invite())
    fill_name(page, "Sam Helix")
    page.get_by_role("button", name=copy("welcome.join_action")).click()
    expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_visible(timeout=60000)
    assert faults == [], faults
    page.close()


def test_used_lab_link_shows_its_error_on_the_first_step(browser, site, app_of, tmp_path):
    """The node refuses the used link: the person
    stays on the first step and reads why (not an empty kit step)."""
    lab = site.lab_invite()
    join(
        tmp_path / "one",
        lab,
        browser=HeadlessBrowser(urllib_fetch),
        login_hint="fake-0000-0005-join-one",
        display_name="One Person",
        open_home=Client.open,
    ).client.vault.close()
    home = tmp_path / "two"
    app_of(home)
    page = browser.new_page()
    open_from_node_page(page, lab, home)
    ready(page, "welcome")
    fill_name(page, "Two Person")
    page.get_by_role("button", name=copy("welcome.join_action")).click()
    expect(page.get_by_role("alert")).to_contain_text("no longer valid", timeout=60000)
    shot(page, "8-used-link")
    expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_hidden()
    page.close()


def test_restore_from_a_recovery_kit(browser, site, app_of, tmp_path):
    """A member on a new computer: "I have a recovery kit", the kit file,
    then the app with no invite and no setup steps."""
    old = join(tmp_path / "old", site.invite(), display_name="Rosa Lind", open_home=Client.open)
    old.client.labs.lab_create("Lind Lab")
    old.client.vault.close()
    home = tmp_path / "new-computer"
    rt = app_of(home)
    page = browser.new_page()
    faults = clean(page)
    page.goto(f"http://127.0.0.1:{rt.port}/open/{rt.tokens.mint()}")
    ready(page, "welcome")
    page.get_by_role("button", name=copy("welcome.have_kit")).click()
    expect(page.get_by_role("heading", name=copy("welcome.restore_title"))).to_be_visible()
    # No kit yet: the error names the one next step, and the input stays.
    page.get_by_role("button", name=copy("welcome.restore_action")).click()
    expect(page.get_by_role("alert")).to_have_text(copy("welcome.restore_need"))
    page.locator("input[type=file]").set_input_files(
        {
            "name": "anagram-recovery-kit.md",
            "mimeType": "text/markdown",
            "buffer": old.kit_text.encode(),
        }
    )
    expect(page.get_by_text("anagram-recovery-kit.md")).to_be_visible()
    shot(page, "9-restore")
    page.get_by_role("button", name=copy("welcome.restore_action")).click()
    expect(page.get_by_role("heading", name=copy("welcome.restore_title"))).to_be_hidden(
        timeout=60000
    )
    ready(page, "welcome")  # the details step: this person has no institution yet
    expect(page.get_by_role("heading", name=copy("details.setup_title"))).to_be_visible()
    assert rt.service.account.overview()["details"]["subject"] == old.subject
    assert faults == [], faults
    page.close()


def test_locked_keychain_has_its_own_state(browser, site, app_of, tmp_path, monkeypatch):
    """The keychain refuses the access (423): a calm screen that says what
    to do, and Try again opens the app when the keychain is open again."""
    from anagram.shell.ui.errors import UIError

    home = tmp_path / "locked"
    rt = app_of(home)
    svc = rt.service

    def locked():
        raise UIError(423, "Anagram cannot get its key from the keychain.", {"keychain": True})

    monkeypatch.setattr(svc.account, "overview", locked)
    page = browser.new_page()
    page.goto(f"http://127.0.0.1:{rt.port}/open/{rt.tokens.mint()}")
    page.wait_for_selector('main[data-screen="locked"]')
    expect(page.get_by_role("heading", name=copy("common.locked_title"))).to_be_visible()
    expect(page.get_by_text(copy("common.locked_text"))).to_be_visible()
    expect(page.get_by_text(copy("common.fault_title"))).to_have_count(0)
    shot(page, "10-locked")
    monkeypatch.undo()
    page.get_by_role("button", name=copy("common.try_again")).click()
    ready(page, "welcome")
    page.close()
