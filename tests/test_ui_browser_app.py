"""Browser test of the slot view "This computer" in Account (Playwright,
headless Chromium).

A joined member, a real `UIServer` on 127.0.0.1 with a fake app runtime and
a fake systemd login service (no real login item). The switch changes
`start_at_login`; with keys in files, the plain-file keys notice
shows; no raw path shows; a helper event changes the state with no reload.

Set ANAGRAM_UI_SHOTS=DIR to save screenshots.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from conftest import make_net
from test_app_routes import FakeRuntime
from test_autostart import FakeRun
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client
from uikit import clean, copy, ready

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.shell.app import settings as settings_mod  # noqa: E402
from anagram.shell.app.autostart import SystemdAutostart, service_command  # noqa: E402
from anagram.shell.ui.server import UIServer  # noqa: E402

SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
expect = sync_api.expect


class Runtime(FakeRuntime):
    """A runtime whose helper state the test sets."""

    def __init__(self, autostart):
        super().__init__(autostart)
        self.state = {
            "errors": 0,
            "last_cycle_at": None,
            "since": "2026-11-16T10:00:00Z",
            "state": "running",
        }

    def status(self) -> dict:
        return dict(self.state)

    def restart_helper(self) -> None:
        super().restart_helper()
        self.state = {**self.state, "state": "running"}


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    root = tmp_path_factory.mktemp("app")
    net = make_net(root)
    svc, tc = ui_client(net, root / "me")
    launched(tc)
    join_via_ui(net, svc, tc, "0000-0002-1825-0097", "Ana Lee")
    tc.post("/api/recovery-kit/saved", headers=ORIGIN)
    body = {"name": "Ana Lee", "ror": "05dxps055", "institution_name": "Test University"}
    assert tc.put("/api/identity", json=body, headers=ORIGIN).json()["setup_done"]
    login = SystemdAutostart(root=root / "user", run=FakeRun())
    rt = Runtime(login)
    server = UIServer(svc, runtime=rt).start()
    yield svc, server, rt, login
    server.stop()


def open_account(browser, server, width=1440, scheme="light"):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    faults = clean(page)
    page.goto(server.url)
    page.goto(f"http://127.0.0.1:{server.port}/#/account")
    ready(page, "account")
    return ctx, page, faults


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(
            path=str(Path(SHOTS) / f"{name}.png"), full_page=True, animations="disabled"
        )


def settled(check, timeout: float = 10.0) -> None:
    """The switch moves at once and the server acts after it: wait for it."""
    end = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < end, "the server did not act in time"
        time.sleep(0.05)


def test_switch_keys_sentence_and_live_helper(browser, app):
    svc, server, rt, login = app
    ctx, page, faults = open_account(browser, server)
    try:
        section = page.get_by_role("region", name=copy("computer.title"))
        expect(section).to_be_visible()
        switch = section.get_by_role("switch", name=copy("computer.login"))
        expect(switch).not_to_be_checked()
        switch.click()
        expect(switch).to_be_checked()
        settled(lambda: login.command() == service_command(svc.home))
        # Tests use the file keystore: the sentence of plan section 10.
        expect(section).to_contain_text(copy("computer.keys_files"))
        expect(section).to_contain_text(copy("computer.helper_running"))
        # No raw path of this computer on the screen.
        text = page.inner_text("main")
        assert str(svc.home) not in text and "/Users/" not in text and "/tmp/" not in text  # noqa: S108 - a text check
        shot(page, "computer-1440-light")
        # A helper fault arrives as an event: the state changes with no reload.
        page.evaluate("window.__same_page = true")
        rt.state = {**rt.state, "state": "error", "errors": 1}
        server.app.state.ctx.bus.publish("app.helper", rt.status())
        restart = section.get_by_role("button", name=copy("computer.restart"))
        expect(restart).to_be_visible()
        expect(section).to_contain_text(copy("computer.helper_error"))
        restart.click()
        expect(restart).to_have_count(0)
        assert rt.restarts == 1 and page.evaluate("window.__same_page === true")
        switch.click()
        expect(switch).not_to_be_checked()
        settled(lambda: login.command() is None)
        assert faults == []
    finally:
        ctx.close()


def test_protected_keys_have_no_warning(browser, app, monkeypatch):
    _, server, _, _ = app
    monkeypatch.setattr(
        settings_mod, "describe", lambda home: {"backend": "macos-keychain", "protected": True}
    )
    ctx, page, faults = open_account(browser, server, width=390, scheme="dark")
    try:
        section = page.get_by_role("region", name=copy("computer.title"))
        expect(section).to_contain_text(copy("computer.keys_macos_keychain"))
        expect(section).not_to_contain_text(copy("computer.keys_files"))
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        shot(page, "computer-390-dark")
        assert faults == []
    finally:
        ctx.close()
