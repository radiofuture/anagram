"""Shared fixtures: an in-process community node behind FastAPI TestClient."""

from __future__ import annotations

import itertools
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from anagram.admission.app.join import join
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.app.browsers import HeadlessBrowser
from anagram.identity.app.keychain import slots as _slots
from anagram.identity.node.mailer import FakeMailer
from anagram.shell.app.autostart import base as _autostart_base
from anagram.shell.client import Client
from anagram.shell.node.home import NodeHome
from anagram.sim import generate_community

# Tests never use the real keychain of this computer. The default keystore of
# the suite is the file keystore. `ANAGRAM_TEST_KEYSTORE=os-memory` runs the
# suite with the sealed keystore and a master key in memory. Only the opt-in
# test in test_keychain.py (ANAGRAM_TEST_OS_KEYCHAIN=1) uses the real keychain,
# through `REAL_OS_SLOT`.
REAL_OS_SLOT = _slots.os_slot
if os.environ.get("ANAGRAM_TEST_KEYSTORE") == "os-memory":
    os.environ["ANAGRAM_KEYSTORE"] = "os"
    _SUITE_SLOT = _slots.MemorySlot()
    _slots.os_slot = lambda: _SUITE_SLOT
else:
    os.environ["ANAGRAM_KEYSTORE"] = "file"

    def _no_os_keychain():
        raise AssertionError("a test tried to use the real OS keychain")

    _slots.os_slot = _no_os_keychain

# Tests never install a real login service (launchd, systemd, Task
# Scheduler): each Autostart in a test needs a temp root and a fake runner.
_autostart_base.REQUIRE_FAKES = True

# The Account screen reads `GET /api/app` (slot "This computer", R1 S8b). A
# test UI with no runtime and no patched login service gets a login service
# that does nothing ("none"), not the guard error.
from anagram.shell.app import autostart as _autostart_pkg  # noqa: E402
from anagram.shell.app import settings as _app_settings  # noqa: E402

_REAL_AUTOSTART_FOR_PLATFORM = _autostart_pkg.autostart_for_platform
_real_app_autostart = _app_settings.AppSettings.autostart


def _test_app_autostart(self):
    if (
        self._autostart is None
        and getattr(self.runtime, "autostart", None) is None
        and _autostart_pkg.autostart_for_platform is _REAL_AUTOSTART_FOR_PLATFORM
    ):
        self._autostart = _autostart_base.NoAutostart(
            root=self.home / ".no-login-service", run=lambda argv: (0, "")
        )
    return _real_app_autostart(self)


_app_settings.AppSettings.autostart = _test_app_autostart

NODE_URL = "https://node.test"
T0 = 1_792_065_600  # 2026-10-15T12:00:00Z


@dataclass
class Clock:
    t: float = T0

    def __call__(self) -> float:
        return self.t


@dataclass
class Net:
    home: NodeHome
    tc: TestClient
    clock: Clock
    mailer: FakeMailer
    identity: object
    service: object
    vault: object = None
    store: object = None
    labs: object = None
    homes: list = field(default_factory=list)
    admission: object = None

    def transport(self, method, path, body, headers=None):
        if isinstance(body, bytes):
            hdrs = {"Content-Type": "application/octet-stream", **(headers or {})}
            r = self.tc.request(method, path, content=body, headers=hdrs)
        else:
            r = self.tc.request(method, path, json=body, headers=headers or {})
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", "")
            except ValueError:
                detail = r.text
            raise NodeHTTPError(r.status_code, str(detail))
        if r.headers.get("content-type", "").startswith("application/octet-stream"):
            return r.content
        return r.json()

    def fetch(self, url):
        r = self.tc.get(url, follow_redirects=False)
        return r.status_code, r.headers.get("location")

    def browser(self):
        return HeadlessBrowser(self.fetch)

    def sid(self, orcid: str) -> str:
        """The person ID (pid) of a person who signed in with this ORCID iD
        (the node's private map; tests only)."""
        subject = self.identity.subject_for_orcid(orcid)
        assert subject is not None, f"{orcid} has not signed in"
        return subject

    def commitment(self, orcid: str) -> str:
        return self.identity.orcid_account(orcid)["commitment"]

    def invite(self, days: float = 7) -> str:
        return self.admission.create_invite(None, days)["invite_url"]

    def join(self, home: Path, orcid: str, name: str = "Test Person", **kw):
        return join(
            home,
            kw.pop("invite", None) or self.invite(),
            transport=kw.pop("transport", self.transport),
            browser=self.browser(),
            login_hint=orcid,
            display_name=name,
            clock=self.clock,
            **kw,
            open_home=Client.open,
        )

    def join_invite(self, home: Path, name: str = "Test Person", **kw):
        """Join with the invite only: no ORCID (R8)."""
        return join(home, kw.pop("invite", None) or self.invite(), transport=self.transport,
                    method="invite", display_name=name, clock=self.clock, **kw, open_home=Client.open)  # fmt: skip


def free_port() -> int:
    """A port that is free now. Only for a child process that binds the port
    itself (a server in this process takes a bound socket: `bind_local`)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_net(tmp_path: Path, enclave=None, enclave_parts=None, **create) -> Net:
    nh = NodeHome(tmp_path / "node")
    nh.create(origin="node.test/log", public_url=NODE_URL, community="Test community", **create)
    clock = Clock()
    mailer = FakeMailer()
    service = nh.service()
    identity = nh.identity(service, mailer=mailer, clock=clock)
    from anagram.shell.node.app import create_app

    vault = nh.vault(identity)
    store = nh.store(identity)
    labs = nh.labs(identity, vault)
    admission = nh.admission(identity, labs, nh.reader_invites(identity))
    app = create_app(
        service,
        nh.trust_info(),
        identity,
        vault=vault,
        store=store,
        labs=labs,
        admission=admission,
        enclave=enclave,
        enclave_parts=enclave_parts(nh, clock) if enclave_parts else None,
    )
    tc = TestClient(app, base_url=NODE_URL)
    net = Net(nh, tc, clock, mailer, identity, service, vault, store, labs)
    net.admission = admission
    return net


@pytest.fixture
def net(tmp_path):
    return make_net(tmp_path)


@pytest.fixture(scope="session")
def sim_community(tmp_path_factory):
    """The synthetic community with a small large file (4 KiB). Read-only:
    copy a lab before a test changes its files."""
    out = tmp_path_factory.mktemp("sim") / "out"
    return generate_community(out, seed=0, large_bytes=4096)


@pytest.fixture
def no_network(monkeypatch):
    """Any socket connect in a test that uses this fixture is a bug."""

    def refuse(*args, **kwargs):
        raise AssertionError("network use in a test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(scope="module")
def browser():
    """A headless Chromium for the browser tests, one for each module. Skip
    when Playwright or its Chromium is not installed (`uv run playwright
    install chromium`)."""
    sync_api = pytest.importorskip("playwright.sync_api")
    try:
        pw = sync_api.sync_playwright().start()
    except Exception as exc:  # Playwright raises many types when it does not start
        pytest.skip(f"playwright does not start: {exc}")
    try:
        b = pw.chromium.launch()
    except Exception as exc:  # the same for a missing Chromium
        pw.stop()
        pytest.skip(f"chromium is not installed: {exc}")
    sync_api.expect.set_options(timeout=20000)  # a loaded machine runs the whole suite at once
    yield b
    b.close()
    pw.stop()


# ---- story modules ---------------------------------------------------------
# A story module (module constant `STORY = True`) is one walk in some tests
# that share one page and its state, in file order: tests/test_ui_browser.py
# and tests/test_ui_browser_sources.py. A plugin that shuffles the order of
# the tests (pytest-randomly, or a `-p` shuffle) can move such a module, but
# its tests keep their file order. Each other test has no order.
_COLLECTED = pytest.StashKey[int]()
_count = itertools.count()


def pytest_itemcollected(item: pytest.Item) -> None:
    item.stash[_COLLECTED] = next(_count)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    keep_story_order(items)


def keep_story_order(items: list[pytest.Item]) -> None:
    """Put the tests of each story module back in collection order, in the
    places that the tests of the module have in `items` now."""
    places: dict[str, list[int]] = {}
    for at, item in enumerate(items):
        module = getattr(item, "module", None)
        if module is not None and getattr(module, "STORY", False):
            places.setdefault(module.__name__, []).append(at)
    for at_list in places.values():
        story = sorted((items[at] for at in at_list), key=lambda it: it.stash[_COLLECTED])
        for at, item in zip(at_list, story, strict=True):
            items[at] = item
