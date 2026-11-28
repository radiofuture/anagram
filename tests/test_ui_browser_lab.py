"""The lab screens in a browser.

A real node (uvicorn, fake ORCID) and two real apps (`AppRuntime`) run on
loopback ports. A PI starts a lab and makes an invite link with one click.
A second person opens the link (`anagram open-url`, as the operating system
does), joins, and adds a note to the lab space. The PI sees the new person
and the note with no reload (task `lab.watch`, events `lab.*`).

Skipped when Playwright or its Chromium is not installed. Set
ANAGRAM_UI_SHOTS=DIR to save a screenshot of each step.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_app_runtime import FakeIndexer
from test_ui_browser_join import INSTITUTIONS, Site
from uikit import clean, copy, ready

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.admission.app.join import join  # noqa: E402
from anagram.identity.app.browsers import HeadlessBrowser, urllib_fetch  # noqa: E402
from anagram.shell.app import launcher  # noqa: E402
from anagram.shell.app.runtime import AppRuntime  # noqa: E402
from anagram.shell.client import Client  # noqa: E402
from anagram.shell.ui.service import UIService  # noqa: E402

SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
expect = sync_api.expect


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(
            path=str(Path(SHOTS) / f"lab-{name}.png"), full_page=True, animations="disabled"
        )


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    s = Site(tmp_path_factory.mktemp("lab-site"))
    yield s
    s.stop()


@pytest.fixture
def person(site, tmp_path):
    """A home that joined the node (no lab), and its running app."""
    made: list[AppRuntime] = []

    def make(name: str, orcid: str) -> Path:
        home = tmp_path / orcid
        c = join(
            home,
            site.invite(),
            browser=HeadlessBrowser(urllib_fetch),
            login_hint=orcid,
            display_name=name,
            open_home=Client.open,
        ).client
        c.vault.close()
        cfg = home / "config.json"
        doc = json.loads(cfg.read_text(encoding="utf-8")) if cfg.exists() else {}
        doc["labs"] = {"poll_wait": 2, "poll_min": 1}
        cfg.write_text(json.dumps(doc), encoding="utf-8")
        rt = AppRuntime(
            home,
            embed=False,
            tick_s=0.05,
            service=UIService(home, institutions=INSTITUTIONS),
            make_indexer=lambda s: FakeIndexer(),
        )
        rt.start()
        made.append(rt)
        # The welcome steps are done (the recovery kit and the details).
        rt.service.state.update(kit_saved=True)
        rt.service.account.set_identity(name, "fake-ror-northbridge", "Northbridge University")
        return home

    yield make
    for rt in made:
        rt.stop()


def open_app(home: Path, link: str | None = None) -> str:
    opened: list[str] = []
    argv = ["anagram://join/" + link.split("#", 1)[1]] if link else ["anagram://open"]
    launcher.open_url(home, argv, start=None, browser=opened.append)
    return opened[0]


def test_pi_invites_and_sees_the_new_person_and_note_live(browser, person):  # noqa: F811
    pi_home = person("Mei-Lin Chen", "fake-0000-0003-lab-pi")
    pi = browser.new_page(viewport={"width": 1440, "height": 900})
    pi_faults = clean(pi)
    pi.goto(open_app(pi_home).split("#", 1)[0] + "#/lab")
    ready(pi, "lab")
    shot(pi, "1-no-lab")

    # Start a lab, then invite with one click (the defaults: one person, 7 days).
    pi.get_by_label(copy("lab.start_name")).fill("Okafor Lab")
    pi.get_by_role("button", name=copy("lab.start_action")).click()
    expect(pi.get_by_role("heading", level=1, name="Okafor Lab")).to_be_visible()
    expect(
        pi.get_by_text(
            copy(
                "lab.invite_summary",
                who=copy("lab.invite_uses", n=1),
                role="member",
                days=copy("lab.days", n=7),
            )
        )
    ).to_be_visible()
    pi.get_by_role("button", name=copy("lab.invite_action")).click()
    field = pi.get_by_role("textbox", name=copy("lab.invite_link"))
    expect(field).to_be_visible()
    link = field.input_value()
    assert "/join#" in link
    expect(pi.get_by_text(copy("lab.invite_who_reads"), exact=False)).to_be_visible()
    expect(pi.get_by_role("heading", name=copy("lab.links_title"))).to_be_visible()
    shot(pi, "2-invite")

    # The second person opens the link and joins.
    member_home = person("Ada Okafor", "fake-0000-0004-lab-member")
    m = browser.new_page(viewport={"width": 390, "height": 844})
    m_faults = clean(m)
    m.goto(open_app(member_home, link))
    ready(m, "labjoin")
    expect(m.get_by_role("heading", name="Okafor Lab")).to_be_visible()
    expect(m.get_by_text("Mei-Lin Chen")).to_be_visible()
    shot(m, "3-join")
    m.get_by_role("button", name=copy("labjoin.join", lab="Okafor Lab")).click()
    ready(m, "lab")
    expect(m.get_by_role("heading", level=1, name="Okafor Lab")).to_be_visible()
    expect(m.get_by_role("button", name=copy("lab.invite_action"))).to_be_hidden()  # a member
    shot(m, "4-member")

    # The PI sees the new person with no reload; the used link is gone.
    expect(pi.get_by_text("Ada Okafor")).to_be_visible(timeout=30000)
    expect(pi.get_by_role("heading", name=copy("lab.links_title"))).to_be_hidden()
    pi.get_by_role("link", name=copy("lab.tab_space")).click()
    expect(pi.get_by_text(copy("lab.space_empty"))).to_be_visible()

    # The member adds a note; it arrives on the screen of the PI.
    m.get_by_role("link", name=copy("lab.tab_space")).click()
    m.get_by_text(copy("lab.note_title")).click()
    m.get_by_label(copy("lab.note_name")).fill("Gel image, lane 3")
    m.get_by_label(copy("lab.note_text")).fill("The band at 40 kDa is clear.")
    m.get_by_role("button", name=copy("lab.note_action")).click()
    expect(m.get_by_text("Gel image, lane 3")).to_be_visible()
    expect(pi.get_by_text("Gel image, lane 3")).to_be_visible(timeout=30000)
    shot(pi, "5-space")
    pi.get_by_text("Gel image, lane 3").click()
    expect(pi.get_by_text("The band at 40 kDa is clear.")).to_be_visible()

    # No internal id or key epoch on the screens.
    for page in (pi, m):
        text = page.locator("main").inner_text()
        assert "lab-" not in text and "epoch" not in text.lower()
    assert pi_faults == [] and m_faults == [], (pi_faults, m_faults)
    pi.close()
    m.close()
