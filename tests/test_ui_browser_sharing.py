"""The sharing screens in a browser, with two people.

Chen (owner) and Okafor (reader) each have their own UI on one demo
community (Playwright, headless Chromium). Chen shares a finding by name,
Okafor reads it in the reading view, and Chen's row changes to "Read" with no
reload of the page. Then Chen stops sharing and invites a person who is not a
member. A second test follows a reader invite from the node page to "Shared
with me".

The task `shares.sync` runs every 60 s while a page is open; the tests call
one run of it (`app.state.sharing.sync()`) where the product waits for the
next run. Skipped when Playwright or its Chromium is not installed. Set
ANAGRAM_UI_SHOTS=DIR to save screenshots at 1440 and 390 px, light and dark.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from readkit import PNG, csv_bytes
from sharekit import commit
from uikit import clean, copy, ready, until

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.sim.demo import Demo  # noqa: E402

SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
CLAIM = "NbT7 binds the pocket ligand at 4 degrees"
FILES = {
    "notes.md": b"# Binding run 3\n\nThe ligand binds in the pocket at 4 degrees.\n",
    "binding.csv": csv_bytes(6),
    "gel.png": PNG,
}
expect = sync_api.expect


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    root = tmp_path_factory.mktemp("share-walk")
    d = Demo(root / "demo", large_bytes=4096).start()
    for slug in ("chen", "okafor"):
        p = d.person(slug)
        p.service.state.update(pending_sources=[])  # no source work in this walk
        d.autopilot(p, approve=False)
    yield d
    d.stop()


def shot(page, name: str) -> None:
    if not SHOTS:
        return
    Path(SHOTS).mkdir(parents=True, exist_ok=True)
    page.screenshot(
        path=str(Path(SHOTS) / f"share-{name}.png"), full_page=True, animations="disabled"
    )


def no_page_scroll(page) -> str:
    return page.evaluate(
        """() => {
          const w = window.innerWidth;
          const sw = document.documentElement.scrollWidth;
          if (sw <= w) return '';
          const out = [`scrollWidth ${sw} > ${w}`];
          for (const el of document.querySelectorAll('body *')) {
            const r = el.getBoundingClientRect();
            if (r.right > w + 0.5) out.push(`${el.tagName.toLowerCase()}.${el.className} right ${r.right}`);
          }
          return out.join('; ');
        }"""
    )


def looks(page, name: str) -> None:
    """The screen at 390 and 1440 px, light and dark: no page scroll, and no
    motion left running."""
    for scheme in ("light", "dark"):
        page.emulate_media(color_scheme=scheme)
        for width in (390, 1440):
            page.set_viewport_size({"width": width, "height": 900})
            until(page, "document.getAnimations().length === 0")
            scroll = no_page_scroll(page)
            assert not scroll, f"{name} at {width} px: {scroll}"
            shot(page, f"{name}-{width}-{scheme}")
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1440, "height": 900})
    until(page, "document.getAnimations().length === 0")


class Person:
    def __init__(self, browser, p) -> None:
        self.p = p
        self.base = p.url.split("/open/")[0]
        self.ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        self.page = self.ctx.new_page()
        self.faults = clean(self.page)
        self.page.goto(p.url)
        ready(self.page, "home")

    def go(self, route: str, screen: str) -> None:
        self.page.goto(f"{self.base}/{route}")
        ready(self.page, screen)

    def sync(self) -> None:
        """One run of the task `shares.sync` of this person's app."""
        self.p.server.app.state.sharing.sync()


def test_share_read_live_and_stop(browser, demo, tmp_path):
    chen_p, okafor_p = demo.person("chen"), demo.person("okafor")
    with chen_p.service.session() as c:
        root = commit(c, tmp_path, FILES, claim=CLAIM)
    chen, okafor = Person(browser, chen_p), Person(browser, okafor_p)
    page, opage = chen.page, okafor.page

    # Okafor waits on "Shared with me"; nothing is there yet.
    okafor.go("#/sharing", "sharing")
    expect(opage.get_by_text(copy("sharing.with_me_empty"))).to_be_visible()

    # Chen opens the finding: nobody has it yet.
    chen.go(f"#/finding/{root}", "finding")
    shared_with = page.locator("section[aria-labelledby=shared-with-title]")
    expect(shared_with.get_by_text(copy("sharing.with_empty"))).to_be_visible()
    looks(page, "finding")

    # The share sheet: one field for a name, an email address, or an ORCID iD.
    page.get_by_role("button", name=copy("sharing.share"), exact=True).click()
    dialog = page.locator("dialog")
    expect(dialog.get_by_role("heading", name=copy("sharing.share_title"))).to_be_visible()
    dialog.get_by_label(copy("sharing.share_field")).fill("Okafor")
    dialog.locator(".rf-ui-search-result", has_text="Chidi Okafor").click()
    expect(dialog.get_by_role("list", name=copy("sharing.chosen"))).to_contain_text("Chidi Okafor")
    expect(dialog.get_by_label(copy("sharing.share_field"))).to_have_value(
        ""
    )  # ready for the next name
    expect(dialog.get_by_text(copy("sharing.share_record"))).to_be_visible()
    looks(page, "sheet")
    dialog.get_by_role("button", name=copy("sharing.share_action", name="Chidi Okafor")).click()
    expect(dialog).to_be_hidden()
    row = shared_with.locator(".ag-rows-item", has_text="Chidi Okafor")
    expect(row).to_contain_text(copy("sharing.state_delivered"))
    page.evaluate("window.__noReload = true")

    # Okafor's list gets the row live, from his own sync.
    okafor.sync()
    title = copy("sharing.untitled", sender="Mei-Lin Chen")
    link = opage.locator("a.ag-row-link", has_text=title)
    expect(link).to_be_visible()
    expect(link).to_contain_text(copy("sharing.not_opened"))
    expect(opage.get_by_text(copy("sharing.record_notice"))).to_be_visible()
    looks(opage, "with-me")

    # Okafor reads the finding in the reading view.
    link.click()
    expect(opage.get_by_text(CLAIM).first).to_be_visible(timeout=30000)
    shot(opage, "reader")

    # Chen's next sync brings the read record: the row changes in place.
    chen.sync()
    expect(row).to_contain_text(copy("sharing.state_read"), timeout=30000)
    expect(row).to_contain_text(copy("sharing.fact_reads", n=1, date="").split("{")[0].strip())
    assert page.evaluate("window.__noReload === true")  # no reload
    looks(page, "finding-read")

    # The history of one person, with the record of the share.
    row.get_by_role("link", name="Chidi Okafor").click()
    ready(page, "history")
    expect(page.get_by_role("heading", level=1)).to_have_text("Chidi Okafor")
    expect(page.locator("main").get_by_text(copy("sharing.state_read"), exact=True)).to_be_visible()
    expect(page.get_by_role("link", name=copy("sharing.export_name", title=CLAIM))).to_be_visible()
    looks(page, "person")

    # Shared by me: the finding and the people who have it.
    chen.go("#/sharing/by-me", "sharing")
    expect(page.locator("main").get_by_text(CLAIM)).to_be_visible()
    looks(page, "by-me")

    # Stop sharing: the sheet says what it does and does not do.
    chen.go(f"#/finding/{root}", "finding")
    row.get_by_role("button", name=copy("sharing.stop_name", name="Chidi Okafor")).click()
    expect(
        dialog.get_by_role("heading", name=copy("sharing.stop_title", name="Chidi Okafor"))
    ).to_be_visible()
    expect(dialog).to_contain_text(copy("sharing.stop_kept", name="Chidi Okafor"))
    expect(dialog).to_contain_text("Chidi Okafor opened this finding one time")
    looks(page, "stop")
    dialog.get_by_role("button", name=copy("sharing.stop_action")).click()
    # A new key is a second, explicit action (the sheet also has "Done").
    expect(dialog.get_by_role("button", name=copy("sharing.done"))).to_be_visible()
    looks(page, "stopped")
    dialog.get_by_role("button", name=copy("sharing.rekey_action")).click()
    expect(dialog).to_be_hidden(timeout=30000)
    until(page, f"!location.hash.includes('{root}')", timeout=30)
    ready(page, "finding")
    expect(page.get_by_text(copy("library.version", n=2), exact=True)).to_be_visible()
    expect(row).to_contain_text(copy("sharing.state_stopped"))
    expect(row.get_by_role("button")).to_have_count(0)

    # Okafor keeps the copy that he opened; the row says that Chen stopped.
    okafor.go("#/sharing", "sharing")
    expect(opage.get_by_text(copy("sharing.withdrawn", sender="Mei-Lin Chen"))).to_be_visible()

    # A person who is not a member: the share field offers an invite.
    page.get_by_role("button", name=copy("sharing.share"), exact=True).click()
    dialog.get_by_label(copy("sharing.share_field")).fill("lena@example.org")
    dialog.locator(".rf-ui-search-result", has_text="lena@example.org").click()
    expect(dialog.get_by_text(copy("sharing.share_invite"))).to_be_visible()
    dialog.get_by_role("button", name=copy("sharing.share_action", name="lena@example.org")).click()
    expect(dialog).to_be_hidden()
    invited = shared_with.locator(".ag-rows-item", has_text="lena@example.org")
    expect(invited).to_contain_text(copy("sharing.state_invited"))

    main = page.locator("main").inner_text() + opage.locator("main").inner_text()
    assert (
        chen_p.service.account.overview()["details"]["subject"] not in main
    )  # no person id on the screen
    assert root not in main
    assert not chen.faults, chen.faults
    assert not okafor.faults, okafor.faults
    chen.ctx.close()
    okafor.ctx.close()


# ------------------------------------------------- a reader invite (rule 8)


def test_reader_invite_ends_on_shared_with_me(browser, tmp_path):
    """A person who is not a member gets a reader invite for an ORCID iD,
    opens the link, joins with no lab, and lands on "Shared with me" with
    the finding ready to read."""
    from test_app_runtime import FakeIndexer
    from test_ui_browser_join import INSTITUTIONS, Site, open_from_node_page, sign_in_at_fake_orcid

    from anagram.shell.app.runtime import AppRuntime
    from anagram.shell.ui.service import UIService

    site = Site(tmp_path / "site")
    rt = None
    try:
        orcid = "fake-0000-0009-reader-ada"
        root = commit(site.pi, tmp_path, FILES, claim=CLAIM)
        invite = site.pi.invites.invite_reader(root, {"kind": "orcid", "value": orcid})["link"]
        home = tmp_path / "reader"
        rt = AppRuntime(
            home,
            embed=False,
            tick_s=0.05,
            service=UIService(home, institutions=INSTITUTIONS),
            make_indexer=lambda s: FakeIndexer(),
        )
        rt.start()
        page = browser.new_page(viewport={"width": 390, "height": 844})
        faults = clean(page)
        open_from_node_page(page, invite, home)
        ready(page, "welcome")
        # R8: the name, then the invite to an ORCID iD asks ORCID for the proof.
        page.get_by_label(copy("welcome.name_label")).fill("Ada Lind")
        page.get_by_role("button", name=copy("welcome.join_action")).click()
        sign_in_at_fake_orcid(page, orcid, "Ada Lind")
        expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_visible(
            timeout=60000
        )
        page.get_by_label(copy("welcome.kit_check")).check()
        page.get_by_role("button", name=copy("welcome.kit_continue")).click()
        expect(page.get_by_role("heading", name=copy("details.setup_title"))).to_be_visible()
        # The owner's computer sees the claim; the owner confirms the person,
        # then the finding goes.
        site.pi.share_sync.sync_shares()
        (claim,) = site.pi.invites.reader_claims()
        assert claim["name"] == "Ada Lind"
        site.pi.invites.confirm_reader_claim(claim["invite_id"], True)
        # No lab for a reader: the lab choice starts on "later", not on "Start a lab".
        expect(page.locator("#lab-later")).to_be_checked()
        page.get_by_label(copy("details.institution")).fill("Northbridge")
        page.get_by_text("Northbridge University").click()
        page.get_by_role("button", name=copy("details.save_setup")).click()

        ready(page, "sharing")
        assert page.url.endswith("#/sharing")
        row = page.locator(
            "a.ag-row-link", has_text=copy("sharing.untitled", sender="Mei-Lin Chen")
        )
        expect(row).to_be_visible()
        looks(page, "reader-invite")
        row.click()
        expect(page.get_by_text(CLAIM).first).to_be_visible(timeout=30000)
        assert faults == [], faults
        page.close()
    finally:
        if rt is not None:
            rt.stop()
        site.stop()
