"""Browser test of network matching with the demo community: the matching
enclave of the demo network (simulated profile) gives Chen a proposal; Chen
says yes on the "Network matching" screen; the reveal comes live, with no
reload, when Okafor said yes too. Matching runs only in the enclave;
the node relays sealed messages.

Skipped when Playwright or its Chromium is not installed. Set
ANAGRAM_UI_SHOTS=DIR to save screenshots.
"""

from __future__ import annotations

import pytest
from test_ui_browser import page_scroll, shot
from uikit import clean, copy, ready

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.sim.demo import Demo  # noqa: E402

expect = sync_api.expect


@pytest.fixture
def enclave_demo(tmp_path):
    """The demo with each person on; the demo says yes for all but Chen.
    The next day gives the proposals. The demo runs on the real clock: a
    setup in the hours before the day's cut (23:00 UTC) joins the round of
    the day after, so one more day may be needed."""
    d = Demo(tmp_path / "demo", large_bytes=4096).start()
    assert d.ready_all() == []
    d.autopilot(d.people[0])
    for _ in range(2):
        d.next_day()
        if any(c["kind"] == "proposal" for c in d.people[0].service.enclave.state()["cards"]):
            break
    yield d
    d.stop()


def say_yes_to_open_proposals(page) -> None:
    """Chen fills in the card and says yes on each proposal with no answer
    yet (the card says that no answer counts as "not now")."""
    yes = copy("netmatch.yes")
    open_cards = page.locator("article.ag-card", has_text=copy("netmatch.reasons")).filter(
        has_text=copy("netmatch.unset")
    )
    for _ in range(open_cards.count()):
        card = open_cards.first
        # The card comes from the account; Chen opens it to set these values.
        change = card.get_by_role("button", name=copy("netmatch.card_edit"))
        if change.count():
            change.click()
        for key, value in (("name", "Mei-Lin Chen"), ("institution", "Northbridge University"),
                           ("email", "mchen@northbridge.example")):  # fmt: skip
            card.get_by_label(copy(f"netmatch.card_{key}")).fill(value)
        before = open_cards.count()
        card.get_by_role("button", name=yes).click()
        expect(open_cards).to_have_count(before - 1)


def test_a_proposal_and_a_live_reveal(browser, enclave_demo):  # noqa: F811
    d = enclave_demo
    chen = d.people[0]
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, color_scheme="dark")
    page = ctx.new_page()
    faults = clean(page)
    page.goto(chen.url)
    page.goto(chen.url.split("/open/")[0] + "/#/network-matching")
    ready(page, "netmatch")
    expect(page.get_by_text(copy("netmatch.simulated"))).to_be_visible()
    # A proposal names no peer: Chen says yes to each one. A slot holds one
    # item for each person and day, so more proposals can come on later
    # days; Chen says yes to each one when it comes.
    cards = page.locator("article.ag-card", has_text=copy("netmatch.reasons"))
    expect(cards.first).to_be_visible()
    shot(page, "30-proposal-390-dark")
    say_yes_to_open_proposals(page)

    loads: list[str] = []
    page.on("framenavigated", lambda f: loads.append(f.url))
    reveal = page.get_by_role("article", name=copy("netmatch.reveal", name="Chidi Okafor"))
    for _ in range(8):  # the answers go out; both said yes; the reveal
        d.next_day()
        if reveal.count():
            break
        say_yes_to_open_proposals(page)
    expect(reveal).to_be_visible()
    assert loads == []
    shot(page, "31-reveal-390-dark")
    scroll = page_scroll(page)
    assert not scroll, f"horizontal page scroll at 390 px: {scroll}"
    ctx.close()
    assert not faults, faults
