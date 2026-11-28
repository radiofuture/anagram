"""Browser tests of the local UI (Playwright, headless Chromium).

The walk of Chen (PI) is four tests on one demo community (module fixture,
the tests run in file order): join and add a source; the router, Back, and
live reloads; timestamp and share a finding; the way to network matching,
the other screens, and sign out. The other three labs join and turn
matching on through the same service methods (`Demo.autopilot`).
`test_ui_browser_matching.py` walks a proposal and a reveal. The tests find elements by the copy files
(`uikit.copy`) and wait for a screen state (`uikit.ready`), not on time.

Skipped when Playwright or its Chromium is not installed
(`uv run playwright install chromium`). Set ANAGRAM_UI_SHOTS=DIR to save
screenshots of each screen.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from uikit import clean, copy, ready, until

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.sim.demo import Demo  # noqa: E402

STORY = True  # the tests share one page, in file order (conftest.keep_story_order)
SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
expect = sync_api.expect


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    root = tmp_path_factory.mktemp("walk")
    d = Demo(root / "demo", large_bytes=4096).start()
    with pytest.MonkeyPatch.context() as mp:
        # The folder picker starts in the home folder: make it the sim labs folder.
        mp.setenv("HOME", str(root / "demo" / "sim" / "labs"))
        chen = d.person("chen")
        chen.service.state.update(pending_sources=[])  # Chen adds the folder in the browser
        for p in d.people[1:]:
            d.autopilot(p)
        yield d
    d.stop()


class Walk:
    """One browser page of Chen that the four walk tests share."""

    def __init__(self, browser, demo) -> None:
        self.demo = demo
        self.chen = demo.person("chen")
        self.base = self.chen.url.split("/open/")[0]
        self.ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        self.page = self.ctx.new_page()
        self.faults = clean(self.page)

    def go(self, route: str, screen: str) -> None:
        self.page.goto(f"{self.base}/{route}")
        ready(self.page, screen)

    def nav(self, key: str):
        return self.page.get_by_role("navigation").get_by_role("link", name=copy(key), exact=True)


@pytest.fixture(scope="module")
def walk(browser, demo):
    w = Walk(browser, demo)
    yield w
    w.ctx.close()


def shot(page, name: str) -> None:
    if not SHOTS:
        return
    Path(SHOTS).mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True, animations="disabled")


def page_scroll(page) -> str:
    """Empty when the page has no horizontal scroll. Else the page width and
    each element that goes past the right edge (in one read of the layout,
    because a scroll that a motion makes can stop before a second read)."""
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


def test_walk_1_join_and_add_a_source(walk):
    page = walk.page
    page.goto(walk.chen.url)
    ready(page, "welcome")
    shot(page, "01-welcome")
    page.keyboard.press("Tab")  # the skip link gets focus first
    expect(page.locator(".ag-skip")).to_be_focused()
    page.get_by_role("button", name=copy("welcome.join_action")).click()  # R8: no ORCID
    expect(page.get_by_role("heading", name=copy("welcome.kit_title"))).to_be_visible(timeout=30000)
    page.get_by_label(copy("welcome.kit_check")).check()
    page.get_by_role("button", name=copy("welcome.kit_continue")).click()
    expect(page.get_by_role("heading", name=copy("details.setup_title"))).to_be_visible()
    page.get_by_label(copy("details.institution")).fill("Northbridge")
    page.get_by_text("Northbridge University").click()
    page.get_by_label(copy("details.new_lab")).fill("Chen Lab")
    page.evaluate(RECORD_SETDOWN)
    page.get_by_role("button", name=copy("details.save_setup")).click()

    # The first Home: what Anagram does now. Its panel sets down one time
    # (the cause is the save), then no animation stays.
    ready(page, "home")
    expect(page.get_by_role("heading", level=1)).to_have_text(copy("home.first_title"))
    set_down(page)
    shot(page, "01b-first-home")
    page.get_by_role("link", name=copy("home.connect")).click()
    ready(page, "sources")
    # No source yet: the screen is the choice of the kinds (the labels come from the server).
    page.get_by_role("button", name="Folder", exact=True).click()
    page.get_by_role("button", name="chen", exact=True).click()
    page.get_by_role("button", name=copy("common.picker.pick")).click()
    # The label of a source is the folder name; no path is on the screen.
    expect(page.get_by_text(copy("sources.state_checked", date="").strip()).first).to_be_visible(
        timeout=60000
    )
    assert str(walk.demo.root) not in page.locator("main").inner_text()
    shot(page, "02-sources")
    assert not walk.faults, walk.faults


RECORD_MOTION = """() => {
  if (window.__motion) { window.__motion.length = 0; return; }
  window.__motion = [];
  const animate = Element.prototype.animate;
  Element.prototype.animate = function (frames, opts) {
    window.__motion.push(String(this.className));
    return animate.call(this, frames, opts);
  };
  document.addEventListener('animationstart', (e) => window.__motion.push(e.animationName), true);
}"""


# T4 (proof set-down) is recorded when its class arrives on a panel, with
# the animations that the class starts. Not by the animation events: on a
# busy machine one long frame can pass the whole set-down, and the handler
# that removes the class at `animationend` can run before Chromium sends
# `animationstart` of the delayed edge animation, so that event never comes.
RECORD_SETDOWN = """() => {
  if (window.__setdown) { window.__setdown.length = 0; return; }
  window.__setdown = [];
  const had = new WeakMap();  // panel -> it had the class at the last record
  new MutationObserver((records) => {
    for (const r of records) {
      const el = r.target;
      const has = el.classList.contains('ag-m-proof');
      if (has && !had.get(el)) window.__setdown.push(getComputedStyle(el).animationName);
      had.set(el, has);
    }
  }).observe(document.body, { subtree: true, attributes: true, attributeFilter: ['class'] });
}"""


def set_down(page) -> None:
    """One panel set down with both animations of T4. Then the test plays
    each animation to its end (no wait on the animation clock), and the
    class goes and no animation stays."""
    until(page, "window.__setdown.length > 0")
    assert page.evaluate("window.__setdown") == ["ag-m-setdown-panel, ag-m-setdown-edge"]
    page.evaluate("document.getAnimations().forEach((a) => a.finish())")
    until(
        page,
        "document.getAnimations().length === 0 && !document.querySelector('.ag-m-proof')",
        timeout=5,
    )


def motion(page) -> list[str]:
    """The motions since `RECORD_MOTION`: element classes (script motion) and CSS animation names."""
    return page.evaluate("window.__motion.slice()")


def test_walk_2_router_back_and_live_reload(walk):
    page = walk.page
    # A route change: the nav link moves the hash, the title, and the focus.
    walk.nav("library.nav").click()
    ready(page, "library")
    assert page.url.endswith("#/library")
    expect(page.get_by_role("heading", level=1)).to_have_text(copy("library.title"))
    expect(walk.nav("library.nav")).to_have_attribute("aria-current", "page")
    expect(page.get_by_role("heading", name=copy("library.new_title"))).to_be_visible()

    # Back restores the scroll position of the list. The window is short for
    # this check: the demo has nine proposed findings since received mail is
    # context only (security fix P0-1), and the list must be taller than the
    # window for a scroll position to exist.
    page.set_viewport_size({"width": 1280, "height": 600})
    link = page.locator("main a[href^='#/draft/']").last
    # The drafts come as the sources are read: wait for a list taller than the window.
    until(page, "document.documentElement.scrollHeight > window.innerHeight + 300", timeout=30)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    until(page, "window.scrollY > 100")
    link.scroll_into_view_if_needed()
    y = page.evaluate("window.scrollY")
    assert y > 100
    link.click()
    ready(page, "draft")
    page.go_back()
    ready(page, "library")
    until(page, f"Math.abs(window.scrollY - {y}) < 4")
    page.set_viewport_size({"width": 1280, "height": 900})

    # An event on the stream reloads the resource that listens to it.
    with page.expect_request(lambda r: r.url.endswith("/api/suggestions")):
        walk.chen.server.app.state.ctx.bus.publish("draft.changed")

    # A reconnect to a server with a new server_id reloads the resources.
    hello = 'id: 0\nevent: hello\ndata: {"v":1,"id":0,"at":"","type":"hello","topic":"hello","key":null,' \
            '"data":{"server_id":"another","last_id":0}}\n\n'  # fmt: skip
    page.route(
        "**/api/events",
        lambda route: route.fulfill(
            status=200, headers={"Content-Type": "text/event-stream"}, body=hello
        ),
    )
    with page.expect_request(lambda r: r.url.endswith("/api/suggestions")):
        page.evaluate(
            "import('/static/js/core/events.js').then((ev) => { ev.disconnect(); ev.connect(); })"
        )
    page.unroute("**/api/events")
    page.evaluate(
        "import('/static/js/core/events.js').then((ev) => { ev.disconnect(); ev.connect(); })"
    )
    assert not walk.faults, walk.faults


def test_walk_3_timestamp_and_share(walk):
    page = walk.page
    walk.go("#/library", "library")
    page.locator("main").get_by_role("link", name="Chen Lab: Q4 project plan").first.click()
    ready(page, "draft")
    expect(page.get_by_role("heading", name=copy("draft.title"))).to_be_visible()
    shot(page, "03-draft")
    page.evaluate(RECORD_SETDOWN)
    page.get_by_role("button", name=copy("draft.stamp")).click()
    expect(page.get_by_test_id("proof-date")).to_be_visible(timeout=30000)
    ready(page, "finding")
    # T4: on the acknowledgement of the server the proof panel sets down one
    # time, then the class goes and no animation stays.
    set_down(page)
    shot(page, "04-proof")

    # The share sheet of R5 (slot finding.actions): a ring is the second choice under the field.
    page.get_by_role("button", name=copy("sharing.share"), exact=True).click()
    dialog = page.locator("dialog")
    expect(dialog.get_by_role("heading", name=copy("sharing.share_title"))).to_be_visible()
    # The 2-character hint shows only while the field has 1 character (W10).
    hint = dialog.get_by_text("Enter at least 2 characters.")
    expect(hint).to_be_hidden()
    dialog.get_by_role("searchbox").fill("C")
    expect(hint).to_be_visible()
    dialog.get_by_role("searchbox").fill("")
    expect(hint).to_be_hidden()
    dialog.get_by_role("button", name="Community", exact=True).click()
    dialog.get_by_role("button", name=copy("sharing.share_action", name="Community")).click()
    expect(dialog).to_be_hidden(timeout=30000)
    shared_with = page.locator("section[aria-labelledby=shared-with-title]")
    expect(shared_with.locator(".ag-rows-item")).to_have_count(3)
    shot(page, "05-shared")
    okafor = walk.demo.person("okafor")
    assert [g["sender"] for g in okafor.service.sharing.inbox()] == ["Mei-Lin Chen"]

    # T3: the title of the chosen row moves to the place of the screen title,
    # and Back runs it in reverse. Each motion ends.
    title = page.get_by_role("heading", level=1).inner_text()
    walk.go("#/library", "library")
    page.evaluate(RECORD_MOTION)
    page.locator("main a.ag-row-link", has_text=title).first.click()
    ready(page, "finding")
    until(page, "window.__motion.includes('ag-title')")
    until(page, "document.getAnimations().length === 0", timeout=5)
    page.go_back()
    ready(page, "library")
    until(page, "window.__motion.includes('ag-row-title')")
    until(page, "document.getAnimations().length === 0", timeout=5)
    assert not walk.faults, walk.faults


def test_walk_4_network_matching_screens_and_sign_out(walk, browser):
    page, demo = walk.page, walk.demo
    # `demo up` sets the log URL, the pins and a draft for a person who
    # joined (the day driver); the test fixture runs no driver.
    demo.set_up_matching(demo.person("chen"))
    walk.nav("netmatch.nav").click()
    ready(page, "netmatch")
    expect(page.get_by_role("heading", name=copy("netmatch.title"))).to_be_visible()
    expect(page.get_by_text(copy("netmatch.simulated"))).to_be_visible()
    shot(page, "06-netmatch")

    # The other screens render, also at 390 px with no page scroll.
    for route, screen, title in (
        ("#/network-matching", "netmatch", "netmatch.title"),
        ("#/sharing", "sharing", "sharing.title"),
        ("#/sharing/by-me", "sharing", "sharing.title"),
        ("#/account", "account", "account.title"),
        ("#/account/details", "details", "details.title"),
        ("#/privacy", "privacy", "privacy.title"),
        ("#/sources", "sources", "sources.title"),
    ):
        walk.go(route, screen)
        expect(page.get_by_role("heading", level=1)).to_have_text(copy(title))
        page.set_viewport_size({"width": 390, "height": 844})
        scroll = page_scroll(page)
        assert not scroll, f"{screen}: horizontal page scroll at 390 px: {scroll}"
        shot(page, f"07-{screen}-390")
        page.set_viewport_size({"width": 1280, "height": 900})

    # Okafor opens the shared finding in his own UI.
    okafor = demo.person("okafor")
    octx = browser.new_context(viewport={"width": 1280, "height": 900})
    opage = octx.new_page()
    ofaults = clean(opage)
    opage.goto(okafor.url)
    opage.goto(okafor.url.split("/open/")[0] + "/#/sharing")
    ready(opage, "sharing")
    # The row opens the reading view of R5 (/reader/#<grant>).
    opage.locator("a.ag-row-link", has_text="Mei-Lin Chen").click()
    expect(opage.get_by_text("Shared by Mei-Lin Chen", exact=False)).to_be_visible(timeout=30000)
    shot(opage, "08-inbox-opened")
    octx.close()
    assert not ofaults, ofaults

    # Sign out, then sign in again with ORCID only (no invite field).
    walk.go("#/account", "account")
    page.get_by_role("button", name=copy("account.signout"), exact=True).click()
    expect(page.get_by_role("heading", name=copy("welcome.again_title"))).to_be_visible()
    expect(page.get_by_label(copy("welcome.invite_label"))).to_be_hidden()
    page.get_by_role("button", name=copy("welcome.again_action")).click()
    ready(page, "home")  # the heading names the state (search or ask), not the screen
    assert not walk.faults, walk.faults


def test_core_module_renders_a_component(browser, tmp_path):
    """The shell has an import map that the CSP permits, the vendored modules
    load, and a component renders and updates from a signal."""
    from anagram.shell.ui.server import UIServer
    from anagram.shell.ui.service import UIService

    server = UIServer(UIService(tmp_path / "home")).start()
    ctx = browser.new_context()
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(server.url)
        expect(page.locator("main h1")).to_be_visible()
        out = page.evaluate(
            """async () => {
              const { html, render, signal } = await import('/static/js/core/html.js');
              const count = signal(1);
              const Hello = ({ name }) => html`<p>${name} ${count} ${null}${false}</p>`;
              const root = document.createElement('div');
              document.body.append(root);
              render(html`<${Hello} name="Anagram" />`, root);
              const first = root.textContent;
              count.value = 2;
              await new Promise((done) => setTimeout(done, 50));
              const second = root.textContent;
              root.remove();
              return [first, second];
            }"""
        )
        assert out == ["Anagram 1 ", "Anagram 2 "]
        assert not faults, faults
    finally:
        ctx.close()
        server.stop()
