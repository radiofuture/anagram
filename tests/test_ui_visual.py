"""Structure checks of the local UI in a browser.

At 1440 x 900 and 390 x 844, light and dark: the screen has one h1, no
horizontal page scroll, the rail and the work area do not overlap, each
target of the nav is at least 44 px high, and dark mode has its own colors.
Motion: nothing loops (no animation runs after a screen change settles), and
with reduced motion a screen change starts no animation.

A server with no community: the welcome and privacy screens. The joined
screens get the 390 px check in test_ui_browser.py (walk 4).
"""

from __future__ import annotations

import pytest
from uikit import clean, copy, ready, until

sync_api = pytest.importorskip("playwright.sync_api")

SIZES = {"desktop": (1440, 900), "phone": (390, 844)}


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    from anagram.shell.ui.server import UIServer
    from anagram.shell.ui.service import UIService

    s = UIServer(UIService(tmp_path_factory.mktemp("visual") / "home")).start()
    yield s
    s.stop()


def colors(page) -> tuple[str, str]:
    return page.evaluate(
        "[getComputedStyle(document.body).backgroundColor, getComputedStyle(document.body).color]"
    )


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_structure(browser, server, size, scheme):
    w, h = SIZES[size]
    ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme=scheme)
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(server.url)
        ready(page, "welcome")
        for route, screen in (("", "welcome"), ("#/privacy", "privacy")):
            if route:
                page.evaluate(f"location.hash = '{route}'")
                ready(page, screen)
            assert page.locator("h1").count() == 1, screen
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
                screen
            )
            rail = page.locator(".ag-rail").bounding_box()
            main = page.locator("main").bounding_box()
            if size == "desktop":
                assert rail["x"] + rail["width"] <= main["x"] + 1, screen
            else:
                assert rail["y"] + rail["height"] <= main["y"] + 1, screen
            for box in page.locator(".ag-nav a").all():
                if box.is_visible():
                    assert box.bounding_box()["height"] >= 44, screen
        bg, fg = colors(page)
        assert bg not in ("rgba(0, 0, 0, 0)", "transparent") and bg != fg
        lum = page.evaluate(
            "(() => { const m = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);"
            " return (m[0] + m[1] + m[2]) / 3; })()"
        )
        assert (lum < 80) if scheme == "dark" else (lum > 160)
        assert not faults, faults
    finally:
        ctx.close()


def test_motion_settles_and_reduced_motion_starts_none(browser, server):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(server.url)
        ready(page, "welcome")
        page.get_by_role("link", name=copy("privacy.nav")).first.click()
        ready(page, "privacy")
        # Each animation ends: nothing loops.
        until(page, "document.getAnimations().length === 0", timeout=5)
        page.emulate_media(reduced_motion="reduce")
        page.go_back()
        ready(page, "welcome")
        assert page.evaluate("document.getAnimations().length") == 0
        assert not faults, faults
    finally:
        ctx.close()


ROWS_SCRIPT = """async (reduced) => {
  const { html, render, signal } = await import('/static/js/core/html.js');
  const { RowList, Row, Progress } = await import('/static/js/components/index.js');
  const items = signal(['a', 'b', 'c']);
  const busy = signal(true);
  const List = () => html`
    <${RowList} items=${items.value} keyOf=${(k) => k} label="Rows"
      render=${(k) => html`<${Row} title=${k} action=${html`<button type="button">Open ${k}</button>`} />`} />`;
  const root = document.createElement('div');
  root.id = 'kit';
  document.querySelector('main').append(root);
  render(html`<${List} />`, root);
  await new Promise((done) => setTimeout(done, 50));
  document.querySelector('#kit button').parentElement.closest('li').nextElementSibling
    .querySelector('button').focus();
  items.value = ['a', 'c'];                       // 'b' goes, with the focus in it
  await new Promise((done) => requestAnimationFrame(() => done()));
  const during = document.querySelectorAll('#kit li').length;
  const leaving = document.querySelectorAll('#kit li[data-leaving]').length;
  const focus = document.activeElement.textContent;
  await new Promise((done) => setTimeout(done, 500));
  const after = [...document.querySelectorAll('#kit li')].map((li) => li.textContent.trim());
  const left = document.getAnimations().length;
  root.remove();
  return { during, leaving, focus, after, left };
}"""


@pytest.mark.parametrize("reduced", [False, True])
def test_row_that_goes_fades_then_closes_and_keeps_the_focus(browser, server, reduced):
    """Motion recipe L3: a removed row stays until its motion ends, cannot be
    used, the focus goes to the next row, and no animation stays. With
    reduced motion the row goes at once."""
    ctx = browser.new_context(reduced_motion="reduce" if reduced else "no-preference")
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(server.url)
        ready(page, "welcome")
        out = page.evaluate(ROWS_SCRIPT, reduced)
        if not reduced:
            assert (out["during"], out["leaving"]) == (3, 1)
        assert out["focus"] == "Open c"
        assert out["after"] == ["aOpen a", "cOpen c"]
        assert out["left"] == 0
        assert not faults, faults
    finally:
        ctx.close()


def test_phone_menu_is_one_sheet_with_the_rail_destinations(browser, server):
    """Below 760 px the rail is one row (mark, place, Menu). The menu is the
    one sheet; a link closes it and goes to its screen."""
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(server.url)
        ready(page, "welcome")
        assert not page.locator(".ag-rail .ag-nav").is_visible()
        menu = page.get_by_role("button", name=copy("common.menu"))
        assert menu.bounding_box()["height"] >= 44
        menu.click()
        page.locator("dialog[open]").get_by_role("link", name=copy("privacy.nav")).click()
        ready(page, "privacy")
        assert page.locator("dialog[open]").count() == 0
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not faults, faults
    finally:
        ctx.close()
