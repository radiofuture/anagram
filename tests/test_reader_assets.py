"""R5 step 7b: the reading view (`src/anagram/web/reader/`).

Static rules (no browser): pdf.js is vendored with a manifest; one module
loads it; the local UI serves `/reader` under its CSP. Browser tests
(Chromium through Playwright; skipped when it is not installed): the reader
draws each fixture of step 5 and the larger fixtures from a reading model, and
it runs no content of a shared file (`test_reader_does_not_run_content`).
No network: the pages come from a local server in a thread.
"""

from __future__ import annotations

import base64
import importlib.util
import re
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from readerkit import reader_app, reading_model
from readkit import ALL, PNG
from readkit_rich import RICH
from uikit import until

from anagram.shell.ui.routers.sharing import READER
from anagram.shell.ui.server import CSP, create_ui_app
from anagram.shell.ui.service import UIService

PRODUCT = Path(__file__).resolve().parents[1]
VENDOR = READER / "vendor"


def _vendor_js():
    spec = importlib.util.spec_from_file_location("vendor_js", PRODUCT / "scripts/vendor_js.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------ static


def test_pdfjs_is_vendored_with_source_version_license_and_hash():
    assert _vendor_js().check(VENDOR) == []
    import json

    files = json.loads((VENDOR / "manifest.json").read_text())["files"]
    assert set(files) == {"pdf.min.mjs", "pdf.worker.min.mjs"}
    for entry in files.values():
        assert entry["package"] == "pdfjs-dist" and entry["license"] == "Apache-2.0"
        assert entry["source"].startswith("https://registry.npmjs.org/pdfjs-dist/-/")
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert "Apache License" in (VENDOR / "LICENSES.txt").read_text()


def test_only_the_pdf_module_loads_the_vendored_files():
    for f in sorted(READER.glob("*.js")):
        text = f.read_text()
        assert ("vendor/" in text) == (f.name == "pdfview.js"), f
        assert not re.search(r"\bimport\s*\(\s*[^'\"n]", text) or f.name == "pdfview.js", f


def test_reader_code_has_no_html_sink_and_no_eval():
    for f in sorted(READER.glob("*.js")):
        text = f.read_text()
        for sink in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ):
            assert sink not in text, f"{f.name}: {sink}"
        assert "setAttribute('style'" not in text and "srcdoc" not in text, f
    # pdf.js runs no script of a PDF.
    pdf = (READER / "pdfview.js").read_text()
    assert "isEvalSupported: false" in pdf and "enableXfa: false" in pdf
    assert "enableScripting" not in pdf


def test_the_local_ui_serves_the_reader_under_its_csp(tmp_path):
    app = create_ui_app(UIService(tmp_path / "home"), port=41997, token="t")  # noqa: S106 - a test value
    tc = TestClient(app, base_url="http://127.0.0.1:41997")
    for path, kind in (
        ("/reader/", "text/html"),
        ("/reader/reader.js", "javascript"),
        ("/reader/reader.css", "text/css"),
        ("/reader/vendor/pdf.worker.min.mjs", "javascript"),
    ):
        r = tc.get(path)
        assert r.status_code == 200, path
        assert kind in r.headers["content-type"], path
        assert r.headers["content-security-policy"] == CSP
    policy = dict(part.strip().split(" ", 1) for part in CSP.split(";"))
    assert policy["worker-src"] == "'self'" and "blob:" in policy["img-src"]
    # The page is a shell with no data and no inline script.
    html = tc.get("/reader/").text
    assert re.findall(r"<script\b[^>]*>", html) == ['<script type="module" src="/reader/page.js">']


# ----------------------------------------------------------------- browser

sync_api = pytest.importorskip("playwright.sync_api")


SVG_BAD = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" onload="window.__ran=1">'
    b'<script>window.__ran=2</script><rect width="40" height="40" fill="#293fa8"/></svg>'
)
HTML_BAD = (
    b'<html><body><h1>Results</h1><p>Text <img src=x onerror="window.__ran=3"></p>'
    b"<script>window.__ran=4</script></body></html>"
)
MD_BAD = (
    b"# Notes <img src=x onerror=window.__ran=5>\n\n"
    b"A [link](javascript:window.__ran=6) and ![pic](https://example.org/a.png) and "
    b"<script>window.__ran=7</script>\n"
)
CSV_BAD = b'name,value\n"<img src=x onerror=window.__ran=8>",1\n'


@pytest.fixture(scope="module")
def site():
    import uvicorn

    hostile = {
        "<img src=x onerror=window.__ran=9>.svg": SVG_BAD,
        "page.html": HTML_BAD,
        "notes.md": MD_BAD,
        "data.csv": CSV_BAD,
    }
    entries = {
        "a" * 32: reading_model(
            "a" * 32, {n: make() for n, make in ALL.items()}, "Growth doubled\nmore text"
        ),
        "b" * 32: reading_model(
            "b" * 32, {n: make() for n, make in RICH.items()}, "Growth of cells"
        ),
        "c" * 32: reading_model(
            "c" * 32,
            hostile,
            "<script>window.__ran=10</script>\n<b onclick=x>claim</b>",
            label="<img src=x onerror=window.__ran=11>",
        ),
    }
    server = uvicorn.Server(
        uvicorn.Config(reader_app(entries), host="127.0.0.1", port=0, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    end = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > end:
            pytest.fail("the reader test server did not start")
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


def _open(browser, site, grant, width=1280):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    page = ctx.new_page()
    faults = []
    page.on("pageerror", lambda e: faults.append(f"pageerror: {e}"))
    page.on("console", lambda m: faults.append(m.text) if m.type == "error" else None)
    page.goto(f"{site}/reader/#{grant}")
    page.wait_for_selector(".rd[data-state=ready]", timeout=20000)
    return ctx, page, faults


def _show(page, name):
    page.locator(".rd-toc-item", has_text=name).click()
    page.wait_for_selector(f".rd-item-title:text-is('{name}')")


def test_reader_draws_each_fixture_of_step_5(browser, site):
    ctx, page, faults = _open(browser, site, "a" * 32)
    try:
        expect = sync_api.expect
        assert page.locator(".rd-toc-item").count() == len(ALL)
        expect(page.locator(".rd-title")).to_have_text("Growth doubled")
        expect(page.locator(".rd-lede")).to_have_text("more text")

        _show(page, "figure.png")
        img = page.locator(".rd-figure--main img")
        expect(img).to_be_visible()
        until(page, "document.querySelector('.rd-figure--main img').naturalWidth === 4")

        _show(page, "data.csv")
        expect(page.locator(".rd-table thead th")).to_have_text(["#", "sample", "value"])
        expect(page.locator(".rd-table tbody tr")).to_have_count(3)
        expect(page.locator(".rd-table td.rd-num")).to_have_text(["0", "2", "4"])

        _show(page, "counts.xlsx")
        expect(page.locator(".rd-table thead th")).to_have_text(["#", "gene", "count"])

        _show(page, "methods.docx")
        expect(page.locator(".rd-prose h3")).to_have_text("Methods")
        expect(page.locator(".rd-prose")).to_contain_text("We grew the cells.")
        expect(page.locator(".rd-gallery img")).to_have_count(1)

        _show(page, "talk.pptx")
        expect(page.locator(".rd-slide")).to_have_count(2)
        expect(page.locator(".rd-slide-title")).to_have_text(["Results", "Next"])

        _show(page, "notes.md")
        expect(page.locator(".rd-prose h3")).to_have_text("Notes")

        _show(page, "analysis.ipynb")
        expect(page.locator(".rd-prose pre")).to_contain_text("plot(x)")
        # The figure of the code cell is under the cell, not at the end.
        expect(page.locator(".rd-output img")).to_have_count(1)
        expect(page.locator(".rd-gallery")).to_have_count(0)

        # The fixture PDF of step 5 has no page tree: pdf.js refuses it and
        # the view shows the text of the reading copy.
        _show(page, "paper.pdf")
        expect(page.locator(".rd-item")).to_contain_text("Cells grow at 37 degrees", timeout=20000)
        assert faults == []
    finally:
        ctx.close()


def test_reader_draws_pdf_pages_and_slides_and_steps_with_the_keyboard(browser, site):
    ctx, page, faults = _open(browser, site, "b" * 32)
    try:
        expect = sync_api.expect
        _show(page, "paper.pdf")
        page.wait_for_selector(".rd-pdf[data-state=ready][data-layout=pages]")
        expect(page.locator(".rd-page")).to_have_count(3)
        page.wait_for_selector(".rd-page[data-drawn] canvas")
        expect(page.locator(".rd-meta")).to_contain_text("3 pages")
        # The text layer makes the words of the page selectable.
        until(
            page, "document.querySelector('.rd-page .textLayer').textContent.includes('Abstract')"
        )
        # A canvas with ink on it (not an empty white page).
        assert page.evaluate(
            """() => { const c = document.querySelector('.rd-page canvas');
                const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
                for (let i = 0; i < d.length; i += 4) if (d[i] < 128) return true; return false; }"""
        )

        _show(page, "talk-slides.pdf")
        page.wait_for_selector(".rd-pdf[data-state=ready][data-layout=slides]")
        expect(page.locator(".rd-count")).to_have_text("Slide 1 of 4")
        page.locator(".rd-item-title").focus()
        page.keyboard.press("ArrowRight")
        expect(page.locator(".rd-count")).to_have_text("Slide 2 of 4")
        page.keyboard.press("ArrowLeft")
        expect(page.locator(".rd-count")).to_have_text("Slide 1 of 4")
        # The step buttons are words, not arrow glyphs (review item B7): the
        # visible text is the accessible name, and a button gets the focus.
        prev = page.get_by_role("button", name="Previous slide", exact=True)
        step = page.get_by_role("button", name="Next slide", exact=True)
        expect(prev).to_have_text("Previous slide")
        expect(step).to_have_text("Next slide")
        expect(prev).to_be_disabled()
        assert page.locator(".rd-controls button[aria-label]").count() == 0
        step.focus()
        step.press("Enter")
        expect(page.locator(".rd-count")).to_have_text("Slide 2 of 4")
        expect(prev).to_be_enabled()
        prev.click()
        expect(page.locator(".rd-count")).to_have_text("Slide 1 of 4")
        # The word buttons fit a phone: no horizontal scroll at 390 px.
        page.set_viewport_size({"width": 390, "height": 844})
        expect(step).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.set_viewport_size({"width": 1280, "height": 900})

        _show(page, "growth.csv")
        expect(page.locator(".rd-table tbody tr")).to_have_count(500)
        expect(page.locator(".rd-tableview .rd-note")).to_contain_text("500 of 1,204")

        _show(page, "fit.py")
        expect(page.locator(".rd-code--lines .rd-line").first).to_contain_text(
            '"""Fit a logistic curve'
        )

        _show(page, "raw-counts.h5")
        save = page.locator(".rd-filecard a")
        expect(save).to_have_attribute("download", "raw-counts.h5")
        assert faults == []
    finally:
        ctx.close()


def test_reader_fits_a_phone_screen(browser, site):
    ctx, page, faults = _open(browser, site, "b" * 32, width=390)
    try:
        for name in ("paper.pdf", "growth.csv", "lab-meeting.pptx", "methods.docx"):
            _show(page, name)
            page.wait_for_timeout(200)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), name
        assert faults == []
    finally:
        ctx.close()


def test_reader_does_not_run_content(browser, site):
    ctx, page, faults = _open(browser, site, "c" * 32)
    try:
        expect = sync_api.expect
        for name in ("page.html", "notes.md", "data.csv"):
            _show(page, name)
        _show(page, "<img src=x onerror=window.__ran=9>.svg")
        until(page, "document.querySelector('.rd-figure--main img').complete")
        page.wait_for_timeout(300)
        assert page.evaluate("window.__ran") is None
        # The words show as text.
        expect(page.locator(".rd-title")).to_have_text("<script>window.__ran=10</script>")
        expect(page.locator(".rd-head .rd-label")).to_contain_text(
            "<img src=x onerror=window.__ran=11>"
        )
        # The content made no element of its own.
        made = page.evaluate(
            """() => [...document.querySelectorAll('.rd script, .rd iframe, .rd object, .rd embed,'
                 + ' .rd [onerror], .rd [onload], .rd [onclick], .rd a[href^="javascript"]')].length"""
        )
        assert made == 0
        # An SVG file shows only as an image; a link to an image in Markdown is not loaded.
        assert page.locator(".rd-figure--main img").get_attribute("src").startswith("/api/shared/")
        _show(page, "notes.md")
        expect(page.locator(".rd-prose .rd-alt")).to_have_text("pic")
        assert page.locator(".rd-prose img").count() == 0
        expect(page.locator(".rd-prose a")).to_have_count(0)
        assert faults == []
    finally:
        ctx.close()


def test_reader_uses_the_png_of_the_reading_copy_for_figures(site):
    # The figure route gives the bytes of the reading copy (used by docx and ipynb).
    import httpx

    r = httpx.get(f"{site}/api/shared/{'a' * 32}/figures/4/image_1")
    assert r.status_code == 200 and r.content == PNG
    assert base64.b64encode(r.content)
