"""Proof certificate in a real browser: the action on the
finding screen saves the file, the file prints to one page (A4 and Letter)
with 8 files, and a phone width has no side scroll. Chromium only; the test
is skipped when Playwright or Chromium is not installed. No network: the UI
talks to the in-process node of `conftest.net`.
"""

from __future__ import annotations

import os
import re
import zipfile

import pytest
from uikit import clean, copy, ready

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.proofs.certificate import load_proof  # noqa: E402
from anagram.shell.ui.library import LibraryUI  # noqa: E402
from anagram.shell.ui.server import UIServer  # noqa: E402
from anagram.shell.ui.service import UIService  # noqa: E402

expect = sync_api.expect
SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
NAMES = [
    "western-blot-replicate-3.tif",
    "qPCR_results_2026-11-02.csv",
    "methods-draft.docx",
    "figure2_dose_response.png",
    "analysis.ipynb",
    "raw_counts_matrix.tsv",
    "supplementary-table-S4.xlsx",
    "microscopy_series_14.czi",
]
CLAIM = (
    "Loss of TMEM175 slows lysosomal alkalinisation in iPSC-derived dopaminergic neurons"
    " under oxidative stress"
)


def pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf))


def eight_files(tmp_path) -> list:
    out = []
    for i, name in enumerate(NAMES):
        p = tmp_path / name
        p.write_bytes(os.urandom(1000 * (i * 137 + 3)))
        out.append(p)
    return out


def member(net, tmp_path):
    """A joined member with an institution (the setup of the UI is done)."""
    return net.join(
        tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor", institution="fake-northbridge"
    ).client


def member_service(net, client) -> UIService:
    """The UI service of a joined member who saved the recovery kit."""
    svc = UIService(client.home, transport=net.transport, clock=net.clock)
    svc.account.kit_saved()
    return svc


def test_save_from_the_finding_screen(browser, net, tmp_path):
    client = member(net, tmp_path)
    files = eight_files(tmp_path)
    root = client.findings.commit_finding(files, claim=CLAIM).subject.root.hex()
    client.vault.close()
    server = UIServer(member_service(net, client)).start()
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
    try:
        page = ctx.new_page()
        faults = clean(page)
        page.goto(server.url)
        page.goto(f"http://127.0.0.1:{server.port}/#/finding/{root}")
        ready(page, "finding")
        # The certificate is the primary action of the proof panel (W9); the
        # raw proof is a secondary link. The finding has one path to the lab
        # (the share sheet), so the panel has no "Add to the lab space" (W8).
        # "Save certificate" opens one sheet with the parts and the save (W15).
        panel = page.locator("main .ag-proof")
        expect(panel.get_by_role("link", name=copy("finding.download"))).to_be_visible()
        expect(panel.get_by_role("button", name=copy("lab.publish"))).to_have_count(0)
        expect(page.get_by_role("heading", name=copy("certify.title"))).to_have_count(0)
        panel.get_by_role("button", name=copy("certify.save")).click()
        sheet = page.locator("dialog")
        expect(sheet.get_by_role("heading", name=copy("certify.title"))).to_be_visible()
        expect(sheet.get_by_text(copy("certify.help"))).to_be_visible()
        sheet.get_by_label(copy("certify.part_name")).uncheck()
        if SHOTS:
            page.screenshot(
                path=f"{SHOTS}/certificate-sheet.png", full_page=True, animations="disabled"
            )
        with page.expect_download() as info:
            sheet.get_by_role("button", name=copy("certify.save")).click()
        expect(sheet).to_be_hidden()
        download = info.value
        assert download.suggested_filename == f"anagram-certificate-{root[:12]}.html"
        saved = tmp_path / download.suggested_filename
        download.save_as(saved)
        assert load_proof(saved).subject.root.hex() == root
        text = saved.read_text()
        assert "Adaeze Okafor" not in text and CLAIM in text

        # The preprint draft is one action that opens a sheet.
        expect(page.get_by_label(copy("certify.draft_authors"))).to_have_count(0)
        panel.get_by_role("button", name=copy("certify.draft_open")).click()
        draft = page.locator("dialog")
        expect(draft.get_by_role("heading", name=copy("certify.draft_title"))).to_be_visible()
        expect(draft.get_by_text(copy("certify.draft_help"))).to_be_visible()
        draft.get_by_label(copy("certify.draft_files")).uncheck()
        with page.expect_download() as info:
            draft.get_by_role("button", name=copy("certify.draft_save")).click()
        expect(draft).to_be_hidden()
        assert info.value.suggested_filename == f"anagram-preprint-{root[:12]}.zip"
        zipped = tmp_path / info.value.suggested_filename
        info.value.save_as(zipped)
        names = zipfile.ZipFile(zipped).namelist()
        assert "manuscript.tex" in names and f"proof/certificate-{root[:12]}.html" in names
        assert not [n for n in names if n.startswith("supplement/")]
        if SHOTS:
            page.screenshot(
                path=f"{SHOTS}/finding-proof-sections.png", full_page=True, animations="disabled"
            )
        assert not faults, faults

        # The file itself: no fault, one printed page, no side scroll on a phone.
        cert = ctx.new_page()
        cert_faults = clean(cert)
        cert.goto(saved.as_uri())
        expect(cert.get_by_role("heading", level=1)).to_have_text(CLAIM)
        for fmt in ("A4", "Letter"):
            assert pages(cert.pdf(format=fmt, print_background=True)) == 1, fmt
        cert.set_viewport_size({"width": 390, "height": 800})
        assert cert.evaluate("document.documentElement.scrollWidth") <= 390
        assert not cert_faults, cert_faults
    finally:
        ctx.close()
        server.stop()


def test_waiting_finding_has_no_save_action(browser, net, tmp_path, monkeypatch):
    client = member(net, tmp_path)
    root = client.findings.commit_finding([], claim="A claim").subject.root.hex()
    client.vault.close()
    svc = member_service(net, client)
    monkeypatch.setattr(LibraryUI, "_proven_by", lambda self, c, r, b: None)
    server = UIServer(svc).start()
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    try:
        page = ctx.new_page()
        page.goto(server.url)
        page.goto(f"http://127.0.0.1:{server.port}/#/finding/{root}")
        ready(page, "finding")
        expect(page.get_by_test_id("proof-date")).to_have_text(copy("library.waiting"))
        expect(page.get_by_role("button", name=copy("certify.save"))).to_have_count(0)
        expect(page.get_by_role("button", name=copy("certify.draft_open"))).to_have_count(0)
    finally:
        ctx.close()
        server.stop()
