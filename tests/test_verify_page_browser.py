"""Verify page in a real browser (R5 step 13): the content digest of the
browser equals the Python digest, a dropped certificate and its files are
checked, and a published proof opens at its link. Chromium only; skipped
when Playwright or Chromium is not installed. The node runs on 127.0.0.1
(no network beyond loopback).
"""

from __future__ import annotations

import os
import threading
import time

import pytest
from uikit import clean

sync_api = pytest.importorskip("playwright.sync_api")

from conftest import NODE_URL, make_net  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from anagram.core.crypto.chunked import hash_bytes  # noqa: E402
from anagram.proofs.certificate import certificate_bundle, make_certificate  # noqa: E402
from anagram.proofs.node.verify_page import VerifyPages  # noqa: E402
from anagram.shell.node.app import create_app  # noqa: E402
from anagram.shell.ui.server import bind_local  # noqa: E402

expect = sync_api.expect
SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")


@pytest.fixture
def node_site(tmp_path):
    """The test node with the verify page on a loopback port, and a member."""
    import uvicorn

    net = make_net(tmp_path)
    sock = bind_local()
    port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    verify = VerifyPages(
        tmp_path / "proofs.sqlite", net.identity, net.home.trust_info(), public_url=base
    )
    app = create_app(
        net.service,
        net.home.trust_info(),
        net.identity,
        vault=net.vault,
        store=net.store,
        labs=net.labs,
        verify=verify,
        admission=net.admission,
    )
    net.tc = TestClient(app, base_url=NODE_URL)  # the member client calls this app too
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    end = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < end, "the node did not start"
        time.sleep(0.05)
    client = net.join(tmp_path / "m", "0000-0002-1825-0097", "Adaeze Okafor").client
    yield net, client, base
    server.should_exit = True
    thread.join(10)


def test_browser_digest_equals_python(browser, node_site):
    _, _, base = node_site
    page = browser.new_page()
    page.goto(f"{base}/verify")
    cases = [(b"", 4), (b"a", 4), (b"abcdefgh", 4), (b"abcdefghi", 4), (os.urandom(5000), 1000)]
    for data, chunk in cases:
        got = page.evaluate(
            """async ([bytes, chunk]) => {
              const m = await import('/verify/assets/anagram-crypto.js');
              return (await m.contentDigest(new Blob([new Uint8Array(bytes)]), chunk)).digest;
            }""",
            [list(data), chunk],
        )
        assert got == hash_bytes(data, chunk).digest.hex(), (len(data), chunk)
    page.close()


def test_drop_a_certificate_and_its_files(browser, node_site, tmp_path):
    _, client, base = node_site
    data = tmp_path / "qPCR_results_2026-11-02.csv"
    data.write_bytes(os.urandom(3000))
    figure = tmp_path / "figure2_dose_response.png"
    figure.write_bytes(os.urandom(5000))
    root = client.findings.commit_finding(
        [data, figure], claim="Loss of TMEM175 slows lysosomal alkalinisation"
    ).subject.root.hex()
    name, text, _ = make_certificate(client, root)
    cert = tmp_path / name
    cert.write_text(text)
    stray = tmp_path / "notes.txt"
    stray.write_bytes(b"x" * 3000)  # same size as a file of the record, other bytes

    page = browser.new_page(viewport={"width": 1280, "height": 900})
    faults = clean(page)
    page.goto(f"{base}/verify")
    page.set_input_files("#files", [str(cert), str(data), str(stray)])
    result = page.locator("#result")
    expect(result.locator(".vf-verdict")).to_have_text("Valid proof")
    expect(result.get_by_role("heading", level=2)).to_have_text(
        "Loss of TMEM175 slows lysosomal alkalinisation"
    )
    expect(result.locator("li[data-slot='0'] .vf-match")).to_have_text("Same file")
    expect(result.locator("li[data-slot='1'] .vf-match")).to_have_text("Not added")
    expect(result.locator("li", has_text="notes.txt").locator(".vf-match")).to_have_text(
        "Not a file of this record"
    )
    expect(result).to_contain_text("A test anchor is in this proof.")
    if SHOTS:
        page.screenshot(path=f"{SHOTS}/verify-1280.png", full_page=True)
        page.set_viewport_size({"width": 390, "height": 800})
        page.screenshot(path=f"{SHOTS}/verify-390.png", full_page=True)
    page.set_viewport_size({"width": 390, "height": 800})
    assert page.evaluate("document.documentElement.scrollWidth") <= 390
    assert not faults, faults

    # A file that is not a proof gives one plain line.
    page.goto(f"{base}/verify")
    page.set_input_files("#files", [str(data)])
    expect(page.locator("#state")).to_contain_text("None of these files is a proof.")
    page.close()


def test_published_proof_opens_at_its_link(browser, node_site, tmp_path):
    _, client, base = node_site
    data = tmp_path / "data.csv"
    data.write_text("x\n1\n")
    root = client.findings.commit_finding([data], claim="A published claim").subject.root.hex()
    bundle = certificate_bundle(client, root)
    url = client.device.http.call("POST", "/proofs", {"bundle": bundle.to_json()}, auth=True)["url"]
    page = browser.new_page()
    faults = clean(page)
    page.goto(url)
    expect(page.locator("#result .vf-verdict")).to_have_text("Valid proof")
    expect(page.locator("#result h2")).to_have_text("A published claim")
    # The file of the record, added on the page of the link.
    page.set_input_files("#files", [str(data)])
    expect(page.locator("li[data-slot='0'] .vf-match")).to_have_text("Same file")
    page.goto(f"{base}/verify/{'0' * 64}")
    expect(page.locator("#state")).to_have_text("No proof is published at this address.")
    assert not [f for f in faults if "404" not in f], faults
    page.close()
