"""The join page of the node, `GET /join`.

The page is static: the invite is in the fragment, which never goes to the
server. Its one script sets the "Open Anagram" link."""

from __future__ import annotations

import logging
import re

from conftest import make_net

from anagram.shell import pages
from anagram.shell.node import join_page

JOIN_JS = pages.NODE_DIR / "join.js"


def test_join_page_has_csp_and_no_inline_script(net):
    r = net.tc.get("/join")
    assert r.status_code == 200
    assert r.headers["content-security-policy"] == pages.CSP
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    scripts = re.findall(r"<script([^>]*)>(.*?)</script>", r.text, re.S)
    assert scripts == [(' src="/brand/node/join.js" defer', "")]
    assert "Join Test community on Anagram" in r.text
    assert 'id="join-open" href="anagram://open"' in r.text
    assert "anagram join" not in r.text  # no terminal step
    assert "Get Anagram" not in r.text  # no download_url on this node


def test_join_script_is_served(net):
    r = net.tc.get(join_page.SCRIPT)
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert r.text == JOIN_JS.read_text()


def test_join_script_uses_only_base64url_and_no_html_sink():
    text = JOIN_JS.read_text()
    assert "location.hash" in text and "anagram://join/" in text
    assert "/^[A-Za-z0-9_-]+$/" in text  # other text leaves anagram://open
    for sink in ("innerHTML", "outerHTML", "document.write", "eval(", "fetch(", "XMLHttp"):
        assert sink not in text, sink


def test_download_link_from_the_node_config(tmp_path, monkeypatch):
    monkeypatch.setenv(join_page.DOWNLOAD_ENV, "https://get.example.org/anagram")
    net = make_net(tmp_path)
    text = net.tc.get("/join").text
    assert 'href="https://get.example.org/anagram"' in text and "Get Anagram" in text


def test_download_url_rules():
    env = join_page.DOWNLOAD_ENV
    assert join_page.download_url({env: " https://a.example/x "}) == "https://a.example/x"
    assert join_page.download_url({env: "http://anagram.localhost:8443/get"}).startswith("http:")
    assert join_page.download_url({env: "http://a.example/x"}) == ""  # not https
    assert join_page.download_url({env: "javascript:alert(1)"}) == ""
    assert join_page.download_url({}) == ""


def test_invite_never_reaches_a_server_log(net, caplog):
    """A browser does not send the fragment. Also a client that sends a
    query (a mistake) gets the same page, and no log line holds it."""
    invite = net.invite()
    token = invite.split("#", 1)[1]
    with caplog.at_level(logging.DEBUG):
        r = net.tc.get(invite)  # the HTTP client drops the fragment, as a browser does
        q = net.tc.get(f"/join?{token[:40]}")
    assert r.text == q.text == net.tc.get("/join").text
    # The test HTTP client logs its own requests; the server side is the rest.
    server = [rec.getMessage() for rec in caplog.records if not rec.name.startswith("http")]
    assert not any(token[:40] in line for line in server)
