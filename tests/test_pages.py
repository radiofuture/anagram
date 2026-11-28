"""Node pages in the brand (`anagram.shell.pages`)."""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from conftest import NODE_URL
from test_admin import ORG, Site
from test_ui_copy import BANNED_CHARS, BANNED_PHRASES

from anagram.shell import pages
from anagram.shell.node.admin import _CSP as ADMIN_CSP
from anagram.shell.node.admin import dashboard, login_page

STATIC = pages.BRAND_DIR.parent


class _Refs(HTMLParser):
    """Each URL that a page loads, and each inline style or script."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.inline: list[str] = []
        self._tag = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self._tag = tag
        if tag == "link":
            self.urls.append(a["href"])
        if tag == "script":
            if "src" in a:
                self.urls.append(a["src"])
        if tag == "style" or "style" in a or any(k.startswith("on") for k in a):
            self.inline.append(tag)

    def handle_data(self, data):
        if self._tag == "script" and data.strip():
            self.inline.append("script")


def refs(text: str) -> _Refs:
    p = _Refs()
    p.feed(text)
    return p


def visible_text(text: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.S)
    return re.sub(r"<[^>]+>", " ", text)


def all_pages() -> dict[str, str]:
    w = pages.WORDS
    return {
        "notice": pages.notice(
            w["open_old_title"], w["open_old_text"], action=("Open", "anagram://open")
        ),
        "code": pages.orcid_code("abc-123"),
        "fake": pages.fake_orcid("s", "https://node.test/auth/orcid/callback"),
        "join": pages.join("Test community", download_url="https://example.org/get"),
        "login": login_page("Test community", "Start again."),
        "dashboard": dashboard(
            {"community": "C", "members": 1, "organizers": 1, "open_invites": 0, "labs": []},
            "pid-internal-7f",
            "csrf",
            new_invite=f"{NODE_URL}/join#x",
        ),
    }


@pytest.mark.parametrize("name", list(all_pages()))
def test_page_loads_only_this_server_and_has_no_inline_code(name):
    text = all_pages()[name]
    found = refs(text)
    assert found.inline == []
    for url in found.urls:
        assert url.startswith("/"), url
    assert "https://fonts" not in text and "//cdn" not in text
    assert 'class="rf-ui"' in text and "/brand/node.css" in text


@pytest.mark.parametrize("name", list(all_pages()))
def test_page_words_follow_the_copy_rules(name):
    text = visible_text(all_pages()[name]).lower()
    assert not BANNED_CHARS.search(text)
    assert not [p for p in BANNED_PHRASES if p in text]
    assert "null" not in text.split() and "undefined" not in text


def test_caller_values_are_escaped():
    text = pages.notice("<b>x</b>", "a & b", action=("<i>go</i>", "/x?a=1&b=2"))
    assert "<b>x" not in text and "&lt;b&gt;" in text and "a &amp; b" in text
    assert 'href="/x?a=1&amp;b=2"' in text
    join = pages.join("<script>x</script>")
    assert "<script>x" not in join
    fake = pages.fake_orcid("'\"><x>", "u")
    assert "<x>" not in fake


def test_dashboard_shows_no_internal_id():
    assert "pid-internal-7f" not in all_pages()["dashboard"]


def test_join_page_shape():
    text = pages.join("Varga", script="/brand/node/join.js")
    assert "Join Varga on Anagram" in text
    assert 'id="join-open" href="anagram://open"' in text
    assert '<script src="/brand/node/join.js" defer></script>' in text
    assert "Get Anagram" not in pages.join("Varga")  # no download_url: no link


def test_local_ui_base_names_its_own_paths():
    text = pages.notice("t", "x", base="/static/brand", node_css="/static/css/node.css")
    urls = refs(text).urls
    assert "/static/css/node.css" in urls and "/static/brand/tokens.css" in urls
    for url in urls:
        assert (STATIC / url.removeprefix("/static/")).is_file(), url


def test_node_css_dark_pairs_equal_base_css():
    def dark(path):
        text = path.read_text()
        block = text[text.index("prefers-color-scheme: dark") :]
        return dict(re.findall(r"(--ag-[a-z-]+):\s*([^;]+);", block[: block.index("}")]))

    node_pairs, base = dark(pages.NODE_CSS), dark(STATIC / "css/base.css")
    assert node_pairs and all(base[k] == v for k, v in node_pairs.items())
    assert set(base) - set(node_pairs) <= {"--ag-offset"}  # node pages have no offset panel


def test_node_css_has_square_corners_and_no_shadow():
    text = pages.NODE_CSS.read_text()
    assert "border-radius" not in text and "box-shadow" not in text and "gradient" not in text


def test_admin_csp_has_no_inline_style():
    assert "unsafe-inline" not in ADMIN_CSP and "style-src 'self'" in ADMIN_CSP
    assert "unsafe-inline" not in pages.CSP


# ------------------------------------------------------------------ routes


@pytest.fixture
def site(tmp_path):
    return Site(tmp_path)


def test_node_serves_the_brand(site):
    tc = site.tc
    r = tc.get("/brand/node.css")
    assert (
        r.status_code == 200
        and "ag-node" in r.text
        and r.headers["content-type"].startswith("text/css")
    )
    assert tc.get("/brand/tokens.css").status_code == 200
    assert tc.get("/brand/assets/dm-sans.ttf").status_code == 200
    assert tc.get("/brand/product-ui/widgets/shared/styles.css").status_code == 200
    for name in ("../pages.py", "nothing.js", "x.html", "%2e%2e%2fnode.css"):
        assert tc.get(f"/brand/node/{name}").status_code == 404, name


def test_node_serves_a_node_script(site, tmp_path, monkeypatch):
    d = tmp_path / "node-scripts"
    d.mkdir()
    (d / "join.js").write_text("export {};")
    monkeypatch.setattr(pages, "NODE_DIR", d)
    r = site.tc.get("/brand/node/join.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]


def test_admin_pages_render_with_brand(site):
    r = site.tc.get("/admin")
    assert 'class="rf-ui"' in r.text and "rf-ui-button" in r.text
    assert r.headers["content-security-policy"] == ADMIN_CSP
    site.orcid_login(ORG)
    page = site.tc.get("/admin").text
    assert "ag-node-facts" in page and "<style" not in page


def test_fake_orcid_page_and_code_page(site):
    r = site.tc.post("/admin/login", headers={"Origin": NODE_URL}, follow_redirects=False)
    r = site.tc.get(r.headers["location"])
    assert "Test sign-in. Not ORCID." in r.text and 'class="rf-ui"' in r.text
    csp = r.headers["content-security-policy"]
    assert "form-action 'self' http://127.0.0.1:*" in csp and "style-src 'self'" in csp


def test_local_ui_pages(tmp_path):
    from test_ui_api import make_net, ui_client

    _, tc = ui_client(make_net(tmp_path), tmp_path / "me")
    r = tc.get("/open/wrong", follow_redirects=False)
    assert r.status_code == 403 and pages.WORDS["open_old_title"] in r.text
    assert 'href="anagram://open"' in r.text and "/static/css/node.css" in r.text
    for url in refs(r.text).urls:
        assert tc.get(url).status_code == 200, url
    r = tc.get("/auth/callback?state=old&code=x", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200 and pages.WORDS["signin_old_title"] in r.text
    assert 'href="/#/welcome"' in r.text and "refresh" not in r.text
