"""Notion source (contract v2) against `FakeNotion`. No network.

Cases of plan R3 section 5: first sync newest first, no change (one search
call), edit, archive, page that left the selection (daily ID list), a reset
after "Choose pages", rate limit, sign-in needed, Markdown, and the OAuth
token call with HTTP Basic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from indexkit import KEY
from sourcekit import creds_for, tokens

from anagram.identity.app.keystore import MemoryKeystore
from anagram.local.index.local import LocalIndex
from anagram.local.index.store import loads
from anagram.local.sources import connector_from_config, notion
from anagram.local.sources import source_state as ss
from anagram.local.sources.base import ConnectorError, SourceContext
from anagram.local.sources.notion import (
    FakeNotion,
    NotionConnector,
    block,
    blocks_to_markdown,
    para,
)
from anagram.local.sources.oauth import NOTION, OAuthClient, parse_tokens, token_request

pytestmark = pytest.mark.usefixtures("no_network")


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Env:
    def __init__(self, tmp_path, monkeypatch):
        self.fake = FakeNotion()
        self.clock = Clock()
        monkeypatch.setattr(notion, "_now", self.clock)
        self.idx = LocalIndex(tmp_path / "index.sqlite", KEY, http=self.fake, clock=self.clock)
        client = OAuthClient(self.fake.client_id, self.fake.client_secret, "user")
        self.creds = creds_for(
            MemoryKeystore(), self.idx.store, self.fake, self.clock, notion=client
        )
        self.idx.credentials = self.creds
        t = tokens(self.fake.grant(), None, None)
        self.acct = self.creds.save(
            "notion", self.fake.bot_id, self.fake.workspace, self.fake.client_id, t
        )

    def add(self, **cfg) -> str:
        conf = {"account": self.acct.id, "kind": "notion", **cfg}
        sid = self.idx.add_source(connector_from_config(conf))
        self.idx.connectors.pop(sid)
        ss.ensure(self.idx.store, sid, self.clock(), account_id=self.acct.id)
        return sid

    def sync(self, sid: str, process: bool = False):
        self.idx.connectors.pop(sid, None)
        return self.idx.scan([sid], process=process)

    def keys(self, sid: str) -> set[str]:
        rows = self.idx.store.q("SELECT key FROM item WHERE source_id = ? AND present = 1", (sid,))
        return {r["key"] for r in rows}

    def record(self, sid: str, key: str) -> dict:
        row = self.idx.store.one(
            "SELECT v.blob FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE i.source_id = ? AND i.key = ? ORDER BY v.n DESC LIMIT 1",
            (sid, key),
        )
        return json.loads(row["blob"])

    def searches(self, start: int) -> list[str]:
        return [u for m, u in self.fake.calls[start:] if u.endswith("/v1/search")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(NotionConnector, "rate", 1e9)
    e = Env(tmp_path, monkeypatch)
    yield e
    e.idx.close()


@pytest.fixture
def pages(env):
    f = env.fake
    plan = f.add_page(
        "Plan",
        [
            block("heading_1", "Aims"),
            para("Make nanodiscs."),
            block("bulleted_list_item", "Order lipids", children=[para("From the store.")]),
            block("to_do", "Book the microscope", checked=True),
            block(
                "image",
                caption=[{"plain_text": "gel.png"}],
                type="external",
                external={"url": "https://x.example/gel.png?sig=1"},
            ),
        ],
    )
    child = f.add_page("Protocol", [para("Step one.")], parent=plan)
    row = f.add_page(
        "Run 4",
        [para("OK.")],
        database="d0000000-0000-4000-8000-0000000000aa",
        properties={"Status": {"select": {"name": "Done"}, "type": "select"}},
    )
    return {"plan": plan, "child": child, "row": row}


def test_markdown_from_blocks():
    md = blocks_to_markdown(
        [
            block("heading_2", "Methods"),
            para("Bold", bold=True),
            block("numbered_list_item", "One"),
            block("numbered_list_item", "Two"),
            block("code", "x = 1", language="python"),
            block("quote", "A quote."),
            block("divider"),
            block(
                "table",
                children=[
                    block("table_row", cells=[[{"plain_text": "a"}], [{"plain_text": "b"}]]),
                    block("table_row", cells=[[{"plain_text": "1"}], [{"plain_text": "2"}]]),
                ],
            ),
            block("child_page", title="Sub"),
        ]
    )
    assert "## Methods" in md and "**Bold**" in md
    assert "1. One\n2. Two" in md
    assert "```python\nx = 1\n```" in md and "> A quote." in md and "---" in md
    assert "| a | b |\n| --- | --- |\n| 1 | 2 |" in md
    assert "[page: Sub]" in md


def test_first_sync_newest_first(env, pages):
    sid = env.add()
    report = env.sync(sid)
    assert not report.errors
    assert env.keys(sid) == set(pages.values())
    order = [
        r["key"]
        for r in env.idx.store.q("SELECT key FROM item WHERE source_id = ? ORDER BY id", (sid,))
    ]
    assert order[0] == pages["row"]  # the newest edit first
    rec = env.record(sid, pages["plan"])
    assert rec["kind"] == "notion_page" and rec["title"] == "Plan" and rec["prose"] is True
    text = rec["text"]
    assert text.startswith("# Plan\n") and "# Aims" in text and "- Order lipids" in text
    assert "  From the store." in text and "- [x] Book the microscope" in text
    assert "[image: gel.png]" in text and "sig=1" not in text  # the URL expires
    assert "[page: Protocol]" in text and "Step one." not in text  # a child page is its own item
    row = env.record(sid, pages["row"])
    assert row["record"]["properties"] == {"Status": "Done", "title": "Run 4"}
    st = ss.get(env.idx.store, sid)
    assert st.status == "live" and st.cursor["backfill"]["done"]
    assert st.cursor["edited_after"] == env.fake.pages[pages["row"]]["last_edited_time"]
    child_of = {(s, d) for _, s, d in env.idx.relations("child_of")}
    ids = {r["key"]: r["id"] for r in env.idx.store.q("SELECT id, key FROM item")}
    assert (f"item:{ids[pages['child']]}", f"item:{ids[pages['plan']]}") in child_of


def test_no_change_is_one_search(env, pages):
    sid = env.add()
    env.sync(sid)
    n = len(env.fake.calls)
    report = env.sync(sid)
    assert env.fake.calls[n:] == [("POST", "https://api.notion.com/v1/search")]
    assert not report.new and not report.changed


def test_edit_and_archive(env, pages):
    sid = env.add()
    env.sync(sid)
    env.fake.edit_page(pages["plan"], [para("New aims.")], title="Plan v2")
    env.fake.archive(pages["row"])
    n = len(env.fake.calls)
    env.sync(sid)
    rec = env.record(sid, pages["plan"])
    assert rec["title"] == "Plan v2" and "New aims." in rec["text"]
    assert env.keys(sid) == {pages["plan"], pages["child"]}
    reads = [u for _, u in env.fake.calls[n:] if "/blocks/" in u]
    assert len(reads) == 1  # only the edited page


def test_page_left_the_selection_goes_in_the_daily_list(env, pages):
    sid = env.add()
    env.sync(sid)
    env.fake.unshare(pages["row"])
    env.sync(sid)
    assert pages["row"] in env.keys(sid)  # no event: it stays until the daily list
    env.clock.now += 24 * 3600
    env.sync(sid)
    assert env.keys(sid) == {pages["plan"], pages["child"]}
    st = ss.get(env.idx.store, sid)
    assert st.cursor["ids_at"] == env.clock.now


def test_reset_reads_the_selection_again(env, pages):
    sid = env.add()
    env.sync(sid)
    old = env.fake.add_page("Old notes", [para("Old.")])
    env.fake.pages[old]["last_edited_time"] = "2025-01-01T00:00:00.000Z"
    env.fake.unshare(pages["plan"])  # the child page goes with it
    ss.set_cursor(env.idx.store, sid, {"reset": True}, now=env.clock())
    n = len(env.fake.calls)
    env.sync(sid)
    assert env.keys(sid) == {pages["row"], old}
    reads = [u for _, u in env.fake.calls[n:] if "/blocks/" in u]
    assert len(reads) == 1  # the known page with the same edit time is not read again


def test_rate_limit_and_sign_in_needed(env, pages):
    sid = env.add()
    env.sync(sid)
    env.fake.fail_next(429, headers={"retry-after": "120"})
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("waiting", "rate_limited")
    assert st.next_at > env.clock()
    ss.clear_fault(env.idx.store, sid, now=env.clock())
    env.fake.revoke_all()
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("attention", "auth_expired")
    assert len(env.keys(sid)) == 3


def test_notion_version_header_and_limiter(env, pages):
    assert NotionConnector.rate == 1e9  # the fixture; the class value is 3
    assert notion.RATE_PER_S == 3.0
    sid = env.add()
    env.sync(sid)  # FakeNotion refuses a call with no `Notion-Version`
    assert ss.get(env.idx.store, sid).error_code is None


def test_choices_and_config(env, pages):
    ctx = SourceContext(http=env.fake, credentials=env.creds)
    out = NotionConnector.choices(ctx, env.acct, None)
    assert out["workspace"] == "Lab workspace"
    assert {p["title"] for p in out["pages"]} == {"Plan", "Protocol", "Run 4"}
    assert NotionConnector.preview(ctx, {}) == {"estimate": None, "of": None}
    sid = env.add()
    assert set(env.idx.source(sid)["config"]) == {"account", "kind", "max_depth"}
    with pytest.raises(ConnectorError):
        NotionConnector("a", max_depth=0)


def test_token_call_uses_basic_auth(env):
    client = OAuthClient(env.fake.client_id, env.fake.client_secret, "user")
    url = env.fake.authorize(
        "https://api.notion.com/v1/oauth/authorize?"
        f"client_id={env.fake.client_id}&redirect_uri=http%3A%2F%2Flocalhost%3A53682%2Foauth%2Fcallback"
        "&response_type=code&owner=user&state=st"
    )
    code = url.split("code=")[1].split("&")[0]
    headers, body = token_request(
        NOTION,
        client,
        {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost:53682/oauth/callback",
        },
    )
    resp = env.fake("POST", NOTION.token_url, headers, body)
    assert resp.status == 200
    data = resp.json()
    t = parse_tokens(data, env.clock())
    assert t.access_token and t.refresh_token is None
    assert data["bot_id"] == env.fake.bot_id


def test_fake_gives_the_documented_shapes(env, pages):
    path = Path(__file__).parent / "fixtures/sources/notion/notion.json"
    shapes = json.loads(path.read_text())
    tok = env.creds.auth_headers(env.acct.id, "https://api.notion.com/v1/search")
    h = {**tok, "Notion-Version": "2022-06-28", "Content-Type": "application/json"}
    body = json.dumps({"sort": {"direction": "descending", "timestamp": "last_edited_time"}})
    found = env.fake("POST", "https://api.notion.com/v1/search", h, body.encode()).json()
    assert set(shapes["search"]) <= set(found)
    assert set(shapes["search"]["results"][0]) <= set(found["results"][0])
    kids = env.fake(
        "GET", f"https://api.notion.com/v1/blocks/{pages['plan']}/children", h, None
    ).json()
    assert set(shapes["children"]) <= set(kids)
    first = kids["results"][0]
    assert (
        set(shapes["children"]["results"][0]) - {"paragraph"} <= set(first)
        and first["type"] in first
    )
    tok_shape = shapes["token"]
    assert {"access_token", "bot_id", "workspace_name"} <= set(tok_shape)
    err = env.fake("GET", "https://api.notion.com/v1/blocks/nope/children", h, None)
    assert err.status == 404 and set(err.json()) == set(shapes["error"])


def test_record_has_no_token(env, pages):
    sid = env.add()
    env.sync(sid)
    for key in pages.values():
        assert "ntn_" not in json.dumps(env.record(sid, key))
    extra = loads(
        env.idx.store.one(
            "SELECT v.extra FROM version v JOIN item i ON i.id = v.item_id WHERE i.key = ?",
            (pages["row"],),
        )["extra"]
    )
    assert extra == {"project": "notion:d0000000-0000-4000-8000-0000000000aa"}
