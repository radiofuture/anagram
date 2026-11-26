"""Gmail source (contract v2) against the Gmail model of `FakeGoogle`. No
network.

Cases of plan R3 section 5: first sync (mode `mine` and the P1 defaults),
no change (one history call), new message, delete, trash, history expired
(reconcile), filter change, attachments, third-party text, private space
only, and scale."""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

import pytest
from indexkit import KEY
from sourcekit import creds_for, fake_client, google_account

from anagram.identity.app.keystore import MemoryKeystore
from anagram.local.index.local import LocalIndex
from anagram.local.index.store import loads
from anagram.local.sources import connector_from_config
from anagram.local.sources import source_state as ss
from anagram.local.sources.base import ConnectorError, SourceContext
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.gmail import (
    MAX_ITEMS,
    GmailConnector,
    GmailFilter,
    attachments,
    default_after,
    is_bulk,
)
from anagram.local.sources.oauth import GMAIL_SCOPE
from anagram.local.sources.sync_engine import SyncEngine

pytestmark = pytest.mark.usefixtures("no_network")

PDF = b"%PDF-1.4 fake paper"


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Env:
    def __init__(self, tmp_path):
        self.fake = FakeGoogle()
        self.mail = self.fake.gmail
        self.clock = Clock()
        self.idx = LocalIndex(tmp_path / "index.sqlite", KEY, http=self.fake, clock=self.clock)
        self.creds = creds_for(
            MemoryKeystore(), self.idx.store, self.fake, self.clock, google=fake_client(self.fake)
        )
        self.idx.credentials = self.creds
        self.idx.owner_emails = frozenset({self.fake.email})
        self.acct = google_account(self.creds, self.fake, self.clock(), GMAIL_SCOPE)

    def add(self, flt: dict | None = None, **cfg) -> str:
        conf = {"account": self.acct.id, "kind": "gmail", **cfg}
        if flt is not None:
            conf["filter"] = flt
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

    def api_calls(self, start: int) -> list[str]:
        return [u for _, u in self.fake.calls[start:] if "oauth2" not in u]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(GmailConnector, "rate", 1e9)
    e = Env(tmp_path)
    yield e
    e.idx.close()


@pytest.fixture
def box(env):
    """A thread of the member, a received thread, a newsletter, and a
    promotion."""
    m = env.mail
    q1, t1 = m.add_message("Nanodiscs", "Can you send the protocol?", sender="peer@uni.example")
    a1, _ = m.add_message(
        "Re: Nanodiscs",
        "Here it is.\n\nOn Monday, peer wrote:\n> Can you send the protocol?",
        thread=t1,
        sent=True,
        attachments=(("protocol.pdf", "application/pdf", PDF),),
    )
    r1, t2 = m.add_message("Seminar", "The seminar is at 3.", sender="dean@uni.example")
    n1, t3 = m.add_message(
        "Weekly digest",
        "News.",
        sender="news@lists.example",
        headers={"List-Unsubscribe": "<mailto:u@lists.example>"},
        sent=False,
    )
    p1, t4 = m.add_message(
        "Sale", "Buy.", sender="shop@example.com", labels=("CATEGORY_PROMOTIONS",)
    )
    return {"q1": q1, "a1": a1, "t1": t1, "r1": r1, "t2": t2, "n1": n1, "t3": t3, "p1": p1}


def test_defaults_are_the_p1_decision():
    flt = GmailFilter.from_config({})
    assert flt.mode == "mine" and flt.after == default_after()
    assert flt.exclude_categories == ("promotions", "social", "updates", "forums")
    assert flt.skip_bulk and flt.max_mb == 25
    conn = GmailConnector("a")
    assert conn.max_items == MAX_ITEMS == 20_000
    assert default_after(date(2026, 11, 16)) == "2024-11-16"
    assert default_after(date(2028, 2, 29)) == "2026-02-28"
    q = flt.query()
    assert q.startswith("from:me after:") and "-category:promotions" in q
    assert "-in:chats" in q and "smaller:25M" in q


def test_filter_config_is_checked():
    for bad in (
        {"mode": "x"},
        {"mode": "labels"},
        {"senders": ["a b"]},
        {"exclude_categories": ["primary"]},
        {"after": "last year"},
        {"max_mb": 99},
    ):
        with pytest.raises(ConnectorError):
            GmailFilter.from_config(bad)
    flt = GmailFilter.from_config(
        {"mode": "labels", "labels": ["Grant 2026"], "senders": ["@Uni.Example"]}
    )
    assert flt.query().startswith("{label:grant-2026} from:(@uni.example)")


def test_local_match_is_the_same_rule_as_the_query():
    flt = GmailFilter.from_config({"mode": "all", "exclude_senders": ["spam.example"]})
    ok = {"from": "Peer <peer@uni.example>"}
    assert flt.matches({"INBOX"}, ok, 100)
    assert not flt.matches({"TRASH"}, ok, 100)
    assert not flt.matches({"CATEGORY_SOCIAL"}, ok, 100)
    assert not flt.matches({"INBOX"}, {"from": "x@mail.spam.example"}, 100)
    assert not flt.matches({"INBOX"}, {"from": "noreply@uni.example"}, 100)
    assert not flt.matches({"INBOX"}, {**ok, "precedence": "bulk"}, 100)
    assert not flt.matches({"INBOX"}, ok, 26 * 1024 * 1024)
    assert not flt.matches({"INBOX"}, ok, 100, internal_ms=0)
    assert is_bulk({"auto-submitted": "auto-generated"}) and not is_bulk({"auto-submitted": "no"})


def test_first_sync_mode_mine(env, box):
    sid = env.add()
    report = env.sync(sid)
    assert not report.errors
    t1 = box["t1"]
    assert env.keys(sid) == {f"{t1}/{box['q1']}", f"{t1}/{box['a1']}", f"{t1}/{box['a1']}/a1"}
    rows = {
        r["key"]: dict(r) for r in env.idx.store.q("SELECT * FROM item WHERE source_id = ?", (sid,))
    }
    msg = rows[f"{t1}/{box['a1']}"]
    assert msg["media_type"] == "message/rfc822" and msg["name"] == "Re: Nanodiscs.eml"
    att = rows[f"{t1}/{box['a1']}/a1"]
    assert att["media_type"] == "application/pdf" and att["name"] == "protocol.pdf"
    rel = {(k, s, d) for k, s, d in env.idx.relations("same_thread")}
    assert ("same_thread", f"item:{msg['id']}", f"thread:gmail:{t1}") in rel
    attached = {(s, d) for _, s, d in env.idx.relations("attached_to")}
    assert (f"item:{att['id']}", f"item:{msg['id']}") in attached
    st = ss.get(env.idx.store, sid)
    assert st.status == "live" and st.cursor["email"] == env.fake.email
    assert "raw" not in str(st.cursor)


def test_no_change_is_one_call(env, box):
    sid = env.add()
    env.sync(sid)
    n = len(env.fake.calls)
    report = env.sync(sid)
    calls = env.api_calls(n)
    assert len(calls) == 1 and "/history?" in calls[0]
    assert not report.new and not report.removed


def test_live_new_messages_follow_the_mine_rule(env, box):
    sid = env.add()
    env.sync(sid)
    m = env.mail
    reply, _ = m.add_message(
        "Re: Nanodiscs", "Thanks!", sender="peer@uni.example", thread=box["t1"]
    )
    other, _ = m.add_message("Other", "Not mine.", sender="peer@uni.example")
    q, t5 = m.add_message("Question", "Please review.", sender="pi@uni.example")
    mine, _ = m.add_message("Re: Question", "Yes.", thread=t5, sent=True)
    env.sync(sid)
    keys = env.keys(sid)
    assert f"{box['t1']}/{reply}" in keys  # a reply in a known thread
    assert not any(other in k for k in keys)  # a received thread with no own message
    assert {f"{t5}/{q}", f"{t5}/{mine}"} <= keys  # an own reply brings the thread


def test_delete_and_trash_and_restore(env, box):
    sid = env.add()
    env.sync(sid)
    t1, a1, q1 = box["t1"], box["a1"], box["q1"]
    env.mail.delete_message(q1)
    env.mail.label(a1, add=("TRASH",))
    env.sync(sid)
    assert env.keys(sid) == set()  # the attachment goes with its message
    # Out of the trash: an own message brings its thread again.
    env.mail.label(a1, remove=("TRASH",))
    env.sync(sid)
    assert env.keys(sid) == {f"{t1}/{a1}", f"{t1}/{a1}/a1"}


def test_history_expired_gives_a_reconcile(env, box):
    sid = env.add()
    env.sync(sid)
    t1, a1, q1 = box["t1"], box["a1"], box["q1"]
    env.mail.messages.pop(q1)  # gone with no history that the source can read
    env.mail.expire_history()
    env.sync(sid)
    assert env.keys(sid) == {f"{t1}/{a1}", f"{t1}/{a1}/a1"}
    st = ss.get(env.idx.store, sid)
    assert st.error_code is None and st.cursor["backfill"]["done"] and "seen" not in st.cursor
    n = len(env.fake.calls)
    env.sync(sid)
    assert len(env.api_calls(n)) == 1


def test_filter_change_reads_again_and_deletes(env, box):
    sid = env.add()
    env.sync(sid)
    conn = connector_from_config(
        {**env.idx.source(sid)["config"], "filter": {"mode": "all", "attachments": False}}
    )
    env.idx.set_source_config(sid, conn.config())
    ss.set_cursor(env.idx.store, sid, {"reset": True}, now=env.clock())
    env.sync(sid)
    t1 = box["t1"]
    # Mode `all`: the received seminar is in; the newsletter and the
    # promotion stay out. The attachment item is gone (attachments off).
    assert env.keys(sid) == {
        f"{t1}/{box['q1']}",
        f"{t1}/{box['a1']}",
        f"{box['t2']}/{box['r1']}",
    }


def test_label_mode(env, box):
    lid = env.mail.add_label("Grant 2026")
    env.mail.label(box["r1"], add=(lid,))
    sid = env.add({"mode": "labels", "labels": ["Grant 2026"]})
    env.sync(sid)
    assert env.keys(sid) == {f"{box['t2']}/{box['r1']}"}


def test_received_text_is_third_party(env, box):
    sid = env.add()
    env.sync(sid, process=True)
    rows = env.idx.store.q(
        "SELECT i.key, d.markdown, d.quoted FROM item i JOIN version v ON v.item_id = i.id"
        " JOIN document d ON d.version_id = v.id WHERE i.source_id = ?",
        (sid,),
    )
    by = {r["key"]: r for r in rows}
    received = by[f"{box['t1']}/{box['q1']}"]
    assert "Can you send" not in received["markdown"] and "Can you send" in received["quoted"]
    own = by[f"{box['t1']}/{box['a1']}"]
    assert "Here it is." in own["markdown"] and "Can you send" in own["quoted"]
    ver = env.idx.store.one(
        "SELECT v.* FROM version v JOIN item i ON i.id = v.item_id WHERE i.key = ?",
        (f"{box['t1']}/{box['q1']}",),
    )
    meta = loads(ver["extra"]) if ver["extra"] else {}
    assert meta["fetch"] == {"id": box["q1"]}


def test_attachments_from_the_mime_tree(env):
    mid, _ = env.mail.add_message(
        "Files",
        "See files.",
        sent=True,
        attachments=(
            ("a.pdf", "application/pdf", PDF),
            ("b.png", "image/png", b"\x89PNG\r\n\x1a\nfake"),
            ("c.txt", "text/plain", b"Notes."),
        ),
    )
    raw = env.mail.messages[mid]["raw"]
    assert [n for n, _ in attachments(raw)] == ["a.pdf", "b.png", "c.txt"]
    sid = env.add()
    env.sync(sid)
    tid = env.mail.messages[mid]["threadId"]
    # The image is not an allowed type; the numbers stay the MIME order.
    assert env.keys(sid) == {f"{tid}/{mid}", f"{tid}/{mid}/a1", f"{tid}/{mid}/a3"}
    conn = env.idx.connector(sid)
    assert conn.fetch(f"{tid}/{mid}/a3", {"fetch": {"attachment": 3, "id": mid}}) == b"Notes."


def test_old_mail_and_max_items(env):
    old = int((time.time() - 3 * 365 * 86_400) * 1000)
    env.mail.add_message("Old", "Old.", sent=True, at_ms=old)
    for i in range(7):
        env.mail.add_message(f"M{i}", "x", sent=True)
    sid = env.add(max_items=5)
    env.sync(sid)
    assert len(env.keys(sid)) == 5


def test_gmail_space_private_only(tmp_path):
    from anagram.shell.ui.source_kinds import KINDS

    info = KINDS["gmail"]
    assert info.spaces == (ss.PRIVATE,) and info.choose == "filter"
    assert info.auth == "oauth"


def test_choices_and_preview(env, box):
    env.mail.add_label("Grant 2026")
    ctx = SourceContext(http=env.fake, credentials=env.creds)
    out = GmailConnector.choices(ctx, env.acct, None)
    assert out["email"] == env.fake.email and out["total"] == 5
    assert [lb["name"] for lb in out["labels"]] == ["Grant 2026"]
    prev = GmailConnector.preview(ctx, {"account": env.acct.id, "filter": {}})
    assert prev == {"estimate": 1, "of": 5}


def test_scope_and_sign_in_needed(env, box):
    sid = env.add()
    env.fake.revoke_grant()
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("attention", "auth_expired")


def test_config_has_no_secret(env):
    sid = env.add()
    cfg = env.idx.source(sid)["config"]
    assert set(cfg) == {"account", "filter", "kind", "max_items"}


def test_fake_gives_the_documented_shapes(env, box):
    path = Path(__file__).parent / "fixtures/sources/google/gmail.json"
    shapes = json.loads(path.read_text())
    base = "https://gmail.googleapis.com/gmail/v1/users/me"
    tok = env.creds.auth_headers(env.acct.id, base + "/profile")

    def get(p):
        return env.fake("GET", base + p, tok, None)

    t1, a1 = box["t1"], box["a1"]
    assert set(shapes["profile"]) <= set(get("/profile").json())
    assert set(shapes["threads_list"]) - {"nextPageToken"} <= set(get("/threads").json()) | {
        "snippet"
    }
    assert set(shapes["messages_list"]) - {"nextPageToken"} <= set(get("/messages").json())
    thread = get(f"/threads/{t1}?format=minimal").json()
    assert set(shapes["thread_minimal"]["messages"][0]) <= set(thread["messages"][0])
    assert set(shapes["message_raw"]) <= set(get(f"/messages/{a1}?format=raw").json())
    hist = get("/history?startHistoryId=1000").json()
    assert set(shapes["history"]) <= set(hist)
    assert set(shapes["history"]["history"][0]) <= set(hist["history"][0])
    env.mail.expire_history()
    gone = get("/history?startHistoryId=1000")
    assert gone.status == 404 and set(gone.json()["error"]) <= set(
        shapes["history_expired"]["error"]
    )
    assert set(shapes["labels"]) <= set(get("/labels").json())
    assert set(shapes["send_as"]["sendAs"][0]) <= set(get("/settings/sendAs").json()["sendAs"][0])


def test_scale_100000_messages(env, monkeypatch):
    """100 000 messages in the box, mode `all`: the source stops at 20 000
    items, with at most 200 upserts between two cursors. `_commit` is a
    stub, so the test measures the source and the engine only."""
    m = env.mail
    for i in range(100_000):
        m.add_message(f"S{i}", "x", sender="peer@uni.example")
    peak = []
    real_commit = SyncEngine._commit

    def commit(self, sid, src, pending, cursor, note, result, report):
        peak.append(len(pending))
        return real_commit(self, sid, src, [], cursor, note, result, report)

    monkeypatch.setattr(SyncEngine, "_commit", commit)
    sid = env.add({"mode": "all"})
    n = len(env.fake.calls)
    t0 = time.monotonic()
    env.sync(sid)
    assert time.monotonic() - t0 < 60
    calls = env.api_calls(n)
    gets = [u for u in calls if "/messages/" in u]
    assert len(gets) == 20_000
    assert len([u for u in calls if "/messages?" in u]) == 40
    assert max(peak) <= 200
    assert ss.get(env.idx.store, sid).cursor["backfill"]["done"]
