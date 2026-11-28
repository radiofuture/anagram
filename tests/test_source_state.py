"""Source contract v2 types, the source state tables, the source event log,
the `own` flag, and the space hooks. No network."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import ClassVar

import pytest
from indexkit import KEY

from anagram.local.index.local import LocalIndex
from anagram.local.index.store import SCHEMA_VERSION, IndexStore
from anagram.local.sources import SOURCES, FolderConnector, connector_from_config
from anagram.local.sources import source_state as ss
from anagram.local.sources.base import (
    Connector,
    EvidenceItem,
    KnownItem,
    SourceContext,
    record_item,
)
from anagram.local.sources.http import HttpResponse
from anagram.local.sources.sync import (
    Cursor,
    Delete,
    Note,
    SyncContext,
    Upsert,
    is_own,
    is_sync_source,
)

pytestmark = pytest.mark.usefixtures("no_network")

NEW_TABLES = ("account", "source_state", "source_event")


@pytest.fixture
def index(tmp_path):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "a.md").write_text("# A note\n\nSome text.\n")
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    yield idx
    idx.close()


@pytest.fixture
def sid(index, tmp_path):
    return index.add_source(FolderConnector(tmp_path / "notes"))


class Events:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict]] = []

    def __call__(self, topic: str, data: dict) -> None:
        self.rows.append((topic, data))


def _tables(store: IndexStore) -> set[str]:
    return {r[0] for r in store.q("SELECT name FROM sqlite_master WHERE type = 'table'")}


# ----------------------------------------------------------------- tables


def test_new_store_has_the_tables_and_schema_version_stays(tmp_path):
    store = IndexStore(tmp_path / "i.sqlite", KEY)
    assert set(NEW_TABLES) <= _tables(store)
    assert SCHEMA_VERSION == 2
    assert store.get_meta("schema") == 2
    store.close()


def test_old_store_opens_and_gets_the_tables(tmp_path):
    """An index store from before this change has no source state tables. It
    opens with no migration, and `ensure` makes the rows."""
    root = tmp_path / "notes"
    root.mkdir()
    (root / "a.md").write_text("# A\n\ntext\n")
    db = tmp_path / "index.sqlite"
    idx = LocalIndex(db, KEY)
    scanned = idx.add_source(FolderConnector(root))
    idx.scan()
    fresh = idx.add_source(FolderConnector(tmp_path))
    for name in NEW_TABLES:
        idx.store.x(f"DROP TABLE {name}")
    assert not set(NEW_TABLES) & _tables(idx.store)
    idx.close()

    idx = LocalIndex(db, KEY)
    try:
        assert set(NEW_TABLES) <= _tables(idx.store)
        assert idx.store.get_meta("schema") == 2
        assert ss.read(idx.store, scanned) is None  # no row before the first read
        assert ss.sources_in_space(idx.store, "private") == sorted([scanned, fresh])
        old = ss.get(idx.store, scanned, now=10.0)
        assert (old.status, old.space, old.paused, old.cursor) == ("live", "private", False, {})
        assert ss.get(idx.store, fresh, now=10.0).status == "first_sync"
        assert len(idx.items()) >= 1  # the old data is still there
    finally:
        idx.close()


def test_ensure_is_idempotent_and_refuses_an_unknown_source(index, sid):
    ss.ensure(index.store, sid, 5.0, account_id="a" * 32, space="lab:lab-0123456789abcdef")
    ss.ensure(index.store, sid, 9.0, space="private")  # the row exists: no change
    state = ss.get(index.store, sid)
    assert (state.account_id, state.space, state.updated_at) == (
        "a" * 32,
        "lab:lab-0123456789abcdef",
        5.0,
    )
    assert index.store.one("SELECT count(*) FROM source_state")[0] == 1
    with pytest.raises(ss.SourceStateError, match="unknown source"):
        ss.ensure(index.store, "no-such-source")
    with pytest.raises(ss.SourceStateError, match="unknown source"):
        ss.get(index.store, "no-such-source")


def test_account_table_holds_no_token_column(index):
    cols = {r[1] for r in index.store.q("PRAGMA table_info(account)")}
    assert cols == {
        "id",
        "provider",
        "external_id",
        "label",
        "client_id",
        "scopes",
        "status",
        "created_at",
    }


# ---------------------------------------------------------- state machine


def test_status_changes_publish_source_state(index, sid):
    events = Events()
    assert ss.get(index.store, sid, 1.0).status == "first_sync"
    ss.set_status(index.store, sid, "live", now=2.0, publish=events)
    ss.set_status(index.store, sid, "live", now=3.0, publish=events)  # no change: no event
    assert events.rows == [
        (
            "source.state",
            {"fault": None, "id": sid, "paused": False, "space": "private", "status": "live"},
        )
    ]
    with pytest.raises(ss.SourceStateError, match="unknown status"):
        ss.set_status(index.store, sid, "paused", now=4.0)


def test_pause_and_resume_keep_the_status_from_before(index, sid):
    events = Events()
    ss.set_status(index.store, sid, "live", now=1.0)
    paused = ss.pause(index.store, sid, now=2.0, publish=events)
    assert (paused.status, paused.stored_status, paused.paused) == ("paused", "live", True)
    assert not paused.due(now=100.0)
    resumed = ss.resume(index.store, sid, now=3.0, publish=events)
    assert (resumed.status, resumed.paused) == ("live", False)
    assert resumed.due(now=100.0)
    assert [(t, d["status"], d["paused"]) for t, d in events.rows] == [
        ("source.state", "paused", True),
        ("source.state", "live", False),
    ]


def test_removing_is_final(index, sid):
    ss.set_status(index.store, sid, "removing", now=1.0)
    for change in (
        lambda: ss.set_status(index.store, sid, "live", now=2.0),
        lambda: ss.pause(index.store, sid, now=2.0),
        lambda: ss.resume(index.store, sid, now=2.0),
        lambda: ss.set_fault(index.store, sid, "offline", now=2.0),
        lambda: ss.clear_fault(index.store, sid, now=2.0),
        lambda: ss.set_space(index.store, sid, "lab:lab-1", now=2.0),
    ):
        with pytest.raises(ss.SourceStateError, match="being removed"):
            change()
    state = ss.get(index.store, sid)
    assert state.status == "removing"
    assert not state.due(now=100.0)


@pytest.mark.parametrize(
    ("code", "status", "action"),
    [
        ("rate_limited", "waiting", None),
        ("offline", "waiting", None),
        ("quota", "waiting", None),
        ("auth_expired", "attention", "signin"),
        ("permission_lost", "attention", "choose"),
        ("not_found", "attention", "choose"),
        ("client_missing", "attention", None),
        ("unknown", "waiting", None),
    ],
)
def test_fault_table(index, sid, code, status, action):
    events = Events()
    state = ss.set_fault(index.store, sid, code, "HTTP 500", now=1000.0, publish=events)
    assert (state.status, state.error_code, state.error_detail) == (status, code, "HTTP 500")
    assert state.error_at == "1970-01-01T00:16:40Z"
    assert state.fault["code"] == code
    assert state.fault["action"] == action
    if status == "waiting":
        assert state.fault["retry_at"] > 1000.0
        assert not state.due(now=1000.0)
        assert state.due(now=state.next_at)
    else:
        assert state.fault["retry_at"] is None
        assert not state.due(now=10**9)  # the person must act
    assert events.rows[-1][1]["fault"] == state.fault


def test_fault_keeps_the_cursor_and_uses_retry_at(index, sid):
    ss.set_cursor(index.store, sid, {"v": 1, "page": "p7"}, now=1.0)
    state = ss.set_fault(index.store, sid, "rate_limited", now=100.0, retry_at=460.0)
    assert state.cursor == {"v": 1, "page": "p7"}
    assert state.next_at == 460.0
    assert state.fault == {"action": None, "code": "rate_limited", "retry_at": 460.0}


def test_offline_backs_off_to_fifteen_minutes(index, sid):
    waits = []
    for _ in range(7):
        state = ss.set_fault(index.store, sid, "offline", now=0.0)
        waits.append(state.next_at)
    assert waits == [30.0, 60.0, 120.0, 240.0, 480.0, 900.0, 900.0]
    assert state.status == "waiting"  # no connection never needs the person


def test_unknown_needs_the_person_after_five_failures(index, sid):
    for n in range(1, 6):
        state = ss.set_fault(index.store, sid, "unknown", now=float(n))
        assert state.status == ("waiting" if n < 5 else "attention")
    assert state.fault == {"action": "retry", "code": "unknown", "retry_at": None}


def test_a_code_that_is_not_a_source_fault_is_unknown_and_detail_is_cut(index, sid):
    state = ss.set_fault(index.store, sid, "too_large", "x" * 500, now=1.0)
    assert state.error_code == "unknown"
    assert len(state.error_detail) == 200


def test_clear_fault_gives_first_sync_or_live(index, sid):
    events = Events()
    ss.set_fault(index.store, sid, "auth_expired", now=1.0)
    state = ss.clear_fault(index.store, sid, now=2.0, publish=events)
    assert (state.status, state.fault, state.failures, state.next_at) == (
        "first_sync",
        None,
        0,
        0.0,
    )
    assert events.rows[-1][1] == {
        "fault": None,
        "id": sid,
        "paused": False,
        "space": "private",
        "status": "first_sync",
    }
    ss.set_progress(index.store, sid, now=3.0, phase="live")
    ss.set_fault(index.store, sid, "offline", now=4.0)
    assert ss.clear_fault(index.store, sid, now=5.0).status == "live"
    n = len(events.rows)
    ss.clear_fault(index.store, sid, now=6.0, publish=events)  # no fault: no event
    assert len(events.rows) == n


def test_status_live_clears_the_fault(index, sid):
    ss.set_fault(index.store, sid, "offline", now=1.0)
    state = ss.set_status(index.store, sid, "live", now=2.0)
    assert (state.fault, state.failures, state.next_at) == (None, 0, 0.0)


def test_cursor_and_progress(index, sid):
    ss.set_cursor(index.store, sid, {"v": 1, "history_id": "88"}, now=1.0)
    ss.set_progress(
        index.store,
        sid,
        now=2.0,
        phase="first_sync",
        total=8400,
        done=200,
        at="2025-03-01T00:00:00Z",
    )
    ss.set_progress(index.store, sid, now=3.0, done=400, skipped=12)  # None keeps a value
    state = ss.get(index.store, sid)
    assert state.cursor == {"v": 1, "history_id": "88"}
    assert (state.phase, state.total, state.done, state.at, state.skipped) == (
        "first_sync",
        8400,
        400,
        "2025-03-01T00:00:00Z",
        12,
    )
    with pytest.raises(ss.SourceStateError, match="JSON object"):
        ss.set_cursor(index.store, sid, ["not", "a", "dict"], now=4.0)
    ss.set_account(index.store, sid, "b" * 32, now=5.0)
    assert ss.get(index.store, sid).account_id == "b" * 32


# ------------------------------------------------------------------ space


def test_space_change_stores_publishes_and_calls_each_hook(index, sid):
    events = Events()
    calls = []
    hooks = (
        lambda s, old, new: calls.append(("one", s, old, new)),
        lambda s, old, new: calls.append(("two", s, old, new)),
    )
    lab = "lab:lab-0123456789abcdef"

    state = ss.set_space(index.store, sid, lab, now=1.0, publish=events, hooks=hooks)
    assert state.space == lab
    assert ss.get(index.store, sid).space == lab
    assert calls == [("one", sid, "private", lab), ("two", sid, "private", lab)]
    assert [(t, d["space"]) for t, d in events.rows] == [("source.state", lab)]

    ss.set_space(index.store, sid, lab, now=2.0, publish=events, hooks=hooks)  # no change
    assert len(calls) == 2
    assert len(events.rows) == 1

    ss.set_space(index.store, sid, "private", now=3.0, publish=events, hooks=hooks)
    assert calls[2:] == [("one", sid, lab, "private"), ("two", sid, lab, "private")]


def test_sources_in_space(index, sid, tmp_path):
    other = index.add_source(FolderConnector(tmp_path))
    lab = "lab:lab-0123456789abcdef"
    assert ss.sources_in_space(index.store, "private") == sorted([sid, other])
    assert ss.sources_in_space(index.store, lab) == []
    ss.set_space(index.store, sid, lab, now=1.0)
    assert ss.sources_in_space(index.store, lab) == [sid]
    assert ss.sources_in_space(index.store, "private") == [other]


@pytest.mark.parametrize("bad", ["", "lab", "lab:", "public", "lab:a b", "private ", "LAB:x", None])
def test_bad_space_is_refused(index, sid, bad):
    with pytest.raises(ss.SourceStateError, match="a space is"):
        ss.set_space(index.store, sid, bad, now=1.0)
    assert ss.get(index.store, sid).space == "private"


def test_hook_that_fails_does_not_stop_the_others(index, sid, caplog):
    calls = []

    def bad(s, old, new):
        raise RuntimeError("secret-detail")

    hooks = (bad, lambda s, old, new: calls.append(new))
    with pytest.raises(ss.SpaceHookError, match="1 space hook"):
        ss.set_space(index.store, sid, "lab:lab-1", now=1.0, hooks=hooks)
    assert calls == ["lab:lab-1"]
    assert ss.get(index.store, sid).space == "lab:lab-1"  # the space is stored
    assert "RuntimeError" in caplog.text
    assert "secret-detail" not in caplog.text


# ----------------------------------------------------------------- events


def test_publisher_appends_a_row(index, sid):
    publish = ss.publisher(index.store, clock=lambda: 42.0)
    assert ss.last_event_id(index.store) == 0
    publish("source.progress", {"id": sid, "done": 3, "total": 10})
    publish("source.state", {"id": sid, "status": "live"})
    rows = ss.events_after(index.store, 0)
    assert rows == [
        {
            "id": 1,
            "at": 42.0,
            "topic": "source.progress",
            "data": {"id": sid, "done": 3, "total": 10},
        },
        {"id": 2, "at": 42.0, "topic": "source.state", "data": {"id": sid, "status": "live"}},
    ]
    assert ss.events_after(index.store, 1) == rows[1:]
    assert ss.events_after(index.store, 0, limit=1) == rows[:1]
    assert ss.events_after(index.store, 2) == []
    assert ss.last_event_id(index.store) == 2


def test_state_changes_reach_the_event_table_through_the_publisher(index, sid):
    publish = ss.publisher(index.store, clock=lambda: 7.0)
    ss.pause(index.store, sid, now=7.0, publish=publish)
    (row,) = ss.events_after(index.store, 0)
    assert (row["topic"], row["data"]["status"], row["data"]["id"]) == (
        "source.state",
        "paused",
        sid,
    )


def test_event_topic_and_data_are_checked(index):
    with pytest.raises(ss.SourceStateError, match="unknown source event topic"):
        ss.append_event(index.store, "item.added", {}, 1.0)
    with pytest.raises(ss.SourceStateError, match="JSON object"):
        ss.append_event(index.store, "source.state", ["x"], 1.0)


def test_event_table_keeps_the_last_rows_and_ids_increase(index, monkeypatch):
    monkeypatch.setattr(ss, "EVENT_KEEP", 5)
    ids = [ss.append_event(index.store, "oauth.flow", {"n": n}, float(n)) for n in range(12)]
    assert ids == list(range(1, 13))
    kept = ss.events_after(index.store, 0)
    assert [r["id"] for r in kept] == [8, 9, 10, 11, 12]
    assert ss.last_event_id(index.store) == 12


# ----------------------------------------------------------- contract v2


class ToySync(Connector):
    """A v2 source: it has `sync`. `scan` is not used."""

    kind: ClassVar[str] = "toy_sync"
    auth: ClassVar[str] = "none"
    refetchable: ClassVar[bool] = False

    def config(self) -> dict:
        return {"kind": self.kind}

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise AssertionError("the index never calls scan of a v2 source")

    def sync(self, ctx: SyncContext):
        page = ctx.state.get("page", 0)
        yield Note(phase="first_sync", total=2, done=page)
        if ctx.known("k1") is None:
            yield Upsert(
                record_item(
                    key="k1", kind="toy", name="one", ref="toy:k1", record={}, text="t", title="one"
                )
            )
        yield Delete("gone/", prefix=True)
        yield Cursor({"page": page + 1})


class LabLike(ToySync):
    kind: ClassVar[str] = "toy_lab"
    own: ClassVar[bool] = False


class PlugIn:
    """An entry-point source with only `scan` and no base class."""

    kind = "plug_in"

    def config(self) -> dict:
        return {"kind": self.kind}

    def scan(self, known):
        return iter(())

    def describe(self) -> str:
        return "plug-in"


def test_is_sync_source():
    assert is_sync_source(ToySync())
    assert is_sync_source(ToySync)
    assert not is_sync_source(PlugIn())
    v2 = {"gdrive", "gmail", "notion"}  # cloud connectors use sync contract v2
    for _, cls in SOURCES:  # each other built-in kind stays contract v1
        assert is_sync_source(cls) == (cls.kind in v2), cls.kind


def test_own_flag_default_is_true_and_a_source_can_clear_it(tmp_path):
    assert Connector.own is True
    assert is_own(FolderConnector(tmp_path))
    assert is_own(PlugIn())  # no flag: the member's own
    assert not is_own(LabLike())
    assert not is_own(LabLike)
    for _, cls in SOURCES:  # each built-in kind (the lab space is not in the registry)
        assert is_own(cls), cls.kind


def test_sync_yields_the_change_types():
    ctx = SyncContext(
        state={},
        known=lambda key: None,
        known_keys=lambda p: iter(()),
        deadline=0.0,
        stop=lambda: False,
    )
    changes = list(ToySync().sync(ctx))
    assert [type(c).__name__ for c in changes] == ["Note", "Upsert", "Delete", "Cursor"]
    assert changes[1].item.key == "k1"
    assert changes[2] == Delete("gone/", prefix=True)
    assert changes[3].state == {"page": 1}
    with pytest.raises(ValueError, match="unknown sync phase"):
        Note(phase="done")


def test_source_context_has_optional_http_and_credentials():
    ctx = SourceContext()
    assert (ctx.secret, ctx.transport, ctx.http, ctx.credentials) == (None, None, None, None)

    def http(method, url, headers, body):
        return HttpResponse(200)

    creds = object()
    ctx = SourceContext(http=http, credentials=creds)
    assert ctx.http is http
    assert ctx.credentials is creds


def test_a_scan_source_works_with_no_change(index, sid, tmp_path):
    """A contract v1 connector needs no change: it scans as before, and its
    state row appears on first read."""
    report = index.scan()
    assert len(report.new) >= 1
    conn = connector_from_config({"kind": "folder", "root": str(tmp_path / "notes")})
    assert not is_sync_source(conn)
    assert is_own(conn)
    assert ss.read(index.store, sid) is None
    assert ss.get(index.store, sid).status == "live"
