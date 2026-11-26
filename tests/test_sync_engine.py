"""The sync engine with a toy contract v2 source, and the `own` guards.
No network."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import ClassVar

import pytest
from indexkit import KEY

from anagram.local.api import lens_items
from anagram.local.index.indexer import Indexer
from anagram.local.index.local import LocalIndex
from anagram.local.index.scan import Scanner, ScanReport
from anagram.local.sources import SOURCES, FolderConnector
from anagram.local.sources import source_state as ss
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    record_item,
)
from anagram.local.sources.http import SourceFault
from anagram.local.sources.sync import Change, Cursor, Delete, Note, SyncContext, Upsert
from anagram.local.sources.sync_engine import SyncEngine
from anagram.local.understanding.drafts import draft_findings

pytestmark = pytest.mark.usefixtures("no_network")


def note(key: str, text: str) -> EvidenceItem:
    return record_item(
        key=key,
        kind="toy_note",
        name=None,
        ref=f"toy:{key}",
        record={"id": key},
        text=text,
        title=f"Note {key}",
        prose=True,
    )


class ToySource(Connector):
    """A v2 source over a list of pages. Each page is a list of changes and
    ends with a cursor. `ToySource.pages` is the provider; a test changes it."""

    kind = "toy"
    auth: ClassVar[str] = "none"
    refetchable: ClassVar[bool] = False
    pages: ClassVar[list[list[Change]]] = []
    calls: ClassVar[int] = 0
    fail_at: ClassVar[int | None] = None  # raise before this page
    fault: ClassVar[Exception | None] = None
    obey_stop: ClassVar[bool] = False

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> ToySource:
        return cls()

    def config(self) -> dict:
        return {"kind": self.kind}

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise ConnectorError("use sync")

    def sync(self, ctx: SyncContext) -> Iterator[Change]:
        type(self).calls += 1
        start = int(ctx.state.get("page", 0))
        for n in range(start, len(self.pages)):
            if self.fail_at == n:
                raise self.fault or RuntimeError("secret-text-in-error")
            yield from self.pages[n]
            yield Cursor({"page": n + 1})
            if self.obey_stop and ctx.stop():
                return


class LabToy(ToySource):
    """Items of other people (as the R2 kind `labspace`)."""

    kind = "toy_lab"
    own = False


@pytest.fixture(autouse=True)
def toy():
    for cls in (ToySource, LabToy):
        cls.pages, cls.calls, cls.fail_at, cls.fault, cls.obey_stop = [], 0, None, None, False
        SOURCES.register(cls.kind, cls)
    yield ToySource
    for cls in (ToySource, LabToy):
        SOURCES.unregister(cls.kind)


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def index(tmp_path, clock):
    idx = LocalIndex(tmp_path / "index.sqlite", KEY, clock=clock)
    yield idx
    idx.close()


def events(index, topic: str | None = None) -> list[dict]:
    rows = ss.events_after(index.store, 0, limit=2000)
    return [r for r in rows if topic is None or r["topic"] == topic]


def keys(index, sid: str) -> list[str]:
    return [i.key for i in index.items(sid)]


def versions(index, sid: str) -> int:
    return index.store.one("SELECT count(*) FROM version WHERE source_id = ?", (sid,))[0]


# ------------------------------------------------------------------ basics


def test_first_sync_applies_each_batch_with_its_cursor(index, toy):
    toy.pages = [
        [Note(phase="first_sync", total=3), Upsert(note("a", "alpha")), Upsert(note("b", "beta"))],
        [Upsert(note("c", "gamma")), Note(phase="live", done=3)],
    ]
    sid = index.add_source(ToySource())
    report = index.scan([sid])
    assert sorted(k for _, k in report.new) == ["a", "b", "c"]
    assert report.more == []
    assert keys(index, sid) == ["a", "b", "c"]
    state = ss.read(index.store, sid)
    assert state.cursor == {"page": 2}
    assert (state.status, state.phase, state.total, state.done) == ("live", "live", 3, 3)
    assert index.source(sid)["last_scan_at"] is not None
    assert index.search("gamma")[0].key == "c"  # the jobs ran: the text is searchable


def test_second_sync_with_no_change_does_nothing(index, toy):
    toy.pages = [[Upsert(note("a", "alpha"))]]
    sid = index.add_source(ToySource())
    index.scan([sid])
    report = index.scan([sid])
    assert report.new == report.changed == report.removed == []
    assert versions(index, sid) == 1
    assert toy.calls == 2


def test_upsert_with_the_current_digest_changes_nothing(index, toy):
    toy.pages = [[Upsert(note("a", "alpha"))], [Upsert(note("a", "alpha"))]]
    sid = index.add_source(ToySource())
    report = index.scan([sid])
    assert report.new == [(sid, "a")] and report.unchanged == [(sid, "a")]
    assert versions(index, sid) == 1


def test_new_bytes_give_a_new_version(index, toy):
    toy.pages = [[Upsert(note("a", "alpha"))]]
    sid = index.add_source(ToySource())
    index.scan([sid])
    toy.pages.append([Upsert(note("a", "alpha two"))])
    report = index.scan([sid])
    assert report.changed == [(sid, "a")]
    assert versions(index, sid) == 2


def test_known_and_known_keys(index, toy):
    seen = {}

    class Asks(ToySource):
        kind = "toy"

        def sync(self, ctx):
            seen["known"] = ctx.known("t1/m1")
            seen["missing"] = ctx.known("nothing")
            seen["keys"] = list(ctx.known_keys("t1/"))
            seen["all"] = list(ctx.known_keys(""))
            yield from super().sync(ctx)

    toy.pages = [[Upsert(note("t1/m1", "one")), Upsert(note("t1/m2", "two"))]]
    toy.pages += [[Upsert(note("t10/m1", "three"))]]
    sid = index.add_source(Asks())
    index.scan([sid])
    assert seen["known"] is None  # first run: nothing is known
    index.scan([sid])
    assert seen["known"].size > 0 and seen["missing"] is None
    assert seen["keys"] == ["t1/m1", "t1/m2"]
    assert seen["all"] == ["t1/m1", "t1/m2", "t10/m1"]


# ------------------------------------------------------------------ deletes


def test_delete_exact_prefix_and_unknown(index, toy):
    toy.pages = [
        [
            Upsert(note("t1/m1", "apple")),
            Upsert(note("t1/m1/a1", "apricot")),
            Upsert(note("t1/m2", "banana")),
            Upsert(note("t2/m1", "cherry")),
        ]
    ]
    sid = index.add_source(ToySource())
    index.scan([sid])
    assert index.search("apricot")
    toy.pages.append([Delete("t1/m1", prefix=True), Delete("no-such-key"), Delete("t2")])
    report = index.scan([sid])
    assert sorted(k for _, k in report.removed) == ["t1/m1", "t1/m1/a1"]
    assert keys(index, sid) == ["t1/m2", "t2/m1"]  # "t2" is not an exact key
    # The text of a deleted item is gone; its versions and openings stay.
    assert index.search("apricot") == [] and index.search("apple") == []
    gone = index.store.one(
        "SELECT count(*) FROM chunk c JOIN version v ON v.id = c.version_id"
        " JOIN item i ON i.id = v.item_id WHERE i.present = 0"
    )[0]
    assert gone == 0
    assert versions(index, sid) == 4
    assert index.evidence_opening(sid, "t1/m1") is not None


def test_item_that_comes_back_gets_a_new_version(index, toy):
    toy.pages = [[Upsert(note("a", "alpha"))], [Delete("a")], [Upsert(note("a", "alpha"))]]
    sid = index.add_source(ToySource())
    index.scan([sid])
    assert keys(index, sid) == ["a"]
    assert versions(index, sid) == 2
    assert index.search("alpha")[0].version == 2


# ---------------------------------------------------------------- atomicity


def test_crash_between_batches_reads_one_batch_again(index, toy, clock):
    toy.pages = [
        [Upsert(note("a", "alpha"))],
        [Upsert(note("b", "beta"))],
        [Upsert(note("c", "gamma"))],
    ]
    toy.fail_at = 2
    sid = index.add_source(ToySource())
    index.scan([sid], process=False)
    assert keys(index, sid) == ["a", "b"]
    assert ss.read(index.store, sid).cursor == {"page": 2}
    toy.fail_at = None
    clock.t += 3600  # after the wait of the fault
    report = index.scan([sid], process=False)
    assert report.new == [(sid, "c")]  # only the batch that was lost
    assert versions(index, sid) == 3


def test_a_batch_and_its_cursor_are_one_transaction(index, toy, monkeypatch):
    """A fault while the second batch is written: nothing of that batch and
    not its cursor is stored. The next run reads the batch again and makes no
    second version."""
    toy.pages = [
        [Upsert(note("a", "alpha"))],
        [Upsert(note("b", "beta")), Upsert(note("c", "gamma"))],
    ]
    sid = index.add_source(ToySource())
    real = Scanner.apply_item

    def broken(self, sid_, kind, item, prev, now, t, report):
        if item.key == "c":
            raise RuntimeError("the process stopped here")
        return real(self, sid_, kind, item, prev, now, t, report)

    monkeypatch.setattr(Scanner, "apply_item", broken)
    index.scan([sid], process=False)
    assert keys(index, sid) == ["a"]
    assert ss.read(index.store, sid).cursor == {"page": 1}
    monkeypatch.setattr(Scanner, "apply_item", real)
    ss.clear_fault(index.store, sid, now=index.clock())
    report = index.scan([sid], process=False)
    assert sorted(k for _, k in report.new) == ["b", "c"]
    assert versions(index, sid) == 3


def test_changes_with_no_cursor_are_applied_in_small_batches(index, toy):
    class NoCursor(ToySource):
        kind = "toy"

        def sync(self, ctx):
            for n in range(450):
                yield Upsert(note(f"k{n:04}", f"text {n}"))

    sizes = []
    sid = index.add_source(NoCursor())
    engine = SyncEngine(index)
    real = engine._commit

    def commit(sid_, src, pending, cursor, note_, result, report):
        sizes.append(len(pending))
        return real(sid_, src, pending, cursor, note_, result, report)

    engine._commit = commit
    result = engine.run(sid, ScanReport())
    assert result.new == 450 and max(sizes) <= 200
    assert ss.read(index.store, sid).cursor == {}


# ---------------------------------------------------- deadline, pause, stop


def test_deadline_gives_more_and_the_next_run_continues(index, toy):
    toy.pages = [[Upsert(note(f"k{n}", f"text {n}"))] for n in range(4)]
    sid = index.add_source(ToySource())
    ticks = iter(range(0, 1000, 30))  # each read of the clock is 30 s later
    engine = SyncEngine(index, budget_s=45.0, monotonic=lambda: float(next(ticks)))
    report = ScanReport()
    first = engine.run(sid, report)
    assert first.more is True
    assert 0 < len(keys(index, sid)) < 4
    done = len(keys(index, sid))
    assert ss.read(index.store, sid).cursor == {"page": done}
    second = SyncEngine(index).run(sid, report)
    assert second.more is False
    assert len(keys(index, sid)) == 4


def test_scan_reports_more_and_the_helper_marks_the_source(index, toy, monkeypatch, tmp_path):
    from contextlib import contextmanager

    import anagram.local.sources.sync_engine as engine_mod

    toy.pages = [[Upsert(note(f"k{n}", f"text {n}"))] for n in range(3)]
    sid = index.add_source(ToySource())
    monkeypatch.setattr(engine_mod, "BUDGET_S", -1.0)  # each run stops at its first cursor

    @contextmanager
    def session():
        yield None, index

    indexer = Indexer(session, watch=False, clock=index.clock)
    out = indexer.cycle()
    assert out["new"] == 1
    assert indexer.take_dirty(debounce=0) == [sid]
    indexer.cycle([sid])
    indexer.cycle([sid])
    assert len(keys(index, sid)) == 3
    assert indexer.take_dirty(debounce=0) == [sid]
    indexer.cycle([sid])  # the source has no more changes
    assert indexer.take_dirty(debounce=0) == []


def test_pause_stops_at_the_next_cursor(index, toy, clock):
    sid = index.add_source(ToySource())

    def pause_now() -> Iterator[Change]:
        ss.pause(index.store, sid, now=clock())
        return iter(())

    class Pauses(ToySource):
        kind = "toy"

        def sync(self, ctx):
            yield Upsert(note("a", "alpha"))
            yield from pause_now()  # the person pauses while a batch is read
            yield Cursor({"page": 1})
            yield Upsert(note("b", "beta"))
            yield Cursor({"page": 2})

    index.connectors[sid] = Pauses()
    report = index.scan([sid], process=False)
    assert keys(index, sid) == ["a"] and report.more == []
    state = ss.read(index.store, sid)
    assert state.status == "paused" and state.cursor == {"page": 1}
    # A paused source is not read.
    index.scan([sid], process=False)
    assert keys(index, sid) == ["a"]
    ss.resume(index.store, sid, now=clock())
    index.connectors[sid] = ToySource()
    toy.pages = [[Upsert(note("a", "alpha"))], [Upsert(note("b", "beta"))]]
    index.scan([sid], process=False)
    assert keys(index, sid) == ["a", "b"]


def test_a_paused_v1_source_is_not_scanned(index, tmp_path, clock):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "a.md").write_text("# A\n")
    sid = index.add_source(FolderConnector(tmp_path / "notes"))
    ss.pause(index.store, sid, now=clock())
    assert index.scan([sid]).new == []
    ss.resume(index.store, sid, now=clock())
    assert index.scan([sid]).new == [(sid, "a.md")]
    assert ss.read(index.store, sid).status == "live"


# ------------------------------------------------------------------- faults


def test_source_fault_keeps_the_cursor_and_sets_the_state(index, toy, clock):
    toy.pages = [[Upsert(note("a", "alpha"))], [Upsert(note("b", "beta"))]]
    toy.fail_at = 1
    toy.fault = SourceFault("rate_limited", "HTTP 429", retry_at=clock() + 600)
    sid = index.add_source(ToySource())
    report = index.scan([sid], process=False)
    assert report.errors == []  # a source fault is state, not a scan error
    state = ss.read(index.store, sid)
    assert state.cursor == {"page": 1}
    assert (state.status, state.error_code, state.next_at) == (
        "waiting",
        "rate_limited",
        clock() + 600,
    )
    fault_events = [e["data"] for e in events(index, "source.state") if e["data"]["fault"]]
    assert fault_events[-1]["fault"]["code"] == "rate_limited"
    # Before the retry time the source is not called.
    calls = toy.calls
    index.scan([sid], process=False)
    assert toy.calls == calls
    # After it, the run continues at the cursor and the fault is gone.
    toy.fail_at = None
    clock.t += 601
    index.scan([sid], process=False)
    state = ss.read(index.store, sid)
    assert keys(index, sid) == ["a", "b"]
    assert (state.status, state.error_code, state.failures) == ("live", None, 0)


def test_attention_fault_waits_for_the_person(index, toy, clock):
    toy.pages = [[Upsert(note("a", "alpha"))]]
    toy.fail_at = 0
    toy.fault = SourceFault("auth_expired")
    sid = index.add_source(ToySource())
    index.scan([sid], process=False)
    assert ss.read(index.store, sid).status == "attention"
    toy.fail_at = None
    clock.t += 10_000
    index.scan([sid], process=False)
    assert keys(index, sid) == []  # no run until the person acts
    ss.clear_fault(index.store, sid, now=clock())
    index.scan([sid], process=False)
    assert keys(index, sid) == ["a"]


def test_other_exception_is_unknown_with_no_text(index, toy, caplog):
    toy.pages = [[Upsert(note("a", "alpha"))]]
    toy.fail_at = 0  # raises RuntimeError("secret-text-in-error")
    sid = index.add_source(ToySource())
    index.scan([sid], process=False)
    state = ss.read(index.store, sid)
    assert (state.status, state.error_code, state.error_detail) == (
        "waiting",
        "unknown",
        "RuntimeError",
    )
    assert "secret-text-in-error" not in str(events(index))
    assert "secret-text-in-error" not in " ".join(r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------- events


def test_progress_events_hold_counts_and_no_item_data(index, toy):
    toy.pages = [
        [Note(phase="first_sync", total=2, at="2026-03-01T00:00:00Z"), Upsert(note("a", "alpha"))],
        [Upsert(note("b", "beta")), Note(done=2)],
    ]
    sid = index.add_source(ToySource())
    ticks = iter(float(n) * 2 for n in range(100))  # 2 s between reads: no event is held back
    SyncEngine(index, monotonic=lambda: next(ticks), budget_s=10_000).run(sid, ScanReport())
    progress = [e["data"] for e in events(index, "source.progress")]
    assert len(progress) == 2
    assert set(progress[0]) == {
        "at",
        "changed",
        "converting",
        "done",
        "embedding",
        "id",
        "indexed",
        "new",
        "phase",
        "removed",
        "total",
    }
    assert progress[0]["new"] == 1 and progress[-1]["new"] == 2
    assert progress[-1]["done"] == 2 and progress[-1]["total"] == 2
    assert progress[-1]["at"] == "2026-03-01T00:00:00Z"
    text = str(events(index))
    assert "alpha" not in text and "Note a" not in text and "toy:a" not in text


def test_progress_events_are_held_back_in_a_fast_run(index, toy):
    toy.pages = [[Upsert(note(f"k{n}", f"text {n}"))] for n in range(20)]
    sid = index.add_source(ToySource())
    SyncEngine(index, monotonic=lambda: 5.0).run(sid, ScanReport())  # a run in no time
    # One after the first batch and one at the end of the run.
    assert len(events(index, "source.progress")) == 2


def test_the_engine_uses_the_given_publish(index, toy):
    got = []
    toy.pages = [[Upsert(note("a", "alpha"))]]
    sid = index.add_source(ToySource())
    SyncEngine(index, publish=lambda topic, data: got.append(topic)).run(sid, ScanReport())
    assert "source.progress" in got and "source.state" in got
    assert events(index) == []


# ---------------------------------------------------------------- v1 faults


def test_v1_scan_fault_goes_into_the_source_state(index, tmp_path, monkeypatch):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "a.md").write_text("# A\n")
    sid = index.add_source(FolderConnector(tmp_path / "notes"))

    def gone(self, known):
        raise FileNotFoundError("/a/private/path")

    monkeypatch.setattr(FolderConnector, "scan", gone)
    report = index.scan([sid])
    assert report.errors and report.errors[0][0] == sid  # the old report stays
    state = ss.read(index.store, sid)
    assert (state.status, state.error_code) == ("attention", "not_found")
    assert "/a/private/path" not in str(events(index))
    monkeypatch.undo()
    index.scan([sid])  # a v1 source is tried again; a good scan clears the fault
    state = ss.read(index.store, sid)
    assert (state.status, state.error_code) == ("live", None)


# ---------------------------------------------------------------- own guard


def test_items_of_a_source_that_is_not_own(index, toy, tmp_path):
    text = "We need a cryo-EM grid robot. We offer nanobody libraries for membrane proteins."
    (tmp_path / "mine").mkdir()
    (tmp_path / "mine" / "plan.md").write_text(f"# My plan\n\n{text}\n")
    mine = index.add_source(FolderConnector(tmp_path / "mine"))
    LabToy.pages = [[Upsert(note("other", f"Colleague text. {text} zebrafish"))]]
    lab = index.add_source(LabToy())
    index.scan()

    assert index.is_own(mine) and not index.is_own(lab)
    assert index.own_sources() == [mine]
    # The item is in the index and in search.
    assert keys(index, lab) == ["other"]
    assert index.search("zebrafish")[0].source_id == lab
    # No checkpoint.
    assert index.streams.pending(lab) == [] and index.streams.pending(mine) != []
    assert index.streams.checkpoint_due(lab, 0) is False
    assert index.streams.checkpoint(object(), lab) is None
    assert index.sources()[lab]["pending"] == []
    # No finding draft, no input of the matching lines draft.
    assert all(i.source_id != lab for d in draft_findings(index) for i in d.items)
    assert "Colleague text" not in str(lens_items(index))
    assert {i.source_id for i in index.items(own_only=True)} == {mine}


def test_is_own_reads_the_class_flag_with_no_open_connector(tmp_path, clock, toy):
    idx = LocalIndex(tmp_path / "index.sqlite", KEY, clock=clock)
    lab = idx.add_source(LabToy())
    idx.close()
    idx = LocalIndex(tmp_path / "index.sqlite", KEY, clock=clock)
    try:
        assert idx.connectors == {}
        assert idx.is_own(lab) is False
        assert idx.connectors == {}  # no connector was opened for the answer
    finally:
        idx.close()
