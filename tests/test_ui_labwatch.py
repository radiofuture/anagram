"""The task `lab.watch` (plan R2 5.6, step S9b), with a fake bus."""

from __future__ import annotations

import json

import pytest
from test_ui_api import ORIGIN
from test_ui_labs import pair  # noqa: F401 - the fixture

from anagram.network.groups.app import labspace
from anagram.shell.ui.labwatch import MAX_WAIT, LabWatch


class Bus:
    def __init__(self) -> None:
        self.seen: list[tuple[str, dict]] = []

    def publish(self, type_: str, data: dict) -> None:
        self.seen.append((type_, data))

    def types(self) -> list[str]:
        return [t for t, _ in self.seen]

    def take(self) -> list[tuple[str, dict]]:
        out, self.seen = self.seen, []
        return out


def _watch(svc) -> tuple[LabWatch, Bus]:
    bus = Bus()
    cfg = json.loads((svc.home / "config.json").read_text())
    cfg["labs"] = {"poll_wait": 0, "poll_min": 5}
    (svc.home / "config.json").write_text(json.dumps(cfg))
    return LabWatch(svc, bus.publish), bus


def test_the_task_is_registered(pair):  # noqa: F811
    _, (_, pi), _ = pair
    assert "lab.watch" in pi.app.state.ctx.tasks.names()


def test_watch_publishes_each_event(pair, monkeypatch):  # noqa: F811
    _, (pi_svc, pi), (m_svc, m) = pair
    calls: list[bool] = []
    real = labspace.sync_index
    with pi_svc.open_client() as c:
        me = c.device.subject

    def spy(c, idx, *, scan=True):
        if c.device.subject == me:
            calls.append(scan)
        return real(c, idx, scan=scan)

    monkeypatch.setattr("anagram.shell.ui.labwatch.sync_lab_index", spy)
    lab = pi.post("/api/labs", json={"name": "Chen Lab"}, headers=ORIGIN).json()["id"]
    w, bus = _watch(pi_svc)
    w.run()  # first turn: a full sync, no change since the cache
    assert bus.take() == [] and calls == [True]

    url = pi.post(f"/api/labs/{lab}/invites", json={}, headers=ORIGIN).json()["url"]
    m.post("/api/labs/join", json={"url": url}, headers=ORIGIN)
    w.run()
    got = bus.take()
    assert ("lab.invites", {"lab": lab}) in got
    joined = [d for t, d in got if t == "lab.members"]
    assert [d["change"] for d in joined] == ["joined"] and joined[0]["person"]

    row = m.post(
        f"/api/labs/{lab}/space", json={"note": {"title": "Gel", "text": "1 %"}}, headers=ORIGIN
    ).json()
    w.run()
    assert bus.take() == [("lab.space", {"change": "published", "item": row["id"], "lab": lab})]
    with pi_svc.open_client() as c:
        assert [v["title"] for v in c.lab_space.lab_items(lab)] == ["Gel"]

    m.put(f"/api/labs/{lab}/settings", json={"matching": {"enabled": False}}, headers=ORIGIN)
    pi.put(f"/api/labs/{lab}/settings", json={"matching": {"enabled": False}}, headers=ORIGIN)
    mw, mbus = _watch(m_svc)
    mw.run()
    assert ("lab.settings", {"lab": lab, "rev": 1}) in mbus.take()

    m.delete(f"/api/labs/{lab}/space/{row['id']}", headers=ORIGIN)
    w.run()
    assert bus.take() == [("lab.space", {"change": "removed", "item": row["id"], "lab": lab})]

    # The member leaves: the PI sees it, and the PI's sync starts a new epoch.
    m.post(f"/api/labs/{lab}/leave", headers=ORIGIN)
    w.run()
    got = bus.take()
    assert [d["change"] for t, d in got if t == "lab.members"] == ["left"]
    key = [d for t, d in got if t == "lab.key"]
    assert key == [{"epoch": 2, "lab": lab, "rotation_due": False}]
    # Each turn reconciles the index (publish_pending); a turn with a change scans.
    assert calls == [True] * 5


def test_removed_person_gets_lab_removed(pair):  # noqa: F811
    _, (_, pi), (m_svc, m) = pair
    view = pi.post("/api/labs", json={"name": "Reyes Lab"}, headers=ORIGIN).json()
    lab = view["id"]
    url = pi.post(f"/api/labs/{lab}/invites", json={}, headers=ORIGIN).json()["url"]
    m.post("/api/labs/join", json={"url": url}, headers=ORIGIN)
    w, bus = _watch(m_svc)
    w.run()
    pid = next(
        x["person"]["id"] for x in pi.get(f"/api/labs/{lab}").json()["members"] if not x["you"]
    )
    pi.delete(f"/api/labs/{lab}/members/{pid}", headers=ORIGIN)
    w.cursor = None  # the next full sync (the change feed has no row for a removed person)
    w.run()
    assert bus.take() == [("lab.removed", {"lab": lab, "name": "Reyes Lab"})]


class Broken:
    def open_client(self, index=False):
        raise OSError("no host")


def test_failed_turn_backs_off():
    w = LabWatch(Broken())
    assert w.wait() < 1
    for want in (5, 10, 20, 40):
        with pytest.raises(OSError):
            w.run()
        assert w.wait() == want
    for _ in range(10):
        with pytest.raises(OSError):
            w.run()
    assert w.wait() == MAX_WAIT
