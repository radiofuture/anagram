"""Live events that do not come from a UI action. (An action of a UI part
publishes its own events with `UIService.publish` after it returns.)

- `JoinBridge` publishes `join.state` when the state of a join or a sign-in
  changes.
- `SourceEventBridge` moves the rows of the table `source_event` to the
  bus, and publishes `draft.changed` after source work.
- `Live` holds the bridges and the task runner of one UI server.

The bridges are threads of the local UI. Other periodic work is a task
(`shell/ui/tasks.py`), not a thread. Event data obeys the data rule of
`shell/ui/events.py`: only what the JSON API gives to the same page.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from anagram.local.api import source_state
from anagram.shell.ui.events import EventBus

if TYPE_CHECKING:
    from anagram.shell.ui.join import JoinUI
    from anagram.shell.ui.routers import UIContext
    from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.ui.bridge")


class _Poller(threading.Thread):
    """A daemon thread that calls `tick` again and again. An error is logged
    (the class only, one time for each class in sequence) and the next turn
    tries again."""

    def __init__(self, name: str, interval: float) -> None:
        super().__init__(name=name, daemon=True)
        self.interval = interval
        self._halt = threading.Event()
        self._fault: str | None = None

    def tick(self) -> None:
        raise NotImplementedError

    def run(self) -> None:
        while not self._halt.wait(self.interval):
            try:
                self.tick()
                self._fault = None
            except Exception as exc:  # logged; try again next time
                fault = type(exc).__name__
                if fault != self._fault:
                    log.warning("%s failed: %s", self.name, fault)
                self._fault = fault

    def stop(self) -> None:
        self._halt.set()


# Join task states after which the overview is different: a join, or an
# ORCID iD link (the account shows the linked iD).
OVERVIEW_STATES = ("joined", "linked")


class JoinBridge(_Poller):
    """While a join task is active (`JoinUI.task`): read its view each 250 ms
    and publish join.state on change. When the state becomes `joined` or
    `linked`, publish overview.changed."""

    def __init__(self, join: JoinUI, bus: EventBus, interval: float = 0.25) -> None:
        super().__init__("join-bridge", interval)
        self.join = join
        self.bus = bus
        self._last: dict | None = None

    def tick(self) -> None:
        view = self.join.status() if self.join.task is not None else None
        if view == self._last:
            return
        before, self._last = self._last, view
        self.bus.publish("join.state", view if view is not None else {"state": "idle"})
        state = view["state"] if view is not None else None
        if state in OVERVIEW_STATES and (before or {}).get("state") != state:
            self.bus.publish("overview.changed")


# Source events after which the drafts can be different. The page reloads
# the drafts on `draft.changed`; one is published for each read of the table.
DRAFT_TOPICS = {"source.added", "source.progress", "source.removed"}


class SourceEventBridge(_Poller):
    """While the bus has a subscriber: call source_state.events_after(store, last_id) each
    500 ms and publish each row: bus.publish(row["topic"], row["data"]). This is the only
    path of source events to the page. The first read starts at the newest row: the page
    has the older state from GET /api/sources."""

    def __init__(self, service: UIService, bus: EventBus, interval: float = 0.5) -> None:
        super().__init__("source-event-bridge", interval)
        self.service = service
        self.bus = bus
        self.last: int | None = None

    def tick(self) -> None:
        if self.bus.subscribers() == 0 or not self.service.joined():
            return
        with self.service.open_client(index=True) as (_, idx):
            if self.last is None:
                self.last = source_state.last_event_id(idx.store)
                return
            rows = source_state.events_after(idx.store, self.last)
        drafts = False
        for row in rows:
            self.last = row["id"]
            data = row["data"] if isinstance(row["data"], dict) else {}
            key = data.get("id")
            if not isinstance(key, str):
                key = (
                    (data.get("source") or {}).get("id")
                    if isinstance(data.get("source"), dict)
                    else None
                )
            try:
                self.bus.publish(row["topic"], data, key=key if isinstance(key, str) else None)
            except (TypeError, ValueError) as exc:
                log.warning("source event %s not sent: %s", row["id"], type(exc).__name__)
            drafts = drafts or row["topic"] in DRAFT_TOPICS
        if drafts:
            self.bus.publish("draft.changed")


class Live:
    """The bridges and the task runner of one UI server. The process that
    hosts the UI calls `start` one time, and `stop` before the server stops
    (`stop` ends the open event streams, so the server can close)."""

    def __init__(self, service: UIService, ctx: UIContext) -> None:
        self.ctx = ctx
        self.bridges: list[_Poller] = [
            JoinBridge(service.join, ctx.bus),
            SourceEventBridge(service, ctx.bus),
        ]

    def start(self) -> None:
        for bridge in self.bridges:
            bridge.start()
        self.ctx.tasks.start()

    def stop(self) -> None:
        self.ctx.bus.close()
        self.ctx.tasks.stop()
        for bridge in self.bridges:
            bridge.stop()
