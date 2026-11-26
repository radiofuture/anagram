"""The live event bus of the local UI.

One bus for each UI server process. All tracks publish with one call:

    bus.publish("source.progress", {"id": sid, "done": 3, "total": 9})

The page reads the events from one stream, `GET /api/events`
(`shell/ui/routers/events.py`). The bus keeps the last events in memory, so a page
that connects again gets the events that it did not see (`Last-Event-ID`). If
the page is too far behind, it gets `resync` and loads all its data again.

Data rule: an event has only what the JSON API gives to the same page. No
token, no key, no file content, no absolute path.

Code outside `anagram.shell.ui` does not import this module. It takes a parameter
`publish: Callable[[str, dict], None] | None`, and the UI gives it
`UIService.publish` (a `Publisher`, below).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from anagram.core.timefmt import iso_seconds

log = logging.getLogger("anagram.shell.ui.events")

KEEP = 512  # events that the bus keeps for replay
QUEUE = 256  # events that one slow subscriber can have in its queue
TYPE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")
HELLO = "hello"
RESYNC = "resync"


@dataclass(frozen=True)
class Event:
    id: int  # 1, 2, 3 … for this server process
    at: str  # ISO time, UTC
    type: str  # "source.progress"
    topic: str  # "source": the text of `type` before the first "."
    key: str | None  # id of the object, for keyed updates
    data: dict = field(default_factory=dict)  # display data only

    def json(self) -> str:
        return json.dumps(
            {
                "v": 1,
                "id": self.id,
                "at": self.at,
                "type": self.type,
                "topic": self.topic,
                "key": self.key,
                "data": self.data,
            },
            separators=(",", ":"),
        )


def frame(event: Event) -> str:
    """One Server-Sent Events frame."""
    return f"id: {event.id}\nevent: {event.type}\ndata: {event.json()}\n\n"


class Closed(Exception):
    """The subscription or the bus is closed. The stream ends."""


class Subscription:
    """The queue of one open page. `publish` fills it from any thread. The
    stream route reads it with `next` in the event loop."""

    def __init__(self, bus: EventBus, first: list[Event], limit: int) -> None:
        self._bus = bus
        self._lock = threading.Lock()
        self._queue: deque[Event] = deque(first)
        self._limit = limit
        self._overflow = False
        self._closed = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None

    # Called by the bus, with the bus lock held, from any thread.
    def offer(self, event: Event) -> None:
        with self._lock:
            if self._closed or self._overflow:
                return
            if len(self._queue) >= self._limit:
                self._queue.clear()
                self._overflow = True
            else:
                self._queue.append(event)
        self.notify()

    def notify(self) -> None:
        loop, wake = self._loop, self._wake
        if loop is None or wake is None:
            return
        try:
            loop.call_soon_threadsafe(wake.set)
        except RuntimeError:  # the loop is closed: the page is gone
            pass

    def _take(self) -> Event | None:
        with self._lock:
            if self._closed:
                raise Closed
            if self._overflow:
                self._overflow = False
                return self._bus.mark(RESYNC)
            if self._queue:
                return self._queue.popleft()
        if self._bus.closed:
            raise Closed
        return None

    async def next(self, timeout: float) -> Event | None:
        """The next event. None after `timeout` seconds with no event (the
        caller sends a keep-alive comment). Raises `Closed` at the end."""
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            self._loop, self._wake = loop, asyncio.Event()
        self._wake.clear()
        event = self._take()
        if event is not None:
            return event
        try:
            await asyncio.wait_for(self._wake.wait(), timeout)
        except TimeoutError:
            pass
        return self._take()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._queue.clear()
        self._bus.drop(self)
        self.notify()


class EventBus:
    def __init__(
        self, keep: int = KEEP, clock: Callable[[], float] = time.time, queue: int = QUEUE
    ) -> None:
        self.server_id = secrets.token_hex(8)  # random for each process start
        self.closed = False
        self._clock = clock
        self._lock = threading.Lock()
        self._events: deque[Event] = deque(maxlen=keep)
        self._last = 0
        self._queue = queue
        self._subs: set[Subscription] = set()
        self._taps: list[Callable[[Event], None]] = []

    def publish(self, type: str, data: dict | None = None, *, key: str | None = None) -> Event:
        """The one publish call of all tracks. Thread-safe; never blocks.
        topic = the text of `type` before the first ".". `key` defaults to
        data["id"] when that is a string."""
        if not isinstance(type, str) or not TYPE.match(type) or type in (HELLO, RESYNC):
            raise ValueError(f"bad event type: {type!r}")
        data = {} if data is None else data
        if not isinstance(data, dict):
            raise TypeError("event data must be a dict")
        json.dumps(data)  # a value that is not JSON fails here, in the publisher
        if key is None and isinstance(data.get("id"), str):
            key = data["id"]
        with self._lock:
            self._last += 1
            event = Event(self._last, self._now(), type, type.split(".", 1)[0], key, data)
            self._events.append(event)
            for sub in self._subs:
                sub.offer(event)
            taps = list(self._taps)
        for fn in taps:
            try:
                fn(event)
            except Exception:  # a tap must not stop a publisher
                log.warning("an event tap failed for %s", event.type)
        return event

    def tap(self, fn: Callable[[Event], None]) -> None:
        """Call `fn(event)` after each publish, in the thread of the
        publisher. For a short in-process record (`routers/activity.py`). A
        tap must be fast; an error in it is logged and ignored."""
        with self._lock:
            self._taps.append(fn)

    def subscribe(self, after: int | None = None) -> Subscription:
        """Open a queue for one page. Its first event is `hello`. With `after`
        (the `Last-Event-ID` of the page), the newer events follow. If the bus
        does not have them all, `resync` follows."""
        with self._lock:
            last = self._last
            first = [self.mark(HELLO, id=last if after is None else after)]
            if after is not None:
                oldest = self._events[0].id if self._events else last + 1
                if after > last or after < oldest - 1:
                    first.append(self.mark(RESYNC))
                else:
                    first.extend(e for e in self._events if e.id > after)
            sub = Subscription(self, first, self._queue)
            if not self.closed:
                self._subs.add(sub)
        return sub

    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    @property
    def last_id(self) -> int:
        return self._last

    def close(self) -> None:
        """End all streams (the server stops)."""
        with self._lock:
            self.closed = True
            subs = list(self._subs)
            self._subs.clear()
        for sub in subs:
            sub.notify()

    def _now(self) -> str:
        return iso_seconds(self._clock())

    # ------------------------------------------------- for the subscriptions

    def mark(self, type: str, id: int | None = None) -> Event:
        """A `hello` or `resync` event. It is not kept and has no new id: a
        page that gets it has all events up to `last_id`."""
        last = self._last
        data = {"server_id": self.server_id, "last_id": last}
        return Event(last if id is None else id, self._now(), type, type, None, data)

    def drop(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)


class Publisher:
    """The publish call of the UI parts (`UIService.publish`). The UI app
    attaches its bus (`create_ui_app`). With no bus (a service with no
    server: the indexer, a script) an event goes nowhere."""

    def __init__(self) -> None:
        self.bus: EventBus | None = None

    def attach(self, bus: EventBus) -> None:
        self.bus = bus

    def __call__(self, type: str, data: dict | None = None, *, key: str | None = None) -> None:
        if self.bus is not None:
            self.bus.publish(type, data, key=key)
