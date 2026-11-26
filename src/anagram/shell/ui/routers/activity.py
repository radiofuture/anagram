"""`GET /api/activity?since=`: what is new, for the Home screen.

The route reads the events of this process from the bus (a tap), not from a
store: a share, a proposed finding, a new source. The page gives each
line its words from `copy/home.json` (`text_key` and `params`), so the route
returns no sentence. Events of one type that come close together become one
line with a count (`params.n`).

Data rule of `shell/ui/events.py`: only values that the JSON API gives to the same
page. No path: a source name is the last part of its place.
"""

from __future__ import annotations

import threading
from collections import deque

from fastapi import FastAPI

from anagram.core.timefmt import seconds
from anagram.shell.ui.events import Event
from anagram.shell.ui.routers import UIContext

KEEP = 50  # lines that the route keeps
JOIN_S = 600  # events of one type in this time become one line

# event type -> (text key in home.json, the screen that the line opens, and
# the route parameters of that screen). A read record is on "Shared by me".
LINES: dict[str, tuple[str, str, dict]] = {
    "shared.received": ("act_shared", "sharing", {}),
    "share.read": ("act_read", "sharing", {"tab": "by-me"}),
    "suggestion.new": ("act_suggestion", "library", {}),
    "source.added": ("act_source", "sources", {}),
}


def _name(value: object) -> str | None:
    """A short name with no folder part."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.replace("\\", "/").rstrip("/").split("/")[-1].strip() or None


def _params(event: Event) -> dict:
    d = event.data
    if event.type == "shared.received":
        return {k: d[k] for k in ("sender", "title") if isinstance(d.get(k), str)}
    if event.type == "share.read":
        return {"name": d["reader"]} if isinstance(d.get("reader"), str) else {}
    if event.type == "suggestion.new":
        return {"title": d["title"]} if isinstance(d.get("title"), str) else {}
    if event.type == "source.added":
        src = d.get("source") if isinstance(d.get("source"), dict) else {}
        name = _name(src.get("name")) or _name(src.get("label"))
        return {"name": name} if name else {}
    return {}


class Activity:
    """The last lines, newest first. Thread-safe."""

    def __init__(self, keep: int = KEEP) -> None:
        self._lock = threading.Lock()
        self._lines: deque[dict] = deque(maxlen=keep)

    def add(self, event: Event) -> None:
        line = LINES.get(event.type)
        if line is None:
            return
        text_key, screen, route = line
        params = _params(event)
        with self._lock:
            last = self._lines[0] if self._lines else None
            if (
                last is not None
                and last["type"] == event.type
                and seconds(event.at) - seconds(last["at"]) <= JOIN_S
            ):
                n = int(last["params"].get("n", 1)) + 1
                last.update(at=event.at, key=event.key, params={**params, "n": n})
                return
            self._lines.appendleft(
                {
                    "at": event.at,
                    "key": event.key,
                    "params": {**params, "n": 1},
                    "route": dict(route),
                    "screen": screen,
                    "text_key": text_key,
                    "type": event.type,
                }
            )

    def lines(self, since: str | None = None) -> list[dict]:
        with self._lock:
            out = [dict(x, params=dict(x["params"]), route=dict(x["route"])) for x in self._lines]
        if since:
            out = [x for x in out if x["at"] > since]
        return out


def register(app: FastAPI, ctx: UIContext) -> None:
    activity = Activity()
    ctx.bus.tap(activity.add)
    app.state.activity = activity

    @app.get("/api/activity")
    def lines(since: str | None = None) -> list[dict]:
        return activity.lines(since)
