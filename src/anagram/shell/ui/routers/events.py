"""`GET /api/events`: the one live stream of the local UI (Server-Sent Events).

The route is a normal GET, so the guard of `shell/ui/server.py` applies: this Host,
this Origin, and the cookie. No other route is a stream. No WebSocket.

    id: 41
    event: source.progress
    data: {"v":1,"id":41,"at":"…","type":"source.progress","topic":"source","key":"…","data":{…}}

- The first frame is `hello` with `{"server_id", "last_id"}`. A page that has
  a different `server_id` loads all its data again.
- With the header `Last-Event-ID`, the newer events follow. If the bus does
  not have them all, the frame `resync` follows and the page loads all its
  data again.
- After 15 s with no event, the comment line `: keep-alive`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from anagram.shell.ui.events import Closed, frame
from anagram.shell.ui.routers import UIContext

KEEPALIVE_S = 15.0
KEEPALIVE = ": keep-alive\n\n"


def last_event_id(value: str | None) -> int | None:
    """The id that the page has. A value that is not a number is no id."""
    if value is None or not value.isascii() or not value.isdigit() or len(value) > 18:
        return None
    return int(value)


def register(app: FastAPI, ctx: UIContext) -> None:
    @app.get("/api/events")
    async def events(request: Request) -> StreamingResponse:
        after = last_event_id(request.headers.get("last-event-id"))

        async def stream() -> AsyncIterator[str]:
            # The subscription opens here, so that `finally` always closes it:
            # a page that goes away frees its queue.
            sub = ctx.bus.subscribe(after)
            try:
                while True:
                    try:
                        event = await sub.next(KEEPALIVE_S)
                    except Closed:
                        return
                    yield KEEPALIVE if event is None else frame(event)
            finally:
                sub.close()

        return StreamingResponse(
            stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )
