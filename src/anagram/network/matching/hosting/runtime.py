"""What each service process shares: logs, a ticker, health, shutdown.

Logs. Each line is one JSON object: `{"at", "event", "level", "service",
...fields}`. `event` is a fixed name and every other field must be in
`SAFE_FIELDS`: sizes, counts, roles, public IDs, status codes. A pack, a
card, a key, a subject or a request body has no field here, so a log line
cannot carry one (`LogFieldRefused` at the call). Access logs are off: a
path can hold a slot address or a request digest.

Ticker. `Ticker` runs one function every `every` seconds in a thread; an
exception is logged by its type name only and the next tick runs.

Shutdown. `serve` runs uvicorn; on SIGTERM or SIGINT uvicorn stops taking
requests, then the app's lifespan stops the tickers and saves the state.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from fastapi import FastAPI

SAFE_FIELDS = frozenset(
    {
        "counter",
        "cosigned",
        "count",
        "day",
        "entries",
        "error",
        "host",
        "index",
        "instance_id",
        "kind",
        "line_id",
        "node",
        "port",
        "profile",
        "reason",
        "role",
        "route",
        "seq",
        "size",
        "status",
        "witness",
        "witnesses",
    }
)


class LogFieldRefused(ValueError):
    """A log field that is not in `SAFE_FIELDS`."""


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        fields = dict(getattr(record, "fields", None) or {})
        doc: dict[str, Any] = {
            "at": int(record.created),
            "event": fields.pop("event") if fields else record.getMessage(),
            "level": record.levelname.lower(),
            "service": self.service,
        }
        if fields:
            doc.update(fields)
        elif record.args:  # a library message: its template, never its values
            doc["event"] = str(record.msg)
        if record.exc_info and record.exc_info[0] is not None:
            doc["error"] = record.exc_info[0].__name__  # no traceback text, no message
        return json.dumps(doc, sort_keys=True)


def setup_logging(service: str, stream: TextIO | None = None) -> None:
    """JSON lines on stderr for this process. Library loggers keep their
    levels; uvicorn's access log is off (`serve`)."""
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def event(logger: logging.Logger, name: str, level: int = logging.INFO, **fields: object) -> None:
    """Log the fixed event `name` with safe fields only."""
    bad = sorted(set(fields) - SAFE_FIELDS)
    if bad:
        raise LogFieldRefused(f"log fields not allowed: {bad}")
    logger.log(level, name, extra={"fields": {"event": name, **fields}})


class Ticker:
    def __init__(self, name: str, fn: Callable[[], None], every: float) -> None:
        self.name = name
        self.fn = fn
        self.every = every
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"anagram-{name}")
        self.log = logging.getLogger(f"anagram.services.{name}")

    def start(self) -> Ticker:
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.wait(self.every):
            try:
                self.fn()
            except Exception as exc:  # noqa: BLE001 - a tick must not stop the process
                event(self.log, "tick_failed", logging.WARNING, error=type(exc).__name__)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout)


def serve(app: FastAPI, host: str, port: int) -> None:  # pragma: no cover - runs a server
    """Run the app until SIGTERM or SIGINT (graceful: uvicorn ends the open
    requests, then the lifespan ends)."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, access_log=False, log_config=None)
