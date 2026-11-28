"""Route modules of the local UI, found by directory.

Each API route of the local UI is in this package; `shell/ui/server.py` has only
the pages (`/`, `/open/{token}`, `/auth/callback`) and the guard. A track
adds its routes with one new file and no change to `shell/ui/server.py`:

    # ui/routers/<name>.py
    def register(app: FastAPI, ctx: UIContext) -> None:
        @app.get("/api/<name>")
        def view() -> dict:
            return ctx.service.<part>.view()

A route is thin: it reads the request and calls one method of one part of
the service (`ctx.service.<part>`, `shell/ui/service.py`). `register_all` imports
each module of this package in name order and calls its `register`. The
guard of `shell/ui/server.py` (Host, Origin, cookie) applies to each route: a path
that starts with `/api/` needs the cookie.

Rules:

- A module does not register a method and path that exists in another
  module. `register_all` stops with an error if it does.
- A route with a fixed segment comes before a route with a parameter at the
  same place (`/api/labs/mine` before `/api/labs/{lab_id}`).
- Live events: a part publishes them (`UIService.publish`); a route can use
  `ctx.bus.publish(type, data)`. Periodic work: `ctx.tasks.add(name, fn,
  every_s)`. A module starts no thread.
- A module whose name starts with `_` is not a route module.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.responses import Response

from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.events import EventBus
    from anagram.shell.ui.service import UIService
    from anagram.shell.ui.tasks import TaskRunner


@dataclass(frozen=True)
class UIContext:
    service: UIService
    bus: EventBus
    tasks: TaskRunner
    port: int
    runtime: object | None = None  # the AppRuntime when `anagram app run` hosts the UI


def body_text(body: dict, name: str, required: bool = True) -> str | None:
    """The text field `name` of a JSON body (400 when it is not text)."""
    value = body.get(name) if isinstance(body, dict) else None
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise UIError(400, f"Missing {name}.")
    return value


def body_dict(body: object) -> dict:
    """A JSON body that must be an object."""
    if not isinstance(body, dict):
        raise UIError(400, "Bad request.")
    return body


def json_download(name: str, text: str) -> Response:
    """A JSON file that the browser saves (a proof file)."""
    from anagram.shell.ui.sharing import disposition

    return Response(
        text,
        media_type="application/json",
        headers={"Content-Disposition": disposition("attachment", name)},
    )


def _twice(app: FastAPI) -> list[tuple[str, str]]:
    """Each method and path that the app has more than one time."""
    count = Counter(
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", None) or ()
        if method != "HEAD"
    )
    return sorted(key for key, n in count.items() if n > 1)


def module_names(package: str = __name__) -> list[str]:
    """The route modules of a package, in name order."""
    pkg = importlib.import_module(package)
    return sorted(m.name for m in pkgutil.iter_modules(pkg.__path__) if not m.name.startswith("_"))


def register_all(app: FastAPI, ctx: UIContext) -> None:
    """Import each module in this package in name order and call register(app, ctx)."""
    register_package(app, ctx, __name__)


def register_package(app: FastAPI, ctx: UIContext, package: str) -> None:
    """The work of register_all, for one package (tests use a temp package)."""
    for name in module_names(package):
        module = importlib.import_module(f"{package}.{name}")
        register = getattr(module, "register", None)
        if not callable(register):
            raise RuntimeError(f"{package}.{name} has no register(app, ctx)")
        register(app, ctx)
        twice = _twice(app)
        if twice:
            method, path = twice[0]
            raise RuntimeError(f"{package}.{name} registers {method} {path}, which exists")
