"""`anagram open`: open the UI of the running app in the browser.

1. Read the runtime file. Ask `GET /health` and compare the instance id.
2. If no app runs: start it (through the login service if it is installed,
   else as a detached process) and wait up to `START_WAIT_S` seconds.
3. `POST /control/open` gives a one-time link. Open it in the browser.

An app of another version (the member installed a new one) is stopped
through `/control/stop`, and this program starts the new app.

The launcher talks only to 127.0.0.1, with no proxy, and sends no browser
headers (the control routes refuse them).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Callable
from pathlib import Path

import anagram
from anagram.shell.app import control, lock, urlscheme
from anagram.shell.app.autostart import (
    Autostart,
    AutostartError,
    autostart_for_platform,
    service_command,
)

START_WAIT_S = 20.0
HTTP_TIMEOUT_S = 5.0
_FRAGMENT = re.compile(r"[A-Za-z0-9_-]+")

_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LaunchError(RuntimeError):
    """The app does not run and did not start."""


def _call(method: str, url: str, body: dict | None = None, bearer: str | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("the launcher talks only to the loopback address")
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - checked above
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if bearer is not None:
        req.add_header("Authorization", f"Bearer {bearer}")
    with _LOCAL.open(req, timeout=HTTP_TIMEOUT_S) as resp:  # http://127.0.0.1 only
        return json.loads(resp.read())


def _pid_alive(pid: int) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, SystemError, ValueError):
        return False
    return True


def live_runtime(home: str | Path) -> dict | None:
    """The runtime file of a running app of this home, or None. A file of a
    process that is gone is removed."""
    doc = control.read_runtime(home)
    if doc is None:
        return None
    try:
        health = _call("GET", f"http://127.0.0.1:{doc['port']}{control.HEALTH_PATH}")
        if health.get("instance") == doc["instance"]:
            return doc
    except (OSError, ValueError, urllib.error.URLError):
        pass
    if not _pid_alive(doc["pid"]):
        control.remove_runtime(home, doc["instance"])
    return None


def spawn_detached(command: list[str]) -> None:
    """Start a process that does not stop with this one."""
    subprocess.Popen(  # noqa: S603 - the app command, fixed arguments
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def default_start(
    home: str | Path,
    autostart: Autostart | None = None,
    scheme: urlscheme.UrlScheme | None = None,
) -> None:
    """Start the app of this home.

    - The login service runs the command of this home: start it there.
    - The login service has an old command (the person moved the app): write
      the unit again, then start it.
    - The packaged app with no login service yet: install it (the first open
      after the install), and make the app the handler of `anagram://` links.
      The person can turn the login service off in the UI.
    - Else (a developer, another data directory): a detached process."""
    service = autostart or autostart_for_platform()
    want = service_command(home)
    have = service.command()
    frozen = getattr(sys, "frozen", False)
    if frozen and have is None:
        with contextlib.suppress(AutostartError):
            links = scheme or urlscheme.scheme_for_platform()
            links.register(urlscheme.handler_command())
    try:
        if have == want:
            service.start()
            return
        if have is not None and have[-4:-2] == want[-4:-2]:  # same home, new program path
            service.install(want)
            return
        if have is None and frozen:
            service.install(want)
            return
    except AutostartError:
        pass  # the app still starts; the login service is not necessary for that
    spawn_detached(want)


def replace_running(home: Path, doc: dict, wait_s: float = START_WAIT_S) -> None:
    """Stop the app of another version and wait until it is gone."""
    with contextlib.suppress(OSError, ValueError, urllib.error.URLError):
        _call("POST", f"http://127.0.0.1:{doc['port']}/control/stop", {}, bearer=doc["control"])
    end = time.monotonic() + wait_s
    # The old app removes its runtime file before it releases the app lock:
    # wait for the lock too, or the new app stops with AlreadyRunning.
    while live_runtime(home) is not None or not _lock_free(home):
        if time.monotonic() > end:
            raise LaunchError("The Anagram app of another version did not stop. Try again.")
        time.sleep(0.2)


def _lock_free(home: Path) -> bool:
    from anagram.shell.app.runtime import APP_LOCK

    handle = lock.acquire(home / APP_LOCK)
    if handle is None:
        return False
    handle.release()
    return True


def ensure_running(
    home: str | Path,
    *,
    start: Callable[[Path], None] | None = None,
    wait_s: float = START_WAIT_S,
) -> dict:
    """The runtime file of the running app; start the app if necessary."""
    home = Path(home)
    doc = live_runtime(home)
    if doc is not None and doc.get("version") == anagram.__version__:
        return doc
    if doc is not None:
        # The member installed another version: stop the app
        # that runs, then start this program.
        replace_running(home, doc, wait_s)
    (start or default_start)(home)
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        doc = live_runtime(home)
        if doc is not None:
            return doc
        time.sleep(0.2)
    raise LaunchError("Anagram did not start. See the log in the data directory.")


def open_link(doc: dict, route: str | None = None, invite: str | None = None) -> str:
    """A one-time open link from the running app."""
    out = _call(
        "POST",
        f"http://127.0.0.1:{doc['port']}/control/open",
        {"invite": invite, "route": route},
        bearer=doc["control"],
    )
    return out["url"]


def open_app(
    home: str | Path,
    route: str | None = None,
    invite: str | None = None,
    *,
    start: Callable[[Path], None] | None = None,
    browser: Callable[[str], object] | None = None,
    wait_s: float = START_WAIT_S,
) -> str:
    """Make sure that the app runs, then open its UI in the browser. Return
    the link that was opened."""
    doc = ensure_running(home, start=start, wait_s=wait_s)
    url = open_link(doc, route, invite)
    (browser or webbrowser.open)(url)
    return url


def invite_of(url: str) -> str | None:
    """The invite link (`<node_url>/join#<fragment>`) of an
    `anagram://join/<fragment>` link, or None. The fragment must parse as a
    node invite (`parse_invite_url`) or a lab invite
    (`admission.formats.parse_lab_invite_link`)."""
    from anagram.admission.api import parse_invite_url, parse_lab_invite_link

    if not url.lower().startswith(urlscheme.JOIN_PREFIX):
        return None
    fragment = url[len(urlscheme.JOIN_PREFIX) :]
    if not _FRAGMENT.fullmatch(fragment):
        return None
    for parse, node_url in (
        (parse_invite_url, lambda doc: doc["node_url"]),
        (parse_lab_invite_link, lambda doc: doc["auth"]["node_url"]),
    ):
        try:
            doc = parse(fragment)
        except Exception:  # noqa: S112 - each fault means: not this kind of invite
            continue
        return f"{node_url(doc).rstrip('/')}/join#{fragment}"
    return None


def open_url(home: str | Path, argv: list[str], **kw) -> str:
    """`anagram open-url <link>`: the operating system gives a link that a
    person selected. Accept exactly one argument that starts with
    `anagram://` and has at most `MAX_URL` characters. An invite link of
    `anagram://join/<fragment>` goes to the app as a pending invite (the app
    chooses the screen). All other input opens the app with no data."""
    args = [a for a in argv if not a.startswith("-psn_")]
    invite = None
    if len(args) == 1 and args[0].lower().startswith(urlscheme.PREFIX):
        url = args[0]
        if len(url) <= urlscheme.MAX_URL:
            invite = invite_of(url)
    return open_app(home, invite=invite, **kw)


def stop_app(home: str | Path) -> bool:
    """Ask the running app to stop. False: no app runs."""
    doc = live_runtime(home)
    if doc is None:
        return False
    _call("POST", f"http://127.0.0.1:{doc['port']}/control/stop", {}, bearer=doc["control"])
    return True
