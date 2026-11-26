"""The state of the app for the UI: `GET /api/app` and its two changes.
Routes: `shell/ui/routers/app.py`.

- `helper`: the index helper thread of `AppRuntime`. Without a runtime (a
  developer runs `anagram ui`), the state is "stopped".
- `keys`: where the keys are (`keychain.describe`; no keychain read).
- `start_at_login`: the login service of this system, for this data
  directory. The switch changes only the next login: it never stops or
  starts the app that runs it.
- `update`: the last result of the update check (`shell/app/update.py`,
  `AppRuntime.update_status`). No network call here; a build with no
  manifest URL always shows "no update".
"""

from __future__ import annotations

from pathlib import Path

import anagram
from anagram.identity.api import describe
from anagram.shell.app.autostart import Autostart, AutostartError, service_command
from anagram.shell.ui.errors import UIError

STOPPED = {"errors": 0, "last_cycle_at": None, "since": None, "state": "stopped"}
NO_UPDATE = {"available": False, "url": None, "version": None}


def _same_home(command: list[str] | None, want: list[str]) -> bool:
    """The unit runs the app for this data directory (the program path can differ)."""
    return command is not None and command[-4:-2] == want[-4:-2]


class AppSettings:
    def __init__(self, home: str | Path, *, runtime=None, autostart: Autostart | None = None):
        self.home = Path(home)
        self.runtime = runtime
        self._autostart = autostart

    def autostart(self) -> Autostart:
        if self._autostart is None:
            found = getattr(self.runtime, "autostart", None)
            if found is None:
                from anagram.shell.app.autostart import autostart_for_platform

                found = autostart_for_platform()
            self._autostart = found
        return self._autostart

    def helper(self) -> dict:
        return self.runtime.status() if self.runtime is not None else dict(STOPPED)

    def start_at_login(self) -> dict:
        a = self.autostart()
        return {"manager": a.manager, "on": _same_home(a.command(), service_command(self.home))}

    def view(self) -> dict:
        update = getattr(self.runtime, "update_status", None)
        return {
            "helper": self.helper(),
            "keys": describe(self.home),
            "start_at_login": self.start_at_login(),
            "update": update() if callable(update) else dict(NO_UPDATE),
            "version": anagram.__version__,
        }

    def set_start_at_login(self, on: bool) -> dict:
        a = self.autostart()
        want = service_command(self.home)
        have = a.command()
        try:
            if on and have != want:
                a.install(want, start=False)
            elif not on and _same_home(have, want):
                a.uninstall(stop=False)
        except AutostartError as exc:
            raise UIError(
                409, "Anagram could not change the start at login on this computer. Try again."
            ) from exc
        return self.start_at_login()

    def restart_helper(self) -> dict:
        if self.runtime is None:
            raise UIError(409, "The helper runs only in the Anagram app.")
        self.runtime.restart_helper()
        return self.helper()
