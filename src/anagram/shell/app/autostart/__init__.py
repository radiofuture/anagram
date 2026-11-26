"""Start the app at login. See `base.py`."""

from __future__ import annotations

import sys
from pathlib import Path

from anagram.shell.app.autostart.base import (
    LABEL,
    Autostart,
    AutostartError,
    NoAutostart,
    Runner,
    check_fakes,
    service_command,
    system_run,
)
from anagram.shell.app.autostart.launchd import LaunchdAutostart
from anagram.shell.app.autostart.systemd import SystemdAutostart, XdgAutostart, has_user_systemd
from anagram.shell.app.autostart.wintask import TaskAutostart


def autostart_for_platform(
    *, root: Path | None = None, run: Runner | None = None, platform: str | None = None
) -> Autostart:
    """The login service class of this system. `root` (the home directory of
    the person) and `run` (the system tools) are for tests."""
    check_fakes(root, run)
    platform = platform or sys.platform
    run = run or system_run
    if platform == "darwin":
        return LaunchdAutostart(root=root, run=run)
    if platform.startswith("linux"):
        if has_user_systemd(run):
            return SystemdAutostart(root=root, run=run)
        return XdgAutostart(root=root, run=run)
    if platform == "win32":
        return TaskAutostart(root=root, run=run)
    return NoAutostart(root=root, run=run)


__all__ = [
    "LABEL",
    "Autostart",
    "AutostartError",
    "LaunchdAutostart",
    "NoAutostart",
    "SystemdAutostart",
    "TaskAutostart",
    "XdgAutostart",
    "autostart_for_platform",
    "service_command",
]
