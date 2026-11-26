"""Start the app at login: the common part of the three systems.

Each system has one class:

- macOS: a launchd agent (`launchd.py`).
- Linux: a systemd user unit, or an XDG autostart file where there is no
  systemd user session (`systemd.py`).
- Windows: a task in the Task Scheduler, or the `Run` key of the user
  (`wintask.py`). Not checked on a real Windows computer yet.

A class writes its unit file under `root` (the home directory of the person;
tests give a temp directory) and runs the system tools through `run` (tests
give a fake). Nothing needs an administrator.

The service manager starts the app again after a crash or exit code 75. A
clean stop (exit code 0) is not started again.
"""

from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

LABEL = "org.radiofuture.anagram"
NAME = "Anagram"

# run(argv) -> (exit code, standard output)
Runner = Callable[[list[str]], tuple[int, str]]

# The test suite sets this to True: then each Autostart needs a fake `root`
# and a fake `run`, so no test writes a real unit or runs a real system tool.
REQUIRE_FAKES = False


def check_fakes(root, run) -> None:
    if REQUIRE_FAKES and (root is None or run is None):
        raise AssertionError("a test tried to use the real login service of this computer")


def system_run(argv: list[str]) -> tuple[int, str]:
    """Run a system tool with fixed arguments (no shell)."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed tool names and arguments
            argv, capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, type(exc).__name__
    return out.returncode, out.stdout


def service_command(home: str | Path) -> list[str]:
    """The command that runs the app for this data directory."""
    home = str(Path(home).expanduser().resolve())
    if getattr(sys, "frozen", False):  # the packaged app
        return [sys.executable, "--home", home, "app", "run"]
    return [sys.executable, "-m", "anagram", "--home", home, "app", "run"]


class AutostartError(RuntimeError):
    """A system tool refused a change."""


class Autostart(ABC):
    manager: str = "none"  # "launchd" | "systemd" | "xdg" | "task" | "run-key" | "none"

    def __init__(self, *, root: Path | None = None, run: Runner | None = None) -> None:
        check_fakes(root, run)
        self.root = Path(root) if root is not None else Path.home()
        self.run = run or system_run

    @abstractmethod
    def install(self, command: list[str], *, start: bool = True) -> None:
        """Write the unit and turn it on. A second install replaces the first.
        `start=False`: only for the next login; the running app is not touched
        (the switch in the UI runs inside the app that the unit starts)."""

    @abstractmethod
    def uninstall(self, *, stop: bool = True) -> None:
        """Turn the unit off and remove it. No error if it is not installed.
        `stop=False`: the running app continues; only the next login changes."""

    @abstractmethod
    def installed(self) -> bool: ...

    @abstractmethod
    def command(self) -> list[str] | None:
        """The command of the installed unit, or None."""

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def restart(self) -> None: ...

    def _must(self, argv: list[str]) -> str:
        code, out = self.run(argv)
        if code != 0:
            raise AutostartError(f"{argv[0]} failed with exit code {code}")
        return out


class NoAutostart(Autostart):
    """A system with no supported service manager."""

    manager = "none"

    def install(self, command: list[str], *, start: bool = True) -> None:
        raise AutostartError("this system has no supported way to start Anagram at login")

    def uninstall(self, *, stop: bool = True) -> None:
        return None

    def installed(self) -> bool:
        return False

    def command(self) -> list[str] | None:
        return None

    def start(self) -> None:
        raise AutostartError("no login service")

    def restart(self) -> None:
        raise AutostartError("no login service")
