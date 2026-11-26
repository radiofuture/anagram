"""Linux: a systemd user unit `~/.config/systemd/user/anagram.service`.

`Restart=on-failure`: start again after a crash or a non-zero exit (75).
Where there is no systemd user session, an XDG autostart file
`~/.config/autostart/anagram.desktop` starts the app at login; it has no
restart (the supervisor of the app is the only guard).
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Callable
from pathlib import Path

from anagram.shell.app.autostart.base import NAME, Autostart

UNIT = "anagram.service"


def _quote(arg: str) -> str:
    """One argument in the quoting of systemd and of desktop files."""
    if arg and all(c.isalnum() or c in "-_./:=@+," for c in arg):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$") + '"'


def exec_line(command: list[str]) -> str:
    return " ".join(_quote(a) for a in command)


def parse_exec(line: str) -> list[str]:
    return [a.replace("$$", "$") for a in shlex.split(line)]


def unit_text(command: list[str]) -> str:
    return (
        "[Unit]\n"
        f"Description={NAME}\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_line(command)}\n"
        "Restart=on-failure\n"
        "RestartSec=30\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def desktop_text(command: list[str]) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={NAME}\n"
        f"Exec={exec_line(command)}\n"
        "NoDisplay=true\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _read_key(path: Path, key: str) -> str | None:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return None
    for line in lines:
        if line.startswith(f"{key}="):
            return line[len(key) + 1 :]
    return None


class SystemdAutostart(Autostart):
    manager = "systemd"

    @property
    def path(self) -> Path:
        return self.root / ".config" / "systemd" / "user" / UNIT

    def _ctl(self, *args: str) -> list[str]:
        return ["systemctl", "--user", *args]

    def install(self, command: list[str], *, start: bool = True) -> None:
        _write(self.path, unit_text(command))
        self._must(self._ctl("daemon-reload"))
        self._must(self._ctl("enable", *(("--now",) if start else ()), UNIT))

    def uninstall(self, *, stop: bool = True) -> None:
        self.run(self._ctl("disable", *(("--now",) if stop else ()), UNIT))
        self.path.unlink(missing_ok=True)
        self.run(self._ctl("daemon-reload"))

    def installed(self) -> bool:
        return self.path.exists()

    def command(self) -> list[str] | None:
        line = _read_key(self.path, "ExecStart")
        return parse_exec(line) if line else None

    def start(self) -> None:
        self._must(self._ctl("start", UNIT))

    def restart(self) -> None:
        self._must(self._ctl("restart", UNIT))


class XdgAutostart(Autostart):
    manager = "xdg"

    def __init__(self, *, spawn: Callable[[list[str]], None] | None = None, **kw) -> None:
        super().__init__(**kw)
        self.spawn = spawn

    @property
    def path(self) -> Path:
        return self.root / ".config" / "autostart" / "anagram.desktop"

    def install(self, command: list[str], *, start: bool = True) -> None:
        _write(self.path, desktop_text(command))

    def uninstall(self, *, stop: bool = True) -> None:
        self.path.unlink(missing_ok=True)

    def installed(self) -> bool:
        return self.path.exists()

    def command(self) -> list[str] | None:
        line = _read_key(self.path, "Exec")
        return parse_exec(line) if line else None

    def start(self) -> None:
        command = self.command()
        if command is None:
            return
        if self.spawn is not None:
            self.spawn(command)
            return
        from anagram.shell.app.launcher import spawn_detached

        spawn_detached(command)

    def restart(self) -> None:
        self.start()  # the launcher stops the old app first


def has_user_systemd(run) -> bool:
    code, _ = run(["systemctl", "--user", "show-environment"])
    return code == 0
