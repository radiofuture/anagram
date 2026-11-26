"""macOS: a launchd agent `~/Library/LaunchAgents/org.radiofuture.anagram.plist`.

`RunAtLoad`: start at login. `KeepAlive {SuccessfulExit: false}`: start again
after a crash or a non-zero exit (75), not after a clean stop. No log paths:
the app writes its own log.
"""

from __future__ import annotations

import os
import plistlib
from pathlib import Path

from anagram.shell.app.autostart.base import LABEL, Autostart


def plist_bytes(command: list[str]) -> bytes:
    doc = {
        "KeepAlive": {"SuccessfulExit": False},
        "Label": LABEL,
        "ProcessType": "Background",
        "ProgramArguments": list(command),
        "RunAtLoad": True,
        "ThrottleInterval": 30,
    }
    return plistlib.dumps(doc, fmt=plistlib.FMT_XML, sort_keys=True)


class LaunchdAutostart(Autostart):
    manager = "launchd"

    def __init__(self, *, uid: int | None = None, **kw) -> None:
        super().__init__(**kw)
        self.uid = os.getuid() if uid is None else uid

    @property
    def path(self) -> Path:
        return self.root / "Library" / "LaunchAgents" / f"{LABEL}.plist"

    @property
    def domain(self) -> str:
        return f"gui/{self.uid}"

    @property
    def target(self) -> str:
        return f"{self.domain}/{LABEL}"

    def install(self, command: list[str], *, start: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(plist_bytes(command))
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.path)
        if not start:
            return  # launchd loads the file at the next login
        self.run(["launchctl", "bootout", self.target])  # an old agent; fails if none
        self._must(["launchctl", "bootstrap", self.domain, str(self.path)])

    def uninstall(self, *, stop: bool = True) -> None:
        if stop:
            self.run(["launchctl", "bootout", self.target])
        self.path.unlink(missing_ok=True)

    def installed(self) -> bool:
        return self.path.exists()

    def command(self) -> list[str] | None:
        try:
            doc = plistlib.loads(self.path.read_bytes())
        except (FileNotFoundError, plistlib.InvalidFileException, ValueError):
            return None
        args = doc.get("ProgramArguments")
        return list(args) if isinstance(args, list) else None

    def start(self) -> None:
        self._must(["launchctl", "kickstart", self.target])

    def restart(self) -> None:
        self._must(["launchctl", "kickstart", "-k", self.target])
