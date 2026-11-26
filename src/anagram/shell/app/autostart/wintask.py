"""Windows: the task `Anagram` in the Task Scheduler, made from XML.

Logon trigger for this user, restart on failure 3 times at 1 minute, no time
limit, hidden. If the task cannot be made without an administrator, the
value `Anagram` in `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` starts
the app at login (no restart; the supervisor of the app is the only guard).

Not checked on a real Windows computer yet.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from anagram.shell.app.autostart.base import NAME, Autostart, AutostartError

RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def task_xml(command: list[str], user: str) -> str:
    program, args = command[0], subprocess.list2cmdline(command[1:])
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        f'<Task version="1.2" xmlns="{TASK_NS}">\n'
        "  <RegistrationInfo>\n"
        f"    <Description>{NAME}</Description>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <LogonTrigger>\n"
        "      <Enabled>true</Enabled>\n"
        f"      <UserId>{escape(user)}</UserId>\n"
        "    </LogonTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        '    <Principal id="Author">\n'
        f"      <UserId>{escape(user)}</UserId>\n"
        "      <LogonType>InteractiveToken</LogonType>\n"
        "      <RunLevel>LeastPrivilege</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "    <Hidden>true</Hidden>\n"
        "    <RestartOnFailure>\n"
        "      <Interval>PT1M</Interval>\n"
        "      <Count>3</Count>\n"
        "    </RestartOnFailure>\n"
        "  </Settings>\n"
        '  <Actions Context="Author">\n'
        "    <Exec>\n"
        f"      <Command>{escape(program)}</Command>\n"
        f"      <Arguments>{escape(args)}</Arguments>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def _split(line: str) -> list[str]:
    """Split a Windows command line (the inverse of list2cmdline for the
    arguments that `service_command` gives)."""
    out, cur, quoted, any_ = [], [], False, False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\":
            n = 0
            while i < len(line) and line[i] == "\\":
                n += 1
                i += 1
            if i < len(line) and line[i] == '"':
                cur.append("\\" * (n // 2))
                if n % 2:
                    cur.append('"')
                    i += 1
                continue
            cur.append("\\" * n)
            continue
        if c == '"':
            quoted, any_ = not quoted, True
        elif c in " \t" and not quoted:
            if cur or any_:
                out.append("".join(cur))
            cur, any_ = [], False
        else:
            cur.append(c)
        i += 1
    if cur or any_:
        out.append("".join(cur))
    return out


class TaskAutostart(Autostart):
    manager = "task"

    def __init__(self, *, user: str | None = None, **kw) -> None:
        super().__init__(**kw)
        domain, name = os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")
        self.user = user or (f"{domain}\\{name}" if domain else name)

    def install(self, command: list[str], *, start: bool = True) -> None:
        # A logon task or a Run key does not start the app now in either case.
        fd, tmp = tempfile.mkstemp(suffix=".xml")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(task_xml(command, self.user).encode("utf-16"))
            code, _ = self.run(["schtasks", "/Create", "/TN", NAME, "/XML", tmp, "/F"])
        finally:
            Path(tmp).unlink(missing_ok=True)
        if code == 0:
            self.run(["reg", "delete", RUN_KEY, "/v", NAME, "/f"])
            self.manager = "task"
            return
        line = subprocess.list2cmdline(command)
        self._must(["reg", "add", RUN_KEY, "/v", NAME, "/t", "REG_SZ", "/d", line, "/f"])
        self.manager = "run-key"

    def uninstall(self, *, stop: bool = True) -> None:
        # Delete does not end a running task; the app stops by /control/stop.
        self.run(["schtasks", "/Delete", "/TN", NAME, "/F"])
        self.run(["reg", "delete", RUN_KEY, "/v", NAME, "/f"])

    def _task_command(self) -> list[str] | None:
        code, out = self.run(["schtasks", "/Query", "/TN", NAME, "/XML"])
        if code != 0 or not out.strip():
            return None
        try:
            # The output of schtasks for our own task (no entities, no DTD).
            root = ET.fromstring(out.strip().split("?>", 1)[-1])  # noqa: S314
        except ET.ParseError:
            return None
        ns = {"t": TASK_NS}
        program = root.findtext("t:Actions/t:Exec/t:Command", namespaces=ns)
        args = root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns) or ""
        return [program, *_split(args)] if program else None

    def _run_key_command(self) -> list[str] | None:
        code, out = self.run(["reg", "query", RUN_KEY, "/v", NAME])
        if code != 0:
            return None
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[0] == NAME and parts[1] == "REG_SZ":
                return _split(parts[2])
        return None

    def command(self) -> list[str] | None:
        found = self._task_command()
        if found is not None:
            self.manager = "task"
            return found
        found = self._run_key_command()
        if found is not None:
            self.manager = "run-key"
        return found

    def installed(self) -> bool:
        return self.command() is not None

    def start(self) -> None:
        if self.command() is None:
            raise AutostartError("no login service")
        if self.manager == "task":
            self._must(["schtasks", "/Run", "/TN", NAME])
            return
        from anagram.shell.app.launcher import spawn_detached

        spawn_detached(self.command())

    def restart(self) -> None:
        if self.command() is not None and self.manager == "task":
            self.run(["schtasks", "/End", "/TN", NAME])
        self.start()


__all__ = ["AutostartError", "TaskAutostart", "task_xml"]
