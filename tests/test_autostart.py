"""The login service of each system. The unit files go
to a temp directory and the system tools are a fake runner: no test installs
a real launchd agent, systemd unit, or task. Golden files are in
tests/fixtures/autostart/ (`ANAGRAM_UPDATE_GOLDEN=1` writes them again)."""

from __future__ import annotations

import os
import plistlib
import sys
from pathlib import Path

import pytest

from anagram.shell.app import autostart, launcher
from anagram.shell.app.autostart import (
    AutostartError,
    LaunchdAutostart,
    NoAutostart,
    SystemdAutostart,
    TaskAutostart,
    XdgAutostart,
    autostart_for_platform,
    service_command,
)
from anagram.shell.app.autostart.launchd import plist_bytes
from anagram.shell.app.autostart.systemd import desktop_text, parse_exec, unit_text
from anagram.shell.app.autostart.wintask import _split, task_xml
from anagram.shell.app.cli import cmd_app_install, cmd_app_status, cmd_app_uninstall
from anagram.shell.app.urlscheme import XdgScheme, handler_command

GOLDEN = Path(__file__).parent / "fixtures" / "autostart"
COMMAND = ["/Applications/Anagram.app/Contents/MacOS/Anagram", "--home", "/Users/mei/.anagram",
           "app", "run"]  # fmt: skip
SPACED = ["/opt/My Apps/python3", "-m", "anagram", "--home", '/home/mei/my "data" $HOME',
          "app", "run"]  # fmt: skip
WIN = [r"C:\Users\Mei Chen\AppData\Local\Anagram\Anagram.exe", "--home",
       r"C:\Users\Mei Chen\.anagram", "app", "run"]  # fmt: skip


class FakeRun:
    """The system tools: records each call; answers from `codes` (by the
    first two words) and `outputs`."""

    def __init__(self, codes=None, outputs=None):
        self.calls: list[list[str]] = []
        self.codes = codes or {}
        self.outputs = outputs or {}

    def __call__(self, argv):
        self.calls.append(list(argv))
        key = " ".join(argv[:2])
        return self.codes.get(key, 0), self.outputs.get(key, "")


def golden(name: str, data: bytes) -> None:
    path = GOLDEN / name
    if os.environ.get("ANAGRAM_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    assert data == path.read_bytes(), f"{name} differs from the golden file"


# --------------------------------------------------------------- golden files


def test_launchd_plist_golden():
    data = plist_bytes(COMMAND)
    golden("org.radiofuture.anagram.plist", data)
    doc = plistlib.loads(data)
    assert doc["RunAtLoad"] is True and doc["KeepAlive"] == {"SuccessfulExit": False}
    assert doc["ThrottleInterval"] == 30 and doc["ProcessType"] == "Background"
    assert "StandardOutPath" not in doc and "StandardErrorPath" not in doc


def test_systemd_unit_golden():
    text = unit_text(COMMAND)
    golden("anagram.service", text.encode())
    assert "Restart=on-failure\n" in text and "RestartSec=30\n" in text
    assert "WantedBy=default.target\n" in text


def test_xdg_desktop_golden():
    golden("anagram.desktop", desktop_text(COMMAND).encode())


def test_task_xml_golden():
    text = task_xml(WIN, r"LAB\mei")
    golden("anagram-task.xml", text.encode())
    for part in ("<LogonTrigger>", "<UserId>LAB\\mei</UserId>", "<Count>3</Count>",
                 "<Interval>PT1M</Interval>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
                 "<Hidden>true</Hidden>", "<RunLevel>LeastPrivilege</RunLevel>"):  # fmt: skip
        assert part in text


def test_commands_with_spaces_and_quotes_read_back():
    for cmd in (COMMAND, SPACED):
        assert parse_exec(unit_text(cmd).split("ExecStart=")[1].split("\n")[0]) == cmd
    assert "$$HOME" in unit_text(SPACED)  # systemd does not expand it
    import subprocess

    assert _split(subprocess.list2cmdline(WIN[1:])) == WIN[1:]


# ------------------------------------------------------------- launchd (macOS)


def test_launchd_install_and_commands(tmp_path):
    run = FakeRun()
    a = LaunchdAutostart(root=tmp_path, run=run, uid=501)
    assert not a.installed() and a.command() is None
    a.install(COMMAND)
    path = tmp_path / "Library" / "LaunchAgents" / "org.radiofuture.anagram.plist"
    assert a.installed() and path.read_bytes() == plist_bytes(COMMAND)
    assert path.stat().st_mode & 0o777 == 0o644
    assert a.command() == COMMAND
    assert run.calls == [
        ["launchctl", "bootout", "gui/501/org.radiofuture.anagram"],
        ["launchctl", "bootstrap", "gui/501", str(path)],
    ]
    run.calls.clear()
    a.start()
    a.restart()
    assert run.calls == [
        ["launchctl", "kickstart", "gui/501/org.radiofuture.anagram"],
        ["launchctl", "kickstart", "-k", "gui/501/org.radiofuture.anagram"],
    ]
    run.calls.clear()
    a.uninstall()
    assert not path.exists()
    assert run.calls == [["launchctl", "bootout", "gui/501/org.radiofuture.anagram"]]
    a.uninstall()  # no error when it is not installed


def test_launchd_refused_bootstrap_is_an_error(tmp_path):
    a = LaunchdAutostart(root=tmp_path, run=FakeRun({"launchctl bootstrap": 5}), uid=501)
    with pytest.raises(AutostartError):
        a.install(COMMAND)


# ------------------------------------------------------------- systemd (Linux)


def test_systemd_install_and_commands(tmp_path):
    run = FakeRun()
    a = SystemdAutostart(root=tmp_path, run=run)
    a.install(SPACED)
    path = tmp_path / ".config" / "systemd" / "user" / "anagram.service"
    assert path.read_text() == unit_text(SPACED) and a.command() == SPACED
    assert run.calls == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", "anagram.service"],
    ]
    run.calls.clear()
    a.start()
    a.restart()
    a.uninstall()
    assert run.calls == [
        ["systemctl", "--user", "start", "anagram.service"],
        ["systemctl", "--user", "restart", "anagram.service"],
        ["systemctl", "--user", "disable", "--now", "anagram.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]
    assert not path.exists()


def test_linux_without_systemd_user_session_uses_xdg(tmp_path):
    run = FakeRun({"systemctl --user": 1})
    a = autostart_for_platform(root=tmp_path, run=run, platform="linux")
    assert isinstance(a, XdgAutostart) and a.manager == "xdg"
    spawned = []
    a.spawn = spawned.append
    a.install(COMMAND)
    assert (tmp_path / ".config" / "autostart" / "anagram.desktop").read_text() == desktop_text(
        COMMAND
    )
    a.start()
    assert spawned == [COMMAND] and a.command() == COMMAND
    a.uninstall()
    assert not a.installed()
    assert isinstance(
        autostart_for_platform(root=tmp_path, run=FakeRun(), platform="linux"), SystemdAutostart
    )


# -------------------------------------------------------------- task (Windows)


def test_task_install_from_xml(tmp_path):
    seen = {}

    def run(argv):
        if argv[:2] == ["schtasks", "/Create"]:
            seen["xml"] = Path(argv[argv.index("/XML") + 1]).read_bytes().decode("utf-16")
        return FakeRun()(argv)

    a = TaskAutostart(root=tmp_path, run=run, user=r"LAB\mei")
    a.install(WIN)
    assert seen["xml"] == task_xml(WIN, r"LAB\mei") and a.manager == "task"


def test_task_reads_back_and_starts(tmp_path):
    xml = task_xml(WIN, r"LAB\mei").replace('encoding="UTF-16"', "")
    run = FakeRun(outputs={"schtasks /Query": xml})
    a = TaskAutostart(root=tmp_path, run=run, user=r"LAB\mei")
    assert a.installed() and a.command() == WIN
    run.calls.clear()
    a.restart()
    assert ["schtasks", "/End", "/TN", "Anagram"] in run.calls
    assert run.calls[-1] == ["schtasks", "/Run", "/TN", "Anagram"]


def test_task_falls_back_to_the_run_key(tmp_path):
    import subprocess

    line = subprocess.list2cmdline(WIN)
    run = FakeRun(
        codes={"schtasks /Create": 1, "schtasks /Query": 1},
        outputs={"reg query": f"\r\n    Anagram    REG_SZ    {line}\r\n"},
    )
    a = TaskAutostart(root=tmp_path, run=run, user="mei")
    a.install(WIN)
    assert a.manager == "run-key"
    add = next(c for c in run.calls if c[:2] == ["reg", "add"])
    assert add[add.index("/d") + 1] == line
    assert a.command() == WIN and a.manager == "run-key"
    a.uninstall()
    assert ["schtasks", "/Delete", "/TN", "Anagram", "/F"] in run.calls


def test_other_system_has_no_login_service(tmp_path):
    a = autostart_for_platform(root=tmp_path, run=FakeRun(), platform="sunos5")
    assert isinstance(a, NoAutostart) and not a.installed()
    with pytest.raises(AutostartError):
        a.install(COMMAND)


def test_suite_refuses_the_real_login_service():
    with pytest.raises(AssertionError, match="real login service"):
        autostart_for_platform()
    with pytest.raises(AssertionError, match="real login service"):
        LaunchdAutostart(run=FakeRun())


# ------------------------------------------------------------ launcher, CLI


class Args:
    def __init__(self, home):
        self.home = str(home)


def test_service_command_is_this_interpreter(tmp_path):
    assert service_command(tmp_path) == [
        sys.executable, "-m", "anagram", "--home", str(tmp_path.resolve()), "app", "run",
    ]  # fmt: skip


def test_default_start_uses_the_login_service(tmp_path, monkeypatch):
    spawned = []
    monkeypatch.setattr(launcher, "spawn_detached", spawned.append)
    home = tmp_path / "home"
    run = FakeRun()
    a = LaunchdAutostart(root=tmp_path, run=run, uid=501)

    # Not installed, not a packaged app: a detached process, no unit.
    launcher.default_start(home, a)
    assert spawned == [service_command(home)] and not a.installed()

    # Installed for this home: the service manager starts it.
    a.install(service_command(home))
    run.calls.clear()
    launcher.default_start(home, a)
    assert run.calls == [["launchctl", "kickstart", "gui/501/org.radiofuture.anagram"]]

    # The program moved: the unit is written again (bootstrap starts it).
    old = ["/old/place/python", *service_command(home)[1:]]
    a.install(old)
    launcher.default_start(home, a)
    assert a.command() == service_command(home) and len(spawned) == 1

    # A unit for another data directory: not touched; a detached process.
    launcher.default_start(tmp_path / "other", a)
    assert a.command() == service_command(home) and len(spawned) == 2


def test_packaged_app_installs_on_first_open(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher.sys, "frozen", True, raising=False)
    monkeypatch.setattr(launcher, "spawn_detached", lambda c: pytest.fail("no spawn"))
    a = LaunchdAutostart(root=tmp_path, run=FakeRun(), uid=501)
    links = XdgScheme(root=tmp_path, run=FakeRun())
    launcher.default_start(tmp_path / "home", a, links)
    assert a.command() == service_command(tmp_path / "home")
    assert links.command() == handler_command()  # anagram:// links open the app


def test_install_uninstall_status_commands(tmp_path, capsys):
    home = tmp_path / "home"
    a = SystemdAutostart(root=tmp_path, run=FakeRun())
    assert cmd_app_status(Args(home), a) == 0
    out = capsys.readouterr().out
    assert "Running: no" in out and "Start at login: off" in out
    assert "Keys: files on this computer" in out
    links = XdgScheme(root=tmp_path, run=FakeRun())
    assert cmd_app_install(Args(home), a, links) == 0
    assert a.command() == service_command(home)
    assert links.command() == handler_command(home)
    cmd_app_status(Args(home), a)
    assert "Start at login: on (systemd)" in capsys.readouterr().out
    assert cmd_app_uninstall(Args(home), a, links) == 0 and not a.installed()
    assert links.command() is None
    assert str(tmp_path) not in capsys.readouterr().out


def test_autostart_module_names():
    assert autostart.LABEL == "org.radiofuture.anagram"


def test_systemd_rejects_newlines_and_escapes_percent():
    for bad in ("/a\nExecStart=/evil", "/a\r/b", "/a\x00b"):
        with pytest.raises(ValueError, match="newline or NUL"):
            unit_text([bad])
    cmd = ["/opt/100% app/anagram", "--home", "/home/user/%u/data", "app", "run"]
    unit = unit_text(cmd)
    assert "100%%" in unit and "%%u" in unit
    assert parse_exec(unit.split("ExecStart=")[1].split("\n")[0]) == cmd
    desk = desktop_text(cmd)
    assert "100%%" in desk and "%%u" in desk
    assert parse_exec(desk.split("Exec=")[1].split("\n")[0]) == cmd


def test_pid_alive_rejects_non_positive():
    assert launcher._pid_alive(0) is False
    assert launcher._pid_alive(-1) is False
