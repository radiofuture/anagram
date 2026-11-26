"""The URL scheme `anagram://`.

Links:

- `anagram://open`: open the app.
- `anagram://join/<fragment>`: open the app with an invite. `<fragment>` is
  the text after `#` of a join link (a node invite or a lab invite,
  integration 1.5). The app only stores it as pending; the person confirms
  the join on the screen.

The operating system starts `<app> open-url <link>` (`launcher.open_url`).
The registration is for this user only and needs no administrator:

- macOS: `CFBundleURLTypes` in the `Info.plist` of `Anagram.app`. Launch
  Services reads it when the bundle is on the disk; `register` asks it to read
  the bundle again (`lsregister -f`).
- Linux: `x-scheme-handler/anagram` in
  `~/.local/share/applications/anagram.desktop`, made the default with
  `xdg-mime`.
- Windows: `HKCU\\Software\\Classes\\anagram` with
  `shell\\open\\command` = `"<exe>" ... open-url "%1"`, written with `reg.exe`.
  Not checked on a real Windows computer yet.

As in `autostart`, a class writes under `root` and runs system tools through
`run`; the test suite gives fakes for both (`autostart.base.REQUIRE_FAKES`).
"""

from __future__ import annotations

import os
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from anagram.shell.app.autostart.base import NAME, AutostartError, Runner, check_fakes, system_run
from anagram.shell.app.autostart.systemd import exec_line, parse_exec

SCHEME = "anagram"
PREFIX = f"{SCHEME}://"
OPEN_URL = f"{PREFIX}open"
JOIN_PREFIX = f"{PREFIX}join/"
MAX_URL = 8192
MIME = f"x-scheme-handler/{SCHEME}"
DESKTOP_FILE = "anagram.desktop"
WIN_KEY = rf"HKCU\Software\Classes\{SCHEME}"
LSREGISTER = (
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
    "LaunchServices.framework/Support/lsregister"
)


def handler_command(home: str | Path | None = None) -> list[str]:
    """The command that the system runs for a link, without the link. With
    `home`, the command names this data directory."""
    if getattr(sys, "frozen", False):  # the packaged app
        base = [sys.executable]
    else:
        base = [sys.executable, "-m", "anagram"]
    if home is not None:
        base += ["--home", str(Path(home).expanduser().resolve())]
    return [*base, "open-url"]


class UrlScheme(ABC):
    manager: str = "none"  # "launch-services" | "xdg" | "registry" | "none"

    def __init__(self, *, root: Path | None = None, run: Runner | None = None) -> None:
        check_fakes(root, run)
        self.root = Path(root) if root is not None else Path.home()
        self.run = run or system_run

    @abstractmethod
    def register(self, command: list[str]) -> None:
        """Make `command` (plus the link) the handler of `anagram://`."""

    @abstractmethod
    def unregister(self) -> None:
        """Remove the handler. No error if there is none."""

    @abstractmethod
    def command(self) -> list[str] | None:
        """The command of the handler of this user, or None."""

    def _must(self, argv: list[str]) -> str:
        code, out = self.run(argv)
        if code != 0:
            raise AutostartError(f"{Path(argv[0]).name} failed with exit code {code}")
        return out


# --------------------------------------------------------------------- macOS


def bundle_of(executable: str | Path) -> Path | None:
    """`.../Anagram.app` for `.../Anagram.app/Contents/MacOS/<exe>`, else None."""
    p = Path(executable)
    if len(p.parents) >= 3 and p.parent.name == "MacOS" and p.parents[1].name == "Contents":
        app = p.parents[2]
        if app.suffix == ".app":
            return app
    return None


class LaunchServicesScheme(UrlScheme):
    """macOS. The scheme is in the `Info.plist` of the bundle; this class only
    asks Launch Services to read the bundle again, or to forget it."""

    manager = "launch-services"

    def __init__(self, *, bundle: Path | None = None, **kw) -> None:
        super().__init__(**kw)
        self.bundle = bundle if bundle is not None else bundle_of(sys.executable)

    def _need_bundle(self) -> Path:
        if self.bundle is None:
            raise AutostartError("the anagram:// links need the packaged Anagram.app")
        return self.bundle

    def register(self, command: list[str]) -> None:
        self._must([LSREGISTER, "-f", str(self._need_bundle())])

    def unregister(self) -> None:
        if self.bundle is not None:
            self.run([LSREGISTER, "-u", str(self.bundle)])

    def command(self) -> list[str] | None:
        if self.bundle is None:
            return None
        return [str(self.bundle / "Contents" / "MacOS" / NAME), "open-url"]


# --------------------------------------------------------------------- Linux


def desktop_text(command: list[str]) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={NAME}\n"
        f"Exec={exec_line(command)} %u\n"
        "NoDisplay=true\n"
        "Terminal=false\n"
        f"MimeType={MIME};\n"
    )


class XdgScheme(UrlScheme):
    manager = "xdg"

    @property
    def path(self) -> Path:
        return self.root / ".local" / "share" / "applications" / DESKTOP_FILE

    def register(self, command: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(desktop_text(command))
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.path)
        self._must(["xdg-mime", "default", DESKTOP_FILE, MIME])
        self.run(["update-desktop-database", str(self.path.parent)])  # optional tool

    def unregister(self) -> None:
        if self.path.exists():
            self.path.unlink()
            self.run(["update-desktop-database", str(self.path.parent)])

    def command(self) -> list[str] | None:
        try:
            lines = self.path.read_text().splitlines()
        except FileNotFoundError:
            return None
        for line in lines:
            if line.startswith("Exec="):
                argv = parse_exec(line[len("Exec=") :])
                return argv[:-1] if argv and argv[-1] == "%u" else argv
        return None


# ------------------------------------------------------------------- Windows


def win_command_line(command: list[str]) -> str:
    """`"<exe>" <args> "%1"`: the value of `shell\\open\\command`."""
    return subprocess.list2cmdline(command) + ' "%1"'


class RegistryScheme(UrlScheme):
    manager = "registry"

    def register(self, command: list[str]) -> None:
        self._must(["reg", "add", WIN_KEY, "/ve", "/d", f"URL:{NAME}", "/f"])
        self._must(["reg", "add", WIN_KEY, "/v", "URL Protocol", "/d", "", "/f"])
        self._must(
            ["reg", "add", rf"{WIN_KEY}\shell\open\command", "/ve", "/d",
             win_command_line(command), "/f"]
        )  # fmt: skip

    def unregister(self) -> None:
        self.run(["reg", "delete", WIN_KEY, "/f"])

    def command(self) -> list[str] | None:
        code, out = self.run(["reg", "query", rf"{WIN_KEY}\shell\open\command", "/ve"])
        if code != 0:
            return None
        for line in out.splitlines():
            if "REG_SZ" in line:
                value = line.split("REG_SZ", 1)[1].strip()
                if value.endswith(' "%1"'):
                    value = value[: -len(' "%1"')]
                return _split_windows(value)
        return None


def _split_windows(text: str) -> list[str]:
    """The reverse of `subprocess.list2cmdline` for the simple cases of this
    module (quoted paths, plain words)."""
    out, cur, quoted, have = [], [], False, False
    for ch in text:
        if ch == '"':
            quoted, have = not quoted, True
        elif ch == " " and not quoted:
            if cur or have:
                out.append("".join(cur))
            cur, have = [], False
        else:
            cur.append(ch)
    if cur or have:
        out.append("".join(cur))
    return out


class NoScheme(UrlScheme):
    manager = "none"

    def register(self, command: list[str]) -> None:
        raise AutostartError("this system has no supported way to open anagram:// links")

    def unregister(self) -> None:
        return None

    def command(self) -> list[str] | None:
        return None


def scheme_for_platform(
    *, root: Path | None = None, run: Runner | None = None, platform: str | None = None
) -> UrlScheme:
    """The URL scheme class of this system. `root` and `run` are for tests."""
    check_fakes(root, run)
    platform = platform or sys.platform
    if platform == "darwin":
        return LaunchServicesScheme(root=root, run=run)
    if platform.startswith("linux"):
        return XdgScheme(root=root, run=run)
    if platform == "win32":
        return RegistryScheme(root=root, run=run)
    return NoScheme(root=root, run=run)
