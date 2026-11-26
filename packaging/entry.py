"""The program of the packaged app.

- No argument (the person opens Anagram from the app list): `anagram open`.
- One `anagram://` argument (macOS gives a link click as an argument with
  the `argv_emulation` of PyInstaller): `anagram open-url <link>`.
- Else: the arguments of the `anagram` command (the login service runs
  `<program> --home <dir> app run`).

macOS can add a `-psn_...` argument when Finder starts the app; it is
removed.
"""

from __future__ import annotations

import multiprocessing
import sys

from anagram.shell.app.urlscheme import PREFIX


def arguments(argv: list[str]) -> list[str]:
    argv = [a for a in argv if not a.startswith("-psn_")]
    if not argv:
        return ["open"]
    if len(argv) == 1 and argv[0].startswith(PREFIX):
        return ["open-url", argv[0]]
    return argv


def run() -> int:
    from anagram.shell.cli.main import main

    return main(arguments(sys.argv[1:]))


if __name__ == "__main__":
    multiprocessing.freeze_support()  # a frozen child process must not run the app again
    sys.exit(run())
