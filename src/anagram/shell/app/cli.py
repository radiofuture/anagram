"""The commands of the app.

    anagram app run [--port N] [--no-embed]   run the app in this terminal (the login
                                              service runs the same command)
    anagram app stop                          stop the running app
    anagram app install | uninstall           start the app at login, or not
    anagram app status                        running, start at login, where the keys are
    anagram app selftest                      checks for a packaged build (no network,
                                              no keychain)
    anagram open [--route NAME]               open the app in the browser; start it if
                                              necessary
    anagram open-url LINK                     an anagram:// link (the operating system
                                              runs this command)

`anagram open GRANT --out DIR` (a grant) is in `anagram.shell.cli.grants`; with no GRANT
it calls `cmd_open_app`. `anagram.shell.cli.main` calls `register(sub)` one time. For the
app commands, `anagram.shell.cli.main.main` sets the keystore policy `auto` (the keychain
of the operating system where there is one).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from anagram.shell.app.control import ROUTES


def cmd_app_run(args) -> int:  # pragma: no cover - runs until stopped
    from anagram.shell.app.runtime import AlreadyRunning, AppRuntime

    runtime = AppRuntime(args.home, port=args.port or None, embed=not args.no_embed)
    runtime.handle_signals()  # before the server answers (AppRuntime.handle_signals)
    try:
        runtime.start()
    except AlreadyRunning as exc:
        # Exit code 0: the login service must not start this command again
        # and again while the other app runs.
        print(f"anagram: {exc}", file=sys.stderr)
        return 0
    print("Anagram is running on this computer only. Press Ctrl+C to stop.")
    return runtime.run_forever()


def cmd_app_stop(args) -> int:
    from anagram.shell.app.launcher import stop_app

    if stop_app(args.home):
        print("Anagram stops.")
    else:
        print("Anagram does not run.")
    return 0


def _wait_stopped(home, timeout: float = 20.0) -> bool:
    from anagram.shell.app.launcher import live_runtime

    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if live_runtime(home) is None:
            return True
        time.sleep(0.2)
    return False


def cmd_app_install(args, autostart=None, scheme=None) -> int:
    """Start the app at login, and open `anagram://` links with it. An app
    that runs now stops first; the login service then starts it."""
    from anagram.shell.app import urlscheme
    from anagram.shell.app.autostart import AutostartError, autostart_for_platform, service_command
    from anagram.shell.app.launcher import stop_app

    service = autostart or autostart_for_platform()
    links = scheme or urlscheme.scheme_for_platform()
    if stop_app(args.home) and not _wait_stopped(args.home):
        print("anagram: the running app did not stop.", file=sys.stderr)
        return 1
    service.install(service_command(args.home))
    print(f"Anagram starts at login ({service.manager}).")
    try:
        links.register(urlscheme.handler_command(args.home))
        print("Invite links open Anagram.")
    except AutostartError as exc:
        print(f"Invite links do not open Anagram on this computer: {exc}.")
    return 0


def cmd_app_uninstall(args, autostart=None, scheme=None) -> int:
    """Do not start the app at login any more, do not open `anagram://`
    links with it, and stop it."""
    from anagram.shell.app import urlscheme
    from anagram.shell.app.autostart import autostart_for_platform
    from anagram.shell.app.launcher import stop_app

    service = autostart or autostart_for_platform()
    service.uninstall()
    (scheme or urlscheme.scheme_for_platform()).unregister()
    stop_app(args.home)
    print("Anagram does not start at login any more. Your data and keys stay.")
    return 0


def cmd_app_status(args, autostart=None) -> int:
    from anagram.identity.api import describe
    from anagram.shell.app.autostart import autostart_for_platform, service_command
    from anagram.shell.app.launcher import live_runtime

    service = autostart or autostart_for_platform()
    have = service.command()
    doc = live_runtime(args.home)
    keys = describe(args.home)
    if have is None:
        login = "off"
    elif have == service_command(args.home):
        login = f"on ({service.manager})"
    else:
        login = f"on ({service.manager}), for another program or data directory"
    print(f"Running: {'yes, version ' + doc['version'] if doc else 'no'}")
    print(f"Start at login: {login}")
    where = "the keychain of this computer" if keys["protected"] else "files on this computer"
    print(f"Keys: {where}")
    return 0


def cmd_open_app(args) -> int:
    from anagram.shell.app.launcher import LaunchError, open_app

    os.environ.setdefault("ANAGRAM_KEYSTORE", "auto")  # for an app that this command starts
    try:
        url = open_app(args.home, route=getattr(args, "route", None))
    except LaunchError as exc:
        print(f"anagram: {exc}", file=sys.stderr)
        return 1
    print("Anagram is open in your browser.")
    print(f"If it did not open, use this link one time in the next minute: {url}")
    return 0


def cmd_app_selftest(args) -> int:
    from anagram.shell.app.selftest import run

    return run()


def cmd_open_url(args) -> int:
    """`anagram open-url <link>`: the operating system runs this command
    when a person selects an `anagram://` link. The link goes to
    `launcher.open_url`, which accepts one `anagram://` argument only."""
    from anagram.shell.app.launcher import LaunchError, open_url

    try:
        open_url(args.home, list(args.link))
    except LaunchError as exc:
        print(f"anagram: {exc}", file=sys.stderr)
        return 1
    return 0


def register_open_options(p) -> None:
    """The app options of `anagram open` (the parser is in anagram.shell.cli.grants)."""
    p.add_argument("--route", choices=sorted(ROUTES), help="the screen to open (app)")


def register(sub) -> None:
    """Add the app commands to the command parser of `anagram.shell.cli.main`."""
    p = sub.add_parser("app", help="the Anagram app (local UI, index helper, login service)")
    p.set_defaults(app_entry=True)  # anagram.shell.cli.main.main sets the keystore policy `auto`
    asub = p.add_subparsers(dest="app_command", required=True)
    s = asub.add_parser("run", help="run the app (the login service runs this command)")
    s.add_argument("--port", type=int, default=0, help="loopback port (default: the last port)")
    s.add_argument("--no-embed", action="store_true", help="do not load the embedding model")
    s.set_defaults(func=cmd_app_run)
    s = asub.add_parser("stop", help="stop the running app")
    s.set_defaults(func=cmd_app_stop)
    s = asub.add_parser("install", help="start the app at login")
    s.set_defaults(func=cmd_app_install)
    s = asub.add_parser("uninstall", help="do not start the app at login; stop it")
    s.set_defaults(func=cmd_app_uninstall)
    s = asub.add_parser("status", help="is the app running, and does it start at login")
    s.set_defaults(func=cmd_app_status)
    s = asub.add_parser("selftest", help="checks for a packaged build (no network, no keychain)")
    s.set_defaults(func=cmd_app_selftest)
    p = sub.add_parser("open-url", help="open an anagram:// link (the operating system runs this)")
    # All the words after `open-url` are data, also words that look like
    # options: `open_url` accepts exactly one `anagram://` word.
    p.add_argument("link", nargs=argparse.REMAINDER, help="the anagram:// link")
    p.set_defaults(func=cmd_open_url, app_entry=True)
