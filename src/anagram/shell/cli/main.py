"""`anagram` command line.

    anagram                                 open the local web UI (same as `anagram ui`)
    anagram ui [--port N] [--no-browser]
    anagram app run|install|uninstall|status  the app: local UI, index helper, login service
    anagram demo up [--dir DIR] [--everyone] [--ready] [--day-seconds N] | anagram demo down [--dir DIR]
    anagram init [--node-url URL --log-key VKEY ...]
    anagram commit PATH... [--claim TEXT] [--supersedes ROOT] [--builds-on ROOT] [--includes ROOT]
    anagram verify PROOF.json [--file PATH] [--log-key VKEY] [--bitcoin-headers FILE] ...
    anagram prove-file FINDING_ID PATH [--out FILE]
    anagram list
    anagram anchors refresh [FINDING]     get background anchors (TSA, Bitcoin) from the node
    anagram join INVITE_URL --name N [--address ADDR] [--kit-file PATH]
                 (the invite is the proof; no ORCID. Optional: --orcid | --fake-orcid ID |
                  --email ADDR | --no-browser)
    anagram login [--orcid | --fake-orcid ID | --email ADDR | --no-browser] [--reset]
                 [--kit-file PATH]       (default: the device key of this computer)
    anagram orcid link [--fake-orcid ID | --no-browser]   link your ORCID iD (optional)
    anagram whoami | anagram logout
    anagram keys lookup PERSON | anagram keys monitor     (PERSON: pid:..., or an ORCID iD
                                           of a member who is findable by ORCID)
    anagram findable on|off                members who know your email address (or linked
                                           ORCID iD) can find you
    anagram device request | anagram device add REQUEST
    anagram lab create|list|show|invite|join|add|remove|leave|sync|publish|items|use ...
                                           (see shell/cli/lab.py)
    anagram recover KIT_FILE | anagram recover --guardians [--invite URL] [--fake-orcid ID]
    anagram ring create NAME | ring add NAME MEMBER... | ring remove NAME MEMBER... | ring list
    anagram upload FINDING
    anagram grant FINDING [--ring NAME] [--to ORCID ...] [--ack-third-party] [--no-upload]
    anagram revoke FINDING --ring NAME [--ack-third-party]
    anagram publish FINDING [--ack-third-party]
    anagram open [--route NAME]            open the app in the browser (start it if necessary)
    anagram inbox | anagram open GRANT --out DIR | anagram open --public RELEASE --out DIR
    anagram sync                           wrap sent grants again for new recipient devices, and
                                           send vault records and an index snapshot to the
                                           personal store (ciphertext only)
    anagram guardians set PERSON... [--threshold K] | guardians requests | guardians approve ID
    anagram node [--node-dir DIR] init [--domain D --community C --orcid-mode M ...] [-y]
    anagram node [--node-dir DIR] invite [--days 7] [--organizer]
    anagram node [--node-dir DIR] serve [--host 127.0.0.1] [--port 8787]
    anagram node [--node-dir DIR] start [--host 0.0.0.0] [--port 8787]   (container: env setup)
    anagram node [--node-dir DIR] enclave setup|status|record|off   (matching enclave)
    anagram enclave devnet|release|line|failover|serve    (simulated profile; development)
    anagram log serve | anagram witness serve | anagram roster serve|admit

The commands are in modules by area: proofs.py, account.py, grants.py,
node.py, lab.py, share.py, mcp.py (this folder), and anagram.shell.app.cli (the app).
This module builds the parser, opens the UI, and runs a command.

The data directory is $ANAGRAM_HOME, else ~/.anagram. --home overrides both.
The node directory is $ANAGRAM_NODE_HOME, else <home>/node. --node-dir overrides both.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from anagram.core.errors import ClientError
from anagram.core.nodeapi import NodeHTTPError
from anagram.shell.cli import account, enclave, grants, node, proofs


def default_home() -> Path:
    return Path(os.environ.get("ANAGRAM_HOME", Path.home() / ".anagram"))


def cmd_ui(args) -> int:  # pragma: no cover - runs a server and a browser
    from anagram.shell.ui.server import run_ui

    return run_ui(
        args.home,
        port=getattr(args, "port", 0),
        open_browser=not getattr(args, "no_browser", False),
    )


def cmd_indexer(args) -> int:  # pragma: no cover - runs until stopped
    from anagram.shell.ui.server import run_indexer

    return run_indexer(
        args.home,
        embed=not args.no_embed,
        poll_s=args.poll * 60 if args.poll else None,
        once=args.once,
        watch=not args.no_watch,
    )


def cmd_demo(args) -> int:  # pragma: no cover - starts processes
    from anagram.sim import demo

    if args.demo_command == "up":
        return demo.up(
            Path(args.dir),
            everyone=args.everyone,
            ready=args.ready,
            day_seconds=args.day_seconds,
        )
    return demo.down(Path(args.dir))


def _register_local(sub) -> None:
    """Add ui and indexer."""
    p = sub.add_parser("ui", help="open the local web UI (the default with no command)")
    p.add_argument("--port", type=int, default=0, help="loopback port (default: a free port)")
    p.add_argument("--no-browser", action="store_true", help="print the link only")
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("indexer", help="background helper: index sources with no UI")
    p.add_argument("--once", action="store_true", help="one scan and all jobs, then stop")
    p.add_argument("--no-embed", action="store_true", help="no local embeddings (no model)")
    p.add_argument("--no-watch", action="store_true", help="poll only, no file events")
    p.add_argument("--poll", type=int, default=0, help="minutes between polls (default 15)")
    p.set_defaults(func=cmd_indexer)


def _register_demo(sub) -> None:
    """Add demo up and demo down."""
    p = sub.add_parser("demo", help="demo community for local tests")
    dsub = p.add_subparsers(dest="demo_command", required=True)
    s = dsub.add_parser("up", help="start a demo node and one UI per fake person")
    s.add_argument("--dir", default="anagram-demo", help="demo data directory")
    s.add_argument("--everyone", action="store_true", help="one UI for each of the 11 people")
    s.add_argument("--ready", action="store_true", help="join and approve all but the first PI")
    s.add_argument("--day-seconds", type=int, default=120, help="length of one matching day")
    s.set_defaults(func=cmd_demo)
    s = dsub.add_parser("down", help="stop the demo")
    s.add_argument("--dir", default="anagram-demo")
    s.set_defaults(func=cmd_demo)


def build_parser() -> argparse.ArgumentParser:
    from anagram.shell.app.cli import register as register_app
    from anagram.shell.cli.lab import register as register_lab
    from anagram.shell.cli.mcp import register as register_mcp
    from anagram.shell.cli.share import register as register_share

    parser = argparse.ArgumentParser(prog="anagram", description="Private priority proofs.")
    parser.add_argument("--home", default=str(default_home()), help="data directory")
    parser.add_argument(
        "--plain-key-files",
        action="store_true",
        help="keep the keys of a new home in plain files, not in the OS keychain",
    )
    sub = parser.add_subparsers(dest="command")
    # The order of the calls is the order of the commands in `anagram --help`.
    _register_local(sub)  # anagram ui, indexer
    register_app(sub)  # the app: anagram app ..., anagram open-url
    _register_demo(sub)
    proofs.register(sub)  # init, commit, verify, prove-file, list, anchors
    account.register(sub)  # join, login, orcid, whoami, logout, keys, device
    register_lab(sub)  # anagram lab ... (shell/cli/lab.py)
    register_share(sub)  # anagram certificate, preprint (shell/cli/share.py)
    register_mcp(sub)  # anagram mcp --assistant ID (shell/cli/mcp.py)
    account.register_recover(sub)  # recover
    grants.register(sub)  # ring, upload, grant, revoke, publish, inbox, open, sync
    account.register_guardians(sub)  # findable, guardians
    node.register(sub)  # node init|invite|serve|start|enclave
    enclave.register(sub)  # enclave, log, witness, roster (simulated profile)
    return parser


# Commands that do not make a client home of a person: they keep the policy of
# the environment (default `file`).
NO_KEYCHAIN_COMMANDS = ("node", "demo", "enclave", "log", "witness", "roster")


def set_keystore_policy(args: argparse.Namespace) -> None:
    """The keystore policy of a new home (security review). Each client
    command, also `anagram` and `anagram ui`, uses the keychain of the
    operating system where there is one (`auto`), as the app does. Plain key
    files only with `--plain-key-files`, or with `ANAGRAM_KEYSTORE=file` in
    the environment (tests and headless hosts). A home that has keys keeps
    its backend."""
    if args.plain_key_files:
        os.environ["ANAGRAM_KEYSTORE"] = "file"
    elif getattr(args, "app_entry", False) or args.command not in NO_KEYCHAIN_COMMANDS:
        os.environ.setdefault("ANAGRAM_KEYSTORE", "auto")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_keystore_policy(args)
    if not getattr(args, "func", None):
        return cmd_ui(args)  # `anagram` with no command opens the local web UI
    try:
        return args.func(args)
    except (ClientError, NodeHTTPError, KeyError, ValueError, FileNotFoundError) as exc:
        print(f"anagram: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
