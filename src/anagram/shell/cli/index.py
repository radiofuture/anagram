"""Local index command line: `python -m anagram.shell.cli.index ...`.

This is separate from the `anagram` command for now (other work owns
`cli.py`). It uses the same data directory: $ANAGRAM_HOME, else ~/.anagram.

    python -m anagram.shell.cli.index add-folder ~/lab
    python -m anagram.shell.cli.index add-git ~/lab/code/repo
    python -m anagram.shell.cli.index add-zotero ~/exports/library.json
    python -m anagram.shell.cli.index scan
    python -m anagram.shell.cli.index checkpoint            # all sources with new items
    python -m anagram.shell.cli.index draft-findings
    python -m anagram.shell.cli.index search "cryo-EM"      # full-text search of your index
    python -m anagram.shell.cli.index skipped               # files that no converter read

Drafts are printed only. Nothing is committed or submitted by a draft command.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from anagram.local.api import (
    FolderConnector,
    GitConnector,
    LocalIndex,
    OrcidWorksConnector,
    ZoteroFileConnector,
    draft_findings,
)
from anagram.shell.client import Client


def _home() -> str:
    return os.environ.get("ANAGRAM_HOME", str(Path.home() / ".anagram"))


def _open(args) -> tuple[Client, LocalIndex]:
    client = Client(args.home)
    return client, LocalIndex.for_client(client)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anagram.shell.cli.index")
    ap.add_argument("--home", default=_home(), help="data directory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, arg in (
        ("add-folder", "path"),
        ("add-git", "path"),
        ("add-zotero", "path"),
        ("add-orcid", "orcid"),
    ):
        p = sub.add_parser(name)
        p.add_argument(arg)
    sub.add_parser("sources")
    sub.add_parser("scan")
    p = sub.add_parser("checkpoint")
    p.add_argument("--source", help="source ID (default: all with new items)")
    p.add_argument("--interval", type=int, default=0, help="only if the last one is older (s)")
    sub.add_parser("draft-findings")
    p = sub.add_parser("search")
    p.add_argument("query")
    p.add_argument("-k", type=int, default=10)
    sub.add_parser("skipped")
    args = ap.parse_args(argv)

    client, index = _open(args)
    _COMMANDS[args.cmd](client, index, args)
    index.close()
    return 0


def _sources(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    for sid, src in index.sources().items():
        print(f"{sid}  {src['label']}  pending={len(src['pending'])}  seq={src['seq']}")


def _scan(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    r = index.scan()
    print(
        f"new {len(r.new)}, changed {len(r.changed)}, unchanged {len(r.unchanged)},"
        f" removed {len(r.removed)}"
    )
    for sid, msg in r.errors:
        print(f"error in {sid}: {msg}", file=sys.stderr)


def _checkpoint(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    sids = [args.source] if args.source else sorted(index.sources())
    for sid in sids:
        if not index.streams.checkpoint_due(sid, args.interval):
            continue
        done = index.streams.checkpoint(client, sid)
        n = done.opening.fields["item_count"]
        print(f"{sid}: checkpoint {done.opening.fields['seq']} ({n} items) {done.root.hex()}")


def _draft_findings(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    for d in draft_findings(index):
        warn = "  [has third-party text]" if d.third_party else ""
        print(f"{d.id}  {d.title}  ({len(d.items)} items){warn}")
        if d.claim_suggestion:
            print(f"    suggested claim: {d.claim_suggestion}")


def _search(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    for h in index.search(args.query, args.k):
        text = " ".join(h.text.split())[:120]
        print(f"{h.score:.4f}  {h.name or h.key}  #{h.anchor}  {text}")


def _skipped(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
    for s in index.skipped():
        print(f"{s.source_id[:8]}  {s.key}  {s.media_type}: {s.reason}")


def _add(make: type, arg: str) -> Callable[[Client, LocalIndex, argparse.Namespace], None]:
    """The handler of an `add-*` command: add a source of the connector
    class `make` from the argument `arg`, and print its ID."""

    def run(client: Client, index: LocalIndex, args: argparse.Namespace) -> None:
        print(index.add_source(make(getattr(args, arg))))

    return run


# The handler of each command: f(client, index, args). An ORCID source reads
# the public ORCID record over the network at scan time.
_COMMANDS = {
    "add-folder": _add(FolderConnector, "path"),
    "add-git": _add(GitConnector, "path"),
    "add-zotero": _add(ZoteroFileConnector, "path"),
    "add-orcid": _add(OrcidWorksConnector, "orcid"),
    "sources": _sources,
    "scan": _scan,
    "checkpoint": _checkpoint,
    "draft-findings": _draft_findings,
    "search": _search,
    "skipped": _skipped,
}


if __name__ == "__main__":
    raise SystemExit(main())
