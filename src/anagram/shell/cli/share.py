"""CLI commands of sharing and proof.

`register(sub)` adds the commands to the `anagram` parser (one call in
`cli.py`). The commands are thin: the logic is in `anagram.proofs.certificate` and
`anagram.proofs.preprint`.

    anagram certificate <finding> [--out FILE] [--no-claim] [--no-files]
                                  [--no-digests] [--no-name]
    anagram preprint <finding> [--out FILE] [--no-files] [--abstract TEXT]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from anagram.core.errors import ClientError
from anagram.shell.client import Client


def cmd_certificate(args) -> int:
    from anagram.proofs.certificate import make_certificate

    client = Client(args.home)
    name, text, report = make_certificate(
        client,
        args.finding,
        claim=not args.no_claim,
        files=not args.no_files,
        digests=not args.no_digests,
        name=not args.no_name,
    )
    if not report.ok:
        raise ClientError(
            "the proof of this finding is not complete yet; try again later\n" + report.summary()
        )
    out = Path(args.out or name)
    out.write_text(text, encoding="utf-8")
    print(f"Certificate: {out}")
    print("Open it in a browser. Print it, or save it as PDF from the print dialog.")
    return 0


def cmd_preprint(args) -> int:
    from anagram.proofs.preprint import build_preprint, preprint_name

    client = Client(args.home)
    root = client.vault.find(args.finding).root
    out = build_preprint(
        client,
        root,
        Path(args.out or preprint_name(root)),
        include_files=not args.no_files,
        abstract=args.abstract,
    )
    print(f"Preprint draft: {out}")
    print("It is a draft. Read and change the text before you send it to a preprint server.")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("certificate", help="make a proof certificate (HTML) for a finding")
    p.add_argument("finding", help="finding ID or root (hex prefix)")
    p.add_argument("--out", help="file to write (default: anagram-certificate-<root>.html)")
    p.add_argument("--no-claim", action="store_true", help="do not show the claim")
    p.add_argument("--no-files", action="store_true", help="do not show the file names")
    p.add_argument("--no-digests", action="store_true", help="do not show the file digests")
    p.add_argument("--no-name", action="store_true", help="do not show your name and ORCID iD")
    p.set_defaults(func=cmd_certificate)

    p = sub.add_parser("preprint", help="make a preprint draft (zip) with the priority proofs")
    p.add_argument(
        "finding", help="finding ID or root (hex prefix); its included findings go in too"
    )
    p.add_argument("--out", help="file to write (default: anagram-preprint-<root>.zip)")
    p.add_argument(
        "--no-files", action="store_true", help="leave out the files that are not figures"
    )
    p.add_argument("--abstract", help="abstract text (default: the claim of the finding)")
    p.set_defaults(func=cmd_preprint)
