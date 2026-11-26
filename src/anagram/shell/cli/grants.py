"""CLI commands that share findings: rings, grants, releases, and sync.

`register(sub)` adds the commands to the `anagram` parser (one call in
`anagram.shell.cli.main`).

    anagram ring create NAME | ring add NAME MEMBER... | ring remove NAME MEMBER... | ring list
    anagram upload FINDING
    anagram grant FINDING [--ring NAME] [--to ORCID ...] [--ack-third-party] [--no-upload]
    anagram revoke FINDING --ring NAME [--ack-third-party]
    anagram publish FINDING [--ack-third-party]
    anagram inbox | anagram open GRANT --out DIR | anagram open --public RELEASE --out DIR
    anagram sync
"""

from __future__ import annotations

import json
import sys

from anagram.core.errors import ClientError
from anagram.shell.client import Client


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def cmd_ring(args) -> int:
    c = Client(args.home)
    if args.ring_command == "create":
        _print(c.grants.ring_create(args.name))
    elif args.ring_command == "add":
        _print(c.grants.ring_add(args.name, args.members))
    elif args.ring_command == "remove":
        _print(c.grants.ring_remove(args.name, args.members))
    else:
        for r in c.grants.ring_list():
            print(f"{r['position']}  {r['name']}: {', '.join(r['members']) or '(empty)'}")
    return 0


def cmd_upload(args) -> int:
    blobs = Client(args.home).grants.upload(args.finding)
    print(f"{len(blobs)} evidence file(s) on the node (ciphertext only).")
    return 0


def _third_party_note(exc: ClientError) -> int:
    print(f"anagram: warning: {exc}", file=sys.stderr)
    return 5


def cmd_grant(args) -> int:
    from anagram.network.api import ThirdPartyWarning

    if not args.ring and not args.to:
        raise ClientError("give --ring NAME or --to ORCID")
    try:
        out = Client(args.home).grants.grant(
            args.finding,
            ring=args.ring,
            recipients=args.to or [],
            warnings_ack=args.ack_third_party,
            upload=not args.no_upload,
        )
    except ThirdPartyWarning as exc:
        return _third_party_note(exc)
    for g in out["granted"]:
        print(f"Granted to {g['recipient']} ({g['devices']} device(s)): grant {g['grant_id']}")
    for s in out["skipped"]:
        print(f"Skipped {s}: no active keys (not joined yet)")
    if out["public"]:
        print(f"Published: release {out['public']}")
    print("Access that you give cannot be taken back. A revoke makes a new version.")
    return 0


def cmd_revoke(args) -> int:
    from anagram.network.api import ThirdPartyWarning

    try:
        out = Client(args.home).grants.revoke(
            args.finding, ring=args.ring, warnings_ack=args.ack_third_party
        )
    except ThirdPartyWarning as exc:
        return _third_party_note(exc)
    print(f"New version {out['root']} granted to {len(out['granted'])} recipient(s).")
    print("People who had the old version can still read the old version.")
    return 0


def cmd_publish(args) -> int:
    from anagram.network.api import ThirdPartyWarning

    try:
        out = Client(args.home).grants.publish(args.finding, warnings_ack=args.ack_third_party)
    except ThirdPartyWarning as exc:
        return _third_party_note(exc)
    print(f"Published: release {out['release_id']}. Anyone can now read and verify it.")
    return 0


def cmd_inbox(args) -> int:
    items = Client(args.home).grants.inbox()
    for g in items:
        note = "" if g["for_this_device"] else "  (not for this device: ask the owner to sync)"
        print(f"{g['grant_id']}  from {g['sender']}  {g['blobs']} file(s){note}")
    if not items:
        print("No grants.")
    return 0


def cmd_open(args) -> int:
    if args.grant is None:  # `anagram open`: the app (anagram.shell.app.cli)
        from anagram.shell.app.cli import cmd_open_app

        return cmd_open_app(args)
    if not args.out:
        raise ClientError("give --out DIR for the opened files")
    c = Client(args.home)
    if args.public:
        res = c.grants.open_release(args.grant, args.out)
    else:
        res = c.grants.open_grant(args.grant, args.out)
    print(f"VALID finding {res['finding_id']} v{res['version']} from {res['owner']}")
    if res["not_after"]:
        print(f"existed no later than: {res['not_after']}")
    print(f"granted at: {res['granted_at']} (receipt {res['receipt_commitment'][:16]}...)")
    for f in res["files"]:
        print(f"file: {f}")
    return 0


def cmd_sync(args) -> int:
    c = Client(args.home)
    changed = c.grants.sync_grants()
    print(f"{len(changed)} grant(s) wrapped again for new devices.")
    if not c.personal.store_ready():
        print("Personal store: needs a community node and a session (`anagram login`).")
        return 0
    r = c.personal.sync_store(snapshot=True)
    snaps = ", ".join(f"{k}: {v}" for k, v in sorted(r["snapshots"].items()))
    print(f"Personal store: {r['pushed']} record(s) sent, {r['pulled']} received ({snaps}).")
    return 0


def register(sub) -> None:
    """Add ring, upload, grant, revoke, publish, inbox, open, and sync."""
    from anagram.shell.app.cli import register_open_options

    p = sub.add_parser("ring", help="rings: ordered, concentric lists of recipients")
    rsub = p.add_subparsers(dest="ring_command")
    s = rsub.add_parser("create", help="add a ring outside the existing rings")
    s.add_argument("name")
    s.set_defaults(func=cmd_ring)
    for name in ("add", "remove"):
        s = rsub.add_parser(name, help=f"{name} members (ORCID, lab-ID, community, public)")
        s.add_argument("name")
        s.add_argument("members", nargs="+")
        s.set_defaults(func=cmd_ring)
    s = rsub.add_parser("list", help="list rings, inner first")
    s.set_defaults(func=cmd_ring)

    p = sub.add_parser("upload", help="encrypt and upload the evidence files of a finding")
    p.add_argument("finding")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("grant", help="share a finding with a ring (and its inner rings)")
    p.add_argument("finding")
    p.add_argument("--ring")
    p.add_argument("--to", action="append", help="ORCID iD of one more recipient")
    p.add_argument("--ack-third-party", action="store_true", help="evidence has others' words")
    p.add_argument("--no-upload", action="store_true", help="keep the files on this device")
    p.set_defaults(func=cmd_grant)

    p = sub.add_parser("revoke", help="new version for a smaller ring (old access stays)")
    p.add_argument("finding")
    p.add_argument("--ring", required=True)
    p.add_argument("--ack-third-party", action="store_true")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("publish", help="publish a finding (content key and opening data)")
    p.add_argument("finding")
    p.add_argument("--ack-third-party", action="store_true")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("inbox", help="grants that you received")
    p.set_defaults(func=cmd_inbox)

    p = sub.add_parser(
        "open", help="open the app in the browser; with GRANT: decrypt and verify a grant"
    )
    p.add_argument("grant", nargs="?", help="grant ID (or release ID with --public)")
    p.add_argument("--out", help="directory for the opened files (with GRANT)")
    p.add_argument("--public", action="store_true")
    register_open_options(p)  # anagram.shell.app.cli: --route
    p.set_defaults(func=cmd_open)

    p = sub.add_parser(
        "sync", help="wrap sent grants again; send vault records to the personal store"
    )
    p.set_defaults(func=cmd_sync)
