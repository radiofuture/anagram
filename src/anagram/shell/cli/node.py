"""CLI commands for the community node.

`register(sub)` adds `anagram node ...` to the `anagram` parser (one call in
`anagram.shell.cli.main`).

    anagram node [--node-dir DIR] init [--domain D --community C --orcid-mode M ...] [-y]
    anagram node [--node-dir DIR] invite [--days 7] [--organizer]
    anagram node [--node-dir DIR] serve [--host 127.0.0.1] [--port 8787]
    anagram node [--node-dir DIR] start [--host 0.0.0.0] [--port 8787]   (container: env setup)
    anagram node [--node-dir DIR] enclave setup --url URL [--url URL] --log-url URL
                 --pins devnet.json --affiliation TEXT --admin ADDR [--ror ID] [--kind lab]
    anagram node [--node-dir DIR] enclave status [--json]   the enclave and the log, checked
    anagram node [--node-dir DIR] enclave record            the node record for the roster
    anagram node [--node-dir DIR] enclave off

The node directory is $ANAGRAM_NODE_HOME, else <home>/node. --node-dir overrides both.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from anagram.core.errors import ClientError


def _node_dir(args) -> Path:
    if args.node_dir:
        return Path(args.node_dir)
    if os.environ.get("ANAGRAM_NODE_HOME"):
        return Path(os.environ["ANAGRAM_NODE_HOME"])
    return Path(args.home) / "node"


def cmd_node_serve(args) -> int:  # pragma: no cover - runs a server
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("Install the node extra: uv pip install 'anagram[node]'", file=sys.stderr)
        return 2
    from anagram.shell.node.home import NodeHome
    from anagram.shell.node.setup import serve_node

    nh = NodeHome(_node_dir(args))
    if not nh.exists():
        print("No node here. Run `anagram node init` first.", file=sys.stderr)
        return 1
    print(f"Node key fingerprint: {nh.fingerprint()}")
    print(f"Public URL: {nh.config()['public_url']}  ORCID: {nh.config()['orcid']['mode']}")
    return serve_node(nh, args.host, args.port)


def cmd_node_start(args) -> int:  # pragma: no cover - runs a server
    from anagram.shell.node.home import NodeHome
    from anagram.shell.node.setup import main_start

    return main_start(NodeHome(_node_dir(args)), args.host, args.port)


def _ask(prompt: str, current, interactive: bool, secret: bool = False):
    if current or not interactive:
        return current
    if secret:
        import getpass

        return getpass.getpass(f"{prompt}: ").strip()
    return input(f"{prompt}: ").strip()


def _orcid_client(args, mode: str, public_url: str, interactive: bool) -> tuple[str, str]:
    """The ORCID client ID and secret. The fake mode needs none."""
    from anagram.identity.api import REGISTER_URL

    client_id, secret = args.orcid_client_id or "", args.orcid_client_secret or ""
    if mode == "fake":
        return client_id, secret
    print(f"Register an ORCID client at {REGISTER_URL}")
    print(f"Redirect URI to register (exact): {public_url}/auth/orcid/callback")
    client_id = _ask("ORCID client ID", client_id, interactive)
    secret = _ask("ORCID client secret", secret, interactive, secret=True)
    if not client_id or not secret:
        raise ClientError("ORCID needs --orcid-client-id and --orcid-client-secret")
    return client_id, secret


def cmd_node_init(args) -> int:
    from anagram.shell.node.home import LOG_ORIGIN_PATH, NodeHome

    nh = NodeHome(_node_dir(args))
    if nh.exists():
        raise ClientError(f"a node exists in {nh.dir}")
    interactive = not args.non_interactive and sys.stdin.isatty()
    domain = _ask("Domain of this node (for example anagram.example.org)", args.domain, interactive)
    domain = domain or "127.0.0.1:8787"
    local = domain.startswith(("127.0.0.1", "localhost"))
    public_url = args.public_url or (f"http://{domain}" if local else f"https://{domain}")
    community = _ask("Community name", args.community, interactive) or "Anagram community"
    mode = args.orcid_mode or ("fake" if local else None)
    mode = _ask("ORCID mode (production, sandbox, fake)", mode, interactive) or "production"
    client_id, secret = _orcid_client(args, mode, public_url, interactive)
    host = "local.anagram" if local else domain.split(":")[0]
    nh.create(
        origin=f"{host}/{LOG_ORIGIN_PATH}",
        anchors=args.anchor or None,
        community=community,
        public_url=public_url,
        orcid_mode=mode,
        orcid_client_id=client_id,
        orcid_client_secret=secret,
        organizers=args.organizer or [],
        anchor_mode="background",
    )
    print(f"Node created in {nh.dir}")
    print(f"Community: {community}")
    print(f"Public URL: {public_url}")
    print(f"ORCID mode: {mode}")
    print(f"ORCID redirect URI: {public_url}/auth/orcid/callback")
    print(f"Node key fingerprint: {nh.fingerprint()}")
    print("Next: `anagram node serve`, then `anagram node invite` for each member.")
    return 0


def cmd_node_invite(args) -> int:
    from anagram.shell.node.home import NodeHome

    nh = NodeHome(_node_dir(args))
    if not nh.exists():
        raise ClientError("no node here; run `anagram node init` first")
    out = nh.admission(nh.identity(nh.service())).create_invite(
        None, args.days, organizer=args.organizer
    )
    print(out["invite_url"])
    role = "an organizer" if args.organizer else "a member"
    print(
        f"Expires: {out['invite']['expires_at']}. One person can use it to join as {role}.",
        file=sys.stderr,
    )
    return 0


def _home(args):
    from anagram.shell.node.home import NodeHome

    nh = NodeHome(_node_dir(args))
    if not nh.exists():
        raise ClientError("no node here; run `anagram node init` first")
    return nh


def cmd_node_enclave(args) -> int:
    """Matching through the network enclave (node.json "enclave"; off by
    default). After `setup`, restart the node."""
    import json

    nh = _home(args)
    if args.action == "setup":
        nh.set_enclave(
            {
                "enabled": True,
                "log_url": args.log_url,
                "pins": json.loads(Path(args.pins).read_text()),
                "profile": "simulated",
                "record": {
                    "admin": args.admin,
                    "affiliation": args.affiliation,
                    "kind": args.kind,
                    "ror": args.ror,
                },
                "urls": args.url or [],
            }
        )
        print("Matching through the enclave: on (simulated profile, development only).")
        print("Restart the node, then give `anagram node enclave record` to the roster operator.")
        return 0
    if args.action == "off":
        nh.set_enclave({**nh.enclave_config(), "enabled": False})
        print("Matching through the enclave: off. Restart the node.")
        return 0
    if args.action == "record":
        print(json.dumps(nh.node_record(), indent=2, sort_keys=True))
        return 0
    enclave = nh.enclave()
    if enclave is None:
        print('Matching through the enclave: off (node.json "enclave").')
        return 0
    status = enclave.status()
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        for key in ("profile", "network", "node", "log", "log_size", "enclave", "instance_id"):
            if key in status:
                print(f"{key}: {status[key]}")
    return 0 if status.get("enclave") == "attested" and status.get("log") == "ok" else 1


def register(sub) -> None:
    """Add `anagram node` and its commands."""
    p = sub.add_parser("node", help="node commands")
    p.add_argument("--node-dir", help="node data directory")
    nsub = p.add_subparsers(dest="node_command")
    s = nsub.add_parser("init", help="set up a node (first start)")
    s.add_argument("--domain")
    s.add_argument("--public-url", help="default: https://DOMAIN")
    s.add_argument("--community")
    s.add_argument("--orcid-mode", choices=["production", "sandbox", "fake"])
    s.add_argument("--orcid-client-id")
    s.add_argument("--orcid-client-secret")
    s.add_argument("--organizer", action="append", help="ORCID iD of an organizer")
    s.add_argument("--anchor", action="append", help="fake, rfc3161:URL, opentimestamps")
    s.add_argument("--non-interactive", "-y", action="store_true")
    s.set_defaults(func=cmd_node_init)
    s = nsub.add_parser("invite", help="make a single-use invite link")
    s.add_argument("--days", type=float, default=7)
    s.add_argument("--organizer", action="store_true", help="the person becomes an organizer")
    s.set_defaults(func=cmd_node_invite)
    s = nsub.add_parser("serve", help="run the HTTP node")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_node_serve)
    s = nsub.add_parser("enclave", help="matching through the network enclave")
    s.add_argument("action", choices=["setup", "status", "record", "off"])
    s.add_argument("--url", action="append", help="URL of an enclave instance (setup)")
    s.add_argument("--log-url", help="URL of the enclave log (setup)")
    s.add_argument("--pins", help="devnet.json of the network (setup)")
    s.add_argument("--affiliation", help="display affiliation of the node record (setup)")
    s.add_argument("--admin", help="contact address of the node admin (setup)")
    s.add_argument("--ror", help="ROR ID of the node (setup)")
    s.add_argument("--kind", default="lab", choices=["individual", "lab", "university"])
    s.add_argument("--json", action="store_true", help="status as JSON")
    s.set_defaults(func=cmd_node_enclave)
    s = nsub.add_parser("start", help="first start from ANAGRAM_* variables, then serve")
    s.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a container
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_node_start)
