"""`anagram mcp`: the agent gateway (MCP) for the person's own agents.

    anagram mcp --assistant <id>        stdio, one agent grant
    anagram mcp --http [--port N]       loopback HTTP; the bearer key names the grant

The person adds the agent in Anagram (Account, Assistant access); the app
gives the setup text with this command. The command opens the client and
the index of this computer for each call. The stdio form opens no network
port; the HTTP form binds to 127.0.0.1 only.

This module is a composition root: it gives the gateway its session and
its trust policy port (`policy`).
"""

from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ASSISTANT_ID = "^[0-9a-f]{16}$"


def command(home: Path | str, assistant_id: str) -> list[str]:
    """The command that an assistant starts (the setup text of the app).

    In the packaged app `sys.executable` is the program of the app, and it
    takes the arguments of the `anagram` command (`packaging/entry.py`); it
    has no `-m`. Else it is the Python that runs Anagram. The home is an
    absolute path, because the assistant starts the command from its own
    working directory."""
    home = str(Path(home).expanduser().resolve())
    program = (
        [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "anagram"]
    )
    return [*program, "--home", home, "mcp", "--assistant", assistant_id]


def http_command(home: Path | str, port: int) -> list[str]:
    return [*command(home, "x")[:-2], "--http", "--port", str(port)]


def setup_json(home: Path | str, assistant_id: str, name: str = "anagram") -> dict:
    """The entry for the `mcpServers` setting of an assistant (the form of
    Claude Desktop and other MCP clients)."""
    cmd = command(home, assistant_id)
    return {"mcpServers": {name: {"args": cmd[1:], "command": cmd[0]}}}


def http_setup_json(port: int, key: str, name: str = "anagram") -> dict:
    """The entry for an MCP client that speaks Streamable HTTP."""
    url = f"http://127.0.0.1:{port}/mcp"
    return {
        "mcpServers": {
            name: {"headers": {"Authorization": f"Bearer {key}"}, "type": "http", "url": url}
        }
    }


def policy(client: Any, index: Any):
    """The trust policy port of the gateway: the signed policy of the person
    in the index store, checked with the key of this device (net 05 step
    1). It raises when the saved policy does not verify; the gateway then
    gives no text."""
    from anagram.local.api import TrustStore

    device = client.device
    return TrustStore(index.store, device.subject, [device.device_key().public_bytes()]).current()


def _session(home: str):
    from anagram.local.api import LocalIndex
    from anagram.shell.client import Client

    @contextmanager
    def session():
        client = Client(home)
        idx = LocalIndex.for_client(client)
        try:
            yield client, idx
        finally:
            idx.close()
            client.close()

    return session


def cmd_mcp(args) -> int:
    import re

    from anagram.gateway.server import Server

    if args.http:
        from anagram.gateway.http import Gateway

        try:
            gateway = Gateway(_session(args.home), policy=policy, port=args.port)
        except OSError as exc:
            print(f"anagram mcp: error: port {args.port}: {exc.strerror}", file=sys.stderr)
            return 1
        print(f"Anagram gateway at {gateway.url()}", file=sys.stderr, flush=True)
        try:
            gateway.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            gateway.server_close()
        return 0
    if not re.match(ASSISTANT_ID, args.assistant or ""):
        print("anagram mcp: error: give the assistant id of the setup text", file=sys.stderr)
        return 2
    Server(_session(args.home), args.assistant, policy=policy).serve(sys.stdin, sys.stdout)
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    from anagram.gateway.http import DEFAULT_PORT

    p = sub.add_parser("mcp", help="access for your own AI assistant (MCP: stdio or loopback)")
    p.add_argument("--assistant", help="the id from the setup text of the app (stdio)")
    p.add_argument("--http", action="store_true", help="serve MCP over HTTP on 127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="the port for --http")
    # The keychain of the operating system, as the app uses it.
    p.set_defaults(func=cmd_mcp, app_entry=True)
