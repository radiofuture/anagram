# ruff: noqa: F811 - the fixture `lib` from test_mcp
"""MCP over loopback HTTP (open-agents stage 3, decision A1): the checks of
`local-ui-boundary` for a route that a browser must not use, and a bearer
key for each grant. A real HTTP server on 127.0.0.1 with a free port."""

from __future__ import annotations

import http.client
import json
import threading
from contextlib import contextmanager

import pytest
from indexkit import KEY
from test_mcp import (
    ME,
    NOW,
    WORD,
    consent,
    default_policy,
    lib,  # noqa: F401 - fixture
)

from anagram.gateway import access
from anagram.gateway.http import LOOPBACK, MAX_BODY, Gateway
from anagram.gateway.server import HEADER
from anagram.local.index.local import LocalIndex

# No `no_network` here: the test talks to its own server on 127.0.0.1 only.


@pytest.fixture
def gw(lib, tmp_path):
    """The gateway in a thread. Each request opens its own index (an SQLite
    connection stays in its thread), as `anagram mcp --http` does."""
    idx, client, _, _ = lib

    @contextmanager
    def session():
        own = LocalIndex(tmp_path / "index.sqlite", KEY, owner_emails=[ME])
        try:
            yield client, own
        finally:
            own.close()

    server = Gateway(session, policy=default_policy, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, idx
    server.shutdown()
    server.server_close()


def _call(server: Gateway, method: str = "POST", body: object = None, **headers) -> tuple:
    conn = http.client.HTTPConnection(LOOPBACK, server.port, timeout=10)
    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    base = {"Host": f"{LOOPBACK}:{server.port}", "Content-Type": "application/json"}
    base.update({k.replace("_", "-"): v for k, v in headers.items() if v is not None})
    for k in [k for k, v in headers.items() if v is None]:
        base.pop(k.replace("_", "-"), None)
    conn.request(method, "/mcp", body=raw or None, headers=base)
    r = conn.getresponse()
    data = r.read()
    out = (r.status, dict(r.getheaders()), json.loads(data) if data else None)
    conn.close()
    return out


def _search(n: int = 1) -> dict:
    return {
        "id": n,
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"arguments": {"query": WORD}, "name": "search"},
    }


def test_a_grant_key_reads_through_loopback(gw):
    server, idx = gw
    assert server.server_address[0] == "127.0.0.1"
    who = consent(idx)
    key = access.new_http_key(idx, who.id)
    auth = f"Bearer {key}"
    status, headers, got = _call(server, body=_search(), Authorization=auth)
    assert status == 200, got
    text = got["result"]["content"][0]["text"]
    assert text.startswith(HEADER) and WORD in text
    assert not any(h.lower().startswith("access-control") for h in headers)
    assert idx.disclosures()[-1]["adapter"] == f"agent:{who.id}"
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert _call(server, body=note, Authorization=auth)[0] == 202
    # A new key replaces the old one; a revoke ends the access at the next request.
    newer = access.new_http_key(idx, who.id)
    assert _call(server, body=_search(), Authorization=auth)[0] == 401
    assert _call(server, body=_search(), Authorization=f"Bearer {newer}")[0] == 200
    access.revoke(idx, who.id, NOW)
    assert _call(server, body=_search(), Authorization=f"Bearer {newer}")[0] == 401


def test_the_boundary_refuses_a_browser_and_a_wrong_host(gw):
    server, idx = gw
    key = access.new_http_key(idx, consent(idx).id)
    auth = f"Bearer {key}"
    cases = {
        "wrong host": ({"Host": "evil.example"}, 421),
        "rebinding": ({"Host": f"evil.example:{server.port}"}, 421),
        "origin": ({"Origin": f"http://{LOOPBACK}:{server.port}"}, 403),
        "cookie": ({"Cookie": "a=b"}, 403),
        "fetch site": ({"Sec_Fetch_Site": "same-origin"}, 403),
        "fetch mode": ({"Sec_Fetch_Mode": "cors"}, 403),
        "no key": ({"Authorization": None}, 401),
        "other scheme": ({"Authorization": f"Basic {key}"}, 401),
        "bad key": ({"Authorization": "Bearer nope"}, 401),
        "form post": ({"Content_Type": "text/plain"}, 415),
    }
    for name, (extra, want) in cases.items():
        headers = {"Authorization": auth, **extra}
        status, got_headers, _ = _call(server, body=_search(), **headers)
        assert status == want, name
        assert not any(h.lower().startswith("access-control") for h in got_headers), name
    for method in ("GET", "OPTIONS", "DELETE", "PUT"):
        status, headers, _ = _call(server, method=method, Authorization=auth)
        assert status == 405 and "Access-Control-Allow-Origin" not in headers, method
    too_long = {"Content_Length": str(MAX_BODY + 1)}  # refused before the body is read
    assert _call(server, body=b"{}", Authorization=auth, **too_long)[0] == 413
    assert _call(server, body=b"not json", Authorization=auth)[0] == 400
    assert idx.disclosures() == []


def test_the_gateway_binds_to_loopback_only(lib):
    _, _, session, _ = lib
    server = Gateway(session, policy=default_policy, port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
        assert server.url() == f"http://127.0.0.1:{server.port}/mcp"
    finally:
        server.server_close()


def test_the_command_has_a_loopback_form(tmp_path):
    from anagram.shell.cli import mcp as cli
    from anagram.shell.cli.main import build_parser, main

    args = build_parser().parse_args(["mcp", "--http", "--port", "0"])
    assert args.http and args.port == 0 and args.func is cli.cmd_mcp
    cmd = cli.http_command(tmp_path, 47830)
    assert cmd[-3:] == ["--http", "--port", "47830"] and "--assistant" not in cmd
    assert main(["--home", str(tmp_path), "mcp"]) == 2  # neither an id nor --http


def test_gateway_handles_concurrent_clients_and_rejects_expired_key_and_dup_host(gw):
    import socket

    server, idx = gw
    who = consent(idx)
    key = access.new_http_key(idx, who.id)
    auth = f"Bearer {key}"

    # An idle open socket must not block another client request (ThreadingHTTPServer).
    idle = socket.create_connection((LOOPBACK, server.port), timeout=5)
    try:
        status, _, got = _call(server, body=_search(), Authorization=auth)
        assert status == 200 and got["result"]["content"][0]["text"].startswith(HEADER)
    finally:
        idle.close()

    # Duplicate Host header must be rejected with 421.
    raw = (
        f"POST /mcp HTTP/1.1\r\n"
        f"Host: {LOOPBACK}:{server.port}\r\n"
        f"Host: evil.example\r\n"
        f"Authorization: {auth}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 2\r\n"
        f"Connection: close\r\n\r\n{{}}"
    ).encode()
    with socket.create_connection((LOOPBACK, server.port), timeout=5) as sock:
        sock.sendall(raw)
        resp = sock.recv(4096).decode("latin-1")
    assert resp.startswith("HTTP/1.1 421")

    # An expired grant key must be refused at HTTP auth (401).
    doc = idx.store.get_meta(access.META)
    for row in doc["grants"]:
        if row["id"] == who.id:
            row["expires"] = "2000-01-01"
    idx.store.set_meta(access.META, doc)
    assert _call(server, body=_search(), Authorization=auth)[0] == 401
