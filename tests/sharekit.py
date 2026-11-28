"""Test helpers for sharing: a community node with the read
ledger, members, and small findings. No network."""

from __future__ import annotations

from pathlib import Path

from conftest import make_net
from fastapi.testclient import TestClient

from anagram.shell.node.app import create_app


def make_share_net(tmp_path: Path, **create):
    """`make_net` with the read ledger and the reader invites on the node,
    as `NodeHome.app_parts` builds them. `net.reads` is the ledger;
    `net.reader_invites` the invites."""
    net = make_net(tmp_path, **create)
    reads = net.home.reads(net.identity, net.vault)
    reader_invites = net.home.reader_invites(net.identity)
    app = create_app(
        net.service,
        net.home.trust_info(),
        net.identity,
        vault=net.vault,
        store=net.store,
        reads=reads,
        labs=net.labs,
        reader_invites=reader_invites,
        admission=net.admission,
    )
    net.tc = TestClient(app, base_url=str(net.tc.base_url))
    net.reads = reads
    net.reader_invites = reader_invites
    return net


def people(net, tmp_path: Path, *names: str) -> dict:
    """Join each person (ORCID iD `fake-<name>`) and return their clients."""
    return {n: net.join(tmp_path / n, f"fake-{n}", n.title()).client for n in names}


def commit(client, tmp_path: Path, files: dict[str, bytes], claim: str = "A result", **kw):
    """Write the files and commit one finding. Return its root (hex)."""
    folder = tmp_path / f"files-{client.device.subject[-8:]}-{len(list(tmp_path.glob('files-*')))}"
    folder.mkdir()
    paths = []
    for name, data in files.items():
        p = folder / name
        p.write_bytes(data)
        paths.append(p)
    bundle = client.findings.commit_finding(paths, claim=claim, **kw)
    return bundle.subject.root.hex()
