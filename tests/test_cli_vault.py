"""CLI (P3b): rings, grant, inbox, open, publish, guardians.

The HTTP transport is a FastAPI TestClient, so no network is used.
"""

import json

from fastapi.testclient import TestClient

from anagram.core import nodeapi
from anagram.core.nodeapi import NodeHTTPError
from anagram.shell.cli.main import main
from anagram.shell.client import Client
from anagram.shell.node.home import NodeHome


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def wire(monkeypatch, node_dir):
    tc = TestClient(NodeHome(node_dir).app(), base_url="http://127.0.0.1:8787")

    def transport_for(base_url):
        def call(method, path, body, headers):
            if isinstance(body, bytes):
                r = tc.request(method, path, content=body, headers=headers)
            else:
                r = tc.request(method, path, json=body, headers=headers)
            if r.status_code >= 400:
                raise NodeHTTPError(r.status_code, r.json().get("detail", ""))
            if r.headers.get("content-type", "").startswith("application/octet-stream"):
                return r.content
            return r.json()

        return call

    def fetch(url):
        r = tc.get(url, follow_redirects=False)
        return r.status_code, r.headers.get("location")

    monkeypatch.setattr(nodeapi, "urllib_transport", transport_for)
    monkeypatch.setattr("anagram.identity.api.urllib_fetch", fetch)
    return tc


def test_cli_vault_and_guardians(tmp_path, capsys, monkeypatch):
    nd = str(tmp_path / "node")
    code, _, err = run(capsys, "node", "--node-dir", nd, "init", "--domain", "127.0.0.1:8787", "-y")
    assert code == 0, err
    wire(monkeypatch, tmp_path / "node")
    homes = {}
    for name in ("alice", "bob", "carol"):
        _, link, _ = run(capsys, "node", "--node-dir", nd, "invite")
        homes[name] = str(tmp_path / name)
        code, _, err = run(
            capsys,
            "--home",
            homes[name],
            "join",
            link.strip(),
            "--fake-orcid",
            f"fake-{name}",
            "--name",
            name.title(),
            "--institution",
            f"fake-ror-{name}",
        )
        assert code == 0, err
    a, b, c = homes["alice"], homes["bob"], homes["carol"]
    # Bob and Carol let members find them by ORCID iD (default off).
    pid = {}
    for name in ("alice", "bob", "carol"):
        if name != "alice":
            assert run(capsys, "--home", homes[name], "findable", "on")[0] == 0
        pid[name] = json.loads(run(capsys, "--home", homes[name], "whoami")[1])["subject"]

    # Commit, ring, grant (third-party gate), inbox, open.
    note = tmp_path / "note.txt"
    note.write_text("CANARY-CLI-0001 private result\n")
    proof = str(tmp_path / "note.proof.json")
    code, out, err = run(
        capsys, "--home", a, "commit", str(note), "--claim", "X binds Y", "--out", proof
    )
    assert code == 0, err
    root = out.split("Root: ")[1].split()[0]
    assert run(capsys, "--home", a, "ring", "create", "lab")[0] == 0
    assert run(capsys, "--home", a, "ring", "add", "lab", "fake-bob")[0] == 0
    code, out, _ = run(capsys, "--home", a, "ring", "list")
    assert f"lab: {pid['bob']}" in out
    Client(a).vault.flag_third_party(root, 0)
    code, _, err = run(capsys, "--home", a, "grant", root[:16], "--ring", "lab")
    assert code == 5 and "other people's words" in err
    code, out, err = run(
        capsys, "--home", a, "grant", root[:16], "--ring", "lab", "--ack-third-party"
    )
    assert code == 0 and f"Granted to {pid['bob']}" in out, err
    code, out, _ = run(capsys, "--home", b, "inbox")
    gid = out.split()[0]
    code, out, err = run(capsys, "--home", b, "open", gid, "--out", str(tmp_path / "bob-out"))
    assert code == 0 and "VALID finding" in out, err
    files = [p for p in (tmp_path / "bob-out").iterdir() if p.name.endswith("note.txt")]
    assert files and files[0].read_text() == note.read_text()
    code, out, _ = run(capsys, "--home", c, "inbox")
    assert "No grants." in out

    # Publish, then anyone opens the release.
    code, out, err = run(capsys, "--home", a, "publish", root[:16], "--ack-third-party")
    assert code == 0, err
    rid = out.split("release ")[1].split(".")[0]
    code, out, err = run(
        capsys, "--home", c, "open", rid, "--public", "--out", str(tmp_path / "carol-out")
    )
    assert code == 0 and "VALID" in out, err

    # Guardians: Bob and Carol, 2 of 2. Recover Alice on a new computer.
    code, out, err = run(
        capsys, "--home", a, "guardians", "set", "fake-bob", "fake-carol", "--threshold", "2"
    )
    assert code == 0, err
    _, link, _ = run(capsys, "node", "--node-dir", nd, "invite")
    new = str(tmp_path / "alice-new")
    code, out, err = run(
        capsys,
        "--home",
        new,
        "recover",
        "--guardians",
        "--invite",
        link.strip(),
        "--fake-orcid",
        "fake-alice",
    )
    assert code == 3, err
    req = out.split("Recovery request: ")[1].split()[0]
    code, out, _ = run(capsys, "--home", b, "guardians", "requests")
    assert req in out and "check: ok" in out
    assert run(capsys, "--home", b, "guardians", "approve", req, "--yes")[0] == 0
    code, _, err = run(capsys, "--home", new, "recover", "--guardians")
    assert code == 1 and "1 of 2" in err
    assert run(capsys, "--home", c, "guardians", "approve", req, "--yes")[0] == 0
    code, out, err = run(capsys, "--home", new, "recover", "--guardians")
    assert code == 0 and f"Keys restored for {pid['alice']}" in out, err
    assert "Personal store:" in out
