"""CLI: node init, node invite, join (fake ORCID), whoami, keys, labs, devices, recover.

The HTTP transport is a FastAPI TestClient, so no network is used.
"""

import json

from fastapi.testclient import TestClient

from anagram.core import nodeapi
from anagram.core.nodeapi import NodeHTTPError
from anagram.shell.cli.main import main
from anagram.shell.node.home import NodeHome


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def wire(monkeypatch, node_dir):
    tc = TestClient(NodeHome(node_dir).app(), base_url="http://127.0.0.1:8787")

    def transport_for(base_url):
        def call(method, path, body, headers):
            r = tc.request(method, path, json=body, headers=headers)
            if r.status_code >= 400:
                raise NodeHTTPError(r.status_code, r.json().get("detail", ""))
            return r.json()

        return call

    def fetch(url):
        r = tc.get(url, follow_redirects=False)
        return r.status_code, r.headers.get("location")

    monkeypatch.setattr(nodeapi, "urllib_transport", transport_for)
    monkeypatch.setattr("anagram.identity.api.urllib_fetch", fetch)
    return tc


def test_node_init_requires_orcid_credentials(tmp_path, capsys):
    nd = str(tmp_path / "node")
    code, _, err = run(
        capsys, "node", "--node-dir", nd, "init", "--domain", "anagram.example.org", "-y"
    )
    assert code == 1 and "orcid-client-id" in err
    code, out, err = run(
        capsys,
        "node",
        "--node-dir",
        nd,
        "init",
        "--domain",
        "anagram.example.org",
        "--community",
        "Example",
        "--orcid-mode",
        "sandbox",
        "--orcid-client-id",
        "APP-1",
        "--orcid-client-secret",
        "s3cret",
        "-y",
    )
    assert code == 0, err
    assert "https://anagram.example.org/auth/orcid/callback" in out
    cfg = json.loads((tmp_path / "node" / "node.json").read_text())
    assert cfg["orcid"] == {"client_id": "APP-1", "mode": "sandbox"}
    assert cfg["origin"] == "anagram.example.org/log-v2"  # v2: person IDs in the log
    assert "s3cret" not in (tmp_path / "node" / "node.json").read_text()
    assert NodeHome(tmp_path / "node").orcid_client_secret() == "s3cret"
    code, _, err = run(capsys, "node", "--node-dir", nd, "init", "-y")
    assert code == 1 and "exists" in err


def test_cli_join_flow(tmp_path, capsys, monkeypatch):
    nd = str(tmp_path / "node")
    code, out, err = run(
        capsys,
        "node",
        "--node-dir",
        nd,
        "init",
        "--domain",
        "127.0.0.1:8787",
        "--community",
        "Local test",
        "-y",
    )
    assert code == 0 and "ORCID mode: fake" in out, err
    wire(monkeypatch, tmp_path / "node")
    code, link, _ = run(capsys, "node", "--node-dir", nd, "invite")
    assert code == 0 and "/join#" in link

    home = str(tmp_path / "alice")
    join = ("--home", home, "join", link.strip(), "--fake-orcid", "fake-alice", "--name", "A")
    # A kit file in the data directory is refused before the sign-in starts.
    code, _, err = run(capsys, *join, "--kit-file", str(tmp_path / "alice" / "kit.md"))
    assert code == 1 and "outside the Anagram data directory" in err
    assert not (tmp_path / "alice").exists()
    kit = tmp_path / "alice-kit.md"
    code, out, err = run(capsys, *join, "--kit-file", str(kit))
    assert code == 0, err
    alice = out.split("Signed in as ")[1].split()[0]
    assert alice.startswith("pid:") and "Recovery code:" in out
    assert f"Recovery kit: {kit}" in out and kit.stat().st_mode & 0o777 == 0o600
    assert out.split("Recovery code: ")[1].split()[0] in kit.read_text()
    assert not (tmp_path / "alice" / "recovery-kit.md").exists()
    assert "ORCID iD: fake-alice" in out

    code, out, _ = run(capsys, "--home", home, "whoami")
    assert code == 0 and json.loads(out)["subject"] == alice
    code, out, _ = run(capsys, "--home", home, "keys", "lookup", alice)
    assert code == 0 and json.loads(out)["subject"] == alice
    # By ORCID iD only after Alice turns on "findable by ORCID".
    code, _, err = run(capsys, "--home", home, "keys", "lookup", "fake-alice")
    assert code == 1 and "findable" in err
    code, out, _ = run(capsys, "--home", home, "findable", "on")
    assert code == 0 and "on" in out
    code, out, _ = run(capsys, "--home", home, "keys", "lookup", "fake-alice")
    assert code == 0 and json.loads(out)["subject"] == alice
    code, out, _ = run(capsys, "--home", home, "keys", "monitor")
    assert code == 0 and "No unexpected keys" in out

    code, out, _ = run(capsys, "--home", home, "lab", "create", "Alice Lab")
    assert code == 0
    lab_id = out.split()[1].rstrip(":")

    _, link2, _ = run(capsys, "node", "--node-dir", nd, "invite")
    bob = str(tmp_path / "bob")
    code, out, err = run(capsys, "--home", bob, "join", link2.strip(), "--fake-orcid", "fake-bob")
    assert code == 0, err
    bob_pid = out.split("Signed in as ")[1].split()[0]
    code, out, _ = run(capsys, "--home", home, "lab", "add", lab_id, bob_pid)
    assert code == 0 and bob_pid in out
    code, _, err = run(capsys, "--home", bob, "lab", "add", lab_id, "fake-alice")
    assert code == 1 and "not in the lab" in err  # the client checks the roster rule

    # Second device for Alice, approved from the first.
    laptop = str(tmp_path / "alice2")
    code, out, _ = run(capsys, "--home", laptop, "join", link.strip(), "--fake-orcid", "fake-alice")
    assert code == 3
    request = out.split("anagram device add ")[1].split()[0]
    code, out, _ = run(capsys, "--home", home, "device", "add", request)
    assert code == 0
    code, out, _ = run(capsys, "--home", laptop, "join", link.strip(), "--fake-orcid", "fake-alice")
    assert code == 0
    # With no --kit-file, the command shows the code and writes no kit file.
    assert "Recovery code:" in out and "Recovery kit: not written" in out
    assert not list((tmp_path / "alice2").rglob("*kit*"))

    # Recovery on a new computer.
    code, out, err = run(capsys, "--home", str(tmp_path / "alice3"), "recover", str(kit))
    assert code == 0 and f"Keys restored for {alice}" in out, err
    assert "Personal store:" in out

    # Logout ends the session on the node and on this device.
    code, out, _ = run(capsys, "--home", laptop, "logout")
    assert code == 0 and "Signed out" in out
    code, _, err = run(capsys, "--home", laptop, "whoami")
    assert code != 0
    # Sign in again without an invite.
    code, out, err = run(capsys, "--home", laptop, "login", "--fake-orcid", "fake-alice")
    assert code == 0 and f"Signed in again as {alice}" in out, err
    code, out, _ = run(capsys, "--home", laptop, "whoami")
    assert code == 0 and json.loads(out)["subject"] == alice
    code, _, err = run(capsys, "--home", laptop, "login", "--fake-orcid", "fake-mallory")
    assert code == 1 and "403" in err
