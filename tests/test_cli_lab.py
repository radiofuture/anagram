"""CLI `anagram lab ...`. The node is the in-process test
node; no network."""

from __future__ import annotations

import pytest

from anagram.core import nodeapi
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.shell.cli import lab as cli_lab
from anagram.shell.cli.main import main
from anagram.shell.client import Client


@pytest.fixture
def cli(net, monkeypatch):
    """`run(home, *argv) -> (code, out, err)` with the clock of the node."""
    monkeypatch.setattr(nodeapi, "urllib_transport", lambda base_url: net.transport)
    monkeypatch.setattr(cli_lab, "Client", lambda home: Client(home, clock=net.clock))

    def run(capsys, home, *argv):
        code = main(["--home", str(home), "lab", *argv])
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


@pytest.fixture
def people(net, tmp_path):
    pi = tmp_path / "cli-pi"
    other = tmp_path / "cli-other"
    net.join(pi, "fake-cli-pi")
    b = net.join(other, "fake-cli-other").client
    return pi, other, b


def test_create_list_show_invite_and_join(net, cli, people, capsys, tmp_path):
    pi, other, b = people
    code, out, err = cli(capsys, pi, "create", "Cli Lab")
    assert code == 0, err
    lab_id = out.split()[1].rstrip(":")
    assert out.strip() == f"Lab {lab_id}: Cli Lab"
    code, out, _ = cli(capsys, pi, "list")
    assert code == 0 and lab_id in out and "Cli Lab  pi  1 members" in out
    code, out, _ = cli(capsys, pi, "invite", "Cli Lab", "--uses", "2", "--days", "3")
    assert code == 0
    url = out.splitlines()[0]
    assert "/join#" in url and "Each person with this link can join" in out
    joiner = net.join(tmp_path / "cli-joiner", "fake-cli-joiner", invite=url).client
    code, out, _ = cli(capsys, pi, "show", lab_id)
    assert code == 0 and f"{joiner.device.subject} (member)" in out and "Your role: pi" in out
    assert "1 of 2 used" in out
    iid = out.split("Invite ")[1].split(":")[0]
    code, out, _ = cli(capsys, pi, "revoke", lab_id, iid)
    assert code == 0 and "does not work now" in out
    # A node member joins with the link: the link was revoked.
    code, _, err = cli(capsys, other, "join", url)
    assert code == 1 and "no longer valid" in err
    code, out, _ = cli(capsys, pi, "invite", lab_id)
    code, out, err = cli(capsys, other, "join", out.splitlines()[0])
    assert code == 0 and "as member" in out, err


def test_add_and_use_behave_as_before(cli, people, capsys):
    pi, other, b = people
    lab_id = cli(capsys, pi, "create", "Old Lab")[1].split()[1].rstrip(":")
    code, out, _ = cli(capsys, pi, "add", lab_id, b.device.subject)
    assert code == 0 and out.startswith(f"Lab {lab_id} members: ") and b.device.subject in out
    code, _, err = cli(capsys, other, "add", lab_id, b.device.subject)
    assert code == 1 and err  # a member cannot add (the client checks the roster)
    code, out, _ = cli(capsys, pi, "use", lab_id)
    assert code == 0 and f"lab {lab_id}" in out


def test_roles_remove_leave_transfer_rename_rotate(cli, people, capsys):
    pi, other, b = people
    lab_id = cli(capsys, pi, "create", "Role Lab")[1].split()[1].rstrip(":")
    cli(capsys, pi, "add", lab_id, b.device.subject)
    code, out, _ = cli(capsys, pi, "role", lab_id, b.device.subject, "admin")
    assert code == 0 and f"{b.device.subject} (admin)" in out
    code, _, err = cli(capsys, pi, "leave", lab_id)
    assert code == 1 and "You are the PI" in err
    code, out, _ = cli(capsys, pi, "rename", lab_id, "Renamed Lab")
    assert code == 0 and "name changed" in out
    code, out, _ = cli(capsys, pi, "rotate", "Renamed Lab")
    assert code == 0 and "epoch 2" in out
    code, out, _ = cli(capsys, pi, "transfer", lab_id, b.device.subject)
    assert code == 0 and f"{b.device.subject} (pi)" in out
    code, out, _ = cli(capsys, other, "remove", lab_id, Client(pi).device.subject)
    assert code == 0 and "lab key changed" in out
    code, out, _ = cli(capsys, other, "show", lab_id)
    assert "Key epoch: 3" in out
    code, out, _ = cli(capsys, pi, "sync")
    assert code == 0 and "you are not in this lab now" in out


def test_publish_sync_and_items(cli, people, capsys, tmp_path):
    pi, other, b = people
    lab_id = cli(capsys, pi, "create", "Space Lab")[1].split()[1].rstrip(":")
    cli(capsys, pi, "add", lab_id, b.device.subject)
    code, out, _ = cli(capsys, other, "items", lab_id)
    assert code == 0 and "no items" in out
    root = tmp_path / "files"
    root.mkdir()
    (root / "result.md").write_text("# Gel result\n\nThe gel shows two bands at 40 kDa.\n")
    idx = LocalIndex.for_client(Client(pi))
    try:
        sid = idx.add_source(FolderConnector(root))
        idx.scan()
        key = idx.items(sid)[0].key
    finally:
        idx.close()
    code, out, err = cli(capsys, pi, "publish", lab_id, sid, key)
    assert code == 0 and "In the lab space:" in out, err
    code, out, _ = cli(capsys, other, "sync")
    assert code == 0 and f"{lab_id}: 1 new items, key epoch 1" in out
    assert "Index: 1 lab sources" in out
    code, out, _ = cli(capsys, other, "items", lab_id)
    assert code == 0 and "Gel result" in out
    idx = LocalIndex.for_client(Client(other))
    try:
        assert idx.search("gel bands")
    finally:
        idx.close()
    code, out, _ = cli(capsys, other, "leave", lab_id)
    assert code == 0 and "You left the lab" in out
    code, out, _ = cli(capsys, other, "list")
    assert "You are in no lab" in out
