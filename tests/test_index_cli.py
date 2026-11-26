"""`python -m anagram.shell.cli.index`: add, scan, checkpoint, drafts. No network."""

from __future__ import annotations

import pytest

from anagram.shell.cli.index import main
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")


def test_cli_flow(tmp_path, capsys):
    home = tmp_path / "home"
    Client.init(home)
    root = tmp_path / "lab"
    root.mkdir()
    (root / "plan.md").write_text(
        "# Plan\n\n## Need\n\n- Statistics help\n\n## Offer\n\n- GPU hours\n"
    )
    h = ["--home", str(home)]
    assert main([*h, "add-folder", str(root)]) == 0
    sid = capsys.readouterr().out.strip()
    main([*h, "scan"])
    assert "new 1" in capsys.readouterr().out
    main([*h, "checkpoint"])
    assert f"{sid}: checkpoint 0 (1 items)" in capsys.readouterr().out
    main([*h, "checkpoint"])
    assert capsys.readouterr().out == ""  # nothing new
    main([*h, "draft-findings"])
    assert "(1 items)" in capsys.readouterr().out
    main([*h, "sources"])
    assert "seq=1" in capsys.readouterr().out
    assert Client(home).findings.list_findings() == []
    (root / "blob.bin").write_bytes(b"\x00\x01binary")
    main([*h, "scan"])
    capsys.readouterr()
    main([*h, "search", "statistics"])
    assert "plan.md" in capsys.readouterr().out
    main([*h, "skipped"])
    assert "blob.bin  application/octet-stream: no converter reads" in capsys.readouterr().out
