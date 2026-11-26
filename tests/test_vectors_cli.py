"""The vector makers treat `--help` as help, not as an output folder.

A run with `--help` once wrote a full vector set into `./--help/`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from anagram.vectors.cli import DEFAULT_DIR, output_dir

MAKERS = (
    "anagram.vectors.build",
    "anagram.vectors.net.build",
    "anagram.vectors.enclave_trust",
)


def test_default_and_explicit_folder() -> None:
    assert output_dir([], prog="t", description="d") == Path(DEFAULT_DIR)
    assert output_dir(["out"], prog="t", description="d") == Path("out")


def test_help_prints_and_exits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        output_dir(["--help"], prog="t", description="d")
    assert exc.value.code == 0
    assert "usage: t" in capsys.readouterr().out


def test_unknown_option_is_refused() -> None:
    with pytest.raises(SystemExit) as exc:
        output_dir(["--hepl"], prog="t", description="d")
    assert exc.value.code == 2


@pytest.mark.parametrize("module", MAKERS)
def test_maker_help_writes_nothing(module: str, tmp_path: Path) -> None:
    run = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", module, "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert run.returncode == 0, run.stderr
    assert "usage:" in run.stdout
    assert list(tmp_path.iterdir()) == []
