"""The version has one source: `anagram.core.version.VERSION`. The build
(hatch), the package and the installed metadata read it."""

from __future__ import annotations

import tomllib
from importlib.metadata import version
from pathlib import Path

import anagram
from anagram.core.version import VERSION

PRODUCT = Path(__file__).resolve().parents[1]


def test_pyproject_reads_the_version_from_core():
    doc = tomllib.loads((PRODUCT / "pyproject.toml").read_text())
    assert "version" not in doc["project"]
    assert doc["project"]["dynamic"] == ["version"]
    assert doc["tool"]["hatch"]["version"]["path"] == "src/anagram/core/version.py"


def test_every_reader_gives_the_same_version():
    assert anagram.__version__ == VERSION
    assert version("anagram") == VERSION  # the installed metadata (uv sync)
