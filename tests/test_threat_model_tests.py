"""Every test that spec/threat-model.md names exists, so a claim never
points to a test of removed code. Like the link test, it reads names in
code spans: a test file (`test_x.py`), a test function (`test_y`), a file
and a function (`test_x.py::test_y`), or a prefix (`test_z_*`)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SPEC = ROOT / "spec" / "threat-model.md"
CODE_SPAN = re.compile(r"`([^`\n]*)`")
NAME = re.compile(r"(test_[A-Za-z0-9_*]+(?:\.py)?)(?:::(test_\w+))?")
DEF = re.compile(r"^\s*(?:async\s+)?def (test_\w+)", re.MULTILINE)


def _defined() -> tuple[set[str], dict[str, set[str]]]:
    """Test file names, and the test functions of each file."""
    by_file: dict[str, set[str]] = {}
    for path in TESTS.rglob("test_*.py"):
        by_file.setdefault(path.name, set()).update(DEF.findall(path.read_text("utf-8")))
    return set(by_file), by_file


def _missing(name: str, fn: str, files: set[str], by_file: dict[str, set[str]]) -> str | None:
    every = set().union(*by_file.values())
    if name.endswith(".py"):
        if name not in files:
            return name
        if fn and fn not in by_file[name]:
            return f"{name}::{fn}"
        return None
    if name.endswith("*"):
        return None if any(d.startswith(name[:-1]) for d in every) else name
    return None if name in every else name


def test_threat_model_names_tests():
    assert len(NAME.findall(SPEC.read_text("utf-8"))) > 100


def test_every_test_in_the_threat_model_exists():
    files, by_file = _defined()
    bad = []
    for n, line in enumerate(SPEC.read_text("utf-8").splitlines(), 1):
        for span in CODE_SPAN.findall(line):
            for name, fn in NAME.findall(span):
                miss = _missing(name, fn, files, by_file)
                if miss:
                    bad.append(f"line {n}: {miss}")
    assert not bad, bad
