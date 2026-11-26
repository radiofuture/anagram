"""The self test of a packaged build and the program of the packaged app
(R1 plan, step S10). The packaged build itself is made by
packaging/macos/build.sh, not by the test suite."""

from __future__ import annotations

import importlib.util
import plistlib
import zipfile
from io import BytesIO
from pathlib import Path

from anagram.shell.app import selftest
from anagram.shell.cli.main import main

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"


def _entry():
    spec = importlib.util.spec_from_file_location("anagram_entry", PACKAGING / "entry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_selftest_passes_here(capsys):
    assert selftest.run() == 0
    out = capsys.readouterr().out.splitlines()
    assert out[-1] == "selftest passed"
    assert [line.split()[1] for line in out[:-1]] == [name for name, _ in selftest.CHECKS]


def test_selftest_reports_a_failed_check(monkeypatch):
    def broken(home):
        raise RuntimeError("no sqlite-vec")

    monkeypatch.setattr(selftest, "CHECKS", [("index", broken), ("keys", selftest._keys)])
    lines: list[str] = []
    assert selftest.run(lines.append) == 1
    assert lines == [
        "FAIL index: RuntimeError: no sqlite-vec",
        lines[1],
        "selftest failed: 1 of 2",
    ]
    assert lines[1].startswith("ok   keys")


def test_selftest_command(monkeypatch):
    monkeypatch.setattr(selftest, "CHECKS", [("keys", selftest._keys)])
    assert main(["app", "selftest"]) == 0


def test_selftest_files_are_complete():
    with zipfile.ZipFile(BytesIO(selftest.docx_bytes("x"))) as zf:
        assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml"} <= set(zf.namelist())
    pdf = selftest.pdf_bytes("x")
    assert pdf.startswith(b"%PDF-1.4") and b"startxref" in pdf and pdf.endswith(b"%%EOF\n")


def test_entry_arguments():
    arguments = _entry().arguments
    assert arguments([]) == ["open"]
    assert arguments(["-psn_0_12345"]) == ["open"]
    assert arguments(["anagram://open"]) == ["open-url", "anagram://open"]
    assert arguments(["--home", "/h", "app", "run"]) == ["--home", "/h", "app", "run"]
    assert arguments(["open-url", "anagram://open"]) == ["open-url", "anagram://open"]


def test_info_plist_registers_the_scheme_and_no_dock_icon():
    info = plistlib.loads((PACKAGING / "macos" / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == "org.radiofuture.anagram"
    assert info["LSUIElement"] is True
    schemes = [s for t in info["CFBundleURLTypes"] for s in t["CFBundleURLSchemes"]]
    assert schemes == ["anagram"]


def test_spec_names_the_entry_and_the_plist():
    text = (PACKAGING / "anagram.spec").read_text()
    assert '"entry.py"' in text and '"Info.plist"' in text
    assert "argv_emulation" in text and "ANAGRAM_NO_BUNDLE" in text
