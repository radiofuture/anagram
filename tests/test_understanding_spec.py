"""The understanding entries of "What leaves this computer" and the threat
model section 17."""

from __future__ import annotations

import re
from pathlib import Path

from anagram.gateway import access
from anagram.shell.ui.flows import FLOWS

ROOT = Path(__file__).resolve().parents[1]
BY_ID = {f["id"]: f for f in FLOWS}


def test_the_model_and_assistant_flows():
    model, assistant = BY_ID["model-provider"], BY_ID["assistant"]
    for f in (model, assistant):
        assert set(f) == {"id", "to", "what", "when", "can_see"}
        assert "other people wrote" in f["what"]
    assert "off by default" in model["to"] and "local model" in model["can_see"]
    assert f"{access.DAILY_CHARS:,}" in assistant["when"]
    assert "lab permits" in assistant["when"]
    text = " ".join(" ".join(f.values()) for f in (model, assistant))
    for word in ("MCP", "API", "token", "profile", "keystore", "stdio"):
        assert word not in text, word


def _section(text: str, number: int) -> str:
    start = text.index(f"\n## {number}. ")
    end = text.index(f"\n## {number + 1}. ", start)
    return text[start:end]


def test_each_test_of_threat_model_section_17_exists():
    section = _section((ROOT / "spec" / "threat-model.md").read_text(), 17)
    names = set()
    for cell in re.findall(r"^\|[^\n]*\| ([^|\n]*test_[^|\n]*) \|$", section, re.M):
        current = None
        for part in re.findall(r"`([^`]+)`", cell):
            if "::" in part:
                current, name = part.split("::")
            else:
                name = part
            assert current is not None, part
            names.add((current, name))
    assert len(names) >= 20
    for file, name in sorted(names):
        source = (ROOT / "tests" / file).read_text()
        assert f"def {name}(" in source, f"{file}::{name}"
