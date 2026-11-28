"""Load the fixed data of the labelled sets from `sim/data/<name>.json`.

The data are nested lists of text in JSON. `load` gives them back as nested
tuples, the form that the modules gave before the data moved to JSON files.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any


def _tuples(value: object) -> object:
    if isinstance(value, list):
        return tuple(_tuples(v) for v in value)
    return value


def load(name: str) -> tuple[Any, ...]:
    text = resources.files("anagram.sim").joinpath("data", f"{name}.json").read_text("utf-8")
    out = _tuples(json.loads(text))
    if not isinstance(out, tuple):
        raise ValueError(f"fixture {name} is not a list")
    return out
