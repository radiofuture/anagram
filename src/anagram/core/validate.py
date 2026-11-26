"""Field validators for the locked formats. Each raises `FormatError`."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from anagram.core.canonical import JsonObject
from anagram.core.errors import FormatError

HEX16 = re.compile(r"^[0-9a-f]{32}$")
HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{128}$")


def exact_fields(obj: Any, names: Iterable[str], what: str) -> JsonObject:
    """`obj` is a dict with exactly the fields `names`."""
    if not isinstance(obj, dict) or set(obj) != set(names):
        raise FormatError(f"{what}: fields do not match the schema")
    return obj


def hex_field(value: Any, pattern: re.Pattern[str], what: str) -> str:
    """Lowercase hex text that matches `pattern` (for example `HEX32`)."""
    if not isinstance(value, str) or not pattern.match(value):
        raise FormatError(f"{what}: bad hex")
    return value


def int_in(value: Any, lo: int, hi: int, what: str) -> int:
    """An integer (not a bool) from `lo` to `hi`."""
    if type(value) is not int or not lo <= value <= hi:
        raise FormatError(f"{what}: integer out of range")
    return value


def int_at_least(value: Any, what: str, low: int = 0) -> int:
    """An integer (not a bool) of `low` or more."""
    if type(value) is not int or value < low:
        raise FormatError(f"{what}: expected an integer >= {low}")
    return value
