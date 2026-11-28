"""Time text: RFC 3339 UTC with whole seconds, for example 2026-10-15T12:00:00Z.

The locked formats use `format_time` and `parse_time` (strict). Local state,
status, and UI data use the epoch helpers.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, overload

from anagram.core.errors import FormatError

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_TIME = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def format_time(dt: datetime) -> str:
    """RFC 3339 UTC with whole seconds. `dt` must be timezone-aware."""
    if dt.tzinfo is None:
        raise FormatError("time must be timezone-aware")
    return dt.astimezone(UTC).replace(microsecond=0).strftime(TIME_FORMAT)


def parse_time(s: str) -> datetime:
    if not isinstance(s, str) or not _TIME.match(s):
        raise FormatError(f"bad time: {s!r}")
    try:
        return datetime.strptime(s, TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise FormatError(f"bad time: {s!r}") from exc


def iso_seconds(t: float) -> str:
    """Epoch seconds as time text (the fraction is dropped)."""
    return datetime.fromtimestamp(int(t), UTC).strftime(TIME_FORMAT)


def iso_or_none(t: float | None) -> str | None:
    return None if t is None else iso_seconds(t)


def epoch_text(value: Any) -> Any:
    """A node time in epoch seconds as time text. Other values stay as they are."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return iso_seconds(value)
    return value


def seconds(text: str) -> float:
    """Time text as epoch seconds. Raises ValueError for other text."""
    return datetime.strptime(text, TIME_FORMAT).replace(tzinfo=UTC).timestamp()


@overload
def seconds_or(text: str | None, default: float) -> float: ...


@overload
def seconds_or(text: str | None, default: None = None) -> float | None: ...


def seconds_or(text: str | None, default: float | None = None) -> float | None:
    """Time text as epoch seconds, or `default` for no text or other text."""
    if not text:
        return default
    try:
        return seconds(text)
    except ValueError:
        return default
