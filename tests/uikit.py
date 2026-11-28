"""Helpers for the browser tests of the local UI.

- `copy(key, **params)`: the text that the page shows for a copy key, from
  the same files (`ui/static/copy/*.json`). A test finds elements by this
  text, so a change of the copy does not break the tests.
- `ready(page, screen)`: wait until the screen has its data
  (`main[data-screen=...][data-state=ready]`). No test waits on time.
- `until(page, script)`: wait until a script is true (for example the
  scroll position).
- `clean(page)`: collect the faults of a page: page errors, console errors,
  and responses with a status of 500 or more. A refused request (4xx) is part
  of some flows (for example the 409 that asks to confirm other people's
  words), so the console line of the browser for it is not a fault.
"""

from __future__ import annotations

import json
import re
import time
from functools import cache
from pathlib import Path

COPY_DIR = Path(__file__).resolve().parents[1] / "src/anagram/shell/ui/static/copy"


@cache
def _copy() -> dict:
    return {
        f.stem: json.loads(f.read_text(encoding="utf-8")) for f in sorted(COPY_DIR.glob("*.json"))
    }


def copy(key: str, **params) -> str:
    """The text of one copy key with its parameters, as `t()` in core/copy.js.
    A key can name a nested object (`common.picker.pick`)."""
    value: object = _copy()
    for part in key.split("."):
        value = value[part]
    if isinstance(value, dict):
        value = value["one"] if params.get("n") == 1 else value["other"]
    return re.sub(r"\{(\w+)\}", lambda m: str(params.get(m.group(1), m.group(0))), value)


def ready(page, screen: str, timeout: float = 30000) -> None:
    page.wait_for_selector(f'main[data-screen="{screen}"][data-state="ready"]', timeout=timeout)


def until(page, script: str, timeout: float = 10.0) -> None:
    """Wait until a script is true. `page.wait_for_function` uses eval, which
    the CSP of the page refuses; `page.evaluate` does not."""
    end = time.monotonic() + timeout
    while not page.evaluate(script):
        if time.monotonic() > end:
            raise AssertionError(f"not true in {timeout} s: {script}")
        page.evaluate("new Promise((done) => requestAnimationFrame(() => done()))")


def clean(page) -> list[str]:
    faults: list[str] = []
    page.on("pageerror", lambda e: faults.append(f"pageerror: {e}"))

    def console(m) -> None:
        if m.type == "error" and not m.text.startswith("Failed to load resource"):
            faults.append(f"console: {m.text}")

    page.on("console", console)
    page.on(
        "response",
        lambda r: faults.append(f"{r.status} {r.request.method} {r.url}")
        if r.status >= 500
        else None,
    )
    return faults
