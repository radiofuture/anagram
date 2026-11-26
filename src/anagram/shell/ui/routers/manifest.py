"""`GET /api/ui/manifest` and `GET /api/ui/copy`: what the page loads.

The page finds its screens, slot modules, screen styles, and copy by
directory, so a track adds a file and edits no shared file:

    static/js/screens/<id>.js     a screen
    static/js/slots/<name>.js     a slot view with no screen
    static/css/screens/<id>.css   styles of one screen (optional)
    static/copy/<id>.json         the words of one screen or slot module

Both routes need the cookie (the guard of `shell/ui/server.py`).
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from pathlib import Path

from fastapi import FastAPI

from anagram.shell.ui.errors import UIError
from anagram.shell.ui.routers import UIContext

STATIC = Path(str(resources.files("anagram.shell.ui").joinpath("static")))
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
GROUPS = {
    "screens": ("js/screens", ".js"),
    "slots": ("js/slots", ".js"),
    "styles": ("css/screens", ".css"),
}


def _listing(static: Path, sub: str, suffix: str) -> list[Path]:
    folder = static / sub
    if not folder.is_dir():
        return []
    return sorted(
        (p for p in folder.iterdir() if p.is_file() and p.suffix == suffix and NAME.match(p.stem)),
        key=lambda p: p.name,
    )


def manifest(static: Path) -> dict:
    """The file names of each group, and `build`: a hash of the names and
    sizes. The page loads its modules again when `build` changes."""
    out: dict = {}
    digest = hashlib.sha256()
    for group, (sub, suffix) in GROUPS.items():
        files = _listing(static, sub, suffix)
        out[group] = [p.name for p in files]
        for p in files:
            digest.update(f"{group}/{p.name}:{p.stat().st_size}\n".encode())
    for p in _listing(static, "copy", ".json"):
        digest.update(f"copy/{p.name}:{p.stat().st_size}\n".encode())
    out["build"] = digest.hexdigest()
    return out


def copy(static: Path) -> dict:
    """The merge of `copy/*.json`, keyed by the file stem."""
    out = {}
    for p in _listing(static, "copy", ".json"):
        try:
            words = json.loads(p.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise UIError(500, f"The copy file {p.name} is not JSON.") from exc
        if not isinstance(words, dict):
            raise UIError(500, f"The copy file {p.name} is not an object.")
        out[p.stem] = words
    return out


def register(app: FastAPI, ctx: UIContext) -> None:
    @app.get("/api/ui/manifest")
    def ui_manifest() -> dict:
        return manifest(STATIC)

    @app.get("/api/ui/copy")
    def ui_copy() -> dict:
        return copy(STATIC)
