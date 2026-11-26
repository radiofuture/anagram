"""The brand for the node pages (`anagram.shell.pages`, shell).

GET /brand/node.css                   the layout of the node pages
GET /brand/node/<name>                the page scripts of `ui/static/node/`
GET /brand/*                          the unchanged brand copy
"""

from __future__ import annotations

import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from anagram.shell import pages

_NODE_FILE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}\.(js|css)$")


def mount_brand(app: FastAPI) -> None:
    """Add the brand routes. They come before the mount of `/brand`."""

    @app.get("/brand/node.css")
    def node_css() -> FileResponse:
        return FileResponse(pages.NODE_CSS, media_type="text/css")

    @app.get("/brand/node/{name}")
    def node_file(name: str) -> FileResponse:
        path = pages.NODE_DIR / name
        if not _NODE_FILE.match(name) or not path.is_file():
            raise HTTPException(404, "not found")
        kind = "text/javascript" if name.endswith(".js") else "text/css"
        return FileResponse(path, media_type=kind)

    app.mount("/brand", StaticFiles(directory=pages.BRAND_DIR), name="brand")
