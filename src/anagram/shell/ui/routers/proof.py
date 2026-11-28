"""Proof routes of the local UI (certificate, verify page, preprint).

    GET /api/findings/{root}/certificate?claim=1&files=1&digests=1&name=1
        The proof certificate (one HTML file) as a download. Each flag is
        "1" (show, the default) or "0" (do not open that part).
    GET    /api/findings/{root}/public-proof   -> {url, available}; url is null when not
        published; available is false when the node has no public proof page
    POST   /api/findings/{root}/public-proof   {claim, files, digests} -> {url}
    DELETE /api/findings/{root}/public-proof   -> {url: null}
        A public link to the proof (not the files) on the verify page of the
        node (`proofs/node/verify_page.py`). Off by default for each finding.
    POST   /api/findings/{root}/preprint   {include_files, abstract, authors} -> zip download
        The preprint draft of the finding and its included findings.

The routes are in their own module, not in `sharing.py`, so that the
sharing work and the proof work do not edit one file. All
routes are under the cookie guard of `shell/ui/server.py`.
"""

from __future__ import annotations

from fastapi import Body, FastAPI
from fastapi.responses import Response

from anagram.core.nodeapi import NodeHTTPError
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.routers import UIContext

NOT_COMPLETE = "The proof of this finding is not complete yet. Try again in a few minutes."
NO_NODE = "A public link needs a community server. This computer has none."
NO_PAGE = "Your community server has no public proof page."


MAX_AUTHORS = 100
MAX_ABSTRACT = 5000
AUTHORS_BAD = "Write each author as a name, then the ORCID iD if there is one."
ABSTRACT_LONG = f"Keep the abstract to {MAX_ABSTRACT} characters."


def _authors(value) -> list[dict] | None:
    """The authors that the page sends ([{name, orcid}]), or None for the
    default (the owner). A name is necessary; affiliation is not asked."""
    if value is None:
        return None
    if not isinstance(value, list) or not value or len(value) > MAX_AUTHORS:
        raise UIError(400, AUTHORS_BAD)
    out = []
    for a in value:
        name = a.get("name") if isinstance(a, dict) else None
        orcid = a.get("orcid") if isinstance(a, dict) else None
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise UIError(400, AUTHORS_BAD)
        if orcid is not None and (not isinstance(orcid, str) or len(orcid) > 40):
            raise UIError(400, AUTHORS_BAD)
        out.append({"affiliation": None, "name": name.strip(), "orcid": orcid or None, "ror": None})
    return out


def _flag(value: str | None) -> bool:
    return value != "0"


def download(name: str, body: str | bytes, media_type: str) -> Response:
    return Response(
        body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


def register(app: FastAPI, ctx: UIContext) -> None:
    @app.get("/api/findings/{root}/certificate")
    def certificate(
        root: str,
        claim: str | None = None,
        files: str | None = None,
        digests: str | None = None,
        name: str | None = None,
    ) -> Response:
        from anagram.proofs.certificate import make_certificate

        with ctx.service.session() as c:
            fname, text, report = make_certificate(
                c,
                root,
                claim=_flag(claim),
                files=_flag(files),
                digests=_flag(digests),
                name=_flag(name),
            )
        if not report.ok:
            raise UIError(409, NOT_COMPLETE)
        return download(fname, text, "text/html; charset=utf-8")

    def public(c, root: str) -> tuple[str | None, bool]:
        """(url, available). A node with `verify.public_page` false has no
        `/proofs` route: its 404 is the plain "Not Found" of the framework,
        not the "no published proof" answer of the verify page."""
        try:
            c.device.http.call("GET", f"/proofs/{root}")
        except NodeHTTPError as exc:
            if exc.status == 404:
                return None, exc.detail != "Not Found"
            raise
        return c.config["node"]["url"].rstrip("/") + f"/verify/{root}", True

    def member_client(c):
        if (c.config.get("node") or {}).get("mode") != "http":
            raise UIError(409, NO_NODE)
        return c

    @app.get("/api/findings/{root}/public-proof")
    def public_proof(root: str) -> dict:
        """-> {url, available}. `available` is false when the node has no
        public proof page (or there is no node): the page then does not
        offer a public link."""
        with ctx.service.session() as c:
            row = c.vault.find(root)
            if (c.config.get("node") or {}).get("mode") != "http":
                return {"available": False, "url": None}
            url, available = public(c, row.root)
            return {"available": available, "url": url}

    @app.post("/api/findings/{root}/public-proof")
    def publish_proof(root: str, body: dict = Body(default={})) -> dict:
        from anagram.proofs.certificate import certificate_bundle

        opts = body if isinstance(body, dict) else {}
        with ctx.service.session() as c:
            row = member_client(c).vault.find(root)
            try:
                c.findings.refresh_anchors(row.root)
            except Exception:  # noqa: S110 - the proof is valid without new anchors
                pass
            bundle = certificate_bundle(
                c,
                row.root,
                claim=opts.get("claim", True) is not False,
                files=opts.get("files", True) is not False,
                digests=opts.get("digests", True) is not False,
            )
            try:
                out = c.device.http.call("POST", "/proofs", {"bundle": bundle.to_json()}, auth=True)
            except NodeHTTPError as exc:
                if exc.status == 404:
                    raise UIError(409, NO_PAGE) from exc
                if exc.status == 400:
                    raise UIError(409, NOT_COMPLETE) from exc
                raise
        return {"url": out["url"]}

    @app.delete("/api/findings/{root}/public-proof")
    def unpublish_proof(root: str) -> dict:
        with ctx.service.session() as c:
            row = member_client(c).vault.find(root)
            try:
                c.device.http.call("DELETE", f"/proofs/{row.root}", auth=True)
            except NodeHTTPError as exc:
                if exc.status != 404:
                    raise
        return {"url": None}

    @app.post("/api/findings/{root}/preprint")
    def preprint(root: str, body: dict = Body(default={})) -> Response:
        import tempfile
        from pathlib import Path

        from anagram.proofs.preprint import build_preprint, preprint_name

        opts = body if isinstance(body, dict) else {}
        abstract = opts.get("abstract") if isinstance(opts.get("abstract"), str) else None
        if abstract is not None and len(abstract) > MAX_ABSTRACT:
            raise UIError(400, ABSTRACT_LONG)
        authors = _authors(opts.get("authors"))
        with tempfile.TemporaryDirectory() as tmp, ctx.service.session() as c:
            row = c.vault.find(root)
            name = preprint_name(row.root)
            out = build_preprint(
                c,
                row.root,
                Path(tmp) / name,
                include_files=opts.get("include_files", True) is not False,
                abstract=abstract,
                authors=authors,
            )
            data = out.read_bytes()
        return download(name, data, "application/zip")
