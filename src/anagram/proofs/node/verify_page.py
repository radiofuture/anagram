"""Public verify page and published proofs.

| Route | Auth | Behaviour |
|---|---|---|
| `GET /verify` | none | The page. Drop a proof file or a certificate, and the files. |
| `GET /verify/{root}` | none | The same page; it loads the published proof of that root. |
| `GET /verify/assets/{name}` | none | The script and the style of the page (`web/verify/`). |
| `POST /verify` | none, rate limit by address | `{bundle}` or `{text}` -> the report of `verify_bundle` with the trust of this node. |
| `POST /proofs` | member | `{bundle}` -> `{url}`. The owner publishes a proof (not the content). |
| `GET /proofs/{root}` | none | `{bundle}` of a published proof. |
| `DELETE /proofs/{root}` | member (the one who published) | Stop the publication. |

The page computes the content digest of a dropped file in the browser and
compares it with the opened digests of the report. A file never goes to the
node. The node checks its own log only; the page says so one time and names
the command for an independent check.

Own file `proofs.sqlite`. A published proof is a public bundle: it has no
sealed opening, it verifies with the trust of this node, and a device of the
member signed it.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from anagram.core.errors import Forbidden, FormatError, NodeError, NotFound
from anagram.core.shared_db import SharedDB
from anagram.proofs.anchors.base import AnchorTrust
from anagram.proofs.anchors.defaults import bundled_tsa_roots
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.certificate import node_facts, proof_from_text, title_of
from anagram.proofs.log.note import NoteVerifier
from anagram.proofs.proof import Trust, VerifyReport, verify_bundle

WEB = Path(str(resources.files("anagram").joinpath("web", "verify")))
_ASSET = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\.(js|css)\Z")
_ROOT = re.compile(r"\A[0-9a-f]{64}\Z")
MAX_BODY = 4 << 20  # a bundle is small; a certificate holds the font
PER_MINUTE = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS published_proofs (
    root TEXT PRIMARY KEY, subject TEXT NOT NULL, bundle TEXT NOT NULL,
    published_at INTEGER NOT NULL);
"""


def node_trust(trust_info: dict) -> Trust:
    """The trust of this node (`NodeHome.trust_info`), with the TSA roots of
    the default TSAs, as a client of this node pins it."""
    return Trust(
        log_keys=[NoteVerifier.parse(v) for v in trust_info["log_keys"]],
        witness_keys=[NoteVerifier.parse(v) for v in trust_info.get("witness_keys", [])],
        anchors=AnchorTrust(
            fake_keys=[bytes.fromhex(k) for k in trust_info.get("fake_anchor_keys", [])],
            tsa_roots=bundled_tsa_roots(),
        ),
        min_anchors=1,
    )


class TooMany(NodeError):
    status = 429


class VerifyPages:
    """The verify service of one node: the trust of the node, the published
    proofs, and the rate limit of `POST /verify`."""

    def __init__(
        self,
        path: str | Path,
        identity,
        trust_info: dict,
        *,
        public_url: str,
        clock=time.time,
        per_minute: int = PER_MINUTE,
    ) -> None:
        self.identity = identity
        self.trust = node_trust(trust_info)
        self.public_url = public_url.rstrip("/")
        self.clock = clock
        self.per_minute = per_minute
        self.origin = self.trust.log_keys[0].name if self.trust.log_keys else ""
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self._db = SharedDB(path)
        self._db.executescript(_SCHEMA)

    # ------------------------------------------------------------ check

    def limit(self, address: str) -> None:
        now = self.clock()
        with self._lock:
            if len(self._hits) > 10_000:  # keep memory small under a flood
                self._hits = {k: q for k, q in self._hits.items() if q and q[-1] > now - 60}
            q = self._hits.setdefault(address, deque())
            while q and q[0] <= now - 60:
                q.popleft()
            if len(q) >= self.per_minute:
                raise TooMany("too many checks from this address; wait one minute")
            q.append(now)

    def check(self, bundle: ProofBundle) -> dict:
        """The report of a bundle as JSON. A bundle of another node gets
        `other_node` and no check (this node has no trust for it)."""
        facts = node_facts(bundle)
        if facts["origin"] != self.origin:
            return {"ok": False, "other_node": facts["origin"], "root": bundle.subject.root.hex()}
        report = verify_bundle(bundle, self.trust)
        return report_json(bundle, report, facts["origin"])

    # ---------------------------------------------------------- publish

    def publish(self, subject: str, bundle: ProofBundle) -> dict:
        self.identity.require_member(subject)
        if bundle.sealed_opening is not None:
            raise Forbidden("a published proof has no sealed opening")
        report = verify_bundle(bundle, self.trust)
        if not report.ok:
            raise NodeError("this proof does not pass the check of this node")
        owner = bundle.subject.owner_key.hex()
        entries = self.identity.directory(subject)["entries"]
        devices = {(e["entry"].get("device") or {}).get("ed25519") for e in entries}
        if owner not in devices:
            raise Forbidden("a device of another person signed this proof")
        root = bundle.subject.root.hex()
        with self._lock:
            row = self._db.execute(
                "SELECT subject FROM published_proofs WHERE root = ?", (root,)
            ).fetchone()
            if row is not None and row[0] != subject:
                raise Forbidden("another person published this proof")
            self._db.execute(
                "INSERT INTO published_proofs (root, subject, bundle, published_at)"
                " VALUES (?, ?, ?, ?) ON CONFLICT (root) DO UPDATE SET bundle = excluded.bundle,"
                " published_at = excluded.published_at",
                (root, subject, bundle.dumps(), int(self.clock())),
            )
        return {"root": root, "url": f"{self.public_url}/verify/{root}"}

    def published(self, root: str) -> dict:
        row = self._db.execute(
            "SELECT bundle FROM published_proofs WHERE root = ?", (root.lower(),)
        ).fetchone()
        if row is None:
            raise NotFound("no published proof with this fingerprint")
        return {"bundle": json.loads(row[0])}

    def unpublish(self, subject: str, root: str) -> dict:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM published_proofs WHERE root = ? AND subject = ?",
                (root.lower(), subject),
            )
        if cur.rowcount == 0:
            raise NotFound("you have no published proof with this fingerprint")
        return {}


def _iso(when: datetime | None) -> str | None:
    return when.isoformat() if when else None


def report_json(bundle: ProofBundle, report: VerifyReport, origin: str) -> dict[str, Any]:
    """The facts of a report that the page shows. No field that is not open."""
    return {
        "anchors": [[label, state] for label, state in report.anchor_notes],
        "anchor_time": _iso(report.anchor_time),
        "checks": [
            {"name": c.name, "ok": c.ok, "detail": c.detail} for c in report.checks if c.required
        ],
        "evidence": {
            str(slot): {k: v for k, v in fields.items() if k in ("name", "content", "media_type")}
            for slot, fields in sorted(report.evidence.items())
        },
        "fake": any(label.startswith("fake") for label, _ in report.anchor_notes),
        "kind": report.kind,
        "log": {"origin": origin, "index": bundle.log.leaf_index, "size": bundle.log.tree_size},
        "not_after": _iso(report.not_after),
        "ok": report.ok,
        "opened": {
            k: v for k, v in report.opened.items() if k in ("claim", "finding_id", "version")
        },
        "owner_key": report.owner_key,
        "root": report.root,
        "title": title_of(bundle, report),
        "witness_time": _iso(report.witness_time),
    }


def _bundle_of(body: Any) -> ProofBundle:
    if not isinstance(body, dict):
        raise HTTPException(400, "send {bundle} or {text}")
    try:
        if isinstance(body.get("text"), str):
            return proof_from_text(body["text"])
        if isinstance(body.get("bundle"), dict):
            return ProofBundle.from_json(body["bundle"])
    except (FormatError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(400, f"this is not a proof file: {exc}") from exc
    raise HTTPException(400, "send {bundle} or {text}")


async def _read_json_body(request: Request, limit: int = MAX_BODY) -> Any:
    size = request.headers.get("content-length")
    if size is not None and (not size.isdigit() or int(size) > limit):
        raise HTTPException(413, "this file is too large for a proof")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, "this file is too large for a proof")
        chunks.append(chunk)
    try:
        return json.loads(b"".join(chunks))
    except ValueError as exc:
        raise HTTPException(400, "send JSON") from exc


def verify_router(verify: VerifyPages, subject_of, headers: dict) -> APIRouter:
    """`headers` are the security headers of the node pages (`pages.HEADERS`:
    the page loads its module script and its style sheet from this node
    only). The composition gives them."""
    router = APIRouter()

    def _page() -> HTMLResponse:
        return HTMLResponse((WEB / "index.html").read_text(encoding="utf-8"), headers=headers)

    @router.get("/verify")
    def page() -> HTMLResponse:
        return _page()

    @router.get("/verify/assets/{name}")
    def asset(name: str) -> FileResponse:
        path = WEB / name
        if not _ASSET.match(name) or not path.is_file():
            raise HTTPException(404, "not found")
        kind = "text/javascript" if name.endswith(".js") else "text/css"
        return FileResponse(path, media_type=kind, headers=headers)

    @router.get("/verify/{root}")
    def published_page(root: str) -> HTMLResponse:
        if not _ROOT.match(root):
            raise HTTPException(404, "not found")
        return _page()

    @router.post("/verify")
    async def check(request: Request) -> dict:
        verify.limit(request.client.host if request.client else "unknown")
        body = await _read_json_body(request, MAX_BODY)
        return verify.check(_bundle_of(body))

    @router.post("/proofs")
    async def publish(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict:
        subject = subject_of(authorization)
        body = await _read_json_body(request, MAX_BODY)
        return verify.publish(subject, _bundle_of(body))

    @router.get("/proofs/{root}")
    def published(root: str) -> dict:
        if not _ROOT.match(root):
            raise HTTPException(404, "not found")
        return verify.published(root)

    @router.delete("/proofs/{root}")
    def unpublish(root: str, authorization: str | None = Header(default=None)) -> dict:
        return verify.unpublish(subject_of(authorization), root)

    return router
