"""`FakeGoogle`: an `HttpTransport` with an in-memory model of the Google
OAuth endpoints (token, refresh, revoke), Drive, and Gmail (`FakeGmail`).

Tests use it; no test calls Google. Its response shapes follow the examples
of the official documentation (`tests/fixtures/sources/google/`). A later
change replaces the fixtures with redacted recordings of a live account.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime

from anagram.local.sources.fake_gmail import FakeGmail
from anagram.local.sources.google import google_error, json_response
from anagram.local.sources.http import HttpResponse
from anagram.local.sources.oauth import DRIVE_SCOPE, GMAIL_SCOPE, GOOGLE

FOLDER = "application/vnd.google-apps.folder"
DRIVE_EPOCH = 1_735_689_600  # 2025-01-01 UTC; the fake Drive clock starts here
SCOPE_NAMES = {"email": "https://www.googleapis.com/auth/userinfo.email"}
TOKEN_URL = GOOGLE.token_url
REVOKE_URL = GOOGLE.revoke_url
GMAIL_PATH = "/gmail/v1/users/me/"


def _jwt(claims: dict) -> str:
    def part(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}.sig"


@dataclass
class _Grant:
    scopes: set[str]
    refresh: str
    access: set[str] = field(default_factory=set)
    revoked: bool = False


@dataclass
class FakeGoogle:
    """A deterministic model of Google for tests. Call it as an
    `HttpTransport`. Script it with `authorize`, `fail_next`, `revoke_grant`,
    and the Drive and Gmail methods."""

    client_id: str = "fake-desktop-client.apps.googleusercontent.com"
    client_secret: str = "fake-desktop-secret"  # noqa: S105 - a test value, not a secret
    sub: str = "100000000000000000001"
    email: str = "member@example.org"
    expires_in: int = 3599
    calls: list[tuple[str, str]] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    _codes: dict[str, dict] = field(default_factory=dict)
    _grants: list[_Grant] = field(default_factory=list)
    _fail: list[HttpResponse] = field(default_factory=list)
    _n: itertools.count = field(default_factory=lambda: itertools.count(1))
    # Drive model.
    files: dict[str, dict] = field(default_factory=dict)
    drives: dict[str, str] = field(default_factory=dict)  # drive id -> name
    changes: list[tuple[str, bool]] = field(default_factory=list)  # (file id, removed)
    root_id: str = "0AFakeRootFolder"
    markdown_export: bool = True  # False: Google refuses text/markdown (fallback test)
    _epoch: int = 0
    _tick: int = 0
    _sorted: tuple[int, list[str]] | None = None
    # Gmail model.
    gmail: FakeGmail = field(default_factory=lambda: FakeGmail())

    def __post_init__(self) -> None:
        self.gmail.email = self.email

    # ----------------------------------------------------------- scripting

    def authorize(self, url: str, *, deny: bool = False, drop: tuple[str, ...] = ()) -> str:
        """The consent screen: the redirect URL that Google sends the
        browser to. `drop` clears scopes in the consent (granular consent)."""
        parts = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.hostname != "accounts.google.com" or q.get("client_id") != self.client_id:
            raise ValueError("FakeGoogle: not an authorize URL of this client")
        redirect = q["redirect_uri"]
        if deny:
            args = {"error": "access_denied", "state": q["state"]}
        else:
            code = f"4/fake-code-{next(self._n)}"
            # Google gives `email` back as its long name.
            scopes = {SCOPE_NAMES.get(s, s) for s in q.get("scope", "").split()} - set(drop)
            if q.get("include_granted_scopes") == "true":
                for g in self._grants:
                    if not g.revoked:
                        scopes |= g.scopes
            self._codes[code] = {
                "challenge": q.get("code_challenge"),
                "method": q.get("code_challenge_method"),
                "redirect": redirect,
                "scopes": scopes,
            }
            args = {"code": code, "scope": " ".join(sorted(scopes)), "state": q["state"]}
        return redirect + "?" + urllib.parse.urlencode(args)

    def fail_next(
        self, status: int, headers: dict | None = None, body: object = None, times: int = 1
    ) -> None:
        resp = (
            body
            if isinstance(body, HttpResponse)
            else json_response(status, body if body is not None else {}, headers)
        )
        self._fail.extend([resp] * times)

    def revoke_grant(self) -> None:
        """The person removed the access at the Google account page."""
        for g in self._grants:
            g.revoked = True

    def expire_access(self) -> None:
        """Each access token stops working (it timed out at Google)."""
        for g in self._grants:
            g.access.clear()

    def tokens_issued(self) -> list[str]:
        return [t for g in self._grants for t in g.access]

    # -------------------------------------------------------------- transport

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        self.calls.append((method, url))
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise AssertionError("FakeGoogle: not https")
        if url == TOKEN_URL and method == "POST":
            return self._token(dict(urllib.parse.parse_qsl((body or b"").decode())))
        if url == REVOKE_URL and method == "POST":
            return self._revoke(dict(urllib.parse.parse_qsl((body or b"").decode())))
        if self._fail:  # scripted faults apply to API calls only
            return self._fail.pop(0)
        grant = self._grant_for(headers)
        if grant is None:
            return google_error(401, "authError", "Invalid Credentials")
        return self.api(method, parts, headers, body, grant)

    def api(self, method, parts, headers, body, grant) -> HttpResponse:
        """The API calls (Drive and Gmail)."""
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.hostname == "www.googleapis.com" and parts.path.startswith("/drive/v3/"):
            if not self.has_scope(grant, DRIVE_SCOPE):
                return google_error(403, "insufficientPermissions")
            return self._drive(parts.path[len("/drive/v3/") :], q)
        if parts.hostname == "gmail.googleapis.com" and parts.path.startswith(GMAIL_PATH):
            if not self.has_scope(grant, GMAIL_SCOPE):
                return google_error(403, "insufficientPermissions")
            many = urllib.parse.parse_qs(parts.query)
            return self.gmail.route(parts.path[len(GMAIL_PATH) :], q, many)
        return google_error(404, "notFound")

    # ------------------------------------------------------------ Drive model

    def _modified(self) -> str:
        self._tick += 1
        t = DRIVE_EPOCH + self._tick
        return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _changed(self, fid: str, removed: bool = False) -> None:
        self.changes.append((fid, removed))
        self._sorted = None

    def add_drive(self, name: str) -> str:
        did = f"0AFakeDrive{len(self.drives) + 1}"
        self.drives[did] = name
        self.files[did] = {
            "canDownload": True,
            "content": None,
            "driveId": did,
            "id": did,
            "mimeType": FOLDER,
            "name": name,
            "owner": None,
            "parents": [],
            "trashed": False,
        }
        return did

    def add_folder(self, name: str, parent: str | None = None) -> str:
        return self.add_file(name, None, parent=parent, mime=FOLDER)

    def add_file(
        self,
        name: str,
        content: bytes | None = b"",
        *,
        parent: str | None = None,
        mime: str = "text/plain",
        owner: str | None = None,
        can_download: bool = True,
        fid: str | None = None,
    ) -> str:
        fid = fid or f"1Fake{next(self._n):08d}"
        parent = parent or self.root_id
        drive = self.files.get(parent, {}).get("driveId")
        self.files[fid] = {
            "canDownload": can_download,
            "content": content,
            "driveId": drive,
            "id": fid,
            "mimeType": mime,
            "modifiedTime": self._modified(),
            "name": name,
            "owner": None if drive else (owner or self.email),
            "parents": [parent],
            "trashed": False,
        }
        self._changed(fid)
        return fid

    def edit_file(self, fid: str, content: bytes) -> None:
        self.files[fid]["content"] = content
        self.files[fid]["modifiedTime"] = self._modified()
        self._changed(fid)

    def trash(self, fid: str) -> None:
        """Trash a file. Drive trashes the tree of a folder too; only the
        folder itself gets a change."""
        self.files[fid]["trashed"] = True
        self.files[fid]["modifiedTime"] = self._modified()
        self._changed(fid)
        todo = [fid]
        while todo:
            node = todo.pop()
            for child in self.files.values():
                if node in child["parents"] and not child["trashed"]:
                    child["trashed"] = True
                    todo.append(child["id"])

    def delete_file(self, fid: str) -> None:
        del self.files[fid]
        self._changed(fid, removed=True)

    def move(self, fid: str, parent: str) -> None:
        f = self.files[fid]
        f["parents"] = [parent]
        f["driveId"] = self.files.get(parent, {}).get("driveId")
        f["modifiedTime"] = self._modified()
        self._changed(fid)

    def expire_changes(self) -> None:
        """Each changes token of before this call stops working."""
        self._epoch += 1

    def _file_json(self, f: dict) -> dict:
        out = {
            "capabilities": {"canDownload": f["canDownload"]},
            "id": f["id"],
            "kind": "drive#file",
            "mimeType": f["mimeType"],
            "modifiedTime": f.get("modifiedTime"),
            "name": f["name"],
            "parents": list(f["parents"]),
            "trashed": f.get("trashed", False),
            "webViewLink": f"https://drive.google.com/file/d/{f['id']}/view",
        }
        if f.get("driveId"):
            out["driveId"] = f["driveId"]
        if f.get("owner"):
            out["owners"] = [{"emailAddress": f["owner"]}]
        if f.get("content") is not None and not self._google_type(f):
            out["size"] = str(len(f["content"]))  # Drive gives int64 values as text
        return out

    def _drive(self, path: str, q: dict) -> HttpResponse:
        """The answer to a Drive API path below `/drive/v3/`."""
        if path in ("changes/startPageToken", "changes", "drives", "files", "files/root"):
            return self._drive_list(path, q)
        parts = path.split("/")
        f = self.files.get(parts[1]) if len(parts) >= 2 else None
        if f is None:
            return google_error(404, "notFound", "File not found.")
        if len(parts) == 2 and q.get("alt") == "media":
            return self._download(f)
        if len(parts) == 3 and parts[2] == "export":
            return self._export(f, q.get("mimeType"))
        if len(parts) == 2:
            return json_response(200, self._file_json(f))
        return google_error(404, "notFound")

    def _drive_list(self, path: str, q: dict) -> HttpResponse:
        """The paths that do not name a file: changes, drives, and file lists."""
        if path == "changes/startPageToken":
            token = self._page_token(len(self.changes) + 1)
            return json_response(200, {"kind": "drive#startPageToken", "startPageToken": token})
        if path == "changes":
            return self._changes(q)
        if path == "drives":
            items = [{"id": d, "kind": "drive#drive", "name": n} for d, n in self.drives.items()]
            return json_response(200, {"drives": items, "kind": "drive#driveList"})
        if path == "files":
            return self._list(q)
        return json_response(200, {"id": self.root_id})  # files/root

    @staticmethod
    def _google_type(f: dict) -> bool:
        return f["mimeType"].startswith("application/vnd.google-apps.")

    def _download(self, f: dict) -> HttpResponse:
        """`files/ID?alt=media`: the bytes of a file that is not a Google type."""
        if self._google_type(f):
            return google_error(403, "fileNotDownloadable")
        if not f["canDownload"]:
            return google_error(403, "cannotDownloadFile")
        return HttpResponse(200, {"content-type": f["mimeType"]}, f["content"] or b"")

    def _export(self, f: dict, target: str | None) -> HttpResponse:
        """`files/ID/export`: a Google type as the media type `target`."""
        if target == "text/markdown" and not self.markdown_export:
            return google_error(400, "badRequest", "The requested conversion is not supported.")
        if not self._google_type(f):
            return google_error(403, "fileNotExportable")
        data = f["content"] or b""
        if len(data) > 10 * 1024 * 1024:
            return google_error(403, "exportSizeLimitExceeded")
        return HttpResponse(200, {"content-type": target or ""}, data)

    def _page_token(self, n: int) -> str:
        return f"{self._epoch}.{n}"

    def _changes(self, q: dict) -> HttpResponse:
        try:
            epoch, n = (int(x) for x in q.get("pageToken", "").split("."))
        except ValueError:
            epoch, n = -1, 0
        token = n
        if epoch != self._epoch or token < 1 or token > len(self.changes) + 1:
            return google_error(404, "notFound", "Page token is not valid.")
        size = int(q.get("pageSize", 100))
        part = self.changes[token - 1 : token - 1 + size]
        out = []
        for fid, removed in part:
            f = self.files.get(fid)
            entry = {
                "changeType": "file",
                "fileId": fid,
                "kind": "drive#change",
                "removed": removed or f is None,
            }
            if f is not None and not removed:
                entry["file"] = self._file_json(f)
            out.append(entry)
        body: dict = {"changes": out, "kind": "drive#changeList"}
        nxt = token + len(part)
        if nxt <= len(self.changes):
            body["nextPageToken"] = self._page_token(nxt)
        else:
            body["newStartPageToken"] = self._page_token(len(self.changes) + 1)
        return json_response(200, body)

    def _list(self, q: dict) -> HttpResponse:
        query = q.get("q", "")
        parent = None
        m = re.search(r"'([^']+)' in parents", query)
        if m:
            parent = self.root_id if m.group(1) == "root" else m.group(1)
        folders_only = f"mimeType='{FOLDER}'" in query
        no_folders = f"mimeType!='{FOLDER}'" in query
        live_only = "trashed=false" in query
        newest = q.get("orderBy") == "modifiedTime desc"
        if parent is None and newest and no_folders and live_only:
            if self._sorted is None:
                ids = [
                    f["id"]
                    for f in self.files.values()
                    if f["mimeType"] != FOLDER and not f["trashed"]
                ]
                ids.sort(key=lambda i: self.files[i]["modifiedTime"], reverse=True)
                self._sorted = (len(self.changes), ids)
            ids = self._sorted[1]
        else:
            ids = [
                f["id"]
                for f in self.files.values()
                if (parent is None or parent in f["parents"])
                and (not folders_only or f["mimeType"] == FOLDER)
                and (not no_folders or f["mimeType"] != FOLDER)
                and (not live_only or not f["trashed"])
                and f["id"] not in self.drives
            ]
            if q.get("orderBy") == "name":
                ids.sort(key=lambda i: self.files[i]["name"])
        start = int(q.get("pageToken") or 0)
        size = int(q.get("pageSize", 100))
        page = ids[start : start + size]
        body: dict = {
            "files": [self._file_json(self.files[i]) for i in page],
            "incompleteSearch": False,
            "kind": "drive#fileList",
        }
        if start + size < len(ids):
            body["nextPageToken"] = str(start + size)
        return json_response(200, body)

    def _grant_for(self, headers: dict[str, str]) -> _Grant | None:
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[len("Bearer ") :]
        for g in self._grants:
            if not g.revoked and token in g.access:
                return g
        return None

    def has_scope(self, grant: _Grant, scope: str) -> bool:
        return scope in grant.scopes

    def _new_access(self, grant: _Grant) -> str:
        token = f"ya29.fake-{secrets.token_hex(8)}"
        grant.access.add(token)
        return token

    def _token(self, form: dict) -> HttpResponse:
        if (
            form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
        ):
            return json_response(401, {"error": "invalid_client"})
        if form.get("grant_type") == "authorization_code":
            entry = self._codes.pop(form.get("code", ""), None)
            if entry is None or entry["redirect"] != form.get("redirect_uri"):
                return json_response(400, {"error": "invalid_grant"})
            if entry["challenge"] is not None:
                verifier = form.get("code_verifier", "")
                digest = hashlib.sha256(verifier.encode()).digest()
                calc = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                if entry["method"] != "S256" or calc != entry["challenge"]:
                    return json_response(400, {"error": "invalid_grant"})
            grant = next((g for g in self._grants if not g.revoked), None)
            if grant is None:
                grant = _Grant(set(), f"1//fake-refresh-{secrets.token_hex(8)}")
                self._grants.append(grant)
            grant.scopes |= entry["scopes"]
            body = {
                "access_token": self._new_access(grant),
                "expires_in": self.expires_in,
                "refresh_token": grant.refresh,
                "scope": " ".join(sorted(grant.scopes)),
                "token_type": "Bearer",
            }
            if "openid" in grant.scopes:
                body["id_token"] = _jwt(
                    {
                        "aud": self.client_id,
                        "email": self.email,
                        "iss": "https://accounts.google.com",
                        "sub": self.sub,
                    }
                )
            return json_response(200, body)
        if form.get("grant_type") == "refresh_token":
            for g in self._grants:
                if g.refresh == form.get("refresh_token") and not g.revoked:
                    return json_response(
                        200,
                        {
                            "access_token": self._new_access(g),
                            "expires_in": self.expires_in,
                            "scope": " ".join(sorted(g.scopes)),
                            "token_type": "Bearer",
                        },
                    )
            return json_response(
                400,
                {
                    "error": "invalid_grant",
                    "error_description": "Token has been expired or revoked.",
                },
            )
        return json_response(400, {"error": "unsupported_grant_type"})

    def _revoke(self, form: dict) -> HttpResponse:
        token = form.get("token", "")
        for g in self._grants:
            if not g.revoked and (token == g.refresh or token in g.access):
                g.revoked = True
                self.revoked.append(token)
                return HttpResponse(200, {}, b"")
        return json_response(400, {"error": "invalid_token"})
