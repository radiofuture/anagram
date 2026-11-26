"""The update check of the app.

The release team publishes a signed manifest at a fixed URL:

    {"min_os": {"macos": "13.0"}, "schema": "anagram.release.v1",
     "sig": "<hex Ed25519>", "url": {"macos": "https://..."}, "version": "0.2.0"}

`sig` signs the canonical JSON of the other keys, with the domain tag
`TAG_SIGN_RELEASE`. The release public key and the manifest URL are build
constants (`MANIFEST_URL`, `RELEASE_KEY`). With no URL or no key, the check
is off and makes no network request.

The request is one plain HTTPS GET: no cookie, no identifier, no query, no
redirect, and a fixed User-Agent. The server sees the IP address and the
time. The check never downloads or installs a program: the UI shows the
download link, and the person replaces the app. The next `anagram open`
sees a new version and starts the new app (`launcher.ensure_running`).
"""

from __future__ import annotations

import json
import platform as _platform
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable

import anagram
from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey, verify

SCHEMA = "anagram.release.v1"
TAG_SIGN_RELEASE = "anagram/v1/sign/release-manifest"
# Build constants. The release build sets them; a developer build has none,
# so the check is off: there is no download location yet.
MANIFEST_URL: str | None = None
RELEASE_KEY: str | None = None  # hex of the Ed25519 public key
MAX_BYTES = 64 * 1024
TIMEOUT_S = 10.0
CHECK_EVERY_S = 24 * 3600.0
USER_AGENT = "anagram-update-check"
NO_UPDATE = {"available": False, "url": None, "version": None}
KEYS = {"min_os", "schema", "sig", "url", "version"}
_VERSION = re.compile(r"^\d{1,4}(\.\d{1,4}){0,3}$")


class UpdateError(Exception):
    """The manifest is not valid, or its signature is wrong."""


def platform_key(plat: str | None = None) -> str:
    plat = plat or sys.platform
    if plat == "darwin":
        return "macos"
    if plat.startswith("win"):
        return "windows"
    return "linux"


def version_tuple(v: str) -> tuple[int, ...]:
    if not isinstance(v, str) or not _VERSION.match(v):
        raise UpdateError("bad version")
    return tuple(int(x) for x in v.split("."))


def _body(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k != "sig"}


def sign_manifest(key: SigningKey, body: dict) -> dict:
    """The release tool: sign a manifest body (all keys but `sig`)."""
    doc = {**body, "schema": SCHEMA}
    sig = key.sign(TAG_SIGN_RELEASE, canonical_json(_body(doc)))
    return {**doc, "sig": sig.hex()}


def verify_manifest(doc: object, release_key: bytes) -> dict:
    """Check the form and the signature. Return the manifest or raise
    `UpdateError`."""
    if not isinstance(doc, dict) or set(doc) != KEYS or doc.get("schema") != SCHEMA:
        raise UpdateError("bad manifest")
    if not isinstance(doc["url"], dict) or not isinstance(doc["min_os"], dict):
        raise UpdateError("bad manifest")
    version_tuple(doc["version"])
    try:
        sig = bytes.fromhex(doc["sig"])
    except (TypeError, ValueError) as exc:
        raise UpdateError("bad signature") from exc
    if not verify(release_key, TAG_SIGN_RELEASE, canonical_json(_body(doc)), sig):
        raise UpdateError("bad signature")
    for url in doc["url"].values():
        if not isinstance(url, str) or not url.startswith("https://"):
            raise UpdateError("bad download URL")
    return doc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def https_fetch(url: str) -> bytes:
    """One GET with no cookie, no identifier, and no redirect."""
    if not url.startswith("https://"):
        raise UpdateError("the manifest URL must be https")
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with opener.open(req, timeout=TIMEOUT_S) as resp:  # https only
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise UpdateError("the manifest is too large")
    return data


def _os_too_old(min_os: dict, key: str, os_version: str | None) -> bool:
    want = min_os.get(key)
    if not want or not os_version:
        return False
    try:
        return version_tuple(os_version) < version_tuple(want)
    except UpdateError:
        return False


def check(
    manifest_url: str | None,
    release_key: str | bytes | None,
    *,
    current: str | None = None,
    plat: str | None = None,
    os_version: str | None = None,
    fetch: Callable[[str], bytes] | None = None,
) -> dict:
    """-> {"available": bool, "url": str | None, "version": str | None}.

    No URL or no key: no request, and no update. A manifest that does not
    verify raises `UpdateError`; a network fault raises `OSError`."""
    if not manifest_url or not release_key:
        return dict(NO_UPDATE)
    key = bytes.fromhex(release_key) if isinstance(release_key, str) else release_key
    raw = (fetch or https_fetch)(manifest_url)
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise UpdateError("bad manifest") from exc
    doc = verify_manifest(doc, key)
    pk = platform_key(plat)
    url = doc["url"].get(pk)
    if os_version is None and pk == "macos" and plat is None:
        os_version = _platform.mac_ver()[0] or None
    newer = version_tuple(doc["version"]) > version_tuple(current or anagram.__version__)
    if not newer or url is None or _os_too_old(doc["min_os"], pk, os_version):
        return dict(NO_UPDATE)
    return {"available": True, "url": url, "version": doc["version"]}


class UpdateChecker:
    """The task `app.update` of the runtime: one check each day when the
    build has a URL and a key. `status()` gives the last result (never a
    network call). `on_change(status)` gets each new result."""

    def __init__(
        self,
        manifest_url: str | None = None,
        release_key: str | None = None,
        *,
        fetch: Callable[[str], bytes] | None = None,
        on_change: Callable[[dict], None] | None = None,
        clock: Callable[[], float] = time.time,
        every_s: float = CHECK_EVERY_S,
    ) -> None:
        self.manifest_url = manifest_url if manifest_url is not None else MANIFEST_URL
        self.release_key = release_key if release_key is not None else RELEASE_KEY
        self.fetch = fetch
        self.on_change = on_change
        self.clock = clock
        self.every_s = every_s
        self._status = dict(NO_UPDATE)
        self._last: float | None = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.manifest_url and self.release_key)

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def tick(self) -> None:
        """Check if the last check is older than `every_s`. A fault keeps the
        last result; the next tick tries again."""
        if not self.enabled:
            return
        now = self.clock()
        if self._last is not None and now - self._last < self.every_s:
            return
        self._last = now
        try:
            new = check(self.manifest_url, self.release_key, fetch=self.fetch)
        except (UpdateError, OSError, urllib.error.URLError, ValueError):
            return
        with self._lock:
            changed = new != self._status
            self._status = new
        if changed and self.on_change is not None:
            self.on_change(dict(new))
