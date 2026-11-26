"""HTTP layer for sources of contract v2.

The v1 `Transport` (`base.py`) gives a status and parsed JSON. It gives no
response headers and no bytes. A source that reads changes with a cursor needs
the `Retry-After` header and file bytes, so contract v2 uses `HttpTransport`.
The v1 transport stays for the old connectors; `as_v1` adapts the new one.

Rules of this layer:

- https only. The one exception is `http://127.0.0.1` (tests and the OAuth
  loopback receiver).
- No redirect to another host. A request can hold an access token.
- A response body has a size limit.
- A fault has a code (`SourceFault`). The text of a fault holds no URL, no
  header, and no body, so that a token or an item name cannot be in it.
- The helper never sleeps for a long time inside a source: a long wait
  becomes a fault with `retry_at`.

Tests pass a fake `HttpTransport`. No test uses the network.
"""

from __future__ import annotations

import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC
from email.utils import parsedate_to_datetime

from anagram.local.sources.base import ConnectorError, Transport

MAX_BYTES = 64 * 1024 * 1024
MAX_BACKOFF_S = 64.0

# Classes that `classify(response)` returns.
OK = "ok"
RETRY = "retry"
AUTH = "auth"
PERMISSION = "permission"
GONE = "gone"
QUOTA = "quota"
FATAL = "fatal"
CLASSES = frozenset({OK, RETRY, AUTH, PERMISSION, GONE, QUOTA, FATAL})

# Fault codes of a source. `too_large` is a fault of one
# item, not of a source.
FAULT_CODES = frozenset(
    {
        "rate_limited",
        "offline",
        "quota",
        "auth_expired",
        "permission_lost",
        "not_found",
        "client_missing",
        "cursor_expired",
        "unknown",
        "too_large",
    }
)

_CLASS_CODE = {
    AUTH: "auth_expired",
    PERMISSION: "permission_lost",
    GONE: "not_found",
    QUOTA: "quota",
    FATAL: "unknown",
}


class SourceFault(ConnectorError):
    """A fault with a code that the UI can show.

    - `code`: one of `FAULT_CODES`.
    - `detail`: a short text with no secret, no URL, and no item text.
    - `retry_at`: epoch seconds; the source can try again at this time.
    - `status`: the HTTP status, when the fault came from a response. A
      connector uses it to make a skipped item from a fault of one item.
    """

    def __init__(
        self,
        code: str,
        detail: str = "",
        retry_at: float | None = None,
        *,
        status: int | None = None,
    ) -> None:
        if code not in FAULT_CODES:
            raise ValueError(f"unknown fault code: {code}")
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.retry_at = retry_at
        self.status = status


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)  # lower-case names
    body: bytes = b""

    def json(self) -> object:
        """The parsed JSON body. An empty body gives None. A body that is not
        JSON raises `SourceFault("unknown")`."""
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except ValueError as exc:
            raise SourceFault("unknown", "the response is not JSON", status=self.status) from exc


# http(method, url, headers, body) -> HttpResponse
HttpTransport = Callable[[str, str, dict[str, str], bytes | None], HttpResponse]


def check_url(url: str) -> urllib.parse.SplitResult:
    """Permit https, and http only for 127.0.0.1. Raise ValueError for each
    other URL."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return parts
    if parts.scheme == "http" and parts.hostname == "127.0.0.1":
        return parts
    raise ValueError("source calls must use https")


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to the same host with a permitted scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        try:
            new = check_url(newurl)
        except ValueError:
            new = None
        if new is None or new.hostname != old.hostname or new.port != old.port:
            raise SourceFault("unknown", "a redirect to another host was refused", status=code)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_SameHostRedirect)


def _read(resp, max_bytes: int) -> bytes:
    raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise SourceFault("too_large", "the response is larger than the limit")
    return raw


def _lower(headers) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers.items() if headers else [])}


def urllib_http(timeout: int = 60, max_bytes: int = MAX_BYTES) -> HttpTransport:
    """Real network transport for contract v2. Only a connected source uses
    it. Tests never use it."""

    def call(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
        check_url(url)
        req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
        try:
            with _opener().open(req, timeout=timeout) as resp:
                return HttpResponse(resp.status, _lower(resp.headers), _read(resp, max_bytes))
        except urllib.error.HTTPError as exc:
            return HttpResponse(exc.code, _lower(exc.headers), _read(exc, max_bytes))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # The class name only: the text of the error can hold the URL.
            raise SourceFault("offline", type(exc).__name__) from None

    return call


def default_http() -> HttpTransport:
    """The transport that `LocalIndex.for_client` gives to contract v2
    sources. Tests replace this function with a fake (monkeypatch)."""
    return urllib_http()


def as_v1(http: HttpTransport) -> Transport:
    """Adapt an `HttpTransport` for a v1 connector: `(status, parsed JSON)`.
    A body that is not JSON gives None, as `urllib_transport` does."""

    def call(method: str, url: str, headers: dict[str, str], body: bytes | None):
        resp = http(method, url, headers, body)
        try:
            return resp.status, (json.loads(resp.body) if resp.body else None)
        except ValueError:
            return resp.status, None

    return call


def classify_status(resp: HttpResponse) -> str:
    """The class of a response from its status only. A provider with more
    exact rules (for example the Google 403 reasons) wraps this function."""
    s = resp.status
    if 200 <= s < 300:
        return OK
    if s in (429, 500, 502, 503, 504):
        return RETRY
    if s == 401:
        return AUTH
    if s == 403:
        return PERMISSION
    if s in (404, 410):
        return GONE
    return FATAL


class RateLimiter:
    """Token bucket. `acquire(cost)` blocks through `sleep` until units are
    free. Safe for more than one thread."""

    def __init__(
        self,
        units_per_s: float,
        burst: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if units_per_s <= 0 or burst <= 0:
            raise ValueError("rate and burst must be more than zero")
        self.rate = float(units_per_s)
        self.burst = float(burst)
        self._clock = clock
        self._sleep = sleep
        self._units = float(burst)
        self._at = clock()
        self._lock = threading.Lock()

    def _wait_for(self, cost: float) -> float:
        """Take `cost` units if they are free and return 0. If not, return
        the time until they are free."""
        with self._lock:
            now = self._clock()
            self._units = min(self.burst, self._units + (now - self._at) * self.rate)
            self._at = now
            # The small tolerance stops a loop of waits that are too short for
            # the clock to show (a float rounding error).
            if self._units + 1e-9 >= cost:
                self._units = max(0.0, self._units - cost)
                return 0.0
            return (cost - self._units) / self.rate

    def acquire(self, cost: float = 1.0) -> None:
        cost = min(float(cost), self.burst)  # a cost above the burst can never be free
        while True:
            wait = self._wait_for(cost)
            if wait <= 0:
                return
            self._sleep(wait)


def retry_after(resp: HttpResponse, now: float) -> float | None:
    """Seconds to wait from the `Retry-After` header (a number of seconds or
    an HTTP date). None if the header is absent or not valid."""
    value = resp.headers.get("retry-after")
    if value is None:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, when.timestamp() - now)


def call_with_backoff(
    http: HttpTransport,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    *,
    limiter: RateLimiter | None = None,
    cost: float = 1.0,
    classify: Callable[[HttpResponse], str] = classify_status,
    max_wait_s: float = 30.0,
    tries: int = 5,
    sleep: Callable[[float], None] = time.sleep,
    rng: Callable[[], float] = random.random,
    clock: Callable[[], float] = time.time,
    reauth: Callable[[], dict[str, str]] | None = None,
) -> HttpResponse:
    """Call `http` and return the response of class `ok`. Each other result
    raises `SourceFault`.

    - `retry`: wait `Retry-After` if the header is present, else
      `min(64, 2**n) + rng()` seconds, and call again, at most `tries` calls.
      A wait longer than `max_wait_s` is not done: it raises
      `SourceFault("rate_limited", retry_at=...)`.
    - `auth`: `reauth()` gives new header values (a new access token). It is
      called one time. A second `auth` result, or no `reauth`, raises
      `SourceFault("auth_expired")`.
    - `permission`, `gone`, `quota`, `fatal`: raise `permission_lost`,
      `not_found`, `quota`, `unknown`. The fault has the HTTP status.
    """
    headers = dict(headers)
    refreshed = False
    n = 0
    while True:
        if limiter is not None:
            limiter.acquire(cost)
        resp = http(method, url, headers, body)
        kind = classify(resp)
        if kind == OK:
            return resp
        if kind == AUTH and reauth is not None and not refreshed:
            refreshed = True
            headers.update(reauth())
            continue
        if kind == RETRY:
            now = clock()
            wait = retry_after(resp, now)
            if wait is None:
                wait = min(MAX_BACKOFF_S, 2.0**n) + rng()
            n += 1
            code = "rate_limited" if resp.status == 429 else "unknown"
            if wait > max_wait_s:
                raise SourceFault(
                    "rate_limited", f"HTTP {resp.status}", now + wait, status=resp.status
                )
            if n >= tries:
                raise SourceFault(code, f"HTTP {resp.status}", now + wait, status=resp.status)
            sleep(wait)
            continue
        code = _CLASS_CODE.get(kind, "unknown")
        raise SourceFault(code, f"HTTP {resp.status}", status=resp.status)
