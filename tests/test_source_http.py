"""The HTTP layer of contract v2 sources: response, classes, rate limit, and
backoff. All tests use a fake transport and a fake clock."""

from __future__ import annotations

import io
import urllib.error
import urllib.request

import pytest

from anagram.local.sources import http as h
from anagram.local.sources.base import ConnectorError
from anagram.local.sources.http import (
    HttpResponse,
    RateLimiter,
    SourceFault,
    as_v1,
    call_with_backoff,
    classify_status,
    urllib_http,
)

pytestmark = pytest.mark.usefixtures("no_network")

URL = "https://api.example.org/v1/things"


class Clock:
    """A fake clock. `sleep` moves the time and records each wait."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s


class Script:
    """A fake transport that gives the scripted responses in order."""

    def __init__(self, *responses: HttpResponse) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict, bytes | None]] = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        return self.responses.pop(0)


def backoff(http, clock, **kw):
    kw.setdefault("rng", lambda: 0.0)
    return call_with_backoff(http, "GET", URL, {}, sleep=clock.sleep, clock=clock, **kw)


# ---------------------------------------------------------------- response


def test_response_json_and_empty_body():
    assert HttpResponse(200, {}, b'{"a": 1}').json() == {"a": 1}
    assert HttpResponse(204).json() is None


def test_response_bad_json_is_a_fault_with_no_body_text():
    with pytest.raises(SourceFault) as exc:
        HttpResponse(200, {}, b"<html>secret-body</html>").json()
    assert exc.value.code == "unknown"
    assert "secret-body" not in str(exc.value)


def test_fault_is_a_connector_error_with_a_known_code():
    fault = SourceFault("rate_limited", "HTTP 429", 12.5, status=429)
    assert isinstance(fault, ConnectorError)
    assert (fault.code, fault.detail, fault.retry_at, fault.status) == (
        "rate_limited",
        "HTTP 429",
        12.5,
        429,
    )
    with pytest.raises(ValueError, match="unknown fault code"):
        SourceFault("no_such_code")


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (200, "ok"),
        (204, "ok"),
        (429, "retry"),
        (500, "retry"),
        (502, "retry"),
        (503, "retry"),
        (504, "retry"),
        (401, "auth"),
        (403, "permission"),
        (404, "gone"),
        (410, "gone"),
        (400, "fatal"),
        (301, "fatal"),
    ],
)
def test_classify_status_table(status, kind):
    assert classify_status(HttpResponse(status)) == kind
    assert kind in h.CLASSES


# ----------------------------------------------------------------- backoff


def test_ok_returns_the_response_with_one_call():
    clock = Clock()
    http = Script(HttpResponse(200, {}, b"{}"))
    assert backoff(http, clock).status == 200
    assert len(http.calls) == 1
    assert clock.sleeps == []


def test_retry_after_header_is_obeyed():
    clock = Clock()
    http = Script(HttpResponse(429, {"retry-after": "7"}), HttpResponse(200))
    assert backoff(http, clock).status == 200
    assert clock.sleeps == [7.0]


def test_retry_after_http_date_is_obeyed():
    clock = Clock(now=1_700_000_000.0)
    date = "Tue, 14 Nov 2023 22:13:32 GMT"  # 12 seconds after the clock
    http = Script(HttpResponse(503, {"retry-after": date}), HttpResponse(200))
    assert backoff(http, clock).status == 200
    assert clock.sleeps == [12.0]


def test_no_header_gives_exponential_wait_with_jitter():
    clock = Clock()
    http = Script(HttpResponse(500), HttpResponse(502), HttpResponse(503), HttpResponse(200))
    assert backoff(http, clock, rng=lambda: 0.25).status == 200
    assert clock.sleeps == [1.25, 2.25, 4.25]


def test_long_wait_becomes_rate_limited_with_retry_at_and_no_sleep():
    clock = Clock(now=5000.0)
    http = Script(HttpResponse(429, {"retry-after": "600"}))
    with pytest.raises(SourceFault) as exc:
        backoff(http, clock)
    assert exc.value.code == "rate_limited"
    assert exc.value.retry_at == 5600.0
    assert exc.value.status == 429
    assert clock.sleeps == []  # the helper does not sleep for a long time in a source
    assert len(http.calls) == 1


def test_tries_are_bounded():
    clock = Clock()
    http = Script(*[HttpResponse(429)] * 5)
    with pytest.raises(SourceFault) as exc:
        backoff(http, clock, tries=5)
    assert exc.value.code == "rate_limited"
    assert len(http.calls) == 5
    assert clock.sleeps == [1.0, 2.0, 4.0, 8.0]
    assert exc.value.retry_at == clock.now + 16.0


def test_server_error_that_stays_is_unknown():
    clock = Clock()
    http = Script(*[HttpResponse(503)] * 3)
    with pytest.raises(SourceFault) as exc:
        backoff(http, clock, tries=3)
    assert exc.value.code == "unknown"
    assert exc.value.retry_at is not None


def test_401_then_one_refresh_then_retry():
    clock = Clock()
    http = Script(HttpResponse(401), HttpResponse(200))
    refreshes = []

    def reauth():
        refreshes.append(1)
        return {"Authorization": "Bearer new"}

    got = call_with_backoff(
        http,
        "GET",
        URL,
        {"Authorization": "Bearer old", "Accept": "application/json"},
        sleep=clock.sleep,
        clock=clock,
        reauth=reauth,
    )
    assert got.status == 200
    assert len(refreshes) == 1
    assert http.calls[0][2]["Authorization"] == "Bearer old"
    assert http.calls[1][2] == {"Authorization": "Bearer new", "Accept": "application/json"}


def test_second_401_is_auth_expired_and_the_token_is_not_in_the_error():
    clock = Clock()
    http = Script(HttpResponse(401), HttpResponse(401))
    with pytest.raises(SourceFault) as exc:
        call_with_backoff(
            http,
            "GET",
            URL + "?id=item-name",
            {"Authorization": "Bearer tok-one"},
            sleep=clock.sleep,
            clock=clock,
            reauth=lambda: {"Authorization": "Bearer tok-two"},
        )
    assert exc.value.code == "auth_expired"
    assert len(http.calls) == 2
    text = str(exc.value) + exc.value.detail
    for secret in ("tok-one", "tok-two", "item-name", "example.org"):
        assert secret not in text


def test_401_with_no_reauth_is_auth_expired():
    clock = Clock()
    http = Script(HttpResponse(401))
    with pytest.raises(SourceFault) as exc:
        backoff(http, clock)
    assert exc.value.code == "auth_expired"
    assert len(http.calls) == 1


@pytest.mark.parametrize(
    ("status", "code"),
    [(403, "permission_lost"), (404, "not_found"), (410, "not_found"), (400, "unknown")],
)
def test_other_classes_raise_their_code_with_the_status(status, code):
    clock = Clock()
    with pytest.raises(SourceFault) as exc:
        backoff(Script(HttpResponse(status)), clock)
    assert (exc.value.code, exc.value.status) == (code, status)
    assert clock.sleeps == []


def test_provider_classify_wins():
    """A provider gives its own classes, for example a Google 403 reason."""
    clock = Clock()

    def classify(resp: HttpResponse) -> str:
        if resp.status == 403:
            reason = resp.json()["error"]["errors"][0]["reason"]
            if reason == "userRateLimitExceeded":
                return "retry"
            if reason == "dailyLimitExceeded":
                return "quota"
        return classify_status(resp)

    def forbidden(reason: str) -> HttpResponse:
        body = b'{"error": {"errors": [{"reason": "%s"}]}}' % reason.encode()
        return HttpResponse(403, {}, body)

    http = Script(forbidden("userRateLimitExceeded"), HttpResponse(200))
    assert backoff(http, clock, classify=classify).status == 200
    assert clock.sleeps == [1.0]
    with pytest.raises(SourceFault) as exc:
        backoff(Script(forbidden("dailyLimitExceeded")), clock, classify=classify)
    assert exc.value.code == "quota"


def test_limiter_is_used_for_each_call_with_the_cost():
    clock = Clock()
    costs = []

    class Limiter:
        def acquire(self, cost=1.0):
            costs.append(cost)

    http = Script(HttpResponse(500), HttpResponse(200))
    backoff(http, clock, limiter=Limiter(), cost=5.0)
    assert costs == [5.0, 5.0]


# ------------------------------------------------------------ rate limiter


def test_rate_limiter_blocks_until_units_are_free():
    clock = Clock(now=0.0)
    limiter = RateLimiter(10.0, burst=20.0, clock=clock, sleep=clock.sleep)
    limiter.acquire(20.0)  # the burst is free at the start
    assert clock.sleeps == []
    limiter.acquire(5.0)
    assert clock.sleeps == [0.5]
    clock.now += 100.0  # a long idle time fills the bucket to the burst only
    limiter.acquire(20.0)
    limiter.acquire(1.0)
    assert clock.sleeps == [0.5, 0.1]


def test_rate_limiter_cost_above_burst_does_not_block_for_ever():
    clock = Clock(now=0.0)
    limiter = RateLimiter(1.0, burst=2.0, clock=clock, sleep=clock.sleep)
    limiter.acquire(50.0)
    limiter.acquire(50.0)
    assert clock.sleeps == [2.0]


def test_rate_limiter_refuses_bad_values():
    with pytest.raises(ValueError, match="more than zero"):
        RateLimiter(0, 1)


# -------------------------------------------------------- transports


def test_as_v1_gives_status_and_json():
    http = Script(HttpResponse(200, {}, b'{"a": 1}'), HttpResponse(500, {}, b"not json"))
    v1 = as_v1(http)
    assert v1("GET", URL, {}, None) == (200, {"a": 1})
    assert v1("GET", URL, {}, None) == (500, None)


@pytest.mark.parametrize(
    "url",
    ["http://api.example.org/x", "http://localhost/x", "ftp://127.0.0.1/x", "file:///etc/hosts"],
)
def test_urllib_http_refuses_urls_that_are_not_https(url):
    with pytest.raises(ValueError, match="https"):
        urllib_http()("GET", url, {}, None)


class _Resp:
    def __init__(self, status: int, headers: dict, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class _Opener:
    def __init__(self, result) -> None:
        self.result = result

    def open(self, req, timeout=None):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_urllib_http_gives_lower_case_headers_and_bytes(monkeypatch):
    resp = _Resp(200, {"Retry-After": "3", "Content-Type": "application/pdf"}, b"%PDF-bytes")
    monkeypatch.setattr(h, "_opener", lambda: _Opener(resp))
    got = urllib_http()("GET", URL, {}, None)
    assert got == HttpResponse(
        200, {"retry-after": "3", "content-type": "application/pdf"}, b"%PDF-bytes"
    )


def test_urllib_http_gives_an_error_status_as_a_response(monkeypatch):
    err = urllib.error.HTTPError(URL, 429, "Too Many", {"Retry-After": "9"}, io.BytesIO(b"{}"))
    monkeypatch.setattr(h, "_opener", lambda: _Opener(err))
    got = urllib_http()("GET", URL, {}, None)
    assert (got.status, got.headers["retry-after"], got.body) == (429, "9", b"{}")


def test_urllib_http_body_over_the_limit_is_too_large(monkeypatch):
    monkeypatch.setattr(h, "_opener", lambda: _Opener(_Resp(200, {}, b"x" * 11)))
    with pytest.raises(SourceFault) as exc:
        urllib_http(max_bytes=10)("GET", URL, {}, None)
    assert exc.value.code == "too_large"


def test_urllib_http_no_connection_is_offline_with_no_url_in_the_text(monkeypatch):
    err = urllib.error.URLError(f"cannot reach {URL}")
    monkeypatch.setattr(h, "_opener", lambda: _Opener(err))
    with pytest.raises(SourceFault) as exc:
        urllib_http()("GET", URL, {}, None)
    assert exc.value.code == "offline"
    assert "example.org" not in str(exc.value)


def _redirect(newurl: str):
    req = urllib.request.Request(URL, headers={"Authorization": "Bearer tok"})  # noqa: S310
    return h._SameHostRedirect().redirect_request(req, io.BytesIO(b""), 302, "Found", {}, newurl)


def test_redirect_to_another_host_is_refused():
    for bad in ("https://evil.example.com/v1/things", "http://api.example.org/v1/things"):
        with pytest.raises(SourceFault) as exc:
            _redirect(bad)
        assert exc.value.code == "unknown"


def test_redirect_to_the_same_host_is_followed():
    assert _redirect("https://api.example.org/v2/things").full_url == (
        "https://api.example.org/v2/things"
    )


def test_v1_urllib_transport_refuses_cross_host_redirect_and_oversize_body(monkeypatch, tmp_path):
    from anagram.local.index.local import LocalIndex
    from anagram.local.sources import base as src_base
    from anagram.shell.client import Client

    req = urllib.request.Request(URL, headers={"Authorization": "Bearer secret"})  # noqa: S310
    for bad in ("https://evil.example.com/v1", "http://api.example.org/v1"):
        with pytest.raises(ConnectorError):
            src_base._SameHostRedirect().redirect_request(
                req, io.BytesIO(b""), 302, "Found", {}, bad
            )

    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a: _Opener(_Resp(200, {}, b"x" * 20))
    )
    with pytest.raises(ConnectorError, match="limit"):
        src_base.urllib_transport(max_bytes=10)("GET", URL, {}, None)

    # LocalIndex.for_client wires transport from http via as_v1.
    client = Client.init(tmp_path / "home")
    script = Script(HttpResponse(200, {}, b'{"ok": true}'))
    idx = LocalIndex.for_client(client, http=script)
    try:
        assert idx.transport is not None
        status, parsed = idx.transport("GET", URL, {}, None)
        assert status == 200 and parsed == {"ok": True}
    finally:
        idx.close()
        client.vault.close()
