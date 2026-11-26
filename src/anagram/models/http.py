"""The HTTP transport of the model providers (standard library, no new dependency).

One transport type for all HTTP providers, so that a test gives one fake:

    transport.request(method, url, headers, body, timeout) -> (status, headers, body)
    transport.lines(method, url, headers, body, timeout)   -> lines of a streamed body

Both raise `OSError` for a connection fault. An HTTP error status is a return
value of `request`; `lines` raises `ModelError` for it.

Rules of the real transport:

- The URL must use HTTPS, unless the host is this computer (loopback).
- A redirect is refused, so that a key is never sent to a second host.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Protocol

from anagram.models.base import ModelError

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def is_loopback(url: str) -> bool:
    p = urllib.parse.urlsplit(url)
    return p.scheme in ("http", "https") and (p.hostname or "") in LOOPBACK_HOSTS


def check_url(url: str) -> str:
    """Give the URL with no final `/`. Refuse a URL that is not HTTPS, unless
    the host is loopback. Refuse a URL that holds a user name or a password."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ModelError("invalid_url")
    if p.scheme != "https" and not is_loopback(url):
        raise ModelError("url_not_https")
    return url.rstrip("/")


def host_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


# Hosts of cloud model providers that bill each call (security review). An
# OpenAI-compatible profile at one of these hosts is paid: with no price it is
# refused until the profile has prices or an explicit `limit`.
CLOUD_HOSTS = frozenset(
    {
        "api.anthropic.com",
        "api.cerebras.ai",
        "api.cohere.ai",
        "api.cohere.com",
        "api.deepinfra.com",
        "api.deepseek.com",
        "api.fireworks.ai",
        "api.groq.com",
        "api.mistral.ai",
        "api.openai.com",
        "api.perplexity.ai",
        "api.together.ai",
        "api.together.xyz",
        "api.x.ai",
        "generativelanguage.googleapis.com",
        "openrouter.ai",
    }
)
CLOUD_SUFFIXES = (".amazonaws.com", ".azure.com", ".googleapis.com", ".openai.azure.com")


def is_cloud(url: str) -> bool:
    """True if the host of the URL is a known cloud model provider."""
    host = host_of(url).lower().rstrip(".")
    return host in CLOUD_HOSTS or host.endswith(CLOUD_SUFFIXES)


class Transport(Protocol):
    def request(
        self, method: str, url: str, headers: dict, body: bytes | None, timeout: float
    ) -> tuple[int, dict, bytes]: ...

    def lines(
        self, method: str, url: str, headers: dict, body: bytes | None, timeout: float
    ) -> Iterator[str]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError with the 3xx status


class UrllibTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _open(self, method: str, url: str, headers: dict, body: bytes | None, timeout: float):
        req = urllib.request.Request(  # noqa: S310 - scheme checked by check_url
            check_url(url), data=body, headers=headers, method=method
        )
        return self._opener.open(req, timeout=timeout)

    def request(
        self, method: str, url: str, headers: dict, body: bytes | None, timeout: float
    ) -> tuple[int, dict, bytes]:
        try:
            with self._open(method, url, headers, body, timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read() or b""
        except urllib.error.URLError as exc:
            raise OSError(type(exc.reason).__name__) from None

    def lines(
        self, method: str, url: str, headers: dict, body: bytes | None, timeout: float
    ) -> Iterator[str]:
        try:
            resp = self._open(method, url, headers, body, timeout)
        except urllib.error.HTTPError as exc:
            raise http_error(exc.code, dict(exc.headers or {})) from None
        except urllib.error.URLError as exc:
            raise OSError(type(exc.reason).__name__) from None
        with resp:
            for raw in resp:
                yield raw.decode("utf-8", errors="replace").rstrip("\r\n")


def retry_after(headers: dict) -> float | None:
    for name, value in headers.items():
        if name.lower() == "retry-after":
            try:
                return max(0.0, float(value))
            except (TypeError, ValueError):
                return None
    return None


def http_error(status: int | None, headers: dict | None = None) -> ModelError:
    """A `ModelError` for an HTTP status. 429 and 5xx are retryable."""
    retryable = status is None or status == 429 or status >= 500
    code = "unreachable" if status is None else "http_error"
    return ModelError(
        code, status=status, retryable=retryable, retry_after=retry_after(headers or {})
    )


def connection_error() -> ModelError:
    return ModelError("unreachable", retryable=True)
