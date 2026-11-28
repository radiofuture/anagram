"""A small client for a local Ollama server (http://127.0.0.1:11434).

Ollama runs a model on this computer. Text that goes to it stays on this
computer, so an Ollama adapter is not external (`external = False`) and not
paid. The client refuses a URL that is not a loopback address: a remote
Ollama would be an external recipient, and that needs its own adapter and the
user's opt-in.

Tests give a fake `transport`. No test calls a real server.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from anagram.models.base import ModelError
from anagram.models.http import LOOPBACK_HOSTS, _NoRedirect, check_url, is_loopback

__all__ = ["LOOPBACK_HOSTS", "OllamaClient", "OllamaError", "is_loopback"]

DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2"
PROBE_TIMEOUT = 0.8
CHAT_TIMEOUT = 180.0

# transport(method, url, body or None, timeout) -> parsed JSON
Transport = Callable[[str, str, dict | None, float], Any]
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


class OllamaError(Exception):
    pass


def _urllib_transport(method: str, url: str, body: dict | None, timeout: float) -> Any:
    try:
        checked = check_url(url)
    except ModelError as exc:
        raise OllamaError(f"Ollama URL is not valid: {exc.code}") from None
    if not is_loopback(checked):
        raise OllamaError("Ollama must run on this computer (a loopback URL)")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(  # noqa: S310 - loopback URL, checked above
        checked, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OllamaError(f"{type(exc).__name__}: {exc}") from exc


@dataclass
class OllamaClient:
    url: str = DEFAULT_URL
    transport: Transport | None = None
    timeout: float = CHAT_TIMEOUT
    _transport: Transport = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            self.url = check_url(self.url)
        except ModelError as exc:
            raise OllamaError(f"Ollama URL is not valid: {exc.code}") from None
        if not is_loopback(self.url):
            raise OllamaError("Ollama must run on this computer (a loopback URL)")
        self._transport = self.transport or _urllib_transport

    def models(self, timeout: float = PROBE_TIMEOUT) -> list[str]:
        """Names of the installed models. Raises OllamaError if no server answers."""
        try:
            got = self._transport("GET", f"{self.url}/api/tags", None, timeout)
        except OllamaError:
            raise
        except Exception as exc:  # any transport failure means "not there"
            raise OllamaError(str(exc)) from exc
        if not isinstance(got, dict) or not isinstance(got.get("models"), list):
            raise OllamaError("unexpected answer from /api/tags")
        return sorted(
            m["name"]
            for m in got["models"]
            if isinstance(m, dict) and isinstance(m.get("name"), str)
        )

    def detect(self) -> dict:
        """{"available": bool, "models": [...], "url": ...} for the Settings page."""
        try:
            return {"available": True, "models": self.models(), "url": self.url}
        except OllamaError:
            return {"available": False, "models": [], "url": self.url}

    def chat(self, model: str, system: str, user: str, schema: dict | None = None) -> str:
        """One non-streaming chat turn. Returns the text of the answer."""
        body: dict = {
            "messages": [{"content": system, "role": "system"}, {"content": user, "role": "user"}],
            "model": model,
            "options": {"temperature": 0},
            "stream": False,
        }
        if schema is not None:
            body["format"] = schema
        got = self.post("/api/chat", body)
        msg = got.get("message") if isinstance(got, dict) else None
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), str):
            raise OllamaError("unexpected answer from /api/chat")
        return msg["content"]

    def post(self, path: str, body: dict, timeout: float | None = None) -> Any:
        """POST one JSON body to the server. Returns the parsed JSON answer.
        The model provider (`anagram.models.providers.ollama`) uses this."""
        try:
            return self._transport("POST", f"{self.url}{path}", body, timeout or self.timeout)
        except OllamaError:
            raise
        except Exception as exc:  # a transport raises many types; one error type out
            raise OllamaError(str(exc)) from exc
