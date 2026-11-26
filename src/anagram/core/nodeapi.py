"""How the client talks to a node: in process (local mode) or over HTTP."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, Protocol

from anagram.core.canonical import JsonObject

# transport(method, path_with_query, body, headers) -> response.
# `body` is a JSON object, raw bytes (sent as application/octet-stream), or None.
# The response is the parsed JSON, or raw bytes for an application/octet-stream
# answer. It is `Any` because it comes off the network: each caller checks the
# fields it reads. A transport raises NodeHTTPError for an HTTP error status.
type Transport = Callable[[str, str, JsonObject | bytes | None, dict[str, str]], Any]


class NodeHTTPError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"node answered {status}: {detail}")
        self.status = status
        self.detail = detail


class NodeAPI(ABC):
    @abstractmethod
    def submit(self, entry: JsonObject) -> JsonObject: ...

    @abstractmethod
    def checkpoint(self) -> JsonObject: ...

    @abstractmethod
    def consistency(self, old_size: int, new_size: int) -> list[str]: ...

    def entries(self, start: int, end: int) -> list[str]:
        raise NotImplementedError

    def inclusion(self, index: int, size: int) -> list[str]:
        raise NotImplementedError

    def anchored(self, size: int) -> JsonObject | None:
        """First checkpoint >= size with background anchors, or None."""
        return None


class LogService(Protocol):
    """The in-process log service of a node (`anagram.proofs.node.service.NodeService`).
    The shell makes it; this module does not import node code."""

    def submit(self, entry: JsonObject) -> JsonObject: ...

    def checkpoint(self) -> JsonObject: ...

    def consistency(self, old_size: int, new_size: int) -> list[str]: ...

    def entries(self, start: int, end: int) -> list[str]: ...

    def inclusion(self, index: int, size: int) -> list[str]: ...


class LocalNode(NodeAPI):
    def __init__(self, service: LogService) -> None:
        self.service = service

    def submit(self, entry: JsonObject) -> JsonObject:
        return self.service.submit(entry)

    def checkpoint(self) -> JsonObject:
        return self.service.checkpoint()

    def consistency(self, old_size: int, new_size: int) -> list[str]:
        return self.service.consistency(old_size, new_size)

    def entries(self, start: int, end: int) -> list[str]:
        return self.service.entries(start, end)

    def inclusion(self, index: int, size: int) -> list[str]:
        return self.service.inclusion(index, size)


def urllib_transport(base_url: str) -> Transport:
    if not base_url.startswith(("https://", "http://")):
        raise ValueError("node URL must be http(s)")

    def call(
        method: str, path: str, body: JsonObject | bytes | None, headers: dict[str, str]
    ) -> Any:
        data: bytes | None
        if isinstance(body, bytes):
            data, ctype = body, "application/octet-stream"
        else:
            data = json.dumps(body).encode() if body is not None else None
            ctype = "application/json"
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            base_url.rstrip("/") + path,
            data=data,
            method=method,
            headers={"Content-Type": ctype, **headers},
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310
                raw = resp.read()
                if resp.headers.get("Content-Type", "").startswith("application/octet-stream"):
                    return raw
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("detail", "")
            except (ValueError, AttributeError):
                detail = exc.reason
            raise NodeHTTPError(exc.code, str(detail)) from exc

    return call


class HttpNode(NodeAPI):
    def __init__(
        self, base_url: str, transport: Transport | None = None, token: str | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport or urllib_transport(base_url)
        self.token = token

    def call(
        self,
        method: str,
        path: str,
        body: JsonObject | bytes | None = None,
        auth: bool = False,
    ) -> Any:
        """One request. The answer is parsed JSON off the network (see `Transport`)."""
        headers: dict[str, str] = {}
        if auth:
            if not self.token:
                raise NodeHTTPError(401, "no session; run `anagram login` to sign in again")
            headers["Authorization"] = f"Bearer {self.token}"
        return self.transport(method, path, body, headers)

    def submit(self, entry: JsonObject) -> JsonObject:
        out: JsonObject = self.call("POST", "/log/entries", {"entry": entry}, auth=True)
        return out

    def checkpoint(self) -> JsonObject:
        out: JsonObject = self.call("GET", "/log/checkpoint")
        return out

    def consistency(self, old_size: int, new_size: int) -> list[str]:
        q = urllib.parse.urlencode({"old": old_size, "new": new_size})
        proof: list[str] = self.call("GET", f"/log/proof/consistency?{q}")["consistency"]
        return proof

    def inclusion(self, index: int, size: int) -> list[str]:
        q = urllib.parse.urlencode({"index": index, "size": size})
        proof: list[str] = self.call("GET", f"/log/proof/inclusion?{q}")["inclusion"]
        return proof

    def entries(self, start: int, end: int) -> list[str]:
        q = urllib.parse.urlencode({"end": end, "start": start})
        rows: list[str] = self.call("GET", f"/log/entries?{q}")["entries"]
        return rows

    def anchored(self, size: int) -> JsonObject | None:
        q = urllib.parse.urlencode({"size": size})
        try:
            out: JsonObject = self.call("GET", f"/log/anchored?{q}")
        except NodeHTTPError as exc:
            if exc.status == 404:
                return None
            raise
        return out
