"""Ollama provider: a model on this computer (the recommended default).

It wraps `OllamaClient` (`anagram.models.ollama_client`), so the loopback rule has one
location: a URL that is not this computer is refused. A remote address is an
OpenAI-compatible profile, and that is external.

Text that goes to this model stays on this computer: `external = False`,
`paid = False`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from anagram.models.base import (
    Capabilities,
    ModelError,
    TextModel,
    TextReply,
    TextRequest,
    checked_reply,
    int_or_zero,
)
from anagram.models.http import Transport, UrllibTransport
from anagram.models.ollama_client import DEFAULT_MODEL, DEFAULT_URL, OllamaClient, OllamaError

RECIPIENT = "This computer (Ollama)"


class OllamaModel(TextModel):
    """`client` is an `OllamaClient` (tests give one with a fake transport).
    `http` is the transport for streamed answers; with a fake client and no
    `http`, `stream` gives the answer in one piece."""

    external = False
    paid = False
    recipient = RECIPIENT

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        url: str = DEFAULT_URL,
        client: OllamaClient | None = None,
        http: Transport | None = None,
        profile_id: str = "",
        max_input_chars: int = 24_000,
    ) -> None:
        try:
            self.client = client or OllamaClient(url)
        except OllamaError as exc:
            raise ModelError("not_loopback") from exc
        self.model_id = model
        self.profile_id = profile_id
        self._http = http or (UrllibTransport() if self.client.transport is None else None)
        self._max_input_chars = max_input_chars

    def capabilities(self) -> Capabilities:
        return Capabilities(
            structured="schema",
            streaming=True,
            temperature=True,
            max_input_chars=self._max_input_chars,
        )

    def _body(self, request: TextRequest, stream: bool) -> dict:
        body: dict = {
            "messages": [
                {"content": request.system, "role": "system"},
                {"content": request.user, "role": "user"},
            ],
            "model": self.model_id,
            "options": {"num_predict": request.max_output_tokens, "temperature": 0},
            "stream": stream,
        }
        if request.schema is not None:
            body["format"] = request.schema
        return body

    def generate(self, request: TextRequest) -> TextReply:
        try:
            got = self.client.post("/api/chat", self._body(request, False), request.timeout_s)
        except OllamaError as exc:
            raise ModelError("unreachable", retryable=True) from exc
        msg = got.get("message") if isinstance(got, dict) else None
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), str):
            raise ModelError("bad_answer")
        reply = TextReply(
            text=msg["content"],
            data=None,
            input_tokens=int_or_zero(got.get("prompt_eval_count")),
            output_tokens=int_or_zero(got.get("eval_count")),
            model=str(got.get("model") or self.model_id),
            stop=str(got.get("done_reason") or "stop"),
        )
        return checked_reply(reply, request.schema)

    def stream(self, request: TextRequest) -> Iterator[str]:
        if self._http is None:
            yield from super().stream(request)
            return
        body = json.dumps(self._body(request, True)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            for line in self._http.lines(
                "POST", f"{self.client.url}/api/chat", headers, body, request.timeout_s
            ):
                if not line.strip():
                    continue
                try:
                    part = json.loads(line)
                except ValueError:
                    raise ModelError("bad_answer") from None
                msg = part.get("message") if isinstance(part, dict) else None
                if isinstance(msg, dict) and isinstance(msg.get("content"), str) and msg["content"]:
                    yield msg["content"]
                if isinstance(part, dict) and part.get("done"):
                    return
        except OSError:
            raise ModelError("unreachable", retryable=True) from None

    def probe(self) -> dict:
        try:
            names = self.client.models()
        except OllamaError:
            return {"models": [], "ok": False, "reason": "unreachable"}
        found = self.model_id in names or (
            ":" not in self.model_id and f"{self.model_id}:latest" in names
        )
        return {"models": names, "ok": found, "reason": None if found else "model_not_installed"}
