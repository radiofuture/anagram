"""Fakes for the model provider tests. Nothing here calls the network.

`NOT_A_KEY` is a placeholder. No test holds a real key."""

from __future__ import annotations

import json

from anagram.models import TextRequest

SCHEMA = {
    "additionalProperties": False,
    "properties": {"kind": {"enum": ["finding", "note"], "type": "string"}},
    "required": ["kind"],
    "type": "object",
}
REQ = TextRequest(system="You sort items.", user="the item", schema=SCHEMA, max_output_tokens=80)
UNI = "https://llm.example.edu/v1"
NOT_A_KEY = "test-key-not-real"


def chat(content: str, **extra) -> dict:
    return {
        "choices": [{"finish_reason": "stop", "message": {"content": content, **extra}}],
        "model": "served-model",
        "usage": {"completion_tokens": 7, "prompt_tokens": 40},
    }


class FakeHTTP:
    """Scripted answers. An entry is `(status, json)` or an exception."""

    def __init__(self, answers=(), lines=()):
        self.answers = list(answers)
        self.stream_lines = list(lines)
        self.calls: list[dict] = []

    def _record(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "body": json.loads(body) if body else None,
                "headers": headers,
                "method": method,
                "timeout": timeout,
                "url": url,
            }
        )

    def request(self, method, url, headers, body, timeout):
        self._record(method, url, headers, body, timeout)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        status, data = answer
        return status, {}, json.dumps(data).encode()

    def lines(self, method, url, headers, body, timeout):
        self._record(method, url, headers, body, timeout)
        yield from self.stream_lines

    def posts(self):
        return [c["body"] for c in self.calls if c["method"] == "POST"]


class FakeOllama:
    def __init__(self, content='{"kind": "note"}', tags=("llama3.2:latest",), down=False):
        self.content, self.tags, self.down = content, tags, down
        self.calls: list[tuple] = []

    def __call__(self, method, url, body, timeout):
        self.calls.append((method, url, body, timeout))
        if self.down:
            raise ConnectionRefusedError("no server")
        if url.endswith("/api/tags"):
            return {"models": [{"name": t} for t in self.tags]}
        return {
            "done_reason": "stop",
            "eval_count": 9,
            "message": {"content": self.content},
            "model": body["model"],
            "prompt_eval_count": 31,
        }
