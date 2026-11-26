"""`FakeTextModel`: a deterministic model for tests. It makes no network call.

It records each request in `calls`, so a test can check what the model read.

Replies:

- No script: with a schema, the answer is the smallest value that agrees with
  the schema (the first `enum` entry, an empty string, 0, false, an empty
  list). With no schema, the answer is the text `"ok"`.
- `replies`: a list that is used in order (the last entry repeats), or a
  function `(TextRequest) -> entry`. An entry is a `dict` (the data), a `str`
  (the raw text, which is checked against the schema), a `TextReply`, or an
  exception (it is raised).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Sequence
from decimal import Decimal

from anagram.models.base import (
    Capabilities,
    TextModel,
    TextReply,
    TextRequest,
    checked_reply,
)

Entry = dict | str | TextReply | BaseException


def minimal(schema: dict) -> object:
    """The smallest value that agrees with `schema` (the subset of `check_schema`)."""
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = kind[0]
    if kind == "object":
        props = schema.get("properties") or {}
        return {name: minimal(props.get(name) or {}) for name in schema.get("required") or ()}
    if kind == "array":
        items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        return [minimal(items) for _ in range(int(schema.get("minItems", 0)))]
    if kind == "string":
        return ""
    if kind in ("integer", "number"):
        return 0
    if kind == "boolean":
        return False
    return None


class FakeTextModel(TextModel):
    def __init__(
        self,
        replies: Sequence[Entry] | Callable[[TextRequest], Entry] | None = None,
        *,
        profile_id: str = "fake-00000000",
        model_id: str = "fake-model",
        external: bool = False,
        recipient: str = "",
        paid: bool = False,
        prices: tuple[Decimal, Decimal] | None = None,
        structured: str = "schema",
        pieces: int = 1,
    ) -> None:
        self.profile_id = profile_id
        self.model_id = model_id
        self.external = external
        self.recipient = recipient or ("a fake outside service" if external else "this computer")
        self.paid = paid
        self.prices = prices
        self._replies = replies
        self._structured = structured
        self._pieces = max(1, pieces)
        self.calls: list[TextRequest] = []

    def capabilities(self) -> Capabilities:
        return Capabilities(
            structured=self._structured, streaming=True, temperature=True, max_input_chars=24_000
        )

    def _entry(self, request: TextRequest) -> Entry | None:
        if self._replies is None:
            return None
        if callable(self._replies):
            return self._replies(request)
        if not self._replies:
            return None
        return self._replies[min(len(self.calls) - 1, len(self._replies) - 1)]

    def generate(self, request: TextRequest) -> TextReply:
        self.calls.append(request)
        entry = self._entry(request)
        if isinstance(entry, BaseException):
            raise entry
        if isinstance(entry, TextReply):
            return checked_reply(entry, request.schema)
        if entry is None:
            entry = "ok" if request.schema is None else minimal(request.schema)
        text = entry if isinstance(entry, str) else json.dumps(entry, sort_keys=True)
        reply = TextReply(
            text=text,
            data=None,
            input_tokens=(len(request.system) + len(request.user)) // 4 + 1,
            output_tokens=len(text) // 4 + 1,
            model=self.model_id,
            stop="stop",
        )
        return checked_reply(reply, request.schema)

    def stream(self, request: TextRequest) -> Iterator[str]:
        reply = self.generate(request)
        if reply.refusal or not reply.text:
            return
        size = -(-len(reply.text) // self._pieces)
        for i in range(0, len(reply.text), size):
            yield reply.text[i : i + size]

    @property
    def read(self) -> list[str]:
        """All text that the model read, one entry for each call."""
        return [c.system + "\n" + c.user for c in self.calls]
