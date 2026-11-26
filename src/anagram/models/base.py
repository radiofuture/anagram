"""The model interface: one contract for each text model that Anagram calls.

A `TextModel` follows the disclosure-recipient contract
(docs/design/disclosure-recipient.md): it declares `external`, `recipient`,
`paid`, and `reads`. The caller refuses an external model unless the person
opted in (`check_model`). A paid model runs only inside `Gate`
(`anagram.models.budget`).

Rules for an adapter:

- `generate` sends one request. A moderated or refused call returns
  `TextReply(refusal=True)`. A transport fault, an HTTP error, or an answer
  that does not agree with the schema raises `ModelError`.
- No error message, log line, or `repr` holds an API key, a prompt, or a raw
  response.
- Tests use `FakeTextModel` or a fake transport. No test calls the network.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, replace
from decimal import Decimal

STRUCTURED_MODES = ("schema", "json", "text")


class ModelError(Exception):
    """A model call failed. `code` is a short stable word for the caller.

    `status` is the HTTP status, if there was one. `retryable` is True for
    429, 5xx, and connection faults. The message holds no key and no body."""

    def __init__(
        self,
        code: str,
        *,
        status: int | None = None,
        retryable: bool = False,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(code if status is None else f"{code} (status {status})")
        self.code = code
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after


class BudgetRefused(ModelError):
    """The spend gate refused: no approval, no prices, or the limit is reached."""


class ModelRefused(Exception):
    """The caller did not permit this model to read the text (no opt-in)."""


@dataclass(frozen=True)
class Capabilities:
    structured: str  # "schema" | "json" | "text"
    streaming: bool
    temperature: bool  # False: the adapter sends no temperature
    max_input_chars: int
    embeddings: int = 0  # vector size, 0 = none


@dataclass(frozen=True)
class TextRequest:
    system: str
    user: str
    schema: dict | None = None  # JSON schema of the answer
    max_output_tokens: int = 512
    purpose: str = ""  # for example "understand.triage", "ask", "digest"
    timeout_s: float = 60.0


@dataclass(frozen=True)
class TextReply:
    text: str
    data: dict | None  # parsed and schema-checked, when the request has a schema
    input_tokens: int
    output_tokens: int
    model: str
    stop: str
    refusal: bool = False
    cost: Decimal | None = None  # USD; the cost that the provider reports, or the gate estimate
    provider: str | None = None


class TextModel(ABC):
    profile_id: str = ""
    model_id: str = ""
    # disclosure-recipient contract
    external: bool = False
    recipient: str = ""  # the name of the party that reads the text, for people
    paid: bool = False
    reads: str = "the text that you permit this model to read"
    # USD per million tokens (input, output). None: no price is known.
    prices: tuple[Decimal, Decimal] | None = None

    @property
    def recipient_id(self) -> str:
        """The opt-in key of this model in `source.prefs.allow_external`."""
        return f"model:{self.profile_id}"

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def generate(self, request: TextRequest) -> TextReply: ...

    def stream(self, request: TextRequest) -> Iterator[str]:
        """Pieces of the answer text. The default gives one piece."""
        reply = self.generate(request)
        if reply.text and not reply.refusal:
            yield reply.text

    def probe(self) -> dict:
        """{"ok": bool, "reason": str | None, "models": [...]}. No paid call."""
        return {"models": [], "ok": True, "reason": None}

    def ready(self) -> None:
        """Raise `ModelError` if a call cannot start (for example, no key)."""
        return None

    def output_limit(self, request: TextRequest) -> int:
        """The largest number of output tokens that one attempt can bill."""
        return request.max_output_tokens

    def max_attempts(self, request: TextRequest) -> int:
        """The largest number of billed attempts that one `generate` makes."""
        return 1


def int_or_zero(value: object) -> int:
    """An int count from a provider answer; any other value is 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def check_model(model: TextModel, allowed: bool) -> None:
    """The same rule as `check_enricher`: an external model needs the opt-in."""
    if model.external and not allowed:
        raise ModelRefused(
            f"this model sends text to {model.recipient or 'an outside service'};"
            " the person must opt in"
        )


def parse_prices(prices: object) -> tuple[Decimal, Decimal] | None:
    """Prices from a profile (two numbers or number strings). None stays None."""
    if prices is None:
        return None
    try:
        price_in, price_out = (Decimal(str(p)) for p in prices)  # type: ignore[union-attr]
    except (ArithmeticError, TypeError, ValueError) as exc:
        raise ModelError("invalid_prices") from exc
    if not (price_in.is_finite() and price_out.is_finite()) or price_in < 0 or price_out < 0:
        raise ModelError("invalid_prices")
    return price_in, price_out


# ------------------------------------------------------------ strict output


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```") and text.endswith("```") and len(text) >= 6:
        body = text[3:-3]
        first, sep, rest = body.partition("\n")
        if sep and first.strip().isalnum():
            body = rest
        return body.strip()
    return text


_TYPES: dict[str, tuple[type, ...]] = {
    "array": (list,),
    "boolean": (bool,),
    "integer": (int,),
    "null": (type(None),),
    "number": (int, float),
    "object": (dict,),
    "string": (str,),
}


def _is_type(value: object, name: str) -> bool:
    if name not in _TYPES:
        return False
    if isinstance(value, bool) and name in ("integer", "number"):
        return False
    if name == "integer" and isinstance(value, float):
        return value.is_integer()
    return isinstance(value, _TYPES[name])


def check_schema(value: object, schema: dict, path: str = "$") -> None:
    """Check `value` against the subset of JSON Schema that Anagram uses:
    `type`, `enum`, `properties`, `required`, `additionalProperties: false`,
    `items`, `minItems`, `maxItems`, `maxLength`. Raise `ModelError`.

    A field that the schema does not list is refused unless the schema sets
    `additionalProperties` to true."""
    kind = schema.get("type")
    if kind is not None:
        kinds = kind if isinstance(kind, list) else [kind]
        if not any(_is_type(value, k) for k in kinds):
            raise ModelError("bad_output")
    if "enum" in schema and value not in schema["enum"]:
        raise ModelError("bad_output")
    if isinstance(value, dict):
        _check_object(value, schema, path)
    if isinstance(value, list):
        _check_array(value, schema, path)
    if isinstance(value, str) and "maxLength" in schema and len(value) > int(schema["maxLength"]):
        raise ModelError("bad_output")


def _check_object(value: dict, schema: dict, path: str) -> None:
    props = schema.get("properties") or {}
    if any(name not in value for name in schema.get("required") or ()):
        raise ModelError("bad_output")
    if schema.get("additionalProperties") is not True and "properties" in schema:
        if any(name not in props for name in value):
            raise ModelError("bad_output")
    for name, sub in props.items():
        if name in value and isinstance(sub, dict):
            check_schema(value[name], sub, f"{path}.{name}")


def _check_array(value: list, schema: dict, path: str) -> None:
    if len(value) < int(schema.get("minItems", 0)):
        raise ModelError("bad_output")
    if "maxItems" in schema and len(value) > int(schema["maxItems"]):
        raise ModelError("bad_output")
    items = schema.get("items")
    if isinstance(items, dict):
        for i, entry in enumerate(value):
            check_schema(entry, items, f"{path}[{i}]")


def parse_strict(text: str, schema: dict) -> dict:
    """The one JSON object in `text`, checked against `schema`.

    The text must be one JSON object (one code fence around it is permitted).
    Text before or after the object, a second object, or a field that the
    schema does not list raises `ModelError("bad_output")`."""
    try:
        value = json.loads(_strip_fence(text))
    except (TypeError, ValueError) as exc:
        raise ModelError("bad_output") from exc
    if not isinstance(value, dict):
        raise ModelError("bad_output")
    check_schema(value, schema)
    return value


def checked_reply(reply: TextReply, schema: dict | None) -> TextReply:
    """Fill `data` from the text when the request has a schema."""
    if schema is None or reply.refusal:
        return reply
    return replace(reply, data=parse_strict(reply.text, schema))
