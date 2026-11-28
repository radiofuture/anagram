"""OpenAI-compatible provider (Chat Completions) for any base URL.

It works for vLLM, LM Studio, and an endpoint of a university. `OpenAIModel`
and `OpenRouterModel` are subclasses with fixed URLs.

Disclosure:

- The model is local only if the host of the base URL is this computer. All
  other hosts are external, and HTTPS is mandatory for them.
- The model is paid if the profile has prices, or if the host is a known
  cloud model provider (`http.is_cloud`). `OpenAIModel` and `OpenRouterModel`
  are always paid. A model that is not paid and not on this computer (a
  university endpoint) runs inside `UsageGate` (`profile.resolve`).

Structured output has three modes (`Capabilities.structured`):

- `schema`: `response_format` with the JSON schema (strict).
- `json`: `response_format` `json_object`; the schema is in the system text.
- `text`: no `response_format`; the schema is in the system text, the answer
  is read with `parse_strict`, and one more attempt is made if it fails.

The mode is found one time. `probe` finds it with a small request (not for a
paid model). `generate` also goes down one mode when the server refuses a mode
with status 400 or 422 (such a call is not billed). The profile layer stores
the mode (`structured=`) so that the search is not done again.

OpenRouter: `route` is mandatory. The request pins the model providers with
no fallback and `data_collection: "deny"`, so no other provider gets the text.

Tests give a fake `transport`. No test calls the network.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import replace
from decimal import Decimal, InvalidOperation

from anagram.models.base import (
    STRUCTURED_MODES,
    Capabilities,
    ModelError,
    TextModel,
    TextReply,
    TextRequest,
    checked_reply,
    int_or_zero,
    parse_prices,
)
from anagram.models.http import (
    Transport,
    UrllibTransport,
    check_url,
    connection_error,
    host_of,
    http_error,
    is_cloud,
    is_loopback,
)

OPENAI_URL = "https://api.openai.com/v1"
OPENROUTER_URL = "https://openrouter.ai/api/v1"
PROBE_TIMEOUT = 5.0
MODE_REFUSED = (400, 422)  # the server does not support this request shape
PROBE_SCHEMA = {
    "additionalProperties": False,
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "type": "object",
}


def schema_text(schema: dict) -> str:
    return (
        "Answer with one JSON object and no other text. The object must agree with"
        " this JSON schema: " + json.dumps(schema, sort_keys=True)
    )


def _moderation(err: object) -> bool:
    if not isinstance(err, dict):
        return False
    text = json.dumps(err).lower()
    return "moderation" in text or "flagged" in text


def _cost(usage: dict) -> Decimal | None:
    if usage.get("cost") is None:
        return None
    try:
        cost = Decimal(str(usage["cost"]))
    except InvalidOperation:
        return None
    return cost if cost.is_finite() and cost >= 0 else None


class OpenAICompatModel(TextModel):
    token_field = "max_tokens"  # noqa: S105 - the name of a request field
    send_temperature = True
    key_mandatory = False

    def __init__(
        self,
        model: str,
        base_url: str,
        *,
        api_key: str | None = None,
        profile_id: str = "",
        label: str = "",
        prices: Sequence[object] | None = None,
        structured: str | None = None,
        transport: Transport | None = None,
        max_input_chars: int = 24_000,
    ) -> None:
        if structured is not None and structured not in STRUCTURED_MODES:
            raise ModelError("invalid_structured_mode")
        self.base_url = check_url(base_url)
        self.model_id = model
        self.profile_id = profile_id
        self.prices = parse_prices(prices)
        self.external = not is_loopback(self.base_url)
        # A cloud host bills each call, also when the profile has no price
        # (security review): the gate then refuses it until a price or a
        # limit is set.
        self.paid = self.prices is not None or (self.external and is_cloud(self.base_url))
        self.recipient = "This computer" if not self.external else (label or host_of(self.base_url))
        self.structured = structured
        self._api_key = api_key or None
        self._transport = transport or UrllibTransport()
        self._max_input_chars = max_input_chars

    # ------------------------------------------------------------ contract

    def capabilities(self) -> Capabilities:
        return Capabilities(
            structured=self.structured or "schema",
            streaming=True,
            temperature=self.send_temperature,
            max_input_chars=self._max_input_chars,
        )

    def ready(self) -> None:
        if self.key_mandatory and not self._api_key:
            raise ModelError("no_key")

    def max_attempts(self, request: TextRequest) -> int:
        # Text mode can make one more billed attempt. An unknown mode can end
        # in text mode.
        return 2 if request.schema is not None and self.structured in (None, "text") else 1

    # ------------------------------------------------------------- request

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _extra(self) -> dict:
        """Fields that a subclass adds to each request body."""
        return {}

    def build_request(self, request: TextRequest, mode: str | None, stream: bool = False) -> dict:
        system = request.system
        body: dict = {"model": self.model_id, self.token_field: request.max_output_tokens}
        if self.send_temperature:
            body["temperature"] = 0
        if request.schema is not None:
            if mode == "schema":
                body["response_format"] = {
                    "json_schema": {"name": "answer", "schema": request.schema, "strict": True},
                    "type": "json_schema",
                }
            else:
                system = (system + "\n\n" if system else "") + schema_text(request.schema)
                if mode == "json":
                    body["response_format"] = {"type": "json_object"}
        messages = [{"content": system, "role": "system"}] if system else []
        body["messages"] = [*messages, {"content": request.user, "role": "user"}]
        if stream:
            body["stream"] = True
        body.update(self._extra())
        return body

    def _post(self, body: dict, timeout: float) -> TextReply:
        """One HTTP attempt. Raise `ModelError` on a fault."""
        raw_body = json.dumps(body).encode("utf-8")
        try:
            status, headers, raw = self._transport.request(
                "POST", f"{self.base_url}/chat/completions", self._headers(), raw_body, timeout
            )
        except OSError:
            raise connection_error() from None
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        err = data.get("error")
        if status != 200 or err:
            code = status
            if status == 200 and isinstance(err, dict) and isinstance(err.get("code"), int):
                code = err["code"]
            if code == 403 and _moderation(err):
                return TextReply("", None, 0, 0, self.model_id, "moderation", refusal=True)
            raise http_error(code if code != 200 else 502, headers)
        choices = data.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            raise http_error(502)
        msg = choices[0].get("message") or {}
        finish = str(choices[0].get("finish_reason"))
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        content = msg.get("content")
        return TextReply(
            text=content if isinstance(content, str) else "",
            data=None,
            input_tokens=int_or_zero(usage.get("prompt_tokens")),
            output_tokens=int_or_zero(usage.get("completion_tokens")),
            model=str(data.get("model") or self.model_id),
            stop=finish,
            refusal=finish == "content_filter" or bool(msg.get("refusal")),
            cost=_cost(usage),
            provider=str(data["provider"]) if data.get("provider") else None,
        )

    def _modes(self) -> tuple[str, ...]:
        if self.structured is not None:
            return (self.structured,)
        return STRUCTURED_MODES

    def generate(self, request: TextRequest) -> TextReply:
        self.ready()
        if request.schema is None:
            return self._post(self.build_request(request, None), request.timeout_s)
        modes = self._modes()
        for i, mode in enumerate(modes):
            body = self.build_request(request, mode)
            try:
                reply = self._post(body, request.timeout_s)
            except ModelError as exc:
                if exc.status in MODE_REFUSED and i + 1 < len(modes):
                    continue  # the server refused the shape: go down one mode
                raise
            self.structured = mode
            if reply.refusal:
                return reply
            try:
                return checked_reply(reply, request.schema)
            except ModelError:
                if mode != "text":
                    raise
            # Text mode: one more attempt, then the fault goes to the caller.
            second = self._post(body, request.timeout_s)
            combined_cost = (
                None
                if reply.cost is None and second.cost is None
                else (reply.cost or Decimal(0)) + (second.cost or Decimal(0))
            )
            combined = replace(
                second,
                input_tokens=reply.input_tokens + second.input_tokens,
                output_tokens=reply.output_tokens + second.output_tokens,
                cost=combined_cost,
            )
            return checked_reply(combined, request.schema)
        raise ModelError("bad_answer")  # pragma: no cover - the loop always returns

    def stream(self, request: TextRequest) -> Iterator[str]:
        self.ready()
        body = json.dumps(self.build_request(request, self.structured, stream=True))
        try:
            for line in self._transport.lines(
                "POST",
                f"{self.base_url}/chat/completions",
                self._headers(),
                body.encode("utf-8"),
                request.timeout_s,
            ):
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    return
                try:
                    part = json.loads(payload)
                except ValueError:
                    continue
                choices = part.get("choices") if isinstance(part, dict) else None
                if not choices or not isinstance(choices[0], dict):
                    continue
                delta = choices[0].get("delta") or {}
                if isinstance(delta.get("content"), str) and delta["content"]:
                    yield delta["content"]
        except OSError:
            raise connection_error() from None

    # --------------------------------------------------------------- probe

    def _list_models(self) -> list[str]:
        try:
            status, headers, raw = self._transport.request(
                "GET", f"{self.base_url}/models", self._headers(), None, PROBE_TIMEOUT
            )
        except OSError:
            raise connection_error() from None
        if status in (401, 403):
            raise ModelError("key_refused", status=status)
        if status != 200:
            return []  # some servers have no model list; that is not a fault
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return []
        rows = data.get("data") if isinstance(data, dict) else None
        return sorted(
            r["id"] for r in rows or [] if isinstance(r, dict) and isinstance(r.get("id"), str)
        )

    def probe(self) -> dict:
        """Check the address and the key. For a model that is not paid, also
        find the structured mode with one small request for each mode. A paid
        model gets no generation call here; `generate` finds its mode."""
        out: dict = {"models": [], "ok": False, "reason": None, "structured": self.structured}
        try:
            self.ready()
            out["models"] = self._list_models()
            if not self.paid and self.structured is None:
                self.generate(
                    TextRequest(
                        system="",
                        user='Answer with the JSON object {"ok": true}.',
                        schema=PROBE_SCHEMA,
                        max_output_tokens=16,
                        purpose="probe",
                        timeout_s=PROBE_TIMEOUT * 4,
                    )
                )
        except ModelError as exc:
            out["reason"] = exc.code
            return out
        out["ok"] = True
        out["structured"] = self.structured
        return out


class OpenAIModel(OpenAICompatModel):
    """OpenAI, fixed base URL. The person gives the model id and the prices.
    The request has no `temperature` (some models refuse it)."""

    token_field = "max_completion_tokens"  # noqa: S105 - the name of a request field
    send_temperature = False
    key_mandatory = True

    def __init__(self, model: str, **kw: object) -> None:
        kw.pop("base_url", None)
        kw.setdefault("structured", "schema")
        super().__init__(model, OPENAI_URL, **kw)  # type: ignore[arg-type]
        self.external = True
        self.paid = True
        self.recipient = "OpenAI (cloud model provider)"


class OpenRouterModel(OpenAICompatModel):
    """OpenRouter. Two parties read the text: the router and the pinned model
    provider. The cost of each call comes from the response."""

    send_temperature = False
    key_mandatory = True

    def __init__(self, model: str, *, route: Sequence[str] = (), **kw: object) -> None:
        route = tuple(route)
        if not route or not all(isinstance(r, str) and r.strip() for r in route):
            raise ModelError("no_route")
        kw.pop("base_url", None)
        kw.setdefault("structured", "schema")
        super().__init__(model, OPENROUTER_URL, **kw)  # type: ignore[arg-type]
        self.route = route
        self.external = True
        self.paid = True
        names = ", ".join(r.strip() for r in route)
        self.recipient = f"OpenRouter (router) and {names} (model provider)"
        if self.prices is None:
            from anagram.models.ledger import OPENROUTER_PRICES

            self.prices = OPENROUTER_PRICES.get(model)

    def _headers(self) -> dict:
        return {**super()._headers(), "X-Title": "radiofuture anagram"}

    def _extra(self) -> dict:
        return {
            "provider": {
                "allow_fallbacks": False,
                "data_collection": "deny",
                "order": list(self.route),
                "require_parameters": True,
            },
            "reasoning": {"effort": "none"},
            "usage": {"include": True},
        }
