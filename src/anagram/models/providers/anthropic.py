"""Anthropic provider (Messages API, through the official SDK).

Anthropic reads the text of each call: `external = True`, `paid = True`. The
model runs only inside `Gate` (`anagram.models.budget`).

Request (checked 2026-11-16 against the Claude API reference notes that were
cached on 2026-11-03; check it again before the first live call):

- Strict JSON output: `output_config.format` with the JSON schema.
- `output_config.effort` is `low`.
- No `temperature`, `top_p`, or `top_k` in any request. The current models
  refuse a value that is not the default (Claude Haiku 5.5 refused one in the
  earlier run).
- Thinking: `{"type": "disabled"}` is sent only to Claude Haiku 5.5, which
  accepts it at this effort. Claude Opus 5.5, Claude Sonnet 5.5, and Claude
  Fable 5.2 refuse it (status 400), so the request has no `thinking` field for
  them and the model decides. Thinking tokens are billed as output tokens, so
  for these models the adapter adds `THINKING_HEADROOM` to `max_tokens`, and
  `output_limit` gives the sum to the spend gate.
- No assistant prefill and no server-side fallback to a different model: the
  spend gate and the consent text name one model.

Prices come from the profile, else from the table in
`anagram.models.ledger`. There is no table price for `claude-fable-5-2`;
the profile must carry it, or the gate refuses.

`client` is for tests: an object with `messages.create(**body)` and
`messages.stream(**body)`. The SDK (the `anagram[anthropic]` extra) is loaded
only when no client is given. No test calls the network.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from anagram.models.base import (
    Capabilities,
    ModelError,
    TextModel,
    TextReply,
    TextRequest,
    checked_reply,
    int_or_zero,
    parse_prices,
)

MODELS = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-2")
DEFAULT_MODEL = "claude-haiku-5-5"  # the default for item understanding
THINKING_OFF = frozenset({"claude-haiku-5-5"})  # models that accept thinking "disabled"
THINKING_HEADROOM = 2048
RECIPIENT = "Anthropic (cloud model provider)"
SAMPLING_FIELDS = ("temperature", "top_p", "top_k")


def _status(exc: BaseException) -> int | None:
    code = getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


def _error(exc: BaseException) -> ModelError:
    """A `ModelError` with the status only. The SDK message can hold request
    text, so it is not copied."""
    status = _status(exc)
    retryable = status is None or status == 429 or status >= 500
    code = "unreachable" if status is None else "http_error"
    return ModelError(code, status=status, retryable=retryable)


class AnthropicModel(TextModel):
    external = True
    paid = True
    recipient = RECIPIENT

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        api_key: str | None = None,
        profile_id: str = "",
        prices: Sequence[object] | None = None,
        client: object | None = None,
        max_input_chars: int = 200_000,
    ) -> None:
        self.model_id = model
        self.profile_id = profile_id
        self.prices = parse_prices(prices)
        if self.prices is None:
            from anagram.models.ledger import ANTHROPIC_PRICES

            self.prices = ANTHROPIC_PRICES.get(model)
        self._api_key = api_key or None
        self._client = client
        self._max_input_chars = max_input_chars

    # ------------------------------------------------------------ contract

    def capabilities(self) -> Capabilities:
        return Capabilities(
            structured="schema",
            streaming=True,
            temperature=False,
            max_input_chars=self._max_input_chars,
        )

    def ready(self) -> None:
        if self._client is None and not self._api_key:
            raise ModelError("no_key")

    def output_limit(self, request: TextRequest) -> int:
        extra = 0 if self.model_id in THINKING_OFF else THINKING_HEADROOM
        return request.max_output_tokens + extra

    # ------------------------------------------------------------- request

    def build_request(self, request: TextRequest) -> dict:
        """The Messages API request body."""
        output_config: dict = {"effort": "low"}
        if request.schema is not None:
            output_config["format"] = {"schema": request.schema, "type": "json_schema"}
        body: dict = {
            "max_tokens": self.output_limit(request),
            "messages": [{"content": request.user, "role": "user"}],
            "model": self.model_id,
            "output_config": output_config,
        }
        if request.system:
            body["system"] = request.system
        if self.model_id in THINKING_OFF:
            body["thinking"] = {"type": "disabled"}
        return body

    def client(self) -> object:
        if self._client is None:
            self.ready()
            try:
                import anthropic
            except ImportError as exc:
                raise ModelError("sdk_not_installed") from exc
            # No SDK retry (security review): `Gate` reserves one call for
            # each attempt, and a caller that retries calls `generate` again,
            # with a new reservation.
            self._client = anthropic.Anthropic(api_key=self._api_key, max_retries=0)
        return self._client

    def generate(self, request: TextRequest) -> TextReply:
        body = self.build_request(request)
        client = self.client()
        try:
            resp = client.messages.create(**body, timeout=request.timeout_s)  # type: ignore[attr-defined]
        except Exception as exc:  # classify by status; hold no message
            raise _error(exc) from None
        usage = getattr(resp, "usage", None)
        stop = str(getattr(resp, "stop_reason", None))
        texts = [
            getattr(b, "text", "")
            for b in getattr(resp, "content", None) or []
            if getattr(b, "type", None) == "text"
        ]
        reply = TextReply(
            text="".join(texts),
            data=None,
            input_tokens=int_or_zero(getattr(usage, "input_tokens", 0)),
            output_tokens=int_or_zero(getattr(usage, "output_tokens", 0)),
            model=str(getattr(resp, "model", None) or self.model_id),
            stop=stop,
            refusal=stop == "refusal",
        )
        if stop == "max_tokens" and request.schema is not None:
            raise ModelError("output_cut")  # the JSON is not complete
        return checked_reply(reply, request.schema)

    def stream(self, request: TextRequest) -> Iterator[str]:
        body = self.build_request(request)
        client = self.client()
        try:
            with client.messages.stream(**body, timeout=request.timeout_s) as stream:  # type: ignore[attr-defined]
                for text in stream.text_stream:
                    if text:
                        yield text
        except ModelError:
            raise
        except Exception as exc:  # the SDK raises many types; _error maps them
            raise _error(exc) from None

    def probe(self) -> dict:
        """Check the key and the model id with the Models API. No paid call."""
        try:
            client = self.client()
            client.models.retrieve(self.model_id)  # type: ignore[attr-defined]
        except ModelError as exc:
            return {"models": [], "ok": False, "reason": exc.code}
        except Exception as exc:  # the SDK raises many types; map the status
            status = _status(exc)
            reason = {401: "key_refused", 403: "key_refused", 404: "model_not_found"}.get(
                status, "unreachable"
            )
            return {"models": [], "ok": False, "reason": reason}
        return {"models": [self.model_id], "ok": True, "reason": None}
