"""Paid providers (Anthropic, OpenAI, OpenRouter) and the spend gate.

A fake client or a fake transport takes each call. No test calls the network,
and no test holds a real key."""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from decimal import Decimal
from types import SimpleNamespace

import pytest
from modelkit import NOT_A_KEY, REQ, SCHEMA, FakeHTTP, chat

from anagram.models import BudgetRefused, ModelError, TextReply, TextRequest
from anagram.models.budget import Gate, ledger_path, open_ledger
from anagram.models.ledger import BudgetLedger
from anagram.models.providers.anthropic import MODELS, SAMPLING_FIELDS, AnthropicModel
from anagram.models.providers.fake import FakeTextModel
from anagram.models.providers.openai_compat import (
    OPENAI_URL,
    OPENROUTER_URL,
    OpenAICompatModel,
    OpenAIModel,
    OpenRouterModel,
)

TODAY = date(2026, 11, 16)
BUDGET = {"approved_by": "researcher", "budget_usd": "0.01", "expires": "2026-12-31"}
HAIKU_PRICES = (Decimal("0.10"), Decimal("0.50"))


class Status(Exception):
    def __init__(self, status_code, message="the SDK message with the item text"):
        super().__init__(message)
        self.status_code = status_code


class FakeStream:
    def __init__(self, pieces):
        self.text_stream = iter(pieces)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeAnthropic:
    """A client with `messages.create`, `messages.stream`, `models.retrieve`."""

    def __init__(self, text='{"kind": "note"}', stop="end_turn", fail=None, known=MODELS):
        self.text, self.stop, self.fail, self.known = text, stop, fail, known
        self.bodies: list[dict] = []
        self.messages = SimpleNamespace(create=self._create, stream=self._stream)
        self.models = SimpleNamespace(retrieve=self._retrieve)

    def _create(self, **body):
        self.bodies.append(body)
        if self.fail is not None:
            raise self.fail
        return SimpleNamespace(
            content=[
                SimpleNamespace(type="thinking", thinking=""),
                SimpleNamespace(type="text", text=self.text),
            ],
            model=body["model"],
            stop_reason=self.stop,
            usage=SimpleNamespace(input_tokens=50, output_tokens=12),
        )

    def _stream(self, **body):
        self.bodies.append(body)
        if self.fail is not None:
            raise self.fail
        return FakeStream(["An ", "", "answer"])

    def _retrieve(self, model_id):
        if self.fail is not None:
            raise self.fail
        if model_id not in self.known:
            raise Status(404)
        return SimpleNamespace(id=model_id)


def ledger(tmp_path, limit="0.01", name="ledger.sqlite"):
    return BudgetLedger(tmp_path / name, limit)


def rows(led):
    with sqlite3.connect(led.path) as db:
        return db.execute("SELECT route, status, usage FROM calls ORDER BY rowid").fetchall()


# --------------------------------------------------------------- Anthropic


@pytest.mark.parametrize("model_id", MODELS)
def test_no_anthropic_body_has_a_sampling_field(model_id):
    client = FakeAnthropic()
    model = AnthropicModel(model_id, client=client, prices=("8.00", "40.00"))
    model.generate(REQ)
    model.generate(TextRequest(system="", user="plain"))
    list(model.stream(TextRequest(system="s", user="q")))
    assert len(client.bodies) == 3
    for body in client.bodies:
        assert not set(SAMPLING_FIELDS) & set(body)
        assert "temperature" not in json.dumps(body)
        assert body["model"] == model_id
        assert body["output_config"]["effort"] == "low"
    assert model.capabilities().temperature is False


def test_anthropic_body_for_haiku():
    client = FakeAnthropic()
    model = AnthropicModel("claude-haiku-5-5", client=client, profile_id="haiku-1")
    reply = model.generate(REQ)
    assert reply.data == {"kind": "note"}
    assert (reply.input_tokens, reply.output_tokens, reply.stop) == (50, 12, "end_turn")
    assert client.bodies[0] == {
        "max_tokens": 80,
        "messages": [{"content": "the item", "role": "user"}],
        "model": "claude-haiku-5-5",
        "output_config": {"effort": "low", "format": {"schema": SCHEMA, "type": "json_schema"}},
        "system": "You sort items.",
        "thinking": {"type": "disabled"},
        "timeout": 60.0,
    }
    assert (model.external, model.paid, model.recipient_id) == (True, True, "model:haiku-1")
    assert model.prices == HAIKU_PRICES  # from the price table


@pytest.mark.parametrize("model_id", ["claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-2"])
def test_anthropic_sends_no_thinking_field_to_models_that_refuse_disabled(model_id):
    client = FakeAnthropic()
    model = AnthropicModel(model_id, client=client)
    model.generate(REQ)
    assert "thinking" not in client.bodies[0]
    # Thinking tokens are output tokens: the limit has headroom, and the gate reserves it.
    assert client.bodies[0]["max_tokens"] == model.output_limit(REQ) > REQ.max_output_tokens


def test_anthropic_prices():
    assert AnthropicModel("claude-fable-5-2", client=FakeAnthropic()).prices is None
    with_prices = AnthropicModel("claude-fable-5-2", client=FakeAnthropic(), prices=("8", "40"))
    assert with_prices.prices == (Decimal("8"), Decimal("40"))


def test_anthropic_refusal_gives_refusal_true():
    model = AnthropicModel(client=FakeAnthropic(text="", stop="refusal"))
    reply = model.generate(REQ)
    assert reply.refusal is True
    assert reply.data is None


def test_anthropic_faults():
    model = AnthropicModel(client=FakeAnthropic(fail=Status(401)))
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert (err.value.status, err.value.retryable) == (401, False)
    assert "item text" not in str(err.value)
    assert err.value.__cause__ is None
    for status in (429, 529):
        with pytest.raises(ModelError) as err:
            AnthropicModel(client=FakeAnthropic(fail=Status(status))).generate(REQ)
        assert err.value.retryable is True
    with pytest.raises(ModelError) as err:
        AnthropicModel(client=FakeAnthropic(fail=ConnectionError("x"))).generate(REQ)
    assert err.value.code == "unreachable"
    with pytest.raises(ModelError) as err:
        list(AnthropicModel(client=FakeAnthropic(fail=Status(500))).stream(REQ))
    assert err.value.status == 500
    with pytest.raises(ModelError) as err:
        AnthropicModel(client=FakeAnthropic(text='{"kind": "no', stop="max_tokens")).generate(REQ)
    assert err.value.code == "output_cut"


def test_anthropic_needs_a_key_and_makes_no_client_without_one():
    model = AnthropicModel()
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert err.value.code == "no_key"
    assert model.probe() == {"models": [], "ok": False, "reason": "no_key"}


def test_anthropic_sdk_does_not_retry_outside_the_reservation(monkeypatch):
    """`Gate` reserves for the attempts of one `generate`
    call (`max_attempts`). An SDK retry is not in that count, so it is off."""
    import sys

    made = {}

    class FakeSDK:
        @staticmethod
        def Anthropic(**kw):  # the name of the SDK class
            made.update(kw)
            return FakeAnthropic()

    monkeypatch.setitem(sys.modules, "anthropic", FakeSDK)
    model = AnthropicModel(api_key=NOT_A_KEY)
    model.generate(REQ)
    assert made["max_retries"] == 0 and model.max_attempts(REQ) == 1


def test_anthropic_stream_and_probe():
    client = FakeAnthropic()
    model = AnthropicModel(client=client)
    assert list(model.stream(TextRequest(system="", user="q"))) == ["An ", "answer"]
    assert model.probe() == {"models": ["claude-haiku-5-5"], "ok": True, "reason": None}
    assert AnthropicModel("claude-old", client=client).probe()["reason"] == "model_not_found"
    refused = AnthropicModel(client=FakeAnthropic(fail=Status(401)))
    assert refused.probe()["reason"] == "key_refused"


# ----------------------------------------------------- OpenAI, OpenRouter


def test_openai_fixed_address_and_body():
    http = FakeHTTP([(200, chat('{"kind": "note"}'))])
    model = OpenAIModel("gpt-example", api_key=NOT_A_KEY, prices=("1", "4"), transport=http)
    assert model.base_url == OPENAI_URL
    assert (model.external, model.paid) == (True, True)
    assert model.generate(REQ).data == {"kind": "note"}
    body = http.calls[0]["body"]
    assert body["max_completion_tokens"] == 80
    assert "temperature" not in body and "max_tokens" not in body
    assert http.calls[0]["url"] == f"{OPENAI_URL}/chat/completions"
    # A base URL from a profile cannot move the key to a different host.
    moved = OpenAIModel("gpt-example", base_url="https://other.example/v1", transport=FakeHTTP())
    assert moved.base_url == OPENAI_URL
    assert OpenAIModel("gpt-example", api_key=NOT_A_KEY, transport=FakeHTTP()).prices is None


@pytest.mark.parametrize("cls", [OpenAIModel, OpenRouterModel])
def test_no_call_without_a_key(cls):
    http = FakeHTTP()
    kw = {"route": ("anthropic",)} if cls is OpenRouterModel else {}
    model = cls("m", transport=http, **kw)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert err.value.code == "no_key"
    assert model.probe()["reason"] == "no_key"
    assert http.calls == []


def test_openrouter_route_is_mandatory_and_pinned():
    for route in ((), ("",), [" "]):
        with pytest.raises(ModelError) as err:
            OpenRouterModel("anthropic/claude-haiku-5.5", route=route, transport=FakeHTTP())
        assert err.value.code == "no_route"
    answer = chat('{"kind": "note"}')
    answer["usage"]["cost"] = 0.0000075
    answer["provider"] = "Anthropic"
    http = FakeHTTP([(200, answer)])
    model = OpenRouterModel(
        "anthropic/claude-haiku-5.5", route=("anthropic",), api_key=NOT_A_KEY, transport=http
    )
    reply = model.generate(REQ)
    assert (reply.cost, reply.provider) == (Decimal("0.0000075"), "Anthropic")
    body = http.calls[0]["body"]
    assert body["provider"] == {
        "allow_fallbacks": False,
        "data_collection": "deny",
        "order": ["anthropic"],
        "require_parameters": True,
    }
    assert body["usage"] == {"include": True}
    assert "temperature" not in body
    assert http.calls[0]["url"] == f"{OPENROUTER_URL}/chat/completions"
    assert model.recipient == "OpenRouter (router) and anthropic (model provider)"
    assert model.prices == HAIKU_PRICES  # from the price table
    assert OpenRouterModel("x/unknown", route=("x",), transport=FakeHTTP()).prices is None


def test_openrouter_moderation_gives_refusal_true():
    blocked = {"error": {"code": 403, "message": "input flagged", "metadata": {"reasons": ["x"]}}}
    http = FakeHTTP([(403, blocked), (403, {"error": {"code": 403, "message": "no credit"}})])
    model = OpenRouterModel("anthropic/claude-haiku-5.5", route=("anthropic",), api_key=NOT_A_KEY)
    model._transport = http
    assert model.generate(REQ).refusal is True
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert err.value.status == 403


# -------------------------------------------------------------------- Gate


def paid_fake(replies=None, prices=HAIKU_PRICES):
    return FakeTextModel(replies, external=True, paid=True, prices=prices, model_id="paid-model")


def test_gate_needs_budget_prices_and_a_ledger_inside_the_approval(tmp_path):
    led = ledger(tmp_path)
    for budget in (None, {}, {**BUDGET, "approved_by": " "}, {**BUDGET, "expires": "2026-11-15"}):
        with pytest.raises(BudgetRefused):
            Gate(paid_fake(), led, budget, today=TODAY)
    with pytest.raises(BudgetRefused) as err:
        Gate(paid_fake(prices=None), led, BUDGET, today=TODAY)
    assert err.value.code == "no_prices"
    with pytest.raises(BudgetRefused):
        Gate(paid_fake(), ledger(tmp_path, "0.02", "big.sqlite"), BUDGET, today=TODAY)
    with pytest.raises(BudgetRefused):  # no table price for this model, and no profile price
        Gate(AnthropicModel("claude-fable-5-2", client=FakeAnthropic()), led, BUDGET, today=TODAY)
    assert rows(led) == []


def test_gate_makes_no_call_without_a_key(tmp_path):
    led = ledger(tmp_path)
    gate = Gate(AnthropicModel("claude-haiku-5-5"), led, BUDGET, today=TODAY)
    with pytest.raises(ModelError) as err:
        gate.generate(REQ)
    assert err.value.code == "no_key"
    assert rows(led) == []  # no reservation


def test_gate_reserves_then_records(tmp_path):
    led = ledger(tmp_path)
    client = FakeAnthropic()
    gate = Gate(AnthropicModel(client=client, profile_id="haiku-1"), led, BUDGET, today=TODAY)
    assert (gate.external, gate.paid, gate.recipient_id) == (True, True, "model:haiku-1")
    assert gate.model_id == "claude-haiku-5-5"
    reply = gate.generate(TextRequest("sys", "the item", SCHEMA, 80, purpose="understand.triage"))
    assert reply.data == {"kind": "note"}
    assert reply.cost == (Decimal("0.10") * 50 + Decimal("0.50") * 12) / 1_000_000
    [(route, status, usage)] = rows(led)
    assert (route, status) == ("understand.triage:claude-haiku-5-5", "reported")
    usage = json.loads(usage)
    assert usage["cost_source"] == "tokens"
    assert (usage["input_tokens"], usage["output_tokens"]) == (50, 12)
    assert "the item" not in json.dumps(usage)
    snap = led.snapshot()
    assert snap["reported_nanousd"] == 11_000
    assert snap["reserved_nanousd"] >= snap["reported_nanousd"]
    assert gate.stats["calls"] == 1 and gate.stats["cost_nanousd"] == 11_000
    assert list(gate.stream(TextRequest("", "q"))) == ['{"kind": "note"}']
    assert len(rows(led)) == 2  # the stream is one gated call


def test_gate_stops_at_the_limit_before_the_call(tmp_path):
    led = ledger(tmp_path, "0.0001")
    budget = {**BUDGET, "budget_usd": "0.0001"}
    model = paid_fake()
    gate = Gate(model, led, budget, today=TODAY)
    req = TextRequest("", "x" * 200, max_output_tokens=80)
    done = 0
    with pytest.raises(BudgetRefused) as err:
        for _ in range(50):
            gate.generate(req)
            done += 1
    assert err.value.code == "spend_limit_reached"
    assert 0 < done < 50
    assert len(model.calls) == done  # the refused call was not sent
    assert led.snapshot()["reserved_nanousd"] <= led.limit_nano


def test_gate_keeps_the_reservation_of_a_failed_call(tmp_path):
    led = ledger(tmp_path)
    fault = ModelError("http_error", status=503, retryable=True)
    gate = Gate(paid_fake([fault]), led, BUDGET, today=TODAY)
    with pytest.raises(ModelError) as err:
        gate.generate(REQ)
    assert err.value is fault
    [(_, status, usage)] = rows(led)
    assert status == "cost_unknown"
    assert json.loads(usage) == {"error": "http_error", "model": "paid-model", "status": 503}
    assert led.snapshot()["reserved_nanousd"] > 0
    assert gate.stats["errors"] == 1


def test_gate_halts_when_the_provider_reports_more_than_the_reservation(tmp_path):
    led = ledger(tmp_path)
    costly = TextReply("ok", None, 5, 5, "paid-model", "stop", cost=Decimal("0.005"))
    gate = Gate(paid_fake([costly]), led, BUDGET, today=TODAY)
    with pytest.raises(BudgetRefused) as err:
        gate.generate(TextRequest("", "short"))
    assert err.value.code == "provider_exceeded_reservation"
    assert led.snapshot()["breached"] is True
    with pytest.raises(BudgetRefused):
        gate.generate(TextRequest("", "short"))


def test_gate_records_a_refusal_and_the_provider_cost(tmp_path):
    led = ledger(tmp_path)
    refused = TextReply("", None, 40, 0, "paid-model", "refusal", refusal=True)
    gate = Gate(paid_fake([refused]), led, BUDGET, today=TODAY)
    assert gate.generate(REQ).refusal is True
    assert gate.stats["refusals"] == 1

    answer = chat('{"kind": "note"}')
    answer["usage"]["cost"] = "0.000002"
    router = OpenRouterModel(
        "anthropic/claude-haiku-5.5",
        route=("anthropic",),
        api_key=NOT_A_KEY,
        transport=FakeHTTP([(200, answer)]),
    )
    gate = Gate(router, led, BUDGET, today=TODAY)
    assert gate.generate(REQ).cost == Decimal("0.000002")
    usage = json.loads(rows(led)[-1][2])
    assert usage["cost_source"] == "provider"
    assert NOT_A_KEY not in json.dumps(rows(led))


def test_gate_reserves_each_attempt_of_text_mode(tmp_path):
    led = ledger(tmp_path)
    text = OpenAICompatModel(
        "m", "https://llm.example.edu/v1", prices=("1", "2"), structured="text"
    )
    one = OpenAICompatModel("m", "https://llm.example.edu/v1", prices=("1", "2"), structured="json")
    two_attempts = Gate(text, led, BUDGET, today=TODAY).reserve_usd(REQ)
    assert two_attempts == 2 * Gate(one, led, BUDGET, today=TODAY).reserve_usd(REQ)


def test_gate_refuses_after_the_approval_expires(tmp_path):
    led = ledger(tmp_path)
    model = paid_fake()
    gate = Gate(model, led, BUDGET, today=TODAY)
    gate._today = date(2027, 1, 1)
    with pytest.raises(BudgetRefused):
        gate.generate(REQ)
    assert model.calls == []


def test_ledger_path_changes_with_the_approval(tmp_path):
    first = ledger_path(tmp_path, BUDGET)
    assert first.parent == tmp_path / "spend" and len(first.stem) == 16
    assert ledger_path(tmp_path, dict(reversed(BUDGET.items()))) == first
    assert ledger_path(tmp_path, {**BUDGET, "budget_usd": "0.02"}) != first
    led = open_ledger(tmp_path, BUDGET, today=TODAY)
    assert led.path == first and led.limit_nano == 10_000_000
    Gate(paid_fake(), led, BUDGET, today=TODAY)
    with pytest.raises(BudgetRefused):
        open_ledger(tmp_path, {**BUDGET, "expires": "2026-01-01"}, today=TODAY)
