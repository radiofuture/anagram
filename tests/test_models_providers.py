"""Ollama and OpenAI-compatible providers. All HTTP goes to a fake transport."""

from __future__ import annotations

import json

import pytest
from modelkit import NOT_A_KEY, REQ, SCHEMA, UNI, FakeHTTP, FakeOllama, chat

from anagram.models import ModelError, TextRequest
from anagram.models.http import UrllibTransport, check_url
from anagram.models.ollama_client import OllamaClient
from anagram.models.providers.ollama import OllamaModel
from anagram.models.providers.openai_compat import OpenAICompatModel

# ------------------------------------------------------------------ Ollama


def test_ollama_is_local_and_sends_the_schema_as_format():
    fake = FakeOllama()
    model = OllamaModel("llama3.2", client=OllamaClient(transport=fake), profile_id="local-1")
    assert (model.external, model.paid) == (False, False)
    assert model.capabilities().structured == "schema"
    reply = model.generate(REQ)
    assert reply.data == {"kind": "note"}
    assert (reply.input_tokens, reply.output_tokens) == (31, 9)
    method, url, body, timeout = fake.calls[0]
    assert url == "http://127.0.0.1:11434/api/chat"
    assert body["format"] == SCHEMA
    assert body["options"] == {"num_predict": 80, "temperature": 0}
    assert body["stream"] is False
    assert timeout == REQ.timeout_s


def test_ollama_refuses_a_remote_address():
    with pytest.raises(ModelError) as err:
        OllamaModel(url="http://ollama.example.edu:11434")
    assert err.value.code == "not_loopback"


def test_ollama_faults_and_probe():
    down = OllamaModel(client=OllamaClient(transport=FakeOllama(down=True)))
    with pytest.raises(ModelError) as err:
        down.generate(REQ)
    assert err.value.retryable
    assert down.probe() == {"models": [], "ok": False, "reason": "unreachable"}

    bad = OllamaModel(client=OllamaClient(transport=FakeOllama(content="I think it is a note")))
    with pytest.raises(ModelError) as err:
        bad.generate(REQ)
    assert err.value.code == "bad_output"

    ok = OllamaModel("llama3.2", client=OllamaClient(transport=FakeOllama()))
    assert ok.probe() == {"models": ["llama3.2:latest"], "ok": True, "reason": None}
    other = OllamaModel("llama3.2:1b", client=OllamaClient(transport=FakeOllama()))
    assert other.probe()["reason"] == "model_not_installed"


def test_ollama_stream_reads_lines():
    lines = [
        json.dumps({"message": {"content": "A "}}),
        "",
        json.dumps({"message": {"content": "note."}}),
        json.dumps({"done": True, "message": {"content": ""}}),
        json.dumps({"message": {"content": "after the end"}}),
    ]
    http = FakeHTTP(lines=lines)
    model = OllamaModel(client=OllamaClient(transport=FakeOllama()), http=http)
    assert list(model.stream(TextRequest(system="s", user="u"))) == ["A ", "note."]
    assert http.calls[0]["body"]["stream"] is True
    assert http.calls[0]["url"] == "http://127.0.0.1:11434/api/chat"
    # With a fake client and no stream transport: one piece.
    one = OllamaModel(client=OllamaClient(transport=FakeOllama(content="whole")))
    assert list(one.stream(TextRequest(system="s", user="u"))) == ["whole"]


# -------------------------------------------------------- OpenAI-compatible


def test_url_rules():
    assert check_url("https://llm.example.edu/v1/") == UNI
    assert check_url("http://127.0.0.1:8000/v1") == "http://127.0.0.1:8000/v1"
    for bad, code in [
        ("http://llm.example.edu/v1", "url_not_https"),
        ("ftp://llm.example.edu", "invalid_url"),
        ("https://name:secret@llm.example.edu/v1", "invalid_url"),
        ("llm.example.edu", "invalid_url"),
    ]:
        with pytest.raises(ModelError) as err:
            check_url(bad)
        assert err.value.code == code
    with pytest.raises(ModelError):
        OpenAICompatModel("m", "http://llm.example.edu/v1", transport=FakeHTTP())
    with pytest.raises(ModelError):  # the real transport checks each URL again
        UrllibTransport().request("GET", "http://llm.example.edu/v1/models", {}, None, 1.0)


def test_disclosure_fields_come_from_the_address_and_the_prices():
    local = OpenAICompatModel("m", "http://localhost:1234/v1", transport=FakeHTTP())
    assert (local.external, local.paid, local.recipient) == (False, False, "This computer")
    uni = OpenAICompatModel("m", UNI, label="Example University", transport=FakeHTTP())
    assert (uni.external, uni.paid, uni.recipient) == (True, False, "Example University")
    assert OpenAICompatModel("m", UNI, transport=FakeHTTP()).recipient == "llm.example.edu"
    priced = OpenAICompatModel("m", UNI, prices=("1", "2"), transport=FakeHTTP())
    assert priced.paid is True


def test_schema_mode():
    http = FakeHTTP([(200, chat('{"kind": "finding"}'))])
    model = OpenAICompatModel("m", UNI, api_key=NOT_A_KEY, transport=http)
    reply = model.generate(REQ)
    assert reply.data == {"kind": "finding"}
    assert (reply.input_tokens, reply.output_tokens, reply.model) == (40, 7, "served-model")
    call = http.calls[0]
    assert call["url"] == f"{UNI}/chat/completions"
    assert call["headers"]["Authorization"] == f"Bearer {NOT_A_KEY}"
    assert call["body"]["response_format"]["type"] == "json_schema"
    assert call["body"]["response_format"]["json_schema"]["schema"] == SCHEMA
    assert call["body"]["max_tokens"] == 80
    assert call["body"]["messages"][0] == {"content": "You sort items.", "role": "system"}
    assert model.structured == "schema"
    assert model.capabilities().structured == "schema"


def test_json_mode_after_the_server_refuses_the_schema_mode():
    http = FakeHTTP([(400, {"error": {"message": "x"}}), (200, chat('{"kind": "note"}'))])
    model = OpenAICompatModel("m", UNI, transport=http)
    assert model.generate(REQ).data == {"kind": "note"}
    first, second = http.posts()
    assert first["response_format"]["type"] == "json_schema"
    assert second["response_format"] == {"type": "json_object"}
    assert json.dumps(SCHEMA, sort_keys=True) in second["messages"][0]["content"]
    assert model.structured == "json"
    # The mode is kept: the next call makes one request.
    http.answers.append((200, chat('{"kind": "note"}')))
    model.generate(REQ)
    assert len(http.posts()) == 3


def test_text_mode_with_one_more_attempt():
    http = FakeHTTP(
        [
            (400, {}),
            (422, {}),
            (200, chat("It is a note.")),
            (200, chat('```json\n{"kind": "note"}\n```')),
        ]
    )
    model = OpenAICompatModel("m", UNI, transport=http)
    assert model.max_attempts(REQ) == 2
    assert model.generate(REQ).data == {"kind": "note"}
    posts = http.posts()
    assert len(posts) == 4
    assert "response_format" not in posts[2]
    assert model.structured == "text"

    # Two bad answers in text mode: the fault goes to the caller.
    http = FakeHTTP([(200, chat("no")), (200, chat("still no"))])
    model = OpenAICompatModel("m", UNI, structured="text", transport=http)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert err.value.code == "bad_output"
    assert len(http.posts()) == 2


def test_a_stored_mode_is_not_searched_again():
    http = FakeHTTP([(400, {})])
    model = OpenAICompatModel("m", UNI, structured="json", transport=http)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert err.value.status == 400
    assert len(http.calls) == 1
    assert model.max_attempts(REQ) == 1


def test_errors_hold_no_key_and_no_body():
    secret_body = {"error": {"message": f"bad key {NOT_A_KEY} for the item"}}
    http = FakeHTTP([(401, secret_body), (503, {}), OSError("connection reset by peer 10.0.0.9")])
    model = OpenAICompatModel("m", UNI, api_key=NOT_A_KEY, structured="schema", transport=http)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert (err.value.status, err.value.retryable) == (401, False)
    assert NOT_A_KEY not in str(err.value) and "item" not in str(err.value)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert (err.value.status, err.value.retryable) == (503, True)
    with pytest.raises(ModelError) as err:
        model.generate(REQ)
    assert (err.value.code, err.value.retryable) == ("unreachable", True)
    assert "10.0.0.9" not in str(err.value)
    assert NOT_A_KEY not in repr(model.__dict__.get("recipient"))


def test_refusal_and_content_filter():
    http = FakeHTTP(
        [
            (200, chat("", refusal="I cannot help with that.")),
            (200, {"choices": [{"finish_reason": "content_filter", "message": {"content": ""}}]}),
        ]
    )
    model = OpenAICompatModel("m", UNI, structured="schema", transport=http)
    for _ in range(2):
        reply = model.generate(REQ)
        assert reply.refusal is True
        assert reply.data is None


def test_stream_reads_server_sent_events():
    def piece(text):
        return "data: " + json.dumps({"choices": [{"delta": {"content": text}}]})

    lines = [": keep-alive", piece("An "), "", piece("answer"), "data: {bad", "data: [DONE]"]
    http = FakeHTTP(lines=[*lines, piece("after the end")])
    model = OpenAICompatModel("m", UNI, transport=http)
    assert list(model.stream(TextRequest(system="", user="q"))) == ["An ", "answer"]
    body = http.calls[0]["body"]
    assert body["stream"] is True
    assert body["messages"] == [{"content": "q", "role": "user"}]


def test_probe_finds_the_mode_for_a_model_that_is_not_paid():
    http = FakeHTTP(
        [(200, {"data": [{"id": "b"}, {"id": "a"}]}), (400, {}), (200, chat('{"ok": true}'))]
    )
    model = OpenAICompatModel("a", UNI, transport=http)
    assert model.probe() == {"models": ["a", "b"], "ok": True, "reason": None, "structured": "json"}
    assert http.calls[0]["method"] == "GET" and http.calls[0]["url"] == f"{UNI}/models"


def test_probe_makes_no_generation_call_for_a_paid_model():
    http = FakeHTTP([(404, {})])
    model = OpenAICompatModel("a", UNI, prices=("1", "2"), transport=http)
    assert model.probe() == {"models": [], "ok": True, "reason": None, "structured": None}
    assert http.posts() == []


def test_probe_reasons():
    refused = OpenAICompatModel("a", UNI, transport=FakeHTTP([(401, {})]))
    assert refused.probe()["reason"] == "key_refused"
    down = OpenAICompatModel("a", UNI, transport=FakeHTTP([OSError("down")]))
    assert down.probe() == {"models": [], "ok": False, "reason": "unreachable", "structured": None}


def test_text_mode_retry_sums_tokens_and_cost_across_attempts():
    from decimal import Decimal

    first = chat("not valid json")
    first["usage"] = {"cost": "0.0001", "prompt_tokens": 30, "completion_tokens": 10}
    second = chat('{"kind": "note"}')
    second["usage"] = {"cost": "0.0002", "prompt_tokens": 50, "completion_tokens": 15}
    http = FakeHTTP([(200, first), (200, second)])
    model = OpenAICompatModel("m", UNI, structured="text", transport=http)
    reply = model.generate(REQ)
    assert reply.data == {"kind": "note"}
    assert reply.input_tokens == 80
    assert reply.output_tokens == 25
    assert reply.cost == Decimal("0.0003")


def test_ollama_and_loopback_transport_disable_proxies_and_redirects():
    import io
    import urllib.request

    from anagram.models import http as models_http
    from anagram.models import ollama_client
    from anagram.models.ollama_client import OllamaError

    # OllamaClient rejects embedded credentials and non-loopback URLs.
    with pytest.raises(OllamaError, match="invalid_url"):
        OllamaClient(url="http://user:pass@127.0.0.1:11434")
    with pytest.raises(OllamaError, match="loopback"):
        OllamaClient(url="https://ollama.example.edu")

    # Both OllamaClient._OPENER and UrllibTransport._loopback_opener disable proxies and redirects.
    transport = UrllibTransport()
    for opener in (ollama_client._OPENER, transport._loopback_opener):
        # Passing ProxyHandler({}) suppresses the default ProxyHandler so no proxy handler is active.
        proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        assert all(h.proxies == {} for h in proxy_handlers)
        redir_handlers = [
            h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
        ]
        assert redir_handlers
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")  # noqa: S310
        assert (
            redir_handlers[0].redirect_request(
                req, io.BytesIO(b""), 302, "Found", {}, "https://evil.example/"
            )
            is None
        )

    assert models_http.is_loopback("http://127.0.0.1:8000/v1/models") is True
    assert models_http.is_loopback("https://llm.example.edu/v1/models") is False
