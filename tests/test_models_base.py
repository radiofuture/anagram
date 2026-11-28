"""Model interface: strict output, the opt-in rule, and the fake model."""

from __future__ import annotations

import pytest

from anagram.models import (
    ModelError,
    ModelRefused,
    TextReply,
    TextRequest,
    check_model,
    parse_prices,
    parse_strict,
)
from anagram.models.providers.fake import FakeTextModel

KIND = {
    "additionalProperties": False,
    "properties": {
        "confidence": {"type": "number"},
        "kind": {"enum": ["finding", "note"], "type": "string"},
        "tags": {"items": {"maxLength": 5, "type": "string"}, "maxItems": 2, "type": "array"},
    },
    "required": ["kind", "confidence"],
    "type": "object",
}


def test_parse_strict_accepts_one_object():
    assert parse_strict('{"kind": "note", "confidence": 0.5}', KIND) == {
        "confidence": 0.5,
        "kind": "note",
    }
    fenced = '```json\n{"kind": "finding", "confidence": 1, "tags": ["a"]}\n```'
    assert parse_strict(fenced, KIND)["tags"] == ["a"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        '["kind"]',
        'Here it is: {"kind": "note", "confidence": 1}',
        '{"kind": "note", "confidence": 1} {"kind": "note", "confidence": 1}',
        '{"kind": "note"}',  # a required field is absent
        '{"kind": "other", "confidence": 1}',  # not in the enum
        '{"kind": "note", "confidence": "high"}',  # wrong type
        '{"kind": "note", "confidence": true}',  # a boolean is not a number
        '{"kind": "note", "confidence": 1, "extra": 1}',  # a field that the schema does not list
        '{"kind": "note", "confidence": 1, "tags": ["a", "b", "c"]}',  # too many items
        '{"kind": "note", "confidence": 1, "tags": ["too long"]}',
    ],
)
def test_parse_strict_refuses(text):
    with pytest.raises(ModelError) as err:
        parse_strict(text, KIND)
    assert err.value.code == "bad_output"


def test_check_model_needs_the_opt_in_for_an_external_model():
    local = FakeTextModel()
    outside = FakeTextModel(external=True, recipient="Example University")
    check_model(local, allowed=False)
    check_model(outside, allowed=True)
    with pytest.raises(ModelRefused) as err:
        check_model(outside, allowed=False)
    assert "Example University" in str(err.value)
    assert outside.recipient_id == "model:fake-00000000"


def test_fake_model_gives_schema_checked_data_and_records_what_it_read():
    model = FakeTextModel()
    reply = model.generate(TextRequest(system="sys", user="the item text", schema=KIND))
    assert reply.data == {"confidence": 0, "kind": "finding"}
    assert reply.refusal is False
    assert model.read == ["sys\nthe item text"]
    assert model.generate(TextRequest(system="", user="hello")).text == "ok"


def test_fake_model_script_and_errors():
    model = FakeTextModel(
        [{"confidence": 0.9, "kind": "note"}, "not json", ModelError("unreachable", retryable=True)]
    )
    req = TextRequest(system="", user="x", schema=KIND)
    assert model.generate(req).data["kind"] == "note"
    with pytest.raises(ModelError):
        model.generate(req)  # the scripted text does not agree with the schema
    with pytest.raises(ModelError) as err:
        model.generate(req)
    assert err.value.retryable is True
    assert len(model.calls) == 3


def test_fake_model_refusal_has_no_data():
    refused = TextReply("", None, 3, 0, "fake-model", "refusal", refusal=True)
    model = FakeTextModel(lambda request: refused)
    reply = model.generate(TextRequest(system="", user="x", schema=KIND))
    assert reply.refusal is True
    assert reply.data is None
    assert list(model.stream(TextRequest(system="", user="x"))) == []


def test_fake_model_stream_gives_the_same_text_in_pieces():
    model = FakeTextModel(["one two three four"], pieces=3)
    pieces = list(model.stream(TextRequest(system="", user="x")))
    assert len(pieces) == 3
    assert "".join(pieces) == "one two three four"


def test_parse_prices():
    assert parse_prices(None) is None
    assert parse_prices(("8.00", "40.00"))[1] == 40
    for bad in (("1",), ("a", "b"), ("-1", "2"), 5, ("0", "0"), ["0", "0"], "12", (True, 1)):
        with pytest.raises(ModelError) as err:
            parse_prices(bad)
        assert err.value.code == "invalid_prices"


def test_int_or_zero_rejects_negative_and_bool():
    from anagram.models.base import int_or_zero

    assert int_or_zero(12) == 12
    assert int_or_zero(0) == 0
    assert int_or_zero(-5) == 0
    assert int_or_zero(True) == 0
    assert int_or_zero("12") == 0


def test_model_error_message_has_only_the_code_and_status():
    err = ModelError("http_error", status=401)
    assert str(err) == "http_error (status 401)"
    assert err.retryable is False
