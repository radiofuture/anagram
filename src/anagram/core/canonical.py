"""Canonical JSON: a strict subset of RFC 8785 (JCS).

Allowed values: null, true, false, integers in [-(2**53-1), 2**53-1], strings
(valid Unicode, no lone surrogates), arrays, and objects with string keys.
Floats are not allowed. This removes the only hard part of RFC 8785 (number
formatting), so each output here is also valid RFC 8785 output.

Rules: object keys sorted by their UTF-16 code units, no whitespace, UTF-8
output, string escapes as in RFC 8785 section 3.2.2.2.
"""

from __future__ import annotations

import json
from json.encoder import encode_basestring
from typing import Any

MAX_SAFE_INT = 2**53 - 1

# A parsed JSON object. The values stay `Any`: each reader checks the fields it
# uses (see `anagram.core.validate`), so a nested type here adds no safety.
type JsonObject = dict[str, Any]


class CanonicalError(ValueError):
    pass


def _string(s: str, out: list[str]) -> None:
    out.append(encode_basestring(s))


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def _encode(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError("integer out of safe range")
        out.append(str(int(value)))
    elif isinstance(value, float):
        raise CanonicalError("floats are not allowed in canonical JSON")
    elif isinstance(value, str):
        _string(value, out)
    elif isinstance(value, list | tuple):
        _array(value, out)
    elif isinstance(value, dict):
        _object(value, out)
    else:
        raise CanonicalError(f"type not allowed: {type(value).__name__}")


def _array(value: list[Any] | tuple[Any, ...], out: list[str]) -> None:
    out.append("[")
    for i, item in enumerate(value):
        if i:
            out.append(",")
        _encode(item, out)
    out.append("]")


def _object(value: dict[Any, Any], out: list[str]) -> None:
    for k in value:
        if not isinstance(k, str):
            raise CanonicalError("object keys must be strings")
    out.append("{")
    for i, k in enumerate(sorted(value, key=_utf16_key)):
        if i:
            out.append(",")
        _string(k, out)
        out.append(":")
        _encode(value[k], out)
    out.append("}")


def canonical_json(value: Any) -> bytes:
    out: list[str] = []
    _encode(value, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalError("string has a lone surrogate") from exc


def _no_float(s: str) -> Any:
    raise CanonicalError("floats are not allowed")


def _no_constant(s: str) -> Any:
    raise CanonicalError(f"constant not allowed: {s}")


def _no_dupes(pairs: list[tuple[str, Any]]) -> JsonObject:
    out: JsonObject = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalError(f"duplicate key: {k}")
        out[k] = v
    return out


def _parse(data: bytes | str) -> Any:
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(
        data,
        parse_float=_no_float,
        parse_constant=_no_constant,
        object_pairs_hook=_no_dupes,
    )


def loads(data: bytes | str) -> Any:
    """Parse JSON with the same value rules. Duplicate keys and floats fail."""
    value = _parse(data)
    canonical_json(value)  # check value rules (int range, surrogates)
    return value


def loads_canonical(data: bytes) -> Any:
    """Parse bytes and require that they are already in canonical form."""
    value = _parse(data)
    if canonical_json(value) != data:
        raise CanonicalError("input is not in canonical form")
    return value
