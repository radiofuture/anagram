"""Small helpers of the node routers: a field of a JSON body, and the token
of an `Authorization: Bearer` header."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from anagram.core.canonical import JsonObject


def field(body: JsonObject, name: str) -> Any:
    """The field `name` of a JSON body; 400 when it is not there."""
    if not isinstance(body, dict) or name not in body:
        raise HTTPException(400, f"missing field: {name}")
    return body[name]


def bearer(authorization: str | None) -> str | None:
    """The token of `Authorization: Bearer <token>`, or None."""
    if authorization and authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ").strip()
    return None
