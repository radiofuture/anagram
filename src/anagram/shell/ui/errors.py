"""The error of a screen action: an HTTP status and one sentence for the
person (`shell/ui/server.py` sends it as `{"error": message, **extra}`)."""

from __future__ import annotations

from anagram.core.nodeapi import NodeHTTPError


class UIError(Exception):
    def __init__(self, status: int, message: str, extra: dict | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra or {}


def plain_error(exc: Exception) -> str:
    """The text of an error of a background task (a join, a sign-in)."""
    if isinstance(exc, NodeHTTPError):
        return f"The community server said: {exc.detail}"
    if isinstance(exc, OSError):
        return "Could not reach the community server. Check the link and your network."
    return str(exc) or type(exc).__name__
