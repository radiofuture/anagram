"""Shared Google code: the Google response classes and the account call.

The fakes for tests are in `fake_google.py` (OAuth and Drive) and
`fake_gmail.py` (Gmail). `json_response` and `google_error` make the response
bodies of the fakes.
"""

from __future__ import annotations

import json
import urllib.parse

from anagram.local.sources.http import (
    PERMISSION,
    QUOTA,
    RETRY,
    HttpResponse,
    RateLimiter,
    SourceFault,
    classify_status,
)

# Google 403 reasons (`error.errors[].reason`, or `error.details[].reason` in
# the newer error shape). Verify the full list with a live check.
RETRY_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "RATE_LIMIT_EXCEEDED"})
QUOTA_REASONS = frozenset({"dailyLimitExceeded", "quotaExceeded", "RESOURCE_EXHAUSTED"})


def google_reasons(resp: HttpResponse) -> set[str]:
    try:
        body = json.loads(resp.body) if resp.body else None
    except ValueError:
        return set()
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return set()
    out = set()
    for e in err.get("errors") or []:
        if isinstance(e, dict) and isinstance(e.get("reason"), str):
            out.add(e["reason"])
    for d in err.get("details") or []:
        if isinstance(d, dict) and isinstance(d.get("reason"), str):
            out.add(d["reason"])
    if isinstance(err.get("status"), str):
        out.add(err["status"])
    return out


def classify_google(resp: HttpResponse) -> str:
    """`classify_status` plus the Google 403 reasons: a rate limit is
    `retry`, a daily limit is `quota`, each other 403 is `permission`."""
    kind = classify_status(resp)
    if resp.status == 403:
        reasons = google_reasons(resp)
        if reasons & RETRY_REASONS:
            return RETRY
        if reasons & QUOTA_REASONS:
            return QUOTA
        return PERMISSION
    return kind


# --------------------------------------------------------------- account call


class GoogleApi:
    """Calls of one Google account: the token from `CredentialStore`, the
    Google response classes, and a rate limiter. A connector never sees the
    token."""

    def __init__(self, creds, account_id: str, limiter: RateLimiter | None = None) -> None:
        self.creds = creds
        self.account_id = account_id
        self.limiter = limiter
        acct = creds.account(account_id)
        if acct is None:
            raise SourceFault("auth_expired", "the account is not there")
        self.email = acct.label if "@" in acct.label else None

    @classmethod
    def open(cls, ctx, account_id: str, limiter: RateLimiter | None = None) -> GoogleApi:
        creds = getattr(ctx, "credentials", None) if ctx is not None else None
        if creds is None:
            raise SourceFault("auth_expired", "no credential store")
        return cls(creds, account_id, limiter)

    def get(self, url: str, params: dict | None = None, *, cost: float = 1.0) -> HttpResponse:
        """`cost`: the units of the call in the limiter (Gmail counts quota
        units for each method). A list value repeats the parameter."""
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        return self.creds.request(
            self.account_id,
            "GET",
            url,
            classify=classify_google,
            limiter=self.limiter,
            cost=cost,
        )

    def json(self, url: str, params: dict | None = None, *, cost: float = 1.0) -> dict:
        body = self.get(url, params, cost=cost).json()
        if not isinstance(body, dict):
            raise SourceFault("unknown", "the answer is not a JSON object")
        return body


# ------------------------------------------------------------ responses


def json_response(status: int, body: object, headers: dict | None = None) -> HttpResponse:
    h = {"content-type": "application/json"}
    h.update(headers or {})
    return HttpResponse(status, h, json.dumps(body).encode())


def google_error(status: int, reason: str, message: str = "") -> HttpResponse:
    """A Google API error body (the shape of the Drive and Gmail docs)."""
    return json_response(
        status,
        {
            "error": {
                "code": status,
                "errors": [{"domain": "global", "message": message or reason, "reason": reason}],
                "message": message or reason,
            }
        },
    )
