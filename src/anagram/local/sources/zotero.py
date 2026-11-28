"""Zotero connectors.

- `ZoteroFileConnector`: a CSL-JSON export file (Zotero: File > Export Library >
  CSL JSON). No network.
- `ZoteroWebConnector`: the Zotero Web API v3 with a user API key
  (`https://api.zotero.org/users/<id>/items?format=csljson`). The key stays in
  the client keystore. Tests use `FakeZotero`.

Each library item is one evidence item (a record): the CSL-JSON item. Its text
(title, venue, abstract, notes, tags) is a strong topic signal. Bibliography
text gives topics only, never needs or offers.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from anagram.local.index.extract import csl_item_text, is_csl_json
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    Suggestion,
    Transport,
    record_item,
    urllib_transport,
    with_query,
)

ITEM_KIND = "zotero_item"
API = "https://api.zotero.org"


def _item_key(item: dict) -> str:
    for k in ("id", "DOI", "URL", "title"):
        if item.get(k):
            return str(item[k])
    raise ConnectorError("CSL item has no id, DOI, URL, or title")


def _year(item: dict) -> str | None:
    try:
        return f"{int(item['issued']['date-parts'][0][0]):04d}-01-01T00:00:00Z"
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def csl_items(items: list[dict], prefix: str) -> Iterator[EvidenceItem]:
    for item in items:
        key = _item_key(item)
        yield record_item(
            key=key,
            kind=ITEM_KIND,
            name=item.get("title"),
            ref=f"{prefix}:{key}",
            record=item,
            text=csl_item_text(item),
            title=item.get("title"),
            prose=False,
            time=_year(item),
        )


ZOTERO_EXPORT_NAMES = ("zotero-export.json", "*.csl.json")


class ZoteroFileConnector(Connector):
    kind = "zotero_file"
    label = "Zotero library"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> ZoteroFileConnector:
        return cls(cfg["path"])

    @classmethod
    def discover(cls, path: Path) -> list[Suggestion]:
        """Zotero CSL-JSON exports: `zotero-export.json` or `*.csl.json`."""
        p = Path(path).expanduser()
        if p.is_file():
            found = [p] if p.suffix.lower() == ".json" else []
        elif p.is_dir():
            found = sorted({f for pat in ZOTERO_EXPORT_NAMES for f in p.rglob(pat)})
        else:
            return []
        out = []
        for f in found:
            z = cls(f)
            out.append(Suggestion(cls.kind, z.describe(), z.config()))
        return out

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    def config(self) -> dict:
        return {"kind": self.kind, "path": str(self.path)}

    def describe(self) -> str:
        return f"zotero export {self.path}"

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        items = json.loads(self.path.read_bytes())
        if not is_csl_json(items):
            raise ConnectorError("not a CSL-JSON list")
        yield from csl_items(items, "zotero")


KEY_URL = f"{API}/keys/current"
_KEY = re.compile(r"^[A-Za-z0-9]{8,64}$")
_USER_ID = re.compile(r"^[0-9]{1,20}$")


def _check_user_id(user_id: object) -> str:
    if not isinstance(user_id, str) or not _USER_ID.match(user_id):
        raise ConnectorError("invalid Zotero user ID")
    return user_id


def check_key(key: str, transport: Transport) -> dict:
    """`{"user_id", "username"}` of a pasted API key (`GET /keys/current`).
    A key that does not work raises `ConnectorError("bad_key")`."""
    if not isinstance(key, str) or not _KEY.match(key):
        raise ConnectorError("bad_key")
    status, body = transport(
        "GET", KEY_URL, {"Zotero-API-Key": key, "Zotero-API-Version": "3"}, None
    )
    if status in (401, 403, 404):
        raise ConnectorError("bad_key")
    if status != 200 or not isinstance(body, dict) or not body.get("userID"):
        raise ConnectorError(f"Zotero API status {status}")
    return {"user_id": str(body["userID"]), "username": str(body.get("username") or "")}


class ZoteroWebConnector(Connector):
    kind = "zotero_web"
    label = "Zotero library"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> ZoteroWebConnector:
        """The key of the account in `cfg["account"]`, else the
        old keystore entry `zotero-api-key`. The key is read at the first
        call, not here."""
        account = cfg.get("account")
        if account:
            creds = ctx.credentials

            def key() -> str:
                tokens = creds.tokens(account) if creds is not None else None
                if tokens is None:
                    raise ConnectorError("the Zotero key is not there")
                return tokens.access_token

            return cls(cfg["user_id"], key, ctx.transport, account=account)
        if ctx.secret is None:
            raise ConnectorError(f"{cls.kind} needs a token from the keystore")
        return cls(cfg["user_id"], ctx.secret("zotero-api-key"), ctx.transport)

    def __init__(
        self,
        user_id: str,
        api_key: str | Callable[[], str],
        transport: Transport | None = None,
        limit: int = 100,
        *,
        account: str | None = None,
    ) -> None:
        self.user_id = _check_user_id(user_id)
        self._key = api_key
        self.transport = transport or urllib_transport()
        self.limit = limit
        self.account = account

    def config(self) -> dict:
        cfg = {"kind": self.kind, "user_id": self.user_id}
        if self.account:
            cfg["account"] = self.account
        return cfg

    def describe(self) -> str:
        return f"zotero web library {self.user_id}"

    def fetch(self) -> list[dict]:
        out: list[dict] = []
        start = 0
        key = self._key() if callable(self._key) else self._key
        headers = {"Zotero-API-Key": key, "Zotero-API-Version": "3"}
        uid = urllib.parse.quote(_check_user_id(self.user_id), safe="")
        while True:
            url = with_query(
                f"{API}/users/{uid}/items",
                {"format": "csljson", "limit": self.limit, "start": start},
            )
            status, body = self.transport("GET", url, headers, None)
            if status != 200 or not isinstance(body, dict):
                raise ConnectorError(f"Zotero API status {status}")
            batch = body.get("items", [])
            out.extend(batch)
            if len(batch) < self.limit:
                return out
            start += self.limit

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        yield from csl_items(self.fetch(), f"zotero-web:{self.user_id}")


@dataclass
class FakeZotero:
    """A deterministic Zotero Web API for tests. Call it as a `Transport`."""

    user_id: str = "1"
    api_key: str = "fake-zotero-key"
    items: list[dict] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None):
        import urllib.parse

        self.calls.append(url)
        if headers.get("Zotero-API-Key") != self.api_key:
            return 403, None
        parsed = urllib.parse.urlparse(url)
        if parsed.path == "/keys/current":
            access = {"user": {"library": True}}
            return 200, {
                "access": access,
                "key": self.api_key,
                "userID": int(self.user_id),
                "username": "member",
            }
        if parsed.path != f"/users/{self.user_id}/items":
            return 404, None
        q = dict(urllib.parse.parse_qsl(parsed.query))
        start, limit = int(q.get("start", 0)), int(q.get("limit", 25))
        return 200, {"items": self.items[start : start + limit]}
