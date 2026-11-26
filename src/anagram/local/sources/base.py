"""Connector interface.

A connector reads one source and yields evidence items. It does not commit,
extract meaning, or change the source. A new connector never changes the
protocol: each item becomes a normal evidence record
(`anagram.evidence.v1`), and each source has its own stream of checkpoints.

Each item has a stable `key` inside its source (a relative path, a commit ID,
a Zotero item key, an ORCID put-code) and a content digest. The index compares
digests with the last scan to find new, changed, and removed items.

API connectors (GitHub, Zotero Web API, ORCID) call the network only through a
`Transport`. Tests pass a fake transport. No test uses the network.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from anagram.core.canonical import canonical_json
from anagram.core.crypto.chunked import ContentDigest, hash_bytes

if TYPE_CHECKING:  # contract v2 (http.py and credentials.py import this module)
    from anagram.local.sources.credentials import CredentialStore
    from anagram.local.sources.http import HttpTransport

RECORD_SCHEMA = "anagram.index.record.v1"
RECORD_MEDIA_TYPE = "application/json"


# transport(method, url, headers, body) -> (status, parsed JSON or None)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, object]]


@dataclass(frozen=True)
class KnownItem:
    """What the index remembers of an item from the last scan."""

    digest: dict  # ContentDigest JSON
    size: int
    mtime_ns: int | None
    media_type: str | None = None  # the sniffed type of the last scan


@dataclass
class EvidenceItem:
    key: str  # stable key inside the source
    kind: str  # file, git_commit, github_commit, zotero_item, orcid_work
    name: str | None  # original name (file name, title)
    media_type: str
    digest: ContentDigest
    ref: str  # where it is: relative path, or a URI such as git:<commit>
    mtime_ns: int | None = None
    time: str | None = None  # RFC 3339, when the source gives a time
    path: Path | None = None  # local file (file items only)
    data: bytes | None = None  # exact evidence bytes for record items
    extra: dict = field(default_factory=dict)  # not committed; hints for extraction

    @property
    def size(self) -> int:
        return self.digest.size


def record_item(
    *,
    key: str,
    kind: str,
    name: str | None,
    ref: str,
    record: dict,
    text: str,
    title: str | None,
    prose: bool = False,
    time: str | None = None,
    extra: dict | None = None,
) -> EvidenceItem:
    """An evidence item for a source record (not a file). The evidence bytes
    are canonical JSON of the record with the text that the source gave."""
    doc = {
        "kind": kind,
        "prose": prose,
        "record": record,
        "schema": RECORD_SCHEMA,
        "text": text,
        "title": title,
    }
    data = canonical_json(doc)
    return EvidenceItem(
        key=key,
        kind=kind,
        name=name,
        media_type=RECORD_MEDIA_TYPE,
        digest=hash_bytes(data),
        ref=ref,
        time=time,
        data=data,
        extra=extra or {},
    )


# secret(name) -> value: reads API tokens from the keystore. Tokens are never
# in a source config.
SecretFn = Callable[[str], str]


@dataclass(frozen=True)
class SourceContext:
    """What a source may need to open from its config: keystore secrets and
    the network transport (API sources only). A contract v2 source uses
    `http` (headers and bytes) and `credentials` (accounts and tokens)."""

    secret: SecretFn | None = None
    transport: Transport | None = None
    http: HttpTransport | None = None
    credentials: CredentialStore | None = None


@dataclass(frozen=True)
class Suggestion:
    """A source that `discover` found in a path. `config` is a source config
    that `connector_from_config` can open. The user confirms each one."""

    kind: str
    label: str
    config: dict


@runtime_checkable
class Source(Protocol):
    """The source plug-in contract (spec/index.md section 2.1).

    - `kind`: the registry name. It is also `config()["kind"]`.
    - `from_config(cfg, ctx)`: open the source from its stored config.
    - `config()`: JSON with no secrets.
    - `scan(known)`: yield all current items (`EvidenceItem`).
    - `describe()`: a label for the person.
    - `discover(path)` (optional, class method): sources of this kind inside
      a local path, as suggestions.
    """

    kind: ClassVar[str]

    def config(self) -> dict: ...

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]: ...

    def describe(self) -> str: ...


class Connector(ABC):
    """Base class for one source (it implements `Source`). `config()` is JSON
    that `connector_from_config` can read."""

    kind: ClassVar[str] = ""
    label: ClassVar[str] = ""  # what the UI calls this kind of source
    # False: the items are the work of other people (the lab space source).
    # They go into no checkpoint, no finding draft, and no matching lines.
    own: ClassVar[bool] = True

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> Connector:
        raise ConnectorError(f"{cls.kind}: from_config is not implemented")

    @classmethod
    def discover(cls, path: Path) -> list[Suggestion]:
        """Sources of this kind inside `path`. The default finds none."""
        return []

    @abstractmethod
    def config(self) -> dict: ...

    @abstractmethod
    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        """Yield all current items. `known` lets a connector skip work for
        items that did not change (for example the same size and mtime)."""

    def describe(self) -> str:
        return self.kind


def urllib_transport(timeout: int = 30) -> Transport:
    """Real network transport. Only API connectors use it, and only when the
    user connects that source. Tests never use it."""

    def call(method: str, url: str, headers: dict[str, str], body: bytes | None):
        if not url.startswith("https://"):
            raise ValueError("API calls must use https")
        req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except ValueError:
                return exc.code, None

    return call


def with_query(url: str, params: Mapping[str, object]) -> str:
    return url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)


class ConnectorError(Exception):
    pass
