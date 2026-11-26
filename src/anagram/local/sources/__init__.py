"""Sources: each source yields evidence items. See `base.py`.

`SOURCES` is the source registry (`anagram.sources` entry points plus the
built-in sources). `SourceKinds` is the view of one index: the registry and
the kinds that a higher layer gives through the composition root (the lab
space). `connector_from_config` opens a stored source config.
`discover(path)` lists the sources that the registered kinds find in a path
(for example "2 Git repositories, 1 Zotero export").
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from anagram.local.index.convert import CONVERTERS
from anagram.local.index.enrich import ENRICHERS
from anagram.local.index.registry import GROUP_SOURCES, Registry
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SecretFn,
    Source,
    SourceContext,
    Suggestion,
    Transport,
    record_item,
)
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.folder import FolderConnector
from anagram.local.sources.gdrive import GoogleDriveConnector
from anagram.local.sources.git import GitConnector
from anagram.local.sources.github import FakeGitHub, GitHubConnector, GitHubDeviceFlow
from anagram.local.sources.gmail import GmailConnector
from anagram.local.sources.notion import FakeNotion, NotionConnector
from anagram.local.sources.obsidian import ObsidianConnector, ObsidianConverter, ObsidianEnricher
from anagram.local.sources.orcid import FakeOrcid, OrcidWorksConnector
from anagram.local.sources.zotero import FakeZotero, ZoteroFileConnector, ZoteroWebConnector

log = logging.getLogger("anagram.local.index")

SOURCES: Registry[type[Connector]] = Registry(GROUP_SOURCES)
for _cls in (
    FolderConnector,
    ObsidianConnector,
    GitConnector,
    ZoteroFileConnector,
    ZoteroWebConnector,
    OrcidWorksConnector,
    GitHubConnector,
    GoogleDriveConnector,
    GmailConnector,
    NotionConnector,
):
    SOURCES.register(_cls.kind, _cls, builtin=True)
# The lab space source (kind `labspace`) is a network (L3) source. It is not
# in this registry: the composition root gives it to the index
# (`LocalIndex(sources=...)`, `Client.index_sources`).
# The converter and the enricher of the Obsidian source. The converter comes
# after `basic` in the registry, so it reads a note only for a source that
# prefers it.
CONVERTERS.register(ObsidianConverter.name, ObsidianConverter, builtin=True)
ENRICHERS.register(ObsidianEnricher.name, ObsidianEnricher, builtin=True)


class SourceKinds:
    """The source kinds of one index: the kinds in `given` (a higher layer
    gives them through the composition root, for example the lab space),
    then the registry `SOURCES`."""

    def __init__(self, given: Iterable[type[Connector]] = ()) -> None:
        self.given = {cls.kind: cls for cls in given}

    def get(self, kind: str) -> type[Connector] | None:
        return self.given.get(kind) or SOURCES.get(kind)

    def label(self, kind: str) -> str:
        cls = self.get(kind)
        return (getattr(cls, "label", "") or kind) if cls is not None else kind


def connector_from_config(
    cfg: dict,
    secret: SecretFn | None = None,
    transport: Transport | None = None,
    *,
    http=None,
    credentials=None,
    kinds: SourceKinds | None = None,
) -> Connector:
    """Open a source from its stored config. `http` and `credentials` are for
    contract v2 sources (`SourceContext`). `kinds`: the kinds of the index
    (default: the registry only)."""
    kind = cfg["kind"]
    cls = (kinds or SourceKinds()).get(kind)
    if cls is None:
        raise ConnectorError(f"unknown connector kind: {kind}")
    return cls.from_config(
        cfg, SourceContext(secret=secret, transport=transport, http=http, credentials=credentials)
    )


def kind_label(kind: str) -> str:
    return SourceKinds().label(kind)


def discover(path: str | Path, kinds: list[str] | None = None) -> list[Suggestion]:
    """Suggestions from each registered source kind with `discover`. A kind
    that fails is logged and left out."""
    p = Path(path).expanduser()
    out: list[Suggestion] = []
    for name, cls in SOURCES:
        if kinds is not None and name not in kinds:
            continue
        fn = getattr(cls, "discover", None)
        if fn is None:
            continue
        try:
            out.extend(fn(p))
        except Exception:  # one plug-in must not stop the others
            log.exception("source %r: discover failed for %s", name, p)
    return out


def describe_suggestions(found: list[Suggestion]) -> str:
    """For example "1 Folder, 2 Git repository, 1 Zotero library"."""
    count = Counter(s.kind for s in found)
    return ", ".join(f"{n} {kind_label(k)}" for k, n in count.items())


__all__ = [
    "SOURCES",
    "Connector",
    "ConnectorError",
    "EvidenceItem",
    "FakeGitHub",
    "FakeGoogle",
    "FakeNotion",
    "FakeOrcid",
    "FakeZotero",
    "FolderConnector",
    "GitConnector",
    "GitHubConnector",
    "GitHubDeviceFlow",
    "GmailConnector",
    "GoogleDriveConnector",
    "KnownItem",
    "NotionConnector",
    "ObsidianConnector",
    "OrcidWorksConnector",
    "SecretFn",
    "Source",
    "SourceContext",
    "SourceKinds",
    "Suggestion",
    "Transport",
    "ZoteroFileConnector",
    "ZoteroWebConnector",
    "connector_from_config",
    "describe_suggestions",
    "discover",
    "kind_label",
    "record_item",
]
