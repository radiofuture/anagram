"""The name of a source that a person sees.

Each source has a label from the time it is made. The label is never a raw
path and never an internal ID (experience rule 9):

- A local source (folder, vault, Git repository, Zotero export): the last
  part of its path, for example "Lab notes".
- A connected source: the kind and the account, for example
  "Google Drive (ana@lab.org)".
- Other sources: the name of the kind, for example "My ORCID works".

`migrate(store)` gives a label to each stored source that has none, or that
has a label of the old form (`connector.describe()`, which held the full
path). `LocalIndex` runs it when it opens the store.
"""

from __future__ import annotations

import logging
import re
from pathlib import PurePath
from typing import TYPE_CHECKING

from anagram.local.index.store import loads
from anagram.local.sources import kind_label

if TYPE_CHECKING:
    from anagram.local.index.store import IndexStore

log = logging.getLogger("anagram.local.index")

PLACE_KEYS = ("root", "repo", "path")
ORCID_LABEL = "My ORCID works"
# A path in a text: "/Users/…", "~/…", "C:\…" at the start or after a space
# or a bracket.
_PATH = re.compile(r"(^|[\s(])(/[^\s/]|~[/\\]|[A-Za-z]:[\\/])")
# Old labels (`describe()`) that hold an internal ID and no path.
_OLD_ID_FORMS = ("zotero web library ",)


def place_of(config: dict) -> str | None:
    for key in PLACE_KEYS:
        value = config.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def source_label(config: dict, account_label: str | None = None) -> str:
    """The label of a new source from its config (and the label of its
    account for a connected source)."""
    kind = str(config.get("kind") or "")
    place = place_of(config)
    if place is not None:
        name = PurePath(place.rstrip("/\\") or place).name
        if name and not _PATH.search(name):
            return name
    if kind == "orcid_works":
        return ORCID_LABEL
    name = kind_label(kind) if kind else "Source"
    if account_label:
        return f"{name} ({account_label})"
    return name


def is_raw(label: object) -> bool:
    """True if the label is empty, holds a path, or is an old form with an
    internal ID."""
    if not isinstance(label, str) or not label.strip():
        return True
    return bool(_PATH.search(label)) or label.startswith(_OLD_ID_FORMS)


def account_label(store: IndexStore, account_id: object) -> str | None:
    if not isinstance(account_id, str):
        return None
    row = store.one("SELECT label FROM account WHERE id = ?", (account_id,))
    return row["label"] if row is not None else None


def shown(store: IndexStore, label: object, config: dict) -> str:
    """The label to show. A raw label (a source from before the migration,
    or a label from a plug-in) gives the label from the config."""
    if not is_raw(label):
        return str(label)
    return source_label(config, account_label(store, config.get("account")))


def migrate(store: IndexStore) -> int:
    """Give each stored source with a raw label a new label. A removed
    source (config kind `removed`) keeps its row as it is. Returns the count
    of changed rows. Safe to run again."""
    changed = 0
    for row in store.q("SELECT id, label, config FROM source"):
        if not is_raw(row["label"]):
            continue
        config = loads(row["config"])
        if not isinstance(config, dict) or config.get("kind") == "removed":
            continue
        label = source_label(config, account_label(store, config.get("account")))
        store.x("UPDATE source SET label = ? WHERE id = ?", (label, row["id"]))
        changed += 1
    if changed:
        log.info("source labels: %d set", changed)
    return changed
