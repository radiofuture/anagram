"""Shared helpers for the local index tests. No network.

The fixtures `sim_community` and `no_network` are in conftest.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector, GitConnector, ZoteroFileConnector

LARGE_BYTES = 4096
KEY = bytes(range(32))


def lab_index(db: Path, lab_root: Path, key: bytes = KEY, **kw) -> tuple[LocalIndex, dict]:
    """Index one lab folder as a lab device would: the folder, each Git
    repository in it, and each Zotero export. Return the index and the source
    IDs by kind. The addresses of the lab people are the owner addresses
    (a mail with no known owner is third-party: fail closed)."""
    kw.setdefault("owner_emails", sim_owners(lab_root))
    index = LocalIndex(db, key, **kw)
    folder = FolderConnector(lab_root)
    ids = {"folder": [index.add_source(folder)], "git": [], "zotero": []}
    for repo in folder.repositories():
        ids["git"].append(index.add_source(GitConnector(repo)))
    for z in sorted(lab_root.rglob("zotero-export.json")):
        ids["zotero"].append(index.add_source(ZoteroFileConnector(z)))
    return index, ids


def lab(sim, slug: str) -> dict:
    return next(x for x in sim.ground_truth["labs"] if x["slug"] == slug)


def sim_owners(root: Path) -> frozenset[str]:
    """The addresses of the sim people whose folders are under `root` (a lab
    or a person folder of the synthetic community)."""
    root = Path(root).resolve()
    for base in (root, *root.parents):
        truth = base / "ground_truth.json"
        if truth.is_file():
            people = json.loads(truth.read_text())["people"]
            return frozenset(
                p["email"].lower()
                for p in people
                if (base / p["path"]).resolve().is_relative_to(root)
                or root.is_relative_to((base / p["path"]).resolve())
            )
    return frozenset()


def own_addresses(monkeypatch, emails) -> None:
    """Give `LocalIndex.for_client` these owner addresses too (the tests of
    the UI index sim mail with no connected Google account)."""
    real = LocalIndex.for_client.__func__
    extra = frozenset(e.lower() for e in emails)

    def for_client(cls, client, **kwargs):
        idx = real(cls, client, **kwargs)
        idx.owner_emails = idx.owner_emails | extra
        return idx

    monkeypatch.setattr(LocalIndex, "for_client", classmethod(for_client))
