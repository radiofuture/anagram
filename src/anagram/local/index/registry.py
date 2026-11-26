"""Plug-in registries for the index stages (spec/index.md section 2).

Each stage has one registry: sources, converters, enrichers. A registry holds
the built-in plug-ins, and it loads more from Python entry points:

    [project.entry-points."anagram.sources"]
    my_source = "my_package.module:MySource"

    [project.entry-points."anagram.converters"]
    my_converter = "my_package.module:MyConverter"

    [project.entry-points."anagram.enrichers"]
    my_enricher = "my_package.module:MyEnricher"

The entry point name is the registry name (for a source: its `kind`). A
built-in name wins over an entry point with the same name, so an installed
package cannot replace a built-in plug-in by accident. A plug-in that does not
load is logged and left out. It does not stop the index.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from importlib.metadata import entry_points
from typing import Generic, TypeVar

log = logging.getLogger("anagram.local.index")

T = TypeVar("T")

GROUP_SOURCES = "anagram.sources"
GROUP_CONVERTERS = "anagram.converters"
GROUP_ENRICHERS = "anagram.enrichers"


class Registry(Generic[T]):
    """An ordered name -> plug-in map. Order is registration order (built-ins
    first, then entry points sorted by name)."""

    def __init__(self, group: str) -> None:
        self.group = group
        self._items: dict[str, T] = {}
        self._builtin: set[str] = set()
        self._loaded = False
        self.errors: dict[str, str] = {}  # entry point name -> load error

    def register(self, name: str, plugin: T, *, builtin: bool = False) -> T:
        if name in self._builtin and not builtin:
            raise ValueError(f"{self.group}: {name!r} is a built-in name")
        self._items[name] = plugin
        if builtin:
            self._builtin.add(name)
        return plugin

    def unregister(self, name: str) -> None:
        """Remove a plug-in (tests and the user's settings). Built-ins too."""
        self._items.pop(name, None)
        self._builtin.discard(name)

    def load_entry_points(self) -> None:
        """Load the installed plug-ins of this group once."""
        if self._loaded:
            return
        self._loaded = True
        for ep in sorted(entry_points(group=self.group), key=lambda e: e.name):
            if ep.name in self._builtin:
                log.warning("%s: entry point %r has a built-in name; ignored", self.group, ep.name)
                continue
            try:
                self._items[ep.name] = ep.load()
            except Exception as exc:  # a bad plug-in must not stop the index
                self.errors[ep.name] = f"{type(exc).__name__}: {exc}"
                log.exception("%s: plug-in %r does not load", self.group, ep.name)

    def get(self, name: str) -> T | None:
        self.load_entry_points()
        return self._items.get(name)

    def names(self) -> list[str]:
        self.load_entry_points()
        return list(self._items)

    def __iter__(self) -> Iterator[tuple[str, T]]:
        self.load_entry_points()
        return iter(list(self._items.items()))

    def __contains__(self, name: object) -> bool:
        self.load_entry_points()
        return name in self._items
