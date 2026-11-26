"""Typed access to the key-value table of the local vault.

The local vault (`vault.sqlite`) has one table `kv` (text key, text value)
that more than one layer uses. Each layer names its own keys with an
accessor object over a `KeyFamily`: a key prefix and how the value is
stored (text or JSON). The keys and the stored text do not change; only
the code that reads and writes them is in one place for each layer.

A key family with the prefix "x/" holds the keys "x/<name>". A family for
one key uses the key as the prefix and the name "".
"""

from __future__ import annotations

import json
from typing import Any, Protocol


class KeyValue(Protocol):
    """The key-value calls of the local vault."""

    def kv_get(self, key: str) -> str | None: ...

    def kv_set(self, key: str, value: str) -> None: ...

    def kv_delete(self, key: str) -> None: ...

    def kv_items(self, prefix: str) -> list[tuple[str, str]]: ...


class TextKeys:
    """The keys `prefix + name`, with text values."""

    def __init__(self, kv: KeyValue, prefix: str) -> None:
        self.kv = kv
        self.prefix = prefix

    def get(self, name: str = "") -> str | None:
        return self.kv.kv_get(self.prefix + name)

    def set(self, name: str, value: str) -> None:
        self.kv.kv_set(self.prefix + name, value)

    def delete(self, name: str = "") -> None:
        self.kv.kv_delete(self.prefix + name)

    def items(self) -> list[tuple[str, str]]:
        """(name, text) of each key of the family, in key order."""
        n = len(self.prefix)
        return [(k[n:], v) for k, v in self.kv.kv_items(self.prefix)]


class JsonKeys(TextKeys):
    """The keys `prefix + name`, with JSON values. `sort_keys` is the form
    in which the family has always been written."""

    def __init__(self, kv: KeyValue, prefix: str, *, sort_keys: bool = False) -> None:
        super().__init__(kv, prefix)
        self.sort_keys = sort_keys

    def load(self, name: str = "") -> Any:
        raw = self.get(name)
        return json.loads(raw) if raw else None

    def dump(self, name: str, value: Any) -> None:
        self.set(name, json.dumps(value, sort_keys=self.sort_keys))

    def loaded_items(self) -> list[tuple[str, Any]]:
        return [(k, json.loads(v)) for k, v in self.items()]
