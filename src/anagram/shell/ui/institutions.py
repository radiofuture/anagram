"""Institution search for the identity step and the block list.

An identity record holds the institution as a ROR ID. A person does not know
that ID, so the UI searches by name. Two adapters:

- `RorApi`: the public ROR API (network). The search words leave this
  computer (see `anagram.shell.ui.flows`, "institution-search").
- `StaticInstitutions`: a fixed list. The demo and the tests use it.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Iterable

from anagram.core.errors import FormatError
from anagram.identity.api import validate_ror

ROR_API = "https://api.ror.org/v2/organizations"
MAX_RESULTS = 20


class InstitutionLookup:
    def search(self, query: str) -> list[dict]:  # pragma: no cover - interface
        """Return at most 20 items: {"id": ROR ID, "label": name, "detail": place}."""
        raise NotImplementedError

    def name(self, ror: str) -> str | None:
        return None


class StaticInstitutions(InstitutionLookup):
    def __init__(self, items: Iterable[dict]) -> None:
        self.items = [
            {"detail": i.get("detail") or "", "id": i["id"], "label": i["label"]} for i in items
        ]

    def search(self, query: str) -> list[dict]:
        q = query.strip().lower()
        return [i for i in self.items if q in i["label"].lower() or q == i["id"]][:MAX_RESULTS]

    def name(self, ror: str) -> str | None:
        return next((i["label"] for i in self.items if i["id"] == ror), None)


class RorApi(InstitutionLookup):  # pragma: no cover - network
    def __init__(self, timeout: float = 10) -> None:
        self.timeout = timeout

    def search(self, query: str) -> list[dict]:
        url = f"{ROR_API}?{urllib.parse.urlencode({'query': query.strip()[:120]})}"
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 - https
            data = json.loads(resp.read())
        out = []
        for org in data.get("items", [])[:MAX_RESULTS]:
            ror = org.get("id", "").rsplit("/", 1)[-1]
            try:
                validate_ror(ror)
            except FormatError:
                continue
            names = org.get("names") or []
            label = next(
                (n["value"] for n in names if "ror_display" in n.get("types", [])),
                names[0]["value"] if names else ror,
            )
            places = [
                loc.get("geonames_details", {}).get("country_name", "")
                for loc in org.get("locations") or []
            ]
            out.append({"detail": ", ".join(p for p in places if p), "id": ror, "label": label})
        return out
