"""ORCID works connector (public API, no token).

Reads `https://pub.orcid.org/v3.0/<orcid>/works` and makes one evidence item
(a record) for each work summary: title, type, year, venue, and external IDs
(DOI). This gives the "known work" baseline. The request sends only the ORCID
iD, which is public. Tests use `FakeOrcid`.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    Transport,
    record_item,
    urllib_transport,
)

API = "https://pub.orcid.org/v3.0"
WORK_KIND = "orcid_work"
_ORCID = re.compile(r"^(?:fake-)?\d{4}-\d{4}-\d{4}-\d{3}[\dX]$")


def _check_orcid(orcid: object) -> str:
    if not isinstance(orcid, str) or not _ORCID.match(orcid):
        raise ConnectorError("invalid ORCID iD")
    return orcid


def _val(obj: object, *path: str) -> object:
    for p in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


def work_record(summary: dict) -> dict:
    ids = []
    for ext in _val(summary, "external-ids", "external-id") or []:
        t, v = ext.get("external-id-type"), ext.get("external-id-value")
        if t and v:
            ids.append({"type": t, "value": v})
    year = _val(summary, "publication-date", "year", "value")
    return {
        "external_ids": sorted(ids, key=lambda x: (x["type"], x["value"])),
        "journal": _val(summary, "journal-title", "value"),
        "put_code": summary.get("put-code"),
        "title": _val(summary, "title", "title", "value"),
        "type": summary.get("type"),
        "year": year,
    }


class OrcidWorksConnector(Connector):
    kind = "orcid_works"
    label = "ORCID works"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> OrcidWorksConnector:
        return cls(cfg["orcid"], ctx.transport)

    def __init__(self, orcid: str, transport: Transport | None = None) -> None:
        self.orcid = _check_orcid(orcid)
        self.transport = transport or urllib_transport()

    def config(self) -> dict:
        return {"kind": self.kind, "orcid": self.orcid}

    def describe(self) -> str:
        return f"ORCID works of {self.orcid}"

    def fetch(self) -> list[dict]:
        safe_orcid = urllib.parse.quote(_check_orcid(self.orcid), safe="")
        status, body = self.transport(
            "GET", f"{API}/{safe_orcid}/works", {"Accept": "application/json"}, None
        )
        if status != 200 or not isinstance(body, dict):
            raise ConnectorError(f"ORCID API status {status}")
        out = []
        for group in body.get("group", []):
            summaries = group.get("work-summary") or []
            if summaries:
                # The first summary is the preferred source of the group.
                out.append(summaries[0])
        return out

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        for s in self.fetch():
            rec = work_record(s)
            key = str(rec["put_code"])
            title = rec["title"] if isinstance(rec["title"], str) else None
            text = "\n".join(str(x) for x in (title, rec["journal"]) if x)
            yield record_item(
                key=key,
                kind=WORK_KIND,
                name=title,
                ref=f"orcid:{self.orcid}/work/{key}",
                record=rec,
                text=text,
                title=title,
                prose=False,
                time=f"{int(rec['year']):04d}-01-01T00:00:00Z" if rec["year"] else None,
            )


@dataclass
class FakeOrcid:
    """A deterministic ORCID public API for tests. Call it as a `Transport`."""

    works: dict[str, list[dict]] = field(default_factory=dict)  # orcid -> work summaries
    calls: list[str] = field(default_factory=list)

    def add_work(
        self, orcid: str, put_code: int, title: str, year: int, doi: str, journal: str
    ) -> None:
        self.works.setdefault(orcid, []).append(
            {
                "put-code": put_code,
                "type": "journal-article",
                "title": {"title": {"value": title}},
                "journal-title": {"value": journal},
                "publication-date": {"year": {"value": str(year)}},
                "external-ids": {
                    "external-id": [{"external-id-type": "doi", "external-id-value": doi}]
                },
            }
        )

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None):
        self.calls.append(url)
        prefix = f"{API}/"
        if not url.startswith(prefix) or not url.endswith("/works"):
            return 404, None
        orcid = url[len(prefix) : -len("/works")]
        if orcid not in self.works:
            return 404, None
        return 200, {"group": [{"work-summary": [w]} for w in self.works[orcid]]}
