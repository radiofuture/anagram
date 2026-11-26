"""The member directory of the local UI (layer L1, with the lab names of
L3): names for the screens, and the search of people, labs, and
institutions. The list is cached for a short time (`PEOPLE_TTL`).

A screen never shows a raw person ID: `label` gives the name, or the ID
when the directory does not have the person.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from anagram.core.errors import FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import validate_orcid
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

PEOPLE_TTL = 30.0


class PeopleUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self._cache: tuple[float, list[dict]] | None = None

    def forget(self) -> None:
        """Read the directory again at the next use (a name or a lab changed)."""
        self._cache = None

    def directory(self) -> list[dict]:
        """Members with their identity records (cached for a short time)."""
        if self._cache and self.ui.clock() - self._cache[0] < PEOPLE_TTL:
            return self._cache[1]
        out = []
        with self.ui.session() as c:
            labs: dict[str, str] = {}
            me = c.device.subject
            my_orcid = c.account.orcid
            for subject in c.device.http.call("GET", "/members", auth=True)["members"]:
                try:
                    rec = c.device.http.call(
                        "GET", f"/identity/{urllib.parse.quote(subject, safe=':')}", auth=True
                    )
                except NodeHTTPError:
                    rec = {}
                lab_id = rec.get("lab_id")
                if lab_id and lab_id not in labs:
                    try:
                        labs[lab_id] = c.device.http.call("GET", f"/labs/{lab_id}", auth=True)[
                            "name"
                        ]
                    except NodeHTTPError:
                        labs[lab_id] = ""
                out.append(
                    {
                        "lab": labs.get(lab_id) if lab_id else None,
                        "lab_id": lab_id,
                        "me": subject == me,
                        "name": rec.get("display_name") or "Member",
                        # Other members' ORCID iDs are private (spec/identity.md).
                        "orcid": my_orcid if subject == me else None,
                        "ror": rec.get("institution"),
                        "subject": subject,
                    }
                )
        self._cache = (self.ui.clock(), out)
        return out

    def known(self) -> list[dict]:
        """The directory, or an empty list when the node cannot give it now."""
        try:
            return self.directory()
        except UIError:
            return []

    def names(self, fresh: bool = False) -> dict[str, str]:
        """Subject -> display name. `fresh`: read the directory again (a
        person who joined after the cache was made has no name in it)."""
        if fresh:
            self.forget()
        return {p["subject"]: p["name"] for p in self.known()}

    def label(self, subject: str) -> str:
        """The name of a member; the subject itself when it is not known."""
        for p in self.known():
            if p["subject"] == subject:
                return p["name"]
        return subject

    def lab_name(self, lab_id: str) -> str | None:
        return next((p["lab"] for p in self.known() if p["lab_id"] == lab_id), None)

    def institution_name(self, ror: str | None) -> str | None:
        if not ror:
            return None
        return self.ui.institutions.name(ror) or ror

    # -------------------------------------------------------------- search

    def search(self, q: str, include_me: bool = False) -> list[dict]:
        q = q.strip().lower()
        out = []
        orcid = typed_orcid(q)
        if orcid:
            # A typed ORCID iD: blocks use it directly; rings and guardians look
            # it up (only a member who is findable by ORCID is found).
            out.append({"detail": "ORCID iD", "id": orcid, "label": f"ORCID iD {orcid}"})
        for p in self.directory():
            if p["me"] and not include_me:
                continue
            hay = f"{p['name']} {p['orcid'] or ''} {p['lab'] or ''}".lower()
            if q in hay:
                detail = ", ".join(x for x in (p["lab"], self.institution_name(p["ror"])) if x)
                out.append({"detail": detail or "Member", "id": p["subject"], "label": p["name"]})
        return out[:20]

    def search_labs(self, q: str) -> list[dict]:
        q = q.strip().lower()
        seen, out = set(), []
        for p in self.directory():
            if p["lab_id"] and p["lab_id"] not in seen and q in (p["lab"] or "").lower():
                seen.add(p["lab_id"])
                out.append(
                    {
                        "detail": self.institution_name(p["ror"]) or "",
                        "id": p["lab_id"],
                        "label": p["lab"] or "Lab",
                    }
                )
        return out[:20]

    def search_institutions(self, q: str) -> list[dict]:
        if len(q.strip()) < 2:
            return []
        try:
            found = self.ui.institutions.search(q)
        except OSError as exc:
            raise UIError(502, "Anagram could not reach the institution list. Try again.") from exc
        known = {i["id"] for i in found}
        for p in self.known():
            if p.get("ror") and p["ror"] not in known and q.lower() in (p["ror"] or "").lower():
                found.append(
                    {"detail": "Used in this community", "id": p["ror"], "label": p["ror"]}
                )
                known.add(p["ror"])
        return found[:20]


def typed_orcid(q: str) -> str | None:
    """The ORCID iD in a search text, or None."""
    for candidate in (q, q.upper()):
        try:
            return validate_orcid(candidate)
        except FormatError:
            continue
    return None
