"""Lens items from the local index.

    items = from_index(index, policy)   # own items only, with role and tier
    first = fast_subset(items, today)   # the fast pass

Only own items (`LocalIndex.items(own_only=True)`): no received mail, no
attachment of a received mail, no file of another owner, no item of a
source of other people's work. The text is `Document.markdown`, never
`Document.quoted` (primitive `third-party-text`).
"""

from __future__ import annotations

import email.utils
import re
from datetime import UTC, date
from typing import TYPE_CHECKING

from anagram.local.trust.policy import OWN_DEFAULT
from anagram.local.understanding.profile.schema import LensItem

if TYPE_CHECKING:
    from anagram.local.index.local import ItemView, LocalIndex
    from anagram.local.trust.policy import TrustPolicy

CODE = (".py", ".r", ".jl", ".m", ".c", ".cpp", ".rs", ".go", ".js", ".ts", ".sh", ".do")
PUBLICATION_KINDS = frozenset({"orcid_work"})
CODE_KINDS = frozenset({"git_commit", "github_commit"})
_ISO_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _parse_date(value: str | None) -> str:
    """Extract YYYY-MM-DD from an ISO date/timestamp or RFC 2822 email Date."""
    if not value:
        return ""
    text = value.strip()
    if _ISO_PREFIX.match(text):
        try:
            return date.fromisoformat(text[:10]).isoformat()
        except ValueError:
            pass
    try:
        dt = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC)
    return dt.date().isoformat()


def role_of(view: ItemView) -> str:
    """The role of an item for the lens, from its kind and its name."""
    name = (view.name or view.path or "").lower()
    if view.kind == "email":
        return "sent"  # own_only: a received mail is never here
    if view.kind in PUBLICATION_KINDS:
        return "publication"
    if view.kind in CODE_KINDS or name.endswith(CODE):
        return "code"
    if name.endswith(".ipynb"):
        return "notebook"
    if "protocol" in name or "sop" in name.split("/")[-1].split("."):
        return "protocol"
    return "doc"


def from_index(index: LocalIndex, policy: TrustPolicy | None = None) -> list[LensItem]:
    out = []
    for view in index.items(own_only=True):
        version = index.current_version(view.source_id, view.key)
        doc = index.document(version["id"]) if version is not None else None
        if doc is None or not doc.markdown.strip():
            continue
        tier = (
            policy.item_tier(view.source_id, view.key, third_party=False)
            if policy is not None
            else OWN_DEFAULT
        )
        meta_date = doc.meta.get("date") if isinstance(doc.meta.get("date"), str) else None
        day = _parse_date(meta_date) or _parse_date(view.time)
        out.append(
            LensItem(
                id=f"{view.source_id}:{view.key}",
                role=role_of(view),
                date=day,
                text=doc.markdown,
                tier=tier,
                published=view.kind in PUBLICATION_KINDS,
            )
        )
    return out


FAST_LIMIT = 400  # items of the fast pass (first profile in ~15 min)
_FAST_ORDER = {"publication": 0, "sent": 1, "doc": 2, "protocol": 2, "notebook": 3, "code": 3}


def fast_subset(items: list[LensItem], today: str, limit: int = FAST_LIMIT) -> list[LensItem]:
    """The items of the fast pass: publications, then sent mail and own
    documents of the last 12 months, newest first, at most `limit`. The full
    pass reads the rest later; the lens cache keeps the items already read."""
    year_ago = f"{int(today[:4]) - 1}{today[4:10]}"
    pick = [i for i in items if i.role == "publication" or i.date >= year_ago]
    pick.sort(key=lambda i: i.date, reverse=True)
    pick.sort(key=lambda i: _FAST_ORDER.get(i.role, 9))
    return pick[:limit]
