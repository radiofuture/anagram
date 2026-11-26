"""The source kinds of the local UI and the sentences for the person.

    info = kind_info("gdrive")          # a `KindInfo`, or a 400 error
    raise error(404, "not_found", "This source is not there.")

The parts `UIService.sources` (`sources.py`), `UIService.connections`
(`connections.py`), and `UIService.lab_sources` (`lab_sources.py`) share
these names. A fault code gets one plain sentence; no
code shows on a screen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from anagram.local.api import (
    PRIVATE,
)
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.local.api import (
        PRIVATE,
        LocalIndex,
    )

LAB = "lab"
SPACE_REFUSED = "Your lab does not permit this source in the lab space."


@dataclass(frozen=True)
class KindInfo:
    """One source kind that the UI offers."""

    kind: str
    auth: str = "none"  # none | oauth | api_key
    provider: str | None = None  # google | notion | zotero; the name in fault text
    choose: str = "path"  # path | folders | filter | provider | none
    spaces: tuple[str, ...] = (PRIVATE, LAB)
    missing: str = "This source is not there."  # the sentence of the fault `not_found`


# The kinds of `GET /api/source-kinds`, in the order of the list. A later
# step adds its kind here. `github` and `labspace` are not in the UI.
KINDS: dict[str, KindInfo] = {
    k.kind: k
    for k in (
        KindInfo("folder", missing="This folder is not there."),
        KindInfo("obsidian", missing="This folder is not there."),
        KindInfo("git", missing="This folder is not there."),
        KindInfo("zotero_file", missing="This file is not there."),
        KindInfo("orcid_works", choose="none"),
        KindInfo(
            "gdrive",
            auth="oauth",
            provider="google",
            choose="folders",
            missing="This folder is not there.",
        ),
        # Mail stays private.
        KindInfo(
            "gmail",
            auth="oauth",
            provider="google",
            choose="filter",
            spaces=(PRIVATE,),
            missing="This label is not there.",
        ),
        # A pasted Zotero API key (`POST /api/accounts/key`).
        KindInfo(
            "zotero_web",
            auth="api_key",
            provider="zotero",
            choose="none",
            missing="This library is not there.",
        ),
        # The person chooses pages in the Notion consent screen.
        KindInfo(
            "notion",
            auth="oauth",
            provider="notion",
            choose="provider",
            missing="This page is not there.",
        ),
    )
}
PROVIDER_NAMES = {"google": "Google", "notion": "Notion", "zotero": "Zotero"}

# fault code -> the sentence for the person. The time of
# the next try is `fault.retry_at`; the screen shows it.
FAULT_TEXT = {
    "rate_limited": "Paused by {provider} for a short time.",
    "offline": "No connection. Anagram tries again.",
    "quota": "The daily limit of the {provider} client is used. Anagram continues tomorrow.",
    "auth_expired": "Your {provider} sign-in has ended.",
    "permission_lost": "Anagram can no longer read this source.",
    "client_missing": "Not set up for this lab. Ask your lab admin.",
    "unknown": "Could not read this source.",
}


# The result of a sign-in flow -> the sentence for the person.
FLOW_TEXT = {
    "denied": "You did not give access. Nothing was connected.",
    "expired": "The sign-in took too long. Start again.",
    "cancelled": "The sign-in was stopped. Nothing was connected.",
    "scope_missing": "Anagram needs read access to this source. Sign in again and allow it.",
    "other_account": "You signed in with a different account. Sign in with {label}.",
    "error": "The sign-in did not work. Start again.",
}


def error(status: int, code: str, message: str) -> UIError:
    return UIError(status, message, {"code": code})


def kind_info(name: object) -> KindInfo:
    """The kind with this name, or a 400 error."""
    if isinstance(name, str) and name in KINDS:
        return KINDS[name]
    raise error(400, "unknown_kind", "Unknown source type.")


def credentials(idx: LocalIndex):
    """The store of connected accounts of the index, or a 409 error."""
    creds = idx.credentials
    if creds is None:
        raise error(409, "no_credentials", "Connected accounts are not ready on this computer.")
    return creds
