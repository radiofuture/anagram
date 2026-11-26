"""The source settings of a lab in the local UI (the part
`UIService.lab_sources`). The routes are in `shell/ui/routers/sources.py`.

The two sections of the lab settings record that the source
code owns: `oauth_clients` and `sources`. A PI or admin changes them; each member
reads them. A client secret never comes back to the page: `has_secret` says
that one is set.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError
from anagram.local.api import (
    PRIVATE,
    kind_label,
)
from anagram.network.api import (
    ADMIN,
    OAUTH_PROVIDERS,
    PI,
    LabError,
)
from anagram.shell.ui.source_kinds import KINDS, LAB, PROVIDER_NAMES, error

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

# The form of a client ID of each provider (lab settings). A wrong
# paste (the secret, or the project number) gets a sentence that says what
# the ID looks like.
CLIENT_ID = {
    "google": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,200}\.apps\.googleusercontent\.com$"),
    "notion": re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$"),
}
CLIENT_ID_TEXT = {
    "google": "This is not a Google client ID. It ends with .apps.googleusercontent.com.",
    "notion": "This is not a Notion client ID. Copy the OAuth client ID of the integration.",
}


class LabSourcesUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def _lab_rows(self, c) -> list[dict]:
        try:
            labs = c.labs.lab_list()
        except ClientError:
            return []
        out = []
        for lab in labs:
            try:
                sections = c.lab_space.lab_settings(lab["lab_id"])["sections"]
            except ClientError:
                continue
            clients = sections.get("oauth_clients") or {}
            src = sections.get("sources") or {}
            out.append(
                {
                    "can_edit": lab.get("role") in (PI, ADMIN),
                    "clients": {
                        p: (
                            {
                                "client_id": clients[p]["client_id"],
                                "has_secret": bool(clients[p].get("client_secret")),
                            }
                            if p in clients
                            else None
                        )
                        for p in OAUTH_PROVIDERS
                    },
                    "id": lab["lab_id"],
                    "name": lab.get("name") or "Lab",
                    "sources": {
                        "allowed_kinds": src.get("allowed_kinds"),
                        "lab_default": src.get("lab_default", PRIVATE),
                    },
                }
            )
        return out

    def lab_source_settings(self) -> dict:
        """`{"labs": [...], "kinds": [{"kind", "label"}]}`: for each lab of
        the person, its OAuth clients and its rules for sources. `kinds` are
        the kinds that a lab can permit in the lab space."""
        with self.ui.session() as c:
            labs = self._lab_rows(c)
        kinds = [
            {"kind": k.kind, "label": kind_label(k.kind)} for k in KINDS.values() if LAB in k.spaces
        ]
        return {"kinds": kinds, "labs": labs}

    def _change_lab(self, lab_id: str, section: str, change: Callable[[dict], dict]) -> dict:
        """Read one section, change it, and write it (PI or admin). Give the
        row of the lab."""
        if not isinstance(lab_id, str) or not lab_id:
            raise error(404, "no_lab", "This lab is not there.")
        with self.ui.session() as c:
            try:
                old = c.lab_space.lab_settings(lab_id)["sections"][section]
                c.lab_space.lab_set_settings(lab_id, {section: change(dict(old))})
            except LabError as exc:
                raise error(403, "lab_refused", str(exc)) from None
            except ClientError:
                raise error(
                    502, "node", "Anagram could not save this on the node. Try again."
                ) from None
            rows = {r["id"]: r for r in self._lab_rows(c)}
        if lab_id not in rows:
            raise error(404, "no_lab", "This lab is not there.")
        return rows[lab_id]

    def set_lab_client(self, lab_id: str, provider: str, body: dict) -> dict:
        """Set the OAuth client of one provider for a lab:
        `{"client_id", "client_secret"?}`. With no secret, a secret that is
        set for the same client ID stays."""
        if provider not in OAUTH_PROVIDERS:
            raise error(404, "no_provider", "Anagram has no client for this service.")
        name = PROVIDER_NAMES[provider]
        cid = body.get("client_id") if isinstance(body, dict) else None
        cid = cid.strip() if isinstance(cid, str) else ""
        if not CLIENT_ID[provider].match(cid):
            raise error(400, "bad_client_id", CLIENT_ID_TEXT[provider].format(provider=name))
        secret = body.get("client_secret")
        secret = secret.strip() if isinstance(secret, str) else ""
        if secret and (len(secret) > 500 or any(ch.isspace() for ch in secret)):
            raise error(400, "bad_secret", "This client secret is not valid. Copy it again.")

        def change(section: dict) -> dict:
            old = section.get(provider) or {}
            keep = old.get("client_secret") if old.get("client_id") == cid else None
            value = secret or keep
            if not value:
                raise error(400, "no_secret", f"Paste the client secret of the {name} client.")
            section[provider] = {"client_id": cid, "client_secret": value}
            return section

        return self._change_lab(lab_id, "oauth_clients", change)

    def remove_lab_client(self, lab_id: str, provider: str) -> dict:
        if provider not in OAUTH_PROVIDERS:
            raise error(404, "no_provider", "Anagram has no client for this service.")

        def change(section: dict) -> dict:
            section.pop(provider, None)
            return section

        return self._change_lab(lab_id, "oauth_clients", change)

    def set_lab_sources(self, lab_id: str, body: dict) -> dict:
        """`{"allowed_kinds": [<kind>] | null, "lab_default": "private" | "lab"}`.
        `null` permits each kind in the lab space."""
        if not isinstance(body, dict):
            raise error(400, "bad_value", "Choose the sources that the lab space permits.")
        lab_kinds = {k.kind for k in KINDS.values() if LAB in k.spaces}
        change_to: dict = {}
        if "allowed_kinds" in body:
            allowed = body["allowed_kinds"]
            if allowed is not None and (
                not isinstance(allowed, list) or not set(allowed) <= lab_kinds
            ):
                raise error(400, "bad_value", "Choose the sources that the lab space permits.")
            change_to["allowed_kinds"] = None if allowed is None else sorted(set(allowed))
        if "lab_default" in body:
            if body["lab_default"] not in (PRIVATE, LAB):
                raise error(400, "bad_value", "Choose Only you or the lab space.")
            change_to["lab_default"] = body["lab_default"]
        if not change_to:
            raise error(400, "bad_value", "Choose the sources that the lab space permits.")
        return self._change_lab(lab_id, "sources", lambda section: {**section, **change_to})
