"""Assistant access in the local UI (the part `UIService.agents`; agent grant
v2 and the act queue of the agent gateway). The routes are in
`shell/ui/routers/agents.py`.

- The grants: add (name, places, "runs on this computer only", proposals
  on or off, end date), change, stop (a revoke: the row stays for the log),
  and a key for loopback HTTP that shows one time.
- What each agent read: the `disclosure` rows of each grant, newest first.
- The proposals of the agents (`gateway.acts`): the person approves or
  declines each one here, never in the agent's chat. An approval runs the
  act of its owner layer: a lines proposal becomes the draft of the matching
  lines (the person approves the lines again on the Network matching screen
  before anything is sent).

This part is in the local UI only, behind the guard of the local UI
boundary (`shell/ui/server.py`).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

from anagram.core.timefmt import iso_seconds
from anagram.gateway import access, acts
from anagram.gateway.http import DEFAULT_PORT
from anagram.local.api import readable_spaces
from anagram.network.api import typed_draft
from anagram.shell.cli import mcp as mcp_cli
from anagram.shell.client import lab_context
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.understanding import space_rows

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

READS_SHOWN = 20  # the newest reads of each grant in the view
NOT_IN_LIST = "This assistant is not in your list."
STALE_LINES = ["/api/enclave"]


class AgentsUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    def _today(self) -> date:
        return datetime.fromtimestamp(self.ui.clock(), UTC).date()

    def _now(self) -> str:
        return iso_seconds(self.ui.clock())

    # -------------------------------------------------------------- view

    def _spaces(self, client: Any) -> list[dict]:
        """The readable spaces. `allowed`: a lab space needs the lab to allow
        assistants; `allowed_cloud`: and to allow cloud assistants too."""
        labs = lab_context(client)
        rows = space_rows(client, readable_spaces(labs))
        for row in rows:
            allowed = cloud = True
            if row["id"].startswith("lab:"):
                try:
                    pol = labs.lab_policy(row["id"][4:]) if labs is not None else None
                    allowed = pol is not None and bool(pol.allows_assistant())
                    cloud = pol is not None and bool(pol.allows_cloud_assistant())
                except Exception:  # a lab with no policy allows nothing
                    allowed = cloud = False
            row["allowed"] = allowed
            row["allowed_cloud"] = cloud
        return rows

    @staticmethod
    def _reads(idx: Any) -> dict[str, list[dict]]:
        """What each agent read: grant id -> the newest rows (no source id)."""
        labels = {sid: s.get("label") or "" for sid, s in idx.sources().items()}
        out: dict[str, list[dict]] = {}
        for row in reversed(idx.disclosures()):
            adapter = row["adapter"] or ""
            if not adapter.startswith(access.ADAPTER + ":"):
                continue
            shown = out.setdefault(adapter.split(":", 1)[1], [])
            if len(shown) < READS_SHOWN:
                shown.append(
                    {"at": row["at"], "source": labels.get(row["source_id"]), "what": row["what"]}
                )
        return out

    def _view(self, client: Any, idx: Any) -> dict:
        today = self._today()
        reads = self._reads(idx)
        rows = []
        for g in access.grants(idx):
            row = g.view(today)
            row["used_today"] = access.used_today(idx, g.id, today.isoformat())
            row["reads"] = reads.get(g.id, [])
            if row["state"] != access.REVOKED:
                row["setup"] = json.dumps(mcp_cli.setup_json(self.ui.home, g.id), indent=2)
            rows.append(row)
        return {
            "assistants": [r for r in rows if r["state"] != access.REVOKED],
            "daily_chars": access.DAILY_CHARS,
            "past": [r for r in rows if r["state"] == access.REVOKED],
            "pending": [a.json() for a in acts.pending(idx)],
            "spaces": self._spaces(client),
            "tools": {"acts": list(access.ACT_TOOLS), "read": list(access.READ_TOOLS)},
        }

    def assistant(self) -> dict:
        with self.ui.session(index=True) as (client, idx):
            return self._view(client, idx)

    # ----------------------------------------------------------- changes

    def _chosen(self, client: Any, value: object, recipient_class: str) -> list[str]:
        """The spaces that the person chose: each one readable and allowed
        for an agent of this class."""
        key = "allowed" if recipient_class == access.LOCAL else "allowed_cloud"
        open_ = {r["id"] for r in self._spaces(client) if r[key]}
        if not isinstance(value, list) or not value:
            raise UIError(400, "Choose one place or more.")
        if not all(isinstance(v, str) and v in open_ for v in value):
            raise UIError(400, "Choose a place from the list.")
        return list(value)

    @staticmethod
    def _class(body: dict) -> str:
        value = body.get("recipient_class", access.CLOUD)
        if value not in access.CLASSES:
            raise UIError(400, "Say if the assistant runs on this computer only.")
        return value

    @staticmethod
    def _tools(acts_on: object) -> list[str]:
        if not isinstance(acts_on, bool):
            raise UIError(400, "Bad request.")
        return list(access.READ_TOOLS + (access.ACT_TOOLS if acts_on else ()))

    def _edit(self, change) -> dict:
        with self.ui.session(index=True) as (client, idx):
            try:
                added = change(client, idx)
            except (access.AccessError, acts.ActError) as exc:
                raise UIError(400, str(exc)) from None
            except KeyError:
                raise UIError(404, NOT_IN_LIST) from None
            view = self._view(client, idx)
        self.ui.publish("assistant.changed", {})
        return {**view, "added": added}

    def add_assistant(self, body: dict) -> dict:
        cls = self._class(body)

        def change(client: Any, idx: Any) -> str:
            return access.add(
                idx,
                body.get("name"),
                self._chosen(client, body.get("spaces"), cls),
                self._now(),
                recipient_class=cls,
                tools=self._tools(body.get("acts", False)),
                expires=body.get("expires"),
            ).id

        return self._edit(change)

    def change_assistant(self, grant_id: str, body: dict) -> dict:
        """Change the places, the class, proposals on or off, or the end date
        (each only if it is in `body`)."""
        if not set(body) <= {"spaces", "recipient_class", "acts", "expires"}:
            raise UIError(400, "Bad request.")

        def change(client: Any, idx: Any) -> None:
            grant = access.find(idx, grant_id)
            if grant is None or grant.revoked_at is not None:
                raise KeyError(grant_id)
            cls = self._class(body) if "recipient_class" in body else grant.recipient_class
            kw: dict[str, Any] = {"today": self._today()}
            if "recipient_class" in body:
                kw["recipient_class"] = cls
            if "spaces" in body or "recipient_class" in body:
                kw["spaces"] = self._chosen(client, body.get("spaces", list(grant.spaces)), cls)
            if "acts" in body:
                kw["tools"] = self._tools(body["acts"])
            if "expires" in body:
                kw["expires"] = body["expires"]
            access.change(idx, grant_id, **kw)

        return self._edit(change)

    def remove_assistant(self, grant_id: str) -> dict:
        """Stop access: a revoke. Its proposals that wait are withdrawn."""

        def change(client: Any, idx: Any) -> None:
            now = self._now()
            with idx.store.transaction():
                access.revoke(idx, grant_id, now)
                acts.withdraw_grant(idx, grant_id, now)

        return self._edit(change)

    def http_key(self, grant_id: str) -> dict:
        """A new key for loopback HTTP. It shows one time; an older key of
        this grant stops working."""
        with self.ui.session(index=True) as (_, idx):
            grant = access.find(idx, grant_id)
            if grant is None or grant.state(self._today()) != access.ACTIVE:
                raise UIError(404, NOT_IN_LIST)
            key = access.new_http_key(idx, grant_id)
        self.ui.publish("assistant.changed", {})
        return {
            "command": " ".join(mcp_cli.http_command(self.ui.home, DEFAULT_PORT)),
            "setup": json.dumps(mcp_cli.http_setup_json(DEFAULT_PORT, key), indent=2),
        }

    # --------------------------------------------------------- proposals

    def _apply(self, client: Any, act: acts.Act) -> None:
        """The act of the owner layer, after the person's approval."""
        if act.kind == acts.LINES:
            client.enclave.set_draft(typed_draft(act.payload["offers"], act.payload["wants"]))
            return
        raise acts.ActError("Anagram cannot do this proposal.")

    def decide(self, act_id: str, body: dict) -> dict:
        """`{"action": "approve" | "decline"}`: the person's decision."""
        action = body.get("action")
        if action not in ("approve", "decline"):
            raise UIError(400, "Bad request.")
        with self.ui.session(index=True) as (client, idx):
            try:
                done = acts.decide(
                    idx, act_id, action == "approve", self._now(),
                    lambda act: self._apply(client, act),
                )  # fmt: skip
            except acts.ActError as exc:
                raise UIError(409, str(exc)) from None
            except KeyError:
                raise UIError(404, "This proposal changed. Open the list again.") from None
            view = self._view(client, idx)
        self.ui.publish("assistant.changed", {})
        if done.state == acts.APPROVED and done.kind == acts.LINES:
            self.ui.publish("resource.stale", {"paths": STALE_LINES})
        return {**view, "decided": done.json()}
