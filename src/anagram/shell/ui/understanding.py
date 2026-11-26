"""Items and suggestions in the local UI (layer L2; the
part `UIService.understanding`). The routes are in
`shell/ui/routers/understanding.py`.

- Items and suggestions: the kinds and the items of a space, one
  item with its claims, names, links, and versions, the kind correction of
  the person, and the proposed findings with their state.
- Assistant access is the part `UIService.agents` (`agents.py`).

The other parts of understanding are `UIService.models` (`models.py`)
and `UIService.ask` (`ask.py`: search, ask, timeline).

Rules:

- Each method uses `UIService.session`, so the person must be joined.
- An item has the space of its source (`spaces.space_of`). A route gives
  only items of the asked scope, and the scope is always inside
  `spaces.readable_spaces`. An item outside the scope is "not found".
- No method here calls a model. A kind correction publishes `item.kind`; a
  proposal change publishes `suggestion.new` or `suggestion.changed`.
"""

from __future__ import annotations

import base64
import json
from collections import Counter
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from anagram.local.api import (
    BUILDS_ON,
    KIND_IDS,
    KINDS,
    PRIVATE,
    RELATED,
    SUPPORTS,
    FindingDraft,
    ScopeError,
    check_scope,
    ensure_understanding_schema,
    humanize_title,
    kind_name,
    kinds_of,
    loads,
    placeholders,
    proposals,
    readable_spaces,
    set_kind_override,
    space_of,
)
from anagram.shell.client import lab_context
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

Publish = Callable[[str, dict], Any]
ALL = "all"  # the `space` value for each readable space
LIMIT = 50
MAX_LIMIT = 200
MAX_QUERY = 200
NOT_FOUND_ITEM = "This item is not in your library."
NOT_FOUND_SUGGESTION = "This suggestion changed. Open the list again."
# The direction of a link, as the other item sees it.
REVERSE = {RELATED: "related", SUPPORTS: "supported_by", BUILDS_ON: "built_on_by"}
LINK_KINDS = (RELATED, SUPPORTS, BUILDS_ON)
SUGGESTION_ACTIONS = ("later", "dismiss")


def _item_id(ref: str) -> int:
    """`item:<id>` -> id. Another form is "not found", not a fault."""
    head, _, tail = ref.partition(":")
    if head != "item" or not tail.isdigit() or len(tail) > 18:
        raise UIError(404, NOT_FOUND_ITEM)
    return int(tail)


def _cursor(row: dict) -> str:
    raw = json.dumps([row["time"] or "", row["id"]]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _after(cursor: str) -> tuple[str, int]:
    try:
        time_, iid = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if not isinstance(time_, str) or not isinstance(iid, int):
            raise ValueError
    except (ValueError, TypeError):
        raise UIError(400, "Open the list again.") from None
    return time_, iid


def space_rows(client: Any, scope: frozenset[str]) -> list[dict]:
    """The readable spaces with a name for people (`label`; None for the
    private space). The screen shows the label, never the lab id."""
    names: dict[str, str] = {}
    labs = lab_context(client)
    if labs is not None:
        for lab in labs.lab_list():
            if isinstance(lab, dict) and lab.get("lab_id"):
                names[f"lab:{lab['lab_id']}"] = lab.get("name") or ""
    rows = [{"id": PRIVATE, "label": None}]
    rows += [{"id": s, "label": names.get(s) or None} for s in sorted(scope - {PRIVATE})]
    return rows


class UnderstandingUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    # ------------------------------------------------ items and suggestions

    def _deferred(self) -> tuple[list[tuple[str, dict]], Publish]:
        """Events are sent after the session ends, as the model routes do."""
        events: list[tuple[str, dict]] = []
        return events, lambda t, d: events.append((t, d))

    def _send(self, events: list[tuple[str, dict]]) -> None:
        for t, d in events:
            self.ui.publish(t, d)

    def scope(self, client: Any, space: object) -> frozenset[str]:
        """`all` (or no value): each readable space. Else one space, which
        must be readable on this computer."""
        if space is None or space in ("", ALL):
            return readable_spaces(lab_context(client))
        if not isinstance(space, str):
            raise UIError(400, "This space is not on this computer.")
        try:
            return check_scope([space], lab_context(client))
        except ScopeError:
            raise UIError(400, "This space is not on this computer.") from None

    @staticmethod
    def _summaries(idx: Any, vids: list[int]) -> dict[int, str]:
        """The summary of each version: the model summary, else the summary
        of the chips pass."""
        best: dict[int, tuple[int, str]] = {}
        for start in range(0, len(vids), 500):
            part = vids[start : start + 500]
            for r in idx.store.q(
                "SELECT version_id, value, enricher FROM fact WHERE kind = 'summary'"  # noqa: S608
                f" AND version_id IN ({placeholders(len(part))})",
                part,
            ):
                rank = 0 if r["enricher"] == "understand" else 1
                if r["value"] and (r[0] not in best or rank < best[r[0]][0]):
                    best[r[0]] = (rank, r["value"])
        return {vid: text for vid, (_, text) in best.items()}

    def rows(self, idx: Any, scope: frozenset[str], ids: list[int] | None = None) -> list[dict]:
        """The present items in `scope` (all, or the items of `ids`), each
        with its kind, title, space, and summary. The keys `id` and `vid` are
        for this module; `_public` removes them."""
        ensure_understanding_schema(idx.store)
        sources = idx.sources()  # no source that is being removed
        space = {sid: space_of(idx, sid) for sid in sources}
        sql = (
            "SELECT i.id, i.source_id, i.name, i.time, (SELECT id FROM version"
            " WHERE item_id = i.id ORDER BY n DESC LIMIT 1) AS vid FROM item i WHERE i.present = 1"
        )
        args: list = []
        if ids is not None:
            if not ids:
                return []
            sql += f" AND i.id IN ({placeholders(len(ids))})"
            args = list(ids)
        rows = [
            r
            for r in idx.store.q(sql, args)
            if r["vid"] is not None and space.get(r["source_id"]) in scope
        ]
        vids = [r["vid"] for r in rows]
        got = kinds_of(idx, vids)
        summary = self._summaries(idx, vids)
        out = []
        for r in rows:
            k = got[r["vid"]]
            out.append(
                {
                    "by": k.by,
                    "confidence": round(k.confidence, 2),
                    "id": r["id"],
                    "kind": k.kind,
                    "polarity": k.polarity,
                    "ref": f"item:{r['id']}",
                    "source_label": sources[r["source_id"]]["label"],
                    "space": space[r["source_id"]],
                    "summary": summary.get(r["vid"]),
                    "time": r["time"],
                    "title": k.title or humanize_title(r["name"]) or "Untitled",
                    "vid": r["vid"],
                }
            )
        return out

    @staticmethod
    def _public(row: dict) -> dict:
        return {k: v for k, v in row.items() if k not in ("id", "vid")}

    def kind_counts(self, space: object = None) -> list[dict]:
        """Each kind of the taxonomy, in its order, with the count of items
        in the scope. The screen shows the kinds with items in the filter and
        all kinds in the correction list."""
        with self.ui.session(index=True) as (client, idx):
            rows = self.rows(idx, self.scope(client, space))
        count = Counter(r["kind"] for r in rows)
        return [{"count": count[k], "id": k, "label": kind_name(k)} for k in KIND_IDS]

    def items(
        self,
        space: object = None,
        kind: object = None,
        q: object = None,
        cursor: object = None,
        limit: object = None,
    ) -> dict:
        """The items of the scope, newest first, in pages of `limit`."""
        if kind not in (None, "") and kind not in KINDS:
            raise UIError(400, "Choose a kind from the list.")
        words = str(q or "").strip().lower()
        if len(words) > MAX_QUERY:
            raise UIError(400, f"Type at most {MAX_QUERY} characters.")
        try:
            size = LIMIT if limit in (None, "") else int(str(limit))
        except ValueError:
            size = 0
        if not 1 <= size <= MAX_LIMIT:
            raise UIError(400, f"Ask for 1 to {MAX_LIMIT} items.")
        after = _after(str(cursor)) if cursor not in (None, "") else None
        with self.ui.session(index=True) as (client, idx):
            rows = self.rows(idx, self.scope(client, space))
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        if words:
            rows = [
                r
                for r in rows
                if words in " ".join((r["title"], r["summary"] or "", r["source_label"])).lower()
            ]
        rows.sort(key=lambda r: (r["time"] or "", r["id"]), reverse=True)
        if after is not None:
            rows = [r for r in rows if (r["time"] or "", r["id"]) < after]
        page = rows[:size]
        return {
            "items": [self._public(r) for r in page],
            "next": _cursor(page[-1]) if len(rows) > size else None,
        }

    def _item(self, idx: Any, scope: frozenset[str], iid: int) -> dict:
        rows = self.rows(idx, scope, [iid])
        if not rows:
            raise UIError(404, NOT_FOUND_ITEM)
        row = rows[0]
        claims, entities, people = [], [], []
        for r in idx.store.q(
            "SELECT kind, value, data FROM fact WHERE version_id = ?"
            " AND kind IN ('claim', 'entity', 'person') ORDER BY score DESC, id",
            (row["vid"],),
        ):
            data = loads(r["data"]) or {}
            if r["kind"] == "claim":
                claims.append({"status": data.get("status"), "text": r["value"]})
            elif r["kind"] == "entity":
                entities.append({"text": r["value"], "type": data.get("type")})
            else:
                people.append({"name": r["value"], "role": data.get("role")})
        ref = row["ref"]
        found: dict[tuple[str, int], None] = {}
        for r in idx.store.q(
            f"SELECT kind, src, dst FROM relation WHERE kind IN ({placeholders(len(LINK_KINDS))})"  # noqa: S608
            " AND (src = ? OR dst = ?) ORDER BY id",
            (*LINK_KINDS, ref, ref),
        ):
            other = r["dst"] if r["src"] == ref else r["src"]
            if other == ref or not other.startswith("item:") or not other[5:].isdigit():
                continue
            relation = r["kind"] if r["src"] == ref else REVERSE[r["kind"]]
            found.setdefault((relation, int(other[5:])), None)
        others = {o["id"]: o for o in self.rows(idx, scope, sorted({i for _, i in found}))}
        link_rows = [
            {
                "kind": others[i]["kind"],
                "ref": others[i]["ref"],
                "relation": rel,
                "title": others[i]["title"],
            }
            for (rel, i) in found
            if i in others  # an item of a space outside the scope is left out
        ]
        versions = [
            {"at": r["created_at"], "n": r["n"]}
            for r in idx.store.q(
                "SELECT n, created_at FROM version WHERE item_id = ? ORDER BY n", (iid,)
            )
        ]
        return {
            **self._public(row),
            "claims": claims,
            "entities": entities,
            "links": link_rows,
            "people": people,
            "versions": versions,
        }

    def item(self, ref: str) -> dict:
        iid = _item_id(ref)
        with self.ui.session(index=True) as (client, idx):
            return self._item(idx, self.scope(client, ALL), iid)

    def set_kind(self, ref: str, kind: object) -> dict:
        """The person's correction. It stays for each later version of the
        item and wins over the kind of the model, the lab, and the rules."""
        iid = _item_id(ref)
        if kind not in KINDS:
            raise UIError(400, "Choose a kind from the list.")
        events, publish = self._deferred()
        with self.ui.session(index=True) as (client, idx):
            scope = self.scope(client, ALL)
            if not self.rows(idx, scope, [iid]):
                raise UIError(404, NOT_FOUND_ITEM)
            set_kind_override(idx, iid, kind, publish=publish)  # type: ignore[arg-type]
            out = self._item(idx, scope, iid)
        self._send(events)
        return out

    def _drafts(self, idx: Any, publish: Publish) -> list[FindingDraft]:
        """The proposals of the person's own work. The finding route
        (`LibraryUI.timestamp`) marks a proposal `stamped`. The old
        `used_drafts` list of the UI state is copied one time
        (`proposals.import_used`), for drafts stamped before that."""
        if not self.ui.state.get("used_drafts_imported"):
            used = [str(d) for d in self.ui.state.get("used_drafts") or []]
            known = proposals.states(idx)
            new = [d for d in dict.fromkeys(used) if known.get(d) != "stamped"]
            proposals.import_used(idx, new)
            for d in new:
                if d in known:  # the screen can show it now
                    publish("suggestion.changed", {"id": d, "state": "stamped", "title": None})
            self.ui.state.update(used_drafts_imported=True)
        return proposals.propose_findings(idx, publish=publish)

    def _suggestions(self, drafts: list[FindingDraft]) -> list[dict]:
        out = [
            {**self.ui.library.draft_json(d), "reason": d.reason, "state": d.state} for d in drafts
        ]
        out.sort(key=lambda d: d["state"] == "later")  # stable: "new" first
        return out

    def suggestions(self) -> list[dict]:
        events, publish = self._deferred()
        with self.ui.session(index=True) as (_, idx):
            out = self._suggestions(self._drafts(idx, publish))
        self._send(events)
        return out

    def act_on_suggestion(self, draft_id: str, action: object) -> list[dict]:
        """`later` puts the proposal at the end of the list. `dismiss` ("Not
        a finding") removes it, and its seeds get the kind `note` from the
        person. Nothing here stamps a finding."""
        if action not in SUGGESTION_ACTIONS:
            raise UIError(400, "Choose Later or Not a finding.")
        events, publish = self._deferred()
        with self.ui.session(index=True) as (_, idx):
            draft = next((d for d in self._drafts(idx, publish) if d.id == draft_id), None)
            if draft is None:
                raise UIError(404, NOT_FOUND_SUGGESTION)
            if action == "dismiss":
                proposals.dismiss(idx, draft, publish=publish)
            else:
                proposals.set_state(idx, draft.id, "later", title=draft.title, publish=publish)
            out = self._suggestions(self._drafts(idx, publish))
        self._send(events)
        return out
