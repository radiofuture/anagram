"""The act queue (open-agents plan 2.3, stage 2; primitive `agent-grant`
rule 5): an act tool only puts a proposal here. The person approves or
declines it in the local UI, never in the agent's chat.

The record is the meta key `agent_pending` of the encrypted index store: a
list of entries, newest last. Each entry names the grant, the tool, the
exact payload, and the disclosure that it causes, in words for the person.

- No MCP tool reads or decides an entry. Only the local UI calls `decide`
  (behind the guard of the local UI boundary). So a planted order that an
  agent obeys can make a proposal, but it cannot approve it.
- `decide` calls the `apply` function of the composition root for an
  approval (for example: put the lines into the draft of the matching lines). If `apply`
  fails, the entry stays pending.
- At most `MAX_PENDING` pending entries for each grant. The decided entries
  stay for the log, at most `KEEP_DONE`.
- A revoke of a grant withdraws its pending entries. An approval needs the
  grant to be active at that time.

In v1 an outside agent prepares only: each kind is a draft
that the person approves, and an approved draft does not leave this
computer by itself.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date
from typing import Any

from anagram.gateway.access import ACTIVE, Grant, find

META = "agent_pending"
MAX_PENDING = 20
KEEP_DONE = 50

PENDING = "pending"
APPROVED = "approved"
DECLINED = "declined"
WITHDRAWN = "withdrawn"
STATES = (PENDING, APPROVED, DECLINED, WITHDRAWN)

LINES = "lines"  # lines for the matching draft (owner: network matching)
KINDS = (LINES,)


class ActError(ValueError):
    """One sentence for the person or the agent."""


@dataclass(frozen=True)
class Act:
    id: str
    grant_id: str
    grant_name: str
    tool: str
    kind: str
    payload: dict
    disclosure: str
    created_at: str
    state: str = PENDING
    decided_at: str | None = None
    flags: tuple[str, ...] = ()

    def json(self) -> dict:
        return {
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "disclosure": self.disclosure,
            "flags": list(self.flags),
            "grant_id": self.grant_id,
            "grant_name": self.grant_name,
            "id": self.id,
            "kind": self.kind,
            "payload": self.payload,
            "state": self.state,
            "tool": self.tool,
        }


def _act(row: dict) -> Act:
    return Act(
        id=row["id"],
        grant_id=row["grant_id"],
        grant_name=row["grant_name"],
        tool=row["tool"],
        kind=row["kind"],
        payload=dict(row["payload"]),
        disclosure=row["disclosure"],
        created_at=row["created_at"],
        state=row.get("state", PENDING),
        decided_at=row.get("decided_at"),
        flags=tuple(row.get("flags") or ()),
    )


def _rows(index: Any) -> list[dict]:
    rows = index.store.get_meta(META)
    return rows if isinstance(rows, list) else []


def _save(index: Any, rows: list[dict]) -> None:
    done = [r for r in rows if r.get("state") != PENDING]
    drop = {id(r) for r in done[: max(0, len(done) - KEEP_DONE)]}
    index.store.set_meta(META, [r for r in rows if id(r) not in drop])


def entries(index: Any) -> list[Act]:
    return [_act(r) for r in _rows(index)]


def pending(index: Any) -> list[Act]:
    return [a for a in entries(index) if a.state == PENDING]


def propose(  # noqa: PLR0913
    index: Any,
    grant: Grant,
    *,
    tool: str,
    kind: str,
    payload: dict,
    disclosure: str,
    now: str,
    flags: tuple[str, ...] = (),
) -> Act:
    """Queue one proposal of `grant`. It changes nothing else."""
    if kind not in KINDS:
        raise ActError("Anagram has no act of this kind.")
    with index.store.transaction():
        rows = _rows(index)
        mine = [r for r in rows if r["grant_id"] == grant.id and r.get("state") == PENDING]
        if len(mine) >= MAX_PENDING:
            raise ActError(
                f"This assistant has {MAX_PENDING} proposals that wait for the person."
                " Wait until the person decides."
            )
        act = Act(
            id=secrets.token_hex(8),
            grant_id=grant.id,
            grant_name=grant.name,
            tool=tool,
            kind=kind,
            payload=payload,
            disclosure=disclosure,
            created_at=now,
            flags=flags,
        )
        rows.append(act.json())
        _save(index, rows)
    return act


Apply = Callable[[Act], None]


def decide(index: Any, act_id: str, approve: bool, now: str, apply: Apply) -> Act:
    """The person's decision in the local UI. For an approval, `apply` runs
    first; the entry is approved only if it did not fail. Raises KeyError
    for an entry that is not pending."""
    with index.store.transaction():
        rows = _rows(index)
        pos = next(
            (n for n, r in enumerate(rows) if r["id"] == act_id and r.get("state") == PENDING),
            None,
        )
        if pos is None:
            raise KeyError(act_id)
        act = _act(rows[pos])
        if approve:
            grant = find(index, act.grant_id)
            if grant is None or grant.state(date.fromisoformat(now[:10])) != ACTIVE:
                raise ActError("This assistant has no access now. Decline the proposal.")
            apply(act)
        done = replace(act, state=APPROVED if approve else DECLINED, decided_at=now)
        rows[pos] = done.json()
        _save(index, rows)
    return done


def withdraw_grant(index: Any, grant_id: str, now: str) -> int:
    """Withdraw the pending entries of a grant (at its revoke)."""
    with index.store.transaction():
        rows = _rows(index)
        n = 0
        for r in rows:
            if r["grant_id"] == grant_id and r.get("state") == PENDING:
                r["state"], r["decided_at"] = WITHDRAWN, now
                n += 1
        if n:
            _save(index, rows)
    return n
