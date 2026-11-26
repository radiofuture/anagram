"""Ports of identity (layers plan, section 4): who may become a node member.
L4 (`anagram.admission`) gives the `RegistrationGate`; the identity service
makes a member only from an `Admission` of the gate, and does not import L4."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Admission:
    """The decision of the registration gate: `subject` becomes a node member.
    `ref` is the vouch reference that the member row keeps (a node invite ID,
    `lab:<invite id>`, or `reader:<invite id>`). `role` is `member` or
    `organizer`. `limit`: at most this many members can come in with `ref`."""

    subject: str
    ref: str
    role: str = "member"
    limit: int | None = None


class RegistrationGate(Protocol):
    """Who may register (L1 does not know what an invite is). `admit` checks a
    ticket (the secret of an invite link) for `subject` under the admission
    policy of the node, and gives the `Admission`, or raises a node error."""

    def admit(self, subject: str, ticket: str) -> Admission: ...
