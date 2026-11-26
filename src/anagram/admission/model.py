"""One internal model for each way into a community (design note:
docs/design/endorsement-chain.md).

An endorser vouches (an `Endorsement`), a claimer claims with the secret of
the link (a `Claim`), and a policy decides. The node invite, the lab invite,
and the reader invite are three forms of this model. Their signed formats do
not change (`anagram.admission.formats`); each service makes an
`Endorsement` from its own records and asks the policy.

The policy is per node (`NodePolicy`). A group can narrow it with its own
rules (`narrow`), but it cannot open what the node policy closes. Today there
is one policy function, `invite_only`. A later policy (open
entry, two vouches) is a new function with the same signature.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from anagram.core.timefmt import parse_time

NODE, GROUP, READER = "node", "group", "reader"  # the kinds of endorsement

# The reasons of a refusal, in the order that the policy checks them.
REVOKED, USED, EXPIRED, ENDORSER, CONTACT = "revoked", "used", "expired", "endorser", "contact"


@dataclass(frozen=True)
class Endorsement:
    """An endorser vouches for the person who holds the secret of a link.

    `ref` is the public ID of the invite. `endorser` is a person ID, or None
    for the node operator. `role` is the role that a claim gives. `contact`
    (a reader invite): the (kind, value) that the claimer must prove."""

    kind: str
    ref: str
    endorser: str | None
    role: str
    max_uses: int
    uses: int
    expires_at: datetime
    revoked: bool = False
    contact: tuple[str, str] | None = None


@dataclass(frozen=True)
class Claim:
    """A person claims an endorsement at `at`. `proved_contact`: the claimer
    proved the contact of the endorsement (a reader invite)."""

    at: datetime
    claimer: str | None = None
    proved_contact: bool = False


# A policy function: None to admit, else the reason of the refusal.
Policy = Callable[[Endorsement, Claim], str | None]


def invite_only(e: Endorsement, c: Claim) -> str | None:
    """The admission policy of today: the claimer holds the
    secret of an endorsement that is not revoked, not used up, not expired,
    and (for a reader invite) the claimer proved its contact."""
    if e.revoked:
        return REVOKED
    if e.uses >= e.max_uses:
        return USED
    if c.at > e.expires_at:
        return EXPIRED
    if e.contact is not None and not c.proved_contact:
        return CONTACT
    return None


def endorser_may(allowed: bool) -> Policy:
    """A group rule: the endorser can still invite in the group (for a lab:
    the creator of the invite is still a PI, or an admin for a member invite)."""
    return lambda e, c: None if allowed else ENDORSER


@dataclass(frozen=True)
class Vouch:
    """Who vouched for a member: `via` is the kind of endorsement, `by` the
    endorser (None: the node operator)."""

    via: str
    by: str | None

    def view(self) -> dict:
        return {"by": self.by, "via": self.via}


GROUP_CREATE = ("member", "organizer_invite")


@dataclass(frozen=True)
class NodePolicy:
    """The admission policy of one node. `admit` is the policy function.
    `create_group`: who can start a group (`member`: each member;
    `organizer_invite`: an organizer, or a member who came in with a node
    invite)."""

    admit: Policy = invite_only
    create_group: str = "organizer_invite"

    def __post_init__(self) -> None:
        if self.create_group not in GROUP_CREATE:
            raise ValueError(f"lab create policy must be one of {GROUP_CREATE}")

    def decide(self, e: Endorsement, c: Claim, narrow: Iterable[Policy] = ()) -> str | None:
        """The node policy, then each rule of the group. A group rule can
        only add a refusal."""
        reason = self.admit(e, c)
        for rule in narrow:
            if reason is not None:
                break
            reason = rule(e, c)
        return reason

    def may_create_group(self, organizer: bool, vouch: Vouch | None) -> bool:
        if self.create_group == "member" or organizer:
            return True
        return vouch is not None and vouch.via == NODE


def group_endorsement(invite: dict) -> Endorsement:
    """The endorsement of a lab invite, from its record in the roster state
    (`{"auth", "uses", "revoked", ...}`)."""
    auth = invite["auth"]
    return Endorsement(
        kind=GROUP,
        ref=auth["invite_pub"],
        endorser=auth["created_by"],
        role=auth["role"],
        max_uses=auth["max_uses"],
        uses=invite["uses"],
        expires_at=parse_time(auth["expires_at"]),
        revoked=invite["revoked"],
    )
