"""New members of each node and month, from the enclave log
(spec/network.md 6.7).

A node writes one `member_credential` entry to the public log for each
credential (network.md 6.5). The first credential of a member at the node
(also after a removal) is a **join entry**: its `member` field holds a
commitment to the subject under a random salt; a renewal has `member` null.
So anyone who reads the log can count the new members of each node in a
month, and the enclave refuses a credential whose join entry is over the
monthly limit of the network policy. Renewals are daily and never count.

The month of a join entry is the UTC calendar month of its `expires`: the
log takes a credential entry only while `expires` is in the next 24 hours
(enclave-trust.md 2.3), so a node cannot move a join into another month.
The rank of a join entry is its place, in log order, among the join entries
of its node and month: the log order is public and fixed, so every reader
gets the same rank, and an entry over the limit stays over it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from anagram.core.canonical import JsonObject
from anagram.network.formats.credential import CLOCK_SKEW, MAX_LIFE, member_commit
from anagram.network.formats.strict import Refused, need, parse_time

KIND = "member_credential"
# The log takes a credential entry only while `expires` is at most this far
# after its own time (enclave-trust.md 2.3). So a join entry was appended
# after `expires - EXPIRY_WINDOW`, whatever the node says.
EXPIRY_WINDOW = MAX_LIFE + CLOCK_SKEW
DEFAULT_LIMIT = 200  # spec/network.md 9: `new_members_per_month`


def month_of(unix: int) -> str:
    """`YYYY-MM` of a Unix time, UTC."""
    return datetime.fromtimestamp(unix, UTC).strftime("%Y-%m")


@dataclass(frozen=True)
class Join:
    """One join entry: its node, its subject commitment, its expiry and its
    rank among the joins of the node and month."""

    node: str
    member: str
    expires: int
    rank: int


@dataclass
class Issuance:
    """The join entries of the log by month and node, read once, in log
    order. `update` reads only the entries after the last call."""

    seen: int = 0  # entries read so far
    joins: dict[int, Join] = field(default_factory=dict)  # log index -> join entry
    counts: dict[str, Counter[str]] = field(default_factory=dict)  # month -> node -> joins

    def update(self, entries: Iterable[JsonObject], start: int) -> None:
        """Read `entries`, which are the log entries from index `start`.
        Entries before `self.seen` are skipped, so a caller may pass more."""
        for index, entry in enumerate(entries, start=start):
            if index < self.seen:
                continue
            if index != self.seen:
                raise ValueError("issuance reads the log in order, with no gap")
            self.seen += 1
            if entry.get("kind") != KIND or entry.get("member") is None:
                continue  # another kind, or a renewal
            expires = parse_time(entry["expires"], "expires")
            node = self.counts.setdefault(month_of(expires), Counter())
            node[entry["node_id"]] += 1
            self.joins[index] = Join(
                entry["node_id"], entry["member"], expires, node[entry["node_id"]]
            )

    def appended_after(self, join: Join) -> int:
        """A time before which the log cannot have taken the join entry."""
        return join.expires - EXPIRY_WINDOW

    def join(self, index: int) -> Join | None:
        """The join entry at `index`; None when the entry there is not a
        join entry that was read."""
        return self.joins.get(index)

    def of_month(self, month: str) -> dict[str, int]:
        """`{node id: new members}` for one month, sorted by node ID."""
        return dict(sorted(self.counts.get(month, Counter()).items()))


def check_join(issuance: Issuance, at: int, node: str, subject: str, salt: str, limit: int) -> Join:
    """The join entry that a credential names (network.md 6.7): a join
    entry of the same node that commits to the subject under the salt
    (`bad_credential`), within the node's limit of new members for its
    month (`issuance_limit`)."""
    join = issuance.join(at)
    if join is None:
        raise Refused("bad_credential", "no join entry at the join index")
    need(join.node == node, "bad_credential", "the join entry is of another node")
    need(join.member == member_commit(subject, salt), "bad_credential", "join commitment")
    need(join.rank <= limit, "issuance_limit", "over the node's new members of the month")
    return join


def policy_limit(policy: JsonObject | None) -> int:
    """The monthly limit of new members of a network policy, or the default
    when the roster has no policy yet (network.md 9)."""
    if policy is None:
        return DEFAULT_LIMIT
    return int(policy["new_members_per_month"])
