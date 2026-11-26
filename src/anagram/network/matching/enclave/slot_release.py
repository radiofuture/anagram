"""The single release check of the enclave (spec/matching.md 5;
spec/enclave-messages.md 6.4).

Every slot item passes `check_item` before it is sealed; a reveal also
passes `check_reveal` when it is made. The check does not trust the code
that made the candidate. It permits only:

- public values and decision enums (`kind`, `type`, `protocol`,
  `checkpoints`, `expires`, `known`), and random proposal IDs of the
  recipient's own copies;
- copies from the recipient's own pack (the `reasons` of a proposal: line
  IDs of the pack that the decision used);
- in a reveal, after two yes answers: the peer's reveal card exactly as the
  peer sent it, the peer's subject key, and the peer's node record exactly
  as the roster has it.

No score, rank, count, affiliation, known mark or peer text is in a
proposal (E1 option a).
"""

from __future__ import annotations

from anagram.core.canonical import JsonObject
from anagram.network.formats.enclave import check_item as check_form
from anagram.network.formats.strict import DAY, Refused, fmt_time
from anagram.network.matching.enclave.ledger import Ledger


class ReleaseDenied(Refused):
    """The release check blocked an output. Nothing is sent."""

    def __init__(self, detail: str) -> None:
        super().__init__("release_denied", detail)


def _deny(cond: bool, why: str) -> None:
    if not cond:
        raise ReleaseDenied(why)


def check_item(ledger: Ledger, recipient: str, item: JsonObject) -> JsonObject:
    """Check one item for one recipient. Return it, or raise ReleaseDenied."""
    try:
        check_form(item)
    except Refused as exc:
        raise ReleaseDenied(f"item form: {exc}") from exc
    if item["kind"] == "proposal":
        _check_proposal(ledger, recipient, item)
    elif item["kind"] == "ended":
        c = ledger.proposals.get(item["proposal"])
        _deny(c is None or c.subject == recipient, "an ended item names another's copy")
    return item


def _check_proposal(ledger: Ledger, recipient: str, item: JsonObject) -> None:
    c = ledger.proposals.get(item["id"])
    if c is None or c.subject != recipient:
        raise ReleaseDenied("not the recipient's copy")
    if c.day is None or c.expires is None or item["expires"] != fmt_time(c.expires):
        raise ReleaseDenied("expiry")  # a delivered copy has both (`Ledger._deliver`)
    plan = [fmt_time(d * DAY) for d in ledger.pairs[c.pair].checkpoints]
    _deny(item["checkpoints"] == plan, "checkpoints are not the pair's")
    _deny(item["type"] == c.type and item["pack_version"] == c.pack_version, "type or version")
    _deny(item["reasons"] == c.reasons, "reasons are not the decision's")
    pack = ledger.subjects[recipient].pack
    if pack is not None and pack["version"] == c.pack_version:
        own = {line["id"] for side in ("offers", "wants") for line in pack["lines"][side]}
        _deny(set(c.reasons) <= own, "a reason is not a line of the recipient's pack")


def check_reveal(
    ledger: Ledger, pair_id: str, recipient: str, item: JsonObject, roster_node: JsonObject
) -> JsonObject:
    """A reveal for `recipient` in pair `pair_id`, made from the peer's yes."""
    check_item(ledger, recipient, item)
    _deny(item["kind"] == "reveal", "not a reveal")
    pair = ledger.pairs[pair_id]
    _deny(recipient in pair.copies and pair.state == "open", "not an open pair of the recipient")
    peer = pair.b if recipient == pair.a else pair.a
    mine, theirs = ledger.copy_of(pair_id, recipient), ledger.copy_of(pair_id, peer)
    _deny(mine.answer == theirs.answer == "yes", "two yes answers")
    _deny(item["proposal"] == pair.copies[recipient], "the recipient's own proposal ID")
    _deny(item["peer"] == peer and item["type"] == pair.type, "peer or type")
    _deny(item["card"] == theirs.card, "the card is the peer's card")
    want = {k: roster_node[k] for k in ("affiliation", "id", "ror")}
    _deny(item["node"] == want, "the node is the roster's record")
    return item
