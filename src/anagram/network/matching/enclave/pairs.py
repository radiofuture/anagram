"""The matching part of an enclave instance: live packs, the sweep, the
reveal and the day batch (plan net 14b; spec/enclave-messages.md 6;
spec/enclave-trust.md 7.1).

`Matching` reads and changes only the ledger that it is given and the
network (roster and node chains) of its instance. Every item that leaves
passes the release check (`release.py`) first.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass

from anagram.core.canonical import JsonObject
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats import credential as cred
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import Network
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.funnel import PackMatch, Party, eligible
from anagram.network.matching.enclave.ledger import Ledger
from anagram.network.matching.enclave.slot_release import ReleaseDenied, check_item, check_reveal


@dataclass
class Matching:
    net: Network  # the instance's network; the instance applies new events to it
    match: PackMatch
    new_id: Callable[[], str]  # random proposal IDs
    count: Callable[[str], None]  # counts an event of the instance (`release_denied`)
    removals_at: int = -1  # control events applied at the last removal pass (7.1)

    # ---- live packs ---------------------------------------------------------

    def party(self, ledger: Ledger, subject: str, now: int) -> Party | None:
        """A live pack: its credential is valid now and usable in the
        network (a dormant pack is not used, spec/pack.md 5)."""
        s = ledger.subjects.get(subject)
        if s is None or s.pack is None or s.facts is None or s.facts["expires"] <= now:
            return None
        node = self.net.nodes.get(s.facts["node"])
        if node is None or not self._usable(subject, s.facts):
            return None
        return Party(subject, s.facts["pid"], node, s.pack)

    def _member(self, subject: str, facts: JsonObject) -> cred.MemberFacts:
        return cred.MemberFacts(
            network=self.net.network,
            node=facts["node"],
            subject=subject,
            kind=str(facts.get("kind", "person")),
            issued=facts["issued"],
            expires=facts["expires"],
            control_head=facts["control_head"],
            pid=facts["pid"],
        )

    @staticmethod
    def _token(facts: JsonObject) -> bytes:
        return cred.unb64url(facts["token"])

    def _usable(self, subject: str, facts: JsonObject) -> bool:
        try:
            self.net.credential_usable(self._member(subject, facts), self._token(facts))
        except Refused:
            return False
        return True

    def erase_removed(self, ledger: Ledger, now: int) -> None:
        """A control event that removes a member (`member_removed`,
        `member_left` other than `moved`, `credential_revoked`,
        `node_removed`, `ban`) erases the subject at once, with a tombstone
        (enclave-trust.md 7.1; network.md 8.4, 8.5). The pass runs when
        new events were applied, and again after a restart, because the
        restored epoch may be older than the erasure (`removals_at` = -1)."""
        applied = sum(c.count for c in self.net.chains.values())
        if applied == self.removals_at:
            return
        for subject, s in sorted(ledger.subjects.items()):
            facts = s.facts
            if facts is not None and self.net.removes(
                self._member(subject, facts), self._token(facts)
            ):
                ledger.erase(subject, s.version, now, "removed")
        self.removals_at = applied

    # ---- the sweep and the reveal --------------------------------------------

    def sweep(self, ledger: Ledger, now: int) -> None:
        parties = {s: p for s in ledger.subjects if (p := self.party(ledger, s, now)) is not None}
        result = self.match.sweep(ledger, parties, now)
        for prop in result.proposals:
            ledger.propose(
                prop.a,
                prop.b,
                prop.kind,
                prop.reasons,
                now,
                self.new_id,
                nodes=prop.nodes,
                answer_day=self.match.rules.answer_day,
            )
        ledger.count("sweeps")
        ledger.count("judge_disagreements", result.disagreements)
        ledger.count("decision_rows", len(result.decisions.rows))

    def try_reveal(self, ledger: Ledger, pair_id: str, now: int) -> None:
        """Both said yes: check the credentials, deny and block again on the
        current packs (14b step 9). Wait while a credential is only expired;
        end the pair on any other failed check (6.6)."""
        pair = ledger.pairs[pair_id]
        records = [f for s in (pair.a, pair.b) if (f := ledger.subjects[s].facts) is not None]
        if len(records) < 2:
            ledger.end_pair(pair_id)
            return
        if any(r["expires"] <= now for r in records):
            return
        a, z = self.party(ledger, pair.a, now), self.party(ledger, pair.b, now)
        if a is None or z is None or not eligible(a, z):
            ledger.end_pair(pair_id)
            return
        try:
            items = {
                me.subject: check_reveal(
                    ledger, pair_id, me.subject, _reveal_item(ledger, pair_id, me, peer), peer.node
                )
                for me, peer in ((a, z), (z, a))
            }
        except ReleaseDenied:
            self.count("release_denied")
            ledger.end_pair(pair_id)
            return
        ledger.reveal(pair_id, items, now)

    # ---- the day batch -------------------------------------------------------

    def make_batch(self, ledger: Ledger, day: int, counter: int, output: SigningKey) -> None:
        """Seal the day's slots after the release check of each item. An
        item that fails the check goes out as `empty` and is counted.
        `counter` is the epoch that will hold the batch."""
        slots = ledger.take_slots(day)
        if slots is None:
            return
        nodes: dict[str, dict[str, str]] = {}
        for s in slots:
            item = {"kind": "empty"}
            if s.item is not None:
                try:
                    item = check_item(ledger, s.subject, s.item)
                except ReleaseDenied:
                    self.count("release_denied")
            reply = bytes.fromhex(s.reply_key)
            sealed = m.seal_slot(reply, day, m.slot_doc(day, item, output))
            address = m.slot_address(day, reply).hex()
            nodes.setdefault(s.node, {})[address] = base64.b64encode(sealed).decode("ascii")
        entries = {n: [[a, v[a]] for a in sorted(v)] for n, v in nodes.items()}
        ledger.store_batch(day, counter, entries)


def _reveal_item(ledger: Ledger, pair_id: str, me: Party, peer: Party) -> JsonObject:
    """The reveal for `me`: the peer's card, subject and roster record,
    and whether my known object names the peer (spec/pack.md 9.2)."""
    known = ledger.subjects[me.subject].known
    tags = {packs.known_tag(packs.person_id(peer.subject)).hex()}
    if peer.pid:
        tags.add(packs.known_tag(peer.pid).hex())
    facts = ledger.subjects[peer.subject].facts
    if facts is None:  # a `Party` has facts (`party`); this narrows the type
        raise ReleaseDenied("the peer has no credential")
    tags.update(facts["email_tags"])
    return {
        "card": ledger.copy_of(pair_id, peer.subject).card,
        "kind": "reveal",
        "known": bool(known and tags & set(known["tags"])),
        "node": {k: peer.node[k] for k in ("affiliation", "id", "ror")},
        "peer": peer.subject,
        "proposal": ledger.pairs[pair_id].copies[me.subject],
        "type": ledger.pairs[pair_id].type,
    }
