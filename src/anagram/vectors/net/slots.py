"""Run the `slot_script` vector on the enclave's own ledger and journal
(spec/enclave-messages.md sections 4.4 and 6.5 to 6.8; W4 findings H-b,
H-c, re-check R1 and R5).

The script names subjects, reply keys and items by labels, so it has no
cryptography; each step calls the real state rules
(`anagram.network.matching.enclave.ledger` and `.journal`):

- a reveal goes into both queues in one state change;
- the batch of day D is made at the cut and is part of the state; the node
  may fetch it only after a cosigned epoch holds it, and it never changes;
- a restart goes back to the latest cosigned epoch;
- one 48 hour rule gives slots for packs, covers and withdrawals; a queued
  item survives a withdrawal;
- a receipt is released only after a cosigned epoch written after its
  request arrived.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from anagram.network.matching.enclave.journal import Journal


def key(name: str) -> str:
    """A subject key for a label (the ledger names subjects by key)."""
    return hashlib.sha256(name.encode()).hexdigest()


@dataclass
class Script:
    journal: Journal = field(default_factory=Journal)
    names: dict[str, str] = field(default_factory=dict)  # key -> label

    def _key(self, name: str) -> str:
        self.names[key(name)] = name
        return key(name)

    def request(self, label: str) -> None:
        self.journal.ledger.add_receipt(label, "", self.journal.counter, label, 0)

    def receipt(self, label: str) -> str:
        found = self.journal.ledger.receipt(label, "", self.journal.cosigned)
        return "filler" if found is None else "receipt"

    def pack(self, subject: str, node: str, reply_key: str, at: int) -> None:
        self.journal.ledger.keep_cover(self._key(subject), node, reply_key, at)

    def cover(self, subject: str, node: str, reply_key: str, at: int) -> None:
        self.journal.ledger.keep_cover(self._key(subject), node, reply_key, at)

    def withdraw(self, subject: str, node: str, reply_key: str, at: int) -> None:
        self.journal.ledger.withdraw(self._key(subject), at, node, reply_key, at)

    def reveal(self, a: str, b: str) -> None:
        items = {self._key(a): {"kind": "reveal", "label": f"reveal of {b}"}}
        items[self._key(b)] = {"kind": "reveal", "label": f"reveal of {a}"}
        self.journal.ledger.queue_together(items, 0)

    def make_batch(self, day: int) -> None:
        slots = self.journal.ledger.take_slots(day)
        if slots is None:
            return
        nodes: dict[str, list] = {}
        for s in slots:
            label = s.item["label"] if s.item else "empty"
            nodes.setdefault(s.node, []).append([self.names[s.subject], s.reply_key, label])
        for entries in nodes.values():
            entries.sort()  # by label, as the script lists them
        self.journal.ledger.store_batch(day, self.journal.counter, nodes)

    def serve(self, day: int, node: str) -> list[list[str]] | str:
        nodes = self.journal.ledger.batch(day, self.journal.cosigned)
        return "not_ready" if nodes is None else nodes.get(node, [])

    def epoch(self) -> int:
        return self.journal.epoch()[0]

    def cosign(self) -> None:
        self.journal.cosign(self.journal.counter - 1)

    def crash(self) -> None:
        self.journal.restart()


def run(steps: list[tuple[str, list]]) -> list[dict]:
    """Run a script of (operation, arguments). Return each step with its result."""
    script = Script()
    return [{"op": op, "args": args, "result": getattr(script, op)(*args)} for op, args in steps]
