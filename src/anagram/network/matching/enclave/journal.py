"""State epochs and commit before output (spec/enclave-trust.md 6.2, 6.3).

The writer keeps the ledger in memory and writes one whole snapshot at each
10-minute epoch. Nothing that leaves the enclave (a receipt, a day batch)
is released before a cosigned checkpoint holds an epoch that holds it. A
restart goes back to the latest cosigned epoch, so "both or neither" holds
across a crash: either both reveal items are in that epoch, or neither is
(W4 findings H-b, H-c).

`Journal` does not seal: the caller passes `seal` and `unseal` (the
enclave seals each snapshot with the line's state key; the reference
script of the vectors keeps plain bytes).
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field

from anagram.core.canonical import canonical_json, loads_canonical
from anagram.network.matching.enclave.ledger import Ledger


def _same(_counter: int, data: bytes) -> bytes:
    return data


@dataclass
class Journal:
    ledger: Ledger = field(default_factory=Ledger)
    counter: int = 0  # the counter of the next state epoch
    cosigned: int = -1  # the latest counter in a cosigned checkpoint
    snapshots: MutableMapping[int, bytes] = field(default_factory=dict)  # host storage (sealed)
    seal: Callable[[int, bytes], bytes] = _same
    unseal: Callable[[int, bytes], bytes] = _same

    def epoch(self) -> tuple[int, bytes]:
        """Write the snapshot of the next epoch. Return (counter, stored bytes)."""
        stored = self.seal(self.counter, canonical_json(self.ledger.to_json()))
        self.snapshots[self.counter] = stored
        self.counter += 1
        return self.counter - 1, stored

    def cosign(self, counter: int) -> None:
        """A cosigned checkpoint holds the epoch `counter`."""
        if counter >= self.counter:
            raise ValueError("an epoch that was not written cannot be cosigned")
        self.cosigned = max(self.cosigned, counter)
        for old in [c for c in self.snapshots if c < self.cosigned]:
            del self.snapshots[old]

    def restart(self, *, keep_pending: bool = False) -> None:
        """Lose the working state; load the latest cosigned snapshot.
        When `keep_pending` is True, snapshots with counter > cosigned are kept
        on disk so an already-logged pre-crash epoch can still be loaded once
        cosigned."""
        if self.cosigned < 0:
            self.ledger = Ledger()
        else:
            raw = self.unseal(self.cosigned, self.snapshots[self.cosigned])
            self.ledger = Ledger.from_json(loads_canonical(raw))
        if not keep_pending:
            for later in [c for c in self.snapshots if c > self.cosigned]:
                del self.snapshots[later]
        self.counter = self.cosigned + 1
