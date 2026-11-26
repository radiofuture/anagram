"""Signed time inside the enclave (spec/enclave-trust.md 6.4).

The enclave compares times only by its signed time: bounds from the witness
cosignature times of a checkpoint with a quorum (and, on real hardware,
Roughtime), carried forward by the guest's monotonic clock. In
`clock_unsafe` it does no sweep, no release, no expiry and no handoff, and
refuses requests with that code.
"""

from __future__ import annotations

from dataclasses import dataclass

FRESH = 3_600  # a signed source newer than 1 hour
WIDTH = 300  # upper - lower at most 300 s
BACK = 300  # time may not go back more than 300 s
HOST = 300  # the host clock within 300 s of the signed middle


def clock_safe(host: int, lower: int, upper: int, fresh_age: int, max_seen: int) -> bool:
    """The clock rule. `fresh_age`: seconds since the newest signed source."""
    if fresh_age > FRESH or upper - lower > WIDTH or lower < max_seen - BACK:
        return False
    return abs(host - (lower + upper) // 2) <= HOST


@dataclass
class SignedClock:
    """Bounds of the newest checkpoint with a quorum, and the host (guest
    monotonic) time when the enclave saw it."""

    lower: int = 0
    upper: int = 0
    seen_at: int | None = None
    max_seen: int = 0

    def observe(self, lower: int, upper: int, host: int) -> None:
        if lower >= self.lower:
            self.lower, self.upper, self.seen_at = lower, upper, host

    def now(self, host: int) -> int | None:
        """Signed now, or None in `clock_unsafe` (the state is counted by
        the caller). The guest clock is monotonic: a `host` time before the
        time of the signed source is `clock_unsafe`, so time read from the
        clock cannot go back."""
        if self.seen_at is None:
            return None
        elapsed = host - self.seen_at
        if elapsed < 0:
            return None
        lower, upper = self.lower + elapsed, self.upper + elapsed
        if not clock_safe(host, lower, upper, elapsed, self.max_seen):
            return None
        self.max_seen = max(self.max_seen, lower)
        return lower
