"""A shared development clock for the `simulated` enclave profile.

The matching enclave works in UTC days: a cut at 23:00, a fixed answer day,
leases of 24 hours, a notice period of 14 days. A test of the deployed
processes cannot wait for real days. So each process of a development
network (log, witnesses, roster, enclave, nodes, apps) can read one offset
from a file:

    ANAGRAM_DEV_CLOCK_FILE=/clock/offset     # the file holds whole seconds, e.g. 1209600

`now = time.time() + offset`. The test driver writes a larger offset to
move every process forward at once. A missing or empty file is offset 0.

Development only. Only the parts of the simulated profile read it (the
enclave processes and the matching parts of a node and of the app), and
`clock_from_env` returns the real clock when the variable is not set. A
real deployment never sets it; the TEE profile does not read it.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

ENV = "ANAGRAM_DEV_CLOCK_FILE"
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OffsetClock:
    """Real time plus the offset in `path`, read again at each call (the
    driver changes it while the processes run)."""

    path: Path
    real: Callable[[], float] = time.time

    def offset(self) -> int:
        """The offset in whole seconds. A missing, empty or bad file is 0
        (a bad file with a warning): the clock never fails."""
        try:
            text = self.path.read_text().strip()
        except FileNotFoundError:
            return 0
        try:
            return int(text) if text else 0
        except ValueError:
            log.warning("the development clock file does not hold whole seconds; offset 0")
            return 0

    def __call__(self) -> int:
        return int(self.real()) + self.offset()


def real_clock() -> int:
    return int(time.time())


def dev_clock_from_env(env: Mapping[str, str] = os.environ) -> OffsetClock | None:
    """The offset clock when `ANAGRAM_DEV_CLOCK_FILE` is set, else None."""
    path = (env.get(ENV) or "").strip()
    return OffsetClock(Path(path)) if path else None


def clock_from_env(
    env: Mapping[str, str] = os.environ, default: Callable[[], float] = real_clock
) -> Callable[[], float]:
    """The clock of a simulated-profile part: the offset clock when
    `ANAGRAM_DEV_CLOCK_FILE` is set, else `default` (the real clock)."""
    return dev_clock_from_env(env) or default
