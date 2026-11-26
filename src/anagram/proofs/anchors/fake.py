"""Deterministic local anchor for tests and the synthetic community.

It gives NO independent time. It signs (digest, time) with a local key. Use it
only where a real anchor is not available. Its key must be pinned explicitly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime

from anagram.core.crypto.hashing import TAG_FAKE_ANCHOR, u64
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.timefmt import format_time, parse_time
from anagram.proofs.anchors.base import Anchor, AnchorCheck, AnchorTrust


class FakeAnchor(Anchor):
    type = "fake"

    def __init__(self, key: SigningKey, clock: Callable[[], float] = time.time) -> None:
        self.key = key
        self.clock = clock

    def stamp(self, digest: bytes) -> dict:
        when = datetime.fromtimestamp(int(self.clock()), UTC)
        ts = int(when.timestamp())
        sig = self.key.sign(TAG_FAKE_ANCHOR, digest + u64(ts))
        return {
            "digest": digest.hex(),
            "key": self.key.public_bytes().hex(),
            "signature": sig.hex(),
            "time": format_time(when),
            "type": self.type,
        }


def verify_fake(record: dict, digest: bytes, trust: AnchorTrust) -> AnchorCheck:
    key = bytes.fromhex(record["key"])
    if key not in trust.fake_keys:
        return AnchorCheck("fake", False, detail="fake anchor key is not pinned")
    if record["digest"] != digest.hex():
        return AnchorCheck("fake", False, detail="digest mismatch")
    when = parse_time(record["time"])
    ts = int(when.timestamp())
    if not verify(key, TAG_FAKE_ANCHOR, digest + u64(ts), bytes.fromhex(record["signature"])):
        return AnchorCheck("fake", False, detail="bad signature")
    return AnchorCheck(
        "fake",
        True,
        time=when,
        detail="local fake anchor (no independent time)",
        source=f"fake:{key.hex()}",
    )
