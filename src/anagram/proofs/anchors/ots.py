"""OpenTimestamps adapter (python-opentimestamps library).

stamp():   submits the digest to public calendar servers (network). The result
           has only "pending" attestations. A calendar commits it to Bitcoin
           after some hours.
upgrade(): asks the calendars for the Bitcoin part of a pending record
           (network). Run it some hours after stamp().
verify:    offline. It replays the operations from the digest to each
           attestation. A Bitcoin attestation is valid only if the computed
           value equals the merkle root of the block header at that height. The
           verifier supplies the header (AnchorTrust.bitcoin_headers), from a
           Bitcoin node or block explorer that it trusts. A record with only
           pending attestations gives ok=False, pending=True.

The record holds a serialized OTS detached timestamp (the same bytes as a .ots
file), so the standard `ots verify` tool can also check it.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime

from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    PendingAttestation,
)
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import (
    BytesDeserializationContext,
    BytesSerializationContext,
)
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from anagram.proofs.anchors.base import Anchor, AnchorCheck, AnchorTrust

DEFAULT_CALENDARS = (
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
)


def serialize(detached: DetachedTimestampFile) -> bytes:
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes()


def deserialize(data: bytes) -> DetachedTimestampFile:
    return DetachedTimestampFile.deserialize(BytesDeserializationContext(data))


def new_detached(digest: bytes) -> tuple[DetachedTimestampFile, Timestamp]:
    """Return a detached timestamp for the digest and the leaf to submit.

    As in the `ots` client, a random nonce is appended first, so the calendar
    does not learn the digest.
    """
    detached = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    nonce_stamp = detached.timestamp.ops.add(OpAppend(secrets.token_bytes(16)))
    leaf = nonce_stamp.ops.add(OpSHA256())
    return detached, leaf


class OpenTimestampsAnchor(Anchor):
    type = "opentimestamps"

    def __init__(self, calendars: tuple[str, ...] = DEFAULT_CALENDARS, timeout: int = 10):
        self.calendars = calendars
        self.timeout = timeout

    def stamp(self, digest: bytes) -> dict:  # pragma: no cover - network
        from opentimestamps.calendar import RemoteCalendar

        detached, leaf = new_detached(digest)
        ok = 0
        for url in self.calendars:
            try:
                leaf.merge(RemoteCalendar(url).submit(leaf.msg, timeout=self.timeout))
                ok += 1
            except Exception:  # noqa: S112 - a calendar may be down; try the next
                continue
        if ok == 0:
            raise RuntimeError("no OpenTimestamps calendar accepted the digest")
        return record_from_detached(detached)

    def upgrade(self, record: dict) -> dict:  # pragma: no cover - network
        from opentimestamps.calendar import RemoteCalendar

        detached = deserialize(base64.b64decode(record["ots"]))
        for msg, att in list(detached.timestamp.all_attestations()):
            if isinstance(att, PendingAttestation):
                try:
                    found = RemoteCalendar(att.uri).get_timestamp(msg, timeout=self.timeout)
                except Exception:  # noqa: S112
                    continue
                for sub in _find(detached.timestamp, msg):
                    sub.merge(found)
        return record_from_detached(detached)


def _find(ts: Timestamp, msg: bytes):
    if ts.msg == msg:
        yield ts
    for sub in ts.ops.values():
        yield from _find(sub, msg)


def is_complete(record: dict) -> bool:
    """True if the record has at least one Bitcoin attestation (no network)."""
    try:
        detached = deserialize(base64.b64decode(record["ots"], validate=True))
    except Exception:  # library raises many types on bad input
        return False
    return any(
        isinstance(att, BitcoinBlockHeaderAttestation)
        for _, att in detached.timestamp.all_attestations()
    )


def record_from_detached(detached: DetachedTimestampFile) -> dict:
    return {"ots": base64.b64encode(serialize(detached)).decode(), "type": "opentimestamps"}


def verify_record(record: dict, digest: bytes, trust: AnchorTrust) -> AnchorCheck:
    try:
        detached = deserialize(base64.b64decode(record["ots"], validate=True))
    except Exception as exc:  # library raises many types on bad input
        return AnchorCheck("opentimestamps", False, detail=f"bad OTS data: {exc}")
    if not isinstance(detached.file_hash_op, OpSHA256) or detached.file_digest != digest:
        return AnchorCheck("opentimestamps", False, detail="OTS file digest does not match")
    best: datetime | None = None
    best_height = -1
    pending: list[str] = []
    unknown_heights: list[int] = []
    for msg, att in detached.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            pending.append(att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            header = trust.bitcoin_headers.get(att.height)
            if header is None:
                unknown_heights.append(att.height)
                continue
            merkle_root, block_time = header
            if msg == merkle_root:
                when = datetime.fromtimestamp(block_time, UTC)
                if best is None or when < best:
                    best, best_height = when, att.height
    if best is not None:
        return AnchorCheck(
            "opentimestamps",
            True,
            time=best,
            detail=f"Bitcoin attestation at height {best_height}",
            source=f"opentimestamps:bitcoin:{best_height}",
        )
    if unknown_heights:
        return AnchorCheck(
            "opentimestamps",
            False,
            detail=f"needs Bitcoin block headers for heights {sorted(set(unknown_heights))}",
        )
    return AnchorCheck(
        "opentimestamps",
        False,
        pending=bool(pending),
        detail="pending: " + ", ".join(pending) if pending else "no usable attestation",
    )
