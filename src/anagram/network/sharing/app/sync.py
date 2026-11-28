"""One tick of the task `shares.sync` (`ShareSync`, `Client.share_sync`,
layer L3). It runs the sync of
each part of sharing on this computer and gives each change as an event.
"""

from __future__ import annotations

import logging

from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import Device
from anagram.network.ports import FindingVault
from anagram.network.sharing.app.grants import Grants
from anagram.network.sharing.app.invites import ReaderInvites
from anagram.network.sharing.app.reads import ReadReceipts
from anagram.network.sharing.app.received import Received
from anagram.network.sharing.app.records import ReadRecords
from anagram.network.sharing.app.shares import Shares
from anagram.network.sharing.app.tables import INVITE_TARGET

log = logging.getLogger(__name__)


class ShareSync:
    """The task `shares.sync` on this computer (layer L3)."""

    def __init__(
        self,
        device: Device,
        grants: Grants,
        shares: Shares,
        invites: ReaderInvites,
        records: ReadRecords,
        received: Received,
        reads: ReadReceipts,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.grants = grants
        self.shares = shares
        self.invites = invites
        self.records = records
        self.received = received
        self.reads = reads

    def sync_shares(self, publish=None) -> dict:
        """One tick of the task `shares.sync`. Owner:
        wraps for new devices, completed reader invites, people who were
        waiting, read records. Reader: queued receipts, new and ready grants.
        Each change is an event `(type, data)`; with
        `publish` (the bus of the UI) each one is published. A node or
        network fault in one part does not stop the other parts.
        -> {"changed": [{"type", "data"}]}."""
        changed: list[dict] = []
        parts = (
            ("grants", self._grants),
            ("invites", self._invites),
            ("waiting", self._waiting),
            ("reads", self._reads),
            ("queue", self._queue),
            ("received", self._received),
        )
        for name, fn in parts:
            try:
                changed.extend({"data": data, "type": kind} for kind, data in fn())
            except (NodeHTTPError, OSError) as exc:
                log.info("shares sync: %s failed: %s", name, type(exc).__name__)
        if publish is not None:
            for c in changed:
                publish(c["type"], c["data"])
        return {"changed": changed}

    def _grants(self) -> list[tuple[str, dict]]:
        self.grants.sync_grants()
        return []

    def _queue(self) -> list[tuple[str, dict]]:
        self.reads.flush_queue()
        return []

    def _invites(self) -> list[tuple[str, dict]]:
        out = []
        for c in self.invites.sync_reader_invites():
            if c["kind"] == "confirm":
                out.append(("share.confirm", {"invite_id": c["invite_id"]}))
            for fid in c["findings"]:
                if c["kind"] == "shared":
                    out.append(("share.delivered", {"finding_id": fid, "subject": c["subject"]}))
                else:
                    out.append(("share.stopped", {"finding_id": fid,
                                                  "target": INVITE_TARGET + c["invite_id"]}))  # fmt: skip
        return out

    def _waiting(self) -> list[tuple[str, dict]]:
        return [("share.delivered", c) for c in self.shares.retry_waiting()]

    def _reads(self) -> list[tuple[str, dict]]:
        out = []
        for c in self.records.sync_reads():
            row = self.vault.get(c["root"]) if c.get("root") else None
            fid = row.finding_id if row is not None else None
            if c["kind"] == "read":
                out.append(("share.read", {"finding_id": fid, "read_at": c["read_at"],
                                           "reads": c["reads"], "root": c["root"],
                                           "subject": c["reader"]}))  # fmt: skip
            else:
                out.append(("share.anomaly", {"detail": c["detail"], "finding_id": fid}))
        return out

    def _received(self) -> list[tuple[str, dict]]:
        return self.received.received_events()
