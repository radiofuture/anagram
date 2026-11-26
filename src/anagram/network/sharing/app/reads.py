"""The reader side of read receipts, and the grant hooks
of sharing. See spec/vault.md sections 12 to 14.

- `ReadReceipts`: the reader's client posts a signed receipt before it
  fetches a grant (`gate`); with no network it queues the receipt and posts
  it at the next sync (`flush_queue`).
- `ShareHooks`: the hooks that sharing gives to `Grants` (`GrantHooks`): the
  reading copy blob in the grant envelope, the read receipt before a fetch,
  and the blob fetch that gets one new receipt when the node window ended.
"""

from __future__ import annotations

import json
import secrets
import urllib.parse

from anagram.core.canonical import loads_canonical
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import Device
from anagram.network.formats.sharing import make_read_receipt, read_receipt_id
from anagram.network.ports import FindingVault
from anagram.network.sharing.app.tables import ShareStore

# A new receipt for each grant and device in each window of this length. The
# node keeps a receipt valid for 24 hours; the client makes a new one a little
# earlier, so that a fetch never meets the end of the window.
RECEIPT_REUSE_S = 23 * 3600


class ReadReceipts:
    def __init__(self, device: Device, store: ShareStore) -> None:
        self.device = device
        self.store = store

    def make(self, grant_id: str) -> dict:
        return make_read_receipt(
            grant_id=bytes.fromhex(grant_id),
            reader=self.device.subject,
            read_at=self.device.now(),
            salt=secrets.token_bytes(32),
            key=self.device.device_key(),
        )

    def post(self, grant_id: str, receipt: dict) -> dict:
        path = f"/grants/{urllib.parse.quote(grant_id, safe='')}/receipts"
        out = self.device.http.call("POST", path, {"receipt": receipt}, auth=True)
        self.store.receipt_posted.dump(
            grant_id, {"posted_at": self.device.clock(), "receipt_id": out["receipt_id"]}
        )
        return out

    def gate(self, grant_id: str, *, force: bool = False) -> str | None:
        """Post a read receipt for this grant and this device, unless one was
        posted in the last 23 hours (`force`: always). Return the receipt ID.

        A node with no read ledger (an older node) has no receipt route: the
        answer is None and the fetch goes on with no record."""
        if not force:
            last = self.store.receipt_posted.load(grant_id)
            if last:
                if self.device.clock() - last["posted_at"] < RECEIPT_REUSE_S:
                    return last["receipt_id"]
        try:
            return self.post(grant_id, self.make(grant_id))["receipt_id"]
        except NodeHTTPError as exc:
            if exc.status == 404 and "unknown grant" not in str(exc):
                return None  # the node has no read ledger
            raise

    def gated_call(self, grant_id: str, method: str, path: str):
        """A fetch of the grant or one of its blobs. A 428 answer (the node
        window ended before ours) gets one new receipt and one more try."""
        http = self.device.http
        try:
            return http.call(method, path, auth=True)
        except NodeHTTPError as exc:
            if exc.status != 428:
                raise
        self.gate(grant_id, force=True)
        return http.call(method, path, auth=True)

    def queue(self, grant_id: str) -> str:
        """An opening with no network: make the receipt now (the real
        `read_at`) and keep it on this device until the next sync. The queue is
        the local `kv` table: it does not go to the personal store, because the
        receipt is signed by this device."""
        receipt = self.make(grant_id)
        rid = read_receipt_id(receipt)
        self.store.receipt_queue.dump(rid, {"grant_id": grant_id, "receipt": receipt})
        return rid

    def flush_queue(self) -> list[str]:
        """Post the queued receipts. Return the receipt IDs that the node
        accepted. A receipt for a grant that is gone is dropped."""
        queue = self.store.receipt_queue
        done = []
        for rid, item in queue.loaded_items():
            try:
                out = self.post(item["grant_id"], item["receipt"])
            except NodeHTTPError as exc:
                if exc.status in (403, 404):
                    queue.delete(rid)  # the grant is gone or not for us
                    continue
                raise
            queue.delete(rid)
            done.append(out["receipt_id"])
        return done


class ShareHooks:
    """The `GrantHooks` of sharing (see `anagram.network.sharing.app.grants`)."""

    def __init__(
        self, device: Device, receipts: ReadReceipts, store: ShareStore, vault: FindingVault
    ) -> None:
        self.device = device
        self.vault = vault
        self.store = store
        self.receipts = receipts

    def extra_blobs(self, grant_id: bytes, plain: bytes) -> set[str]:
        """The reading copy blob, if one is uploaded for the version. The first
        answer for a grant ID is kept, so that `sync_grants` posts the same
        blob list again (the node refuses a changed list). A grant that was
        sent before this record existed has no extra blob."""
        vault = self.vault
        gid = grant_id.hex()
        got = self.store.grant_extra.get(gid)
        if got is not None:
            return set(json.loads(got))
        if any(g["grant_id"] == gid for g in vault.grants_sent()):
            return set()
        root = loads_canonical(plain)["receipt"]["finding_root"]
        reading = self.store.reading_copy.get(root)
        out = [reading] if reading else []
        self.store.grant_extra.dump(gid, out)
        return set(out)

    def read_gate(self, grant_id: str) -> str | None:
        return self.receipts.gate(grant_id)

    def fetch_blob(self, blob_id: str, grant_id: str | None = None) -> bytes:
        http = self.device.http
        if grant_id is None or self.device.config.get("identity") is None:
            return http.call(
                "GET", f"/blobs/{blob_id}", auth=self.device.config.get("identity") is not None
            )
        return self.receipts.gated_call(grant_id, "GET", f"/blobs/{blob_id}")
