"""The reader side of shares: the encrypted received
store and "Shared with me" (`Received`, `Client.received`, layer L3). See
spec/vault.md sections 12 to 14.

- the received store: `open_received` fetches and checks a shared finding
  and keeps its files encrypted on disk (`received/<grant_id>/<slot>.blob`);
  `received_file`, `received_figure`, `save_received`, `migrate_received`;
- "Shared with me": `shared_with_me`, `read_shared` (with no network, the
  local copy and a queued read receipt), `received_events` (the reader
  events of the task `shares.sync`).
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

from anagram.core.canonical import CanonicalError, canonical_json, loads_canonical
from anagram.core.crypto.blob import BlobError, decrypt_bytes
from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import epoch_text, format_time
from anagram.identity.api import Device, is_subject
from anagram.network.formats.sharing import SAFE_FIGURE_MEDIA_TYPES, reading_blob_id
from anagram.network.ports import FindingVault
from anagram.network.sharing.app import readcopy
from anagram.network.sharing.app.grants import Grants, safe_name
from anagram.network.sharing.app.reads import ReadReceipts
from anagram.network.sharing.app.tables import ShareStore
from anagram.proofs.bundle import EvidenceOpening, ProofBundle
from anagram.proofs.records import LINK_INCLUDES, OpeningDocument, finding_links

log = logging.getLogger(__name__)

RECEIVED_DIR = "received"
READING_FILE = "reading.blob"
_STORE_FILE = re.compile(r"^(\d+\.blob|reading\.blob)$")
_GRANT_ID = re.compile(r"^[0-9a-f]{32}$")
FILE_PIECE = 1 << 20
REPORT_KEYS = ("claim", "granted_at", "not_after", "root", "verified")
TITLE_MAX = 160  # characters of the first claim line that make a title


def write_atomic(target: Path, data: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".part-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(data)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()


def reading_model(grant_id: str | None, payload: dict, doc, copy: dict, report: dict) -> dict:
    """The reading model. Figure data and the original
    files are not in it (the UI gets them by URL)."""
    items = []
    for it in copy["items"]:
        figures = [{"id": f["id"], "media_type": f["media_type"]} for f in it["figures"]]
        items.append({**it, "figures": figures})
    children = [
        link.target.hex()
        for link in finding_links(doc.finding.fields)
        if link.type == LINK_INCLUDES
    ]
    return {
        "claim": report["claim"],
        "grant_id": grant_id,
        "granted_at": report["granted_at"],
        "items": items,
        "owner": {"label": None, "subject": payload["owner"]},
        "proven_by": report["not_after"],
        "root": report["root"],
        "set": {"children": children, "parent": None},
        "title": copy["title"],
        "verified": report["verified"],
        "version": payload["version"],
    }


class Received:
    """Shared findings that this person received, on this computer (layer L3)."""

    def __init__(
        self,
        device: Device,
        grants: Grants,
        reads: ReadReceipts,
        store: ShareStore,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.store = store
        self.grants = grants
        self.reads = reads

    # ------------------------------------------------------ received store

    def _received_dir(self, grant_id: str) -> Path:
        if not _GRANT_ID.match(grant_id or ""):
            raise ClientError("unknown shared finding")
        return self.device.home / RECEIVED_DIR / grant_id

    def _received_payload(self, grant_id: str) -> dict:
        plain = self.device.unseal("received-payload", grant_id)
        if plain is None:
            raise ClientError("this shared finding is not opened on this computer")
        return loads_canonical(plain)

    def _received_report(self, grant_id: str) -> dict | None:
        return self.store.received_report.load(grant_id)

    def open_received(self, grant_id: str) -> dict:
        """Fetch, check, and keep a shared finding. The files stay encrypted on
        disk (`received/<grant_id>/<slot>.blob`, the ciphertext of the owner);
        the payload with the content key is sealed in the vault. No plaintext
        is written. Return the reading model."""
        folder = self._received_dir(grant_id)
        payload, envelope = self.grants.fetch_payload(grant_id)
        folder.mkdir(parents=True, exist_ok=True)
        root = bytes.fromhex(payload["receipt"]["finding_root"])
        key = bytes.fromhex(payload["content_key"])
        reading_id = reading_blob_id(key, root)
        local = reading_id not in envelope.get("blobs", [])
        plain_files: dict[int, bytes] = {}

        def sink(slot, ev, ciphertext, plain):
            write_atomic(folder / f"{slot}.blob", ciphertext)
            if local:
                plain_files[slot] = plain  # only to build a reading copy here

        report = self.grants.verify_payload(payload, None, sink=sink)
        doc = OpeningDocument.from_json(payload["opening"])
        copy = None if local else self._owner_copy(grant_id, reading_id, key, root, folder)
        if copy is None:
            if not plain_files:  # the owner's copy was bad: decrypt our blobs again
                plain_files = self._received_plain(payload, folder)
            copy = readcopy.build(doc, plain_files)
            write_atomic(folder / READING_FILE, readcopy.seal(copy, key, root))
        plain_files.clear()
        self.device.seal("received-payload", grant_id, canonical_json(payload))
        self.store.received_report.dump(grant_id, {k: report[k] for k in REPORT_KEYS})
        self.store.add_received(grant_id, payload, root.hex(), format_time(self.device.now()))
        return reading_model(grant_id, payload, doc, copy, report)

    def _owner_copy(
        self, grant_id: str, reading_id: str, key: bytes, root: bytes, folder: Path
    ) -> dict | None:
        """The reading copy that the owner uploaded, kept in the store. None
        if it is not on the node or does not open."""
        try:
            blob = self.grants.hooks.fetch_blob(reading_id, grant_id)
            copy = readcopy.unseal(blob, key, root)
            write_atomic(folder / READING_FILE, blob)
            return copy
        except (BlobError, FormatError, CanonicalError, ValueError) as exc:
            log.info("reading copy of %s does not open: %s", grant_id, exc)
        except NodeHTTPError as exc:
            if exc.status != 404:
                raise
        return None

    def _received_plain(self, payload: dict, folder: Path) -> dict[int, bytes]:
        doc = OpeningDocument.from_json(payload["opening"])
        return {
            b["slot"]: self._decrypt_received(payload, doc, folder, b) for b in payload["blobs"]
        }

    def _decrypt_received(self, payload, doc, folder: Path, b: dict) -> bytes:
        slot = b["slot"]
        try:
            return decrypt_bytes(
                (folder / f"{slot}.blob").read_bytes(),
                content_key=bytes.fromhex(payload["content_key"]),
                finding_root=bytes.fromhex(payload["receipt"]["finding_root"]),
                evidence_root=doc.evidence[slot].root(),
                slot=slot,
                chunk_size=b["chunk_size"],
            )
        except (OSError, BlobError) as exc:
            raise ClientError(f"evidence {slot} of this shared finding does not open") from exc

    def received_reading(self, grant_id: str) -> dict:
        """The full reading copy (with figure data) of a received finding."""
        payload = self._received_payload(grant_id)
        blob = (self._received_dir(grant_id) / READING_FILE).read_bytes()
        key = bytes.fromhex(payload["content_key"])
        return readcopy.unseal(blob, key, bytes.fromhex(payload["receipt"]["finding_root"]))

    def received_file(self, grant_id: str, slot: int) -> Iterator[bytes]:
        """The bytes of one received file, in pieces. Decrypted in memory."""
        payload = self._received_payload(grant_id)
        doc = OpeningDocument.from_json(payload["opening"])
        for b in payload["blobs"]:
            if b["slot"] == slot:
                data = self._decrypt_received(payload, doc, self._received_dir(grant_id), b)
                return (data[i : i + FILE_PIECE] for i in range(0, max(len(data), 1), FILE_PIECE))
        raise ClientError("no such file in this shared finding")

    def save_received(self, grant_id: str, out_dir: str | Path) -> list[str]:
        """Write the received files as plaintext into a folder that the person
        chose ("Save a copy"). Return the paths."""
        payload = self._received_payload(grant_id)
        doc = OpeningDocument.from_json(payload["opening"])
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = []
        for b in payload["blobs"]:
            slot = b["slot"]
            data = self._decrypt_received(payload, doc, self._received_dir(grant_id), b)
            target = out / safe_name(slot, doc.evidence[slot].fields.get("name"))
            write_atomic(target, data)
            paths.append(str(target))
        return paths

    def migrate_received(self) -> dict:
        """Move old plaintext folders `received/<grant_id>/` (from `open_grant`)
        into the encrypted store, then erase the plaintext. A folder whose
        grant does not open now (no network, or the owner stopped the share)
        is kept. -> {"moved": [grant_id], "kept": [grant_id]}."""
        base = self.device.home / RECEIVED_DIR
        moved, kept = [], []
        if not base.is_dir():
            return {"kept": kept, "moved": moved}
        for folder in sorted(p for p in base.iterdir() if p.is_dir()):
            gid = folder.name
            plain = [p for p in folder.iterdir() if not _STORE_FILE.match(p.name)]
            if not _GRANT_ID.match(gid) or not plain:
                continue
            if self.device.vault.get_sealed("received-payload", gid) is None:
                try:
                    self.open_received(gid)
                except (ClientError, NodeHTTPError, OSError) as exc:
                    log.info("received %s stays as it is: %s", gid, type(exc).__name__)
                    kept.append(gid)
                    continue
            for p in plain:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
            moved.append(gid)
        return {"kept": kept, "moved": moved}

    # ---------------------------------------------------- "Shared with me"

    def reader_invites_mine(self) -> list[dict]:
        """The reader invites that this person claimed, with the owner pid
        ("<owner> shared a finding with you" until the grant comes)."""
        got = self.device.http.call("GET", "/reader-invites/mine", None, auth=True)
        return [i for i in got.get("invites", []) if is_subject(i.get("owner"))]

    def received_events(self) -> list[tuple[str, dict]]:
        """The reader part of the task `shares.sync`: a new grant gives
        `shared.received`; a grant that gets a key for this device (or comes
        after a reader invite) gives `shared.ready`."""
        seen = self.store.seen.load() or {}
        try:
            waiting_on = {i["owner"] for i in self.reader_invites_mine()}
        except NodeHTTPError:
            waiting_on = set()  # an older node with no reader invites
        out = []
        for g in self.grants.inbox():
            gid, state = g["grant_id"], "ready" if g["for_this_device"] else "waiting"
            before = seen.get(gid)
            if before is None:
                out.append(("shared.received", {"grant_id": gid, "sender": g["sender"],
                                                "title": None}))  # fmt: skip
                if state == "ready" and g["sender"] in waiting_on:
                    out.append(("shared.ready", {"grant_id": gid}))
            elif before == "waiting" and state == "ready":
                out.append(("shared.ready", {"grant_id": gid}))
            seen[gid] = state
        self.store.seen.dump("", seen)
        return out

    def shared_with_me(self) -> list[dict]:
        """The rows of "Shared with me": each grant to me (new or opened), a
        finding that I opened before and the owner withdrew (its local copy
        stays readable), and a row "waiting" for each claimed reader invite
        whose owner has sent nothing yet. Sets: a received finding that
        another received finding includes has that one as its parent."""
        local = self.store.received_rows()
        rows = []
        listed = set()
        for g in self.grants.inbox():
            gid = g["grant_id"]
            listed.add(gid)
            rows.append(self._shared_row(gid, g["sender"], epoch_text(g["received_at"]),
                                         g["for_this_device"], local.get(gid), False))  # fmt: skip
        for gid, loc in local.items():
            if gid not in listed:
                rows.append(self._shared_row(gid, loc[1], loc[5], True, loc, True))
        _link_sets(rows)
        rows += self._waiting_rows({r["sender"] for r in rows})
        for row in rows:
            row.pop("root", None)
        return sorted(rows, key=lambda r: r["received_at"] or "9999", reverse=True)

    def _waiting_rows(self, senders: set[str]) -> list[dict]:
        """A row "waiting" for each claimed reader invite of an owner who
        has sent nothing yet."""
        try:
            mine = self.reader_invites_mine()
        except NodeHTTPError:
            mine = []
        rows = []
        for inv in mine:
            if inv["owner"] in senders:
                continue
            senders.add(inv["owner"])
            rows.append({"grant_id": None, "invite_id": inv["invite_id"], "new": True,
                         "opened_at": None, "ready": False, "received_at": None, "root": None,
                         "sender": inv["owner"], "set": {"children": [], "parent": None},
                         "title": None, "withdrawn": False})  # fmt: skip
        return rows

    def _shared_row(self, gid, sender, received_at, ready, loc, withdrawn) -> dict:
        report = self._received_report(gid) if loc else None
        children: list[str] = []
        title = None
        if loc:
            try:
                doc = OpeningDocument.from_json(self._received_payload(gid)["opening"])
                children = [ln.target.hex() for ln in finding_links(doc.finding.fields)
                            if ln.type == LINK_INCLUDES]  # fmt: skip
                claim = (doc.finding.fields.get("claim") or "").strip()
                title = claim.splitlines()[0][:TITLE_MAX] if claim else None
            except (ClientError, FormatError, KeyError):
                pass
        return {
            "_children": children,
            "grant_id": gid,
            "invite_id": None,
            "new": loc is None,
            "opened_at": loc[6] if loc else None,
            "ready": bool(ready),
            "received_at": received_at,
            "root": (report or {}).get("root") or (loc[2] if loc else None),
            "sender": sender,
            "set": {"children": [], "parent": None},
            "title": title,
            "withdrawn": withdrawn,
        }

    def received_model(self, grant_id: str) -> dict:
        """The reading model of a finding that this computer opened before,
        from the local encrypted store only (no node call)."""
        payload = self._received_payload(grant_id)
        report = self._received_report(grant_id)
        if report is None:
            raise ClientError("this shared finding is not opened on this computer")
        doc = OpeningDocument.from_json(payload["opening"])
        return reading_model(grant_id, payload, doc, self.received_reading(grant_id), report)

    def read_shared(self, grant_id: str) -> dict:
        """Open a shared finding for the reading view. With the node: fetch
        and check (`open_received`, which posts the read receipt). With no
        network: the local copy, and a queued read receipt. A finding that
        the owner withdrew: the local copy, if this computer opened it."""
        try:
            model = self.open_received(grant_id)
        except OSError:
            if self._received_report(grant_id) is None:
                raise
            self.reads.queue(grant_id)
            model = self.received_model(grant_id)
        except NodeHTTPError as exc:
            if exc.status not in (403, 404) or self._received_report(grant_id) is None:
                raise
            model = self.received_model(grant_id)
        self.store.mark_opened(grant_id, format_time(self.device.now()))
        return model

    def received_item(self, grant_id: str, slot: int) -> dict:
        """Name and media type of one received file (from its opening)."""
        payload = self._received_payload(grant_id)
        if not any(b["slot"] == slot for b in payload["blobs"]):
            raise ClientError("no such file in this shared finding")
        doc = OpeningDocument.from_json(payload["opening"])
        fields = doc.evidence[slot].fields
        name = Path(fields.get("name") or f"file-{slot}").name
        return {"media_type": readcopy.file_media_type(name, fields.get("media_type") or ""),
                "name": name}  # fmt: skip

    def received_figure(self, grant_id: str, slot: int, figure_id: str) -> tuple[str, bytes]:
        """(media type, bytes) of one figure of the reading copy."""
        for item in self.received_reading(grant_id)["items"]:
            if item["slot"] != slot:
                continue
            for fig in item["figures"]:
                if fig["id"] == figure_id:
                    if fig["media_type"] not in SAFE_FIGURE_MEDIA_TYPES:
                        raise ClientError("unsupported figure media type")
                    return fig["media_type"], base64.b64decode(fig["data"])
        raise ClientError("no such figure in this shared finding")

    def received_proof(self, grant_id: str) -> str:
        """The proof bundle of a received finding with all fields opened (the
        bundle that `open_received` checked). JSON text for "Download proof"."""
        payload = self._received_payload(grant_id)
        bundle = ProofBundle.from_json(payload["bundle"])
        doc = OpeningDocument.from_json(payload["opening"])
        full = ProofBundle(
            subject=bundle.subject,
            log=bundle.log,
            anchors=bundle.anchors,
            finding_openings=tuple(doc.finding.prove(n) for n in doc.finding.names()),
            evidence_openings=tuple(
                EvidenceOpening(i, tuple(ev.prove(n) for n in ev.names()))
                for i, ev in enumerate(doc.evidence)
            ),
            sealed_opening=None,
        )
        return full.dumps() + "\n"


def _link_sets(rows: list[dict]) -> None:
    """Sets: a received finding that another received finding of the same
    sender includes has that one as its parent."""
    roots = {row["root"]: row for row in rows if row["root"]}
    for row in rows:
        for child in row.pop("_children"):
            if child in roots and roots[child]["sender"] == row["sender"]:
                roots[child]["set"]["parent"] = row["grant_id"]
                row["set"]["children"].append(roots[child]["grant_id"])
