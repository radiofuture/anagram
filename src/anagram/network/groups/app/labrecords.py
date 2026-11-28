"""The lab space on the client: `LabSpace`.

The lab space is a set of encrypted records on the node, with the key of an
epoch (`LabKeys`). It holds lab items (with their text parts and their
attached files) and the lab settings. The client reads the records after a
cursor and keeps each record that verifies in the local lab cache: the
signature, a roster head in the verified chain (else a fork:
`LogMisbehaved`), and a writer who could write it at that roster seq. A
record that does not verify is dropped. The bridge to the local index is in
`labspace`.
"""

from __future__ import annotations

import io
import mimetypes
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from anagram.core.crypto import aead
from anagram.core.crypto.blob import DEFAULT_CHUNK_SIZE, BlobError, decrypt_stream, encrypt_stream
from anagram.core.errors import FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import parse_time
from anagram.identity.api import Device, open_record, seal_record
from anagram.local.api import Findings
from anagram.network.formats import lab as labfmt
from anagram.network.formats import labitem, labkey, labsettings
from anagram.network.groups.app.labkeys import LabKeys
from anagram.network.groups.app.labroster import LabError, LabRoster
from anagram.network.ports import FindingVault


@dataclass(frozen=True)
class LabItemDraft:
    """What a member puts into the lab space. `item_id` is set
    for a new revision of an item. `origin` has no path and no source ID.
    `files` are attachments: local files, encrypted and uploaded
    as blobs. A revision with no `files` keeps the files of the old one."""

    kind: str
    title: str
    text: str
    origin: dict
    type: str | None = None
    facts: tuple = ()
    finding_root: str | None = None
    item_id: str | None = None
    files: tuple[Path, ...] = ()


@dataclass(frozen=True)
class LabPolicy:
    """The five settings sections of one lab, with defaults (integration
    1.7). Enforcement is in the client."""

    lab_id: str
    models: dict
    disclosure: dict
    oauth_clients: dict
    sources: dict
    matching: dict

    def allows_recipient(self, recipient_id: str, external: bool = True) -> bool:
        """May this recipient read lab-space text? A local recipient always
        may. The AI assistant (`mcp`) follows `allow_assistant`."""
        if not external:
            return True
        if recipient_id == "mcp":
            return self.allows_assistant()
        return recipient_id in (self.disclosure.get("allow_external") or [])

    def allows_assistant(self) -> bool:
        return bool(self.disclosure.get("allow_assistant"))

    def allows_cloud_assistant(self) -> bool:
        """May an agent of class `cloud` read the lab space? It needs
        `allows_assistant` too (open-agents plan 2.2)."""
        return self.allows_assistant() and bool(self.disclosure.get("allow_cloud_assistant"))

    def allows_source(self, kind: str) -> bool:
        """May a source of this kind go into this lab space? (A private
        source is never asked.)"""
        kinds = self.sources.get("allowed_kinds")
        return kinds is None or kind in kinds

    def lab_default(self) -> str:
        return self.sources.get("lab_default") or "private"

    def matching_enabled(self) -> bool:
        return bool(self.matching.get("enabled", True))


@dataclass(frozen=True)
class SpaceRecord:
    """One record to put into the lab space (`LabSpace.put_record`). `drop`
    names the records that the node deletes with it; `blobs` names the blobs
    that it holds."""

    kind: str
    ref: str
    value: dict
    version: int
    drop: tuple[str, ...] = ()
    topic: str = "space"
    blobs: tuple[str, ...] = ()


class LabSpace:
    """The lab space of the labs of this person (layer L3): items, files,
    settings, and the sync of the records."""

    def __init__(
        self,
        device: Device,
        findings: Findings,
        roster: LabRoster,
        keys: LabKeys,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.findings = findings
        self.roster = roster
        self.keys = keys

    # ------------------------------------------------------------ writing

    def space_keys(self, lab_id: str) -> dict[int, labkey.LabStoreKeys]:
        """Record keys of each epoch that this device holds."""
        keys = self.keys.epoch_keys(lab_id)
        if 1 not in keys:
            return {}
        return {n: labkey.LabStoreKeys(k, keys[1]) for n, k in keys.items()}

    def writer(self, lab_id: str) -> tuple[labfmt.LabState, labkey.LabStoreKeys]:
        """The verified state and the keys of the newest epoch (pulled now,
        so that a write after a rotation uses the new key)."""
        state = self.roster.lab_state(lab_id)
        if not state.can(self.device.subject, "publish"):
            raise LabError("Your role in this lab does not permit this.")
        self.keys.pull_keys(lab_id, state)
        sks = self.space_keys(lab_id)
        if not sks:
            raise LabError("This computer has no key for this lab yet. Sync, then try again.")
        return state, sks[max(sks)]

    def put_record(self, lab_id: str, sk: labkey.LabStoreKeys, rec: SpaceRecord) -> dict:
        """Seal one record with the keys `sk` and put it on the node."""
        doc = seal_record(sk, rec.kind, rec.ref, rec.value, rec.version)
        body = {
            "blobs": list(rec.blobs),
            "drop": list(rec.drop),
            "record": doc,
            "topic": rec.topic,
        }
        try:
            return self.device.http.call(
                "PUT", f"/labs/{lab_id}/space/records/{doc['record_id']}", body, auth=True
            )
        except NodeHTTPError as exc:
            if exc.status == 409:
                raise LabError(
                    "This item changed on another computer. Sync, then try again."
                ) from exc
            if exc.status == 403:
                raise LabError("The lab space does not accept this change now.") from exc
            if exc.status == 413:
                raise LabError(
                    "The lab space is full. Ask the organizer of your node for more space."
                ) from exc
            raise

    def _cached_item(self, lab_id: str, item_id: str) -> dict:
        got = self.roster.labcache.item(lab_id, item_id) if isinstance(item_id, str) else None
        if got is None or got[0]["deleted"]:
            raise LabError("This item is not in the lab space.")
        return got[0]

    def _finding_ref(self, root: str) -> dict:
        """The finding of an item: IDs and the public proof bundle (it opens
        no evidence)."""
        row = self.vault.find(root)
        return {
            "bundle": self.findings.public_bundle(row.root).to_json(),
            "claim": None,
            "finding_id": row.finding_id,
            "root": row.root,
            "version": row.version,
        }

    # -------------------------------------------------------------- items

    def lab_publish(self, lab_id: str, item: LabItemDraft) -> str:
        """Put an item (or a new revision of my item) into the lab space.
        The text goes in parts of at most 1 MiB, then the signed item record.
        Return the item ID."""
        lab_id = self.roster.check_lab_id(lab_id)
        if item.kind not in labitem.ITEM_KINDS:
            raise LabError("This kind of item cannot go into the lab space.")
        state, sk = self.writer(lab_id)
        old = None
        if item.item_id is not None:
            old = self._cached_item(lab_id, item.item_id)
            if old["author"] != self.device.subject:
                raise LabError("Only the author changes this item.")
        item_id = item.item_id or secrets.token_hex(16)
        rev = old["rev"] + 1 if old else 1
        now = self.device.now()
        if item.files:
            attachments = self._attach(lab_id, item_id, item.files)
        else:
            attachments = list(old["attachments"]) if old else []
        value = self._item_value(state, item, item_id, rev, now, old, attachments)
        parts = labitem.split_text(item.text)
        for n, part in enumerate(parts):
            ref = labitem.part_ref(item_id, n)
            self.put_record(
                lab_id, sk, SpaceRecord(labitem.KIND_ITEM_TEXT, ref, {"text": part}, rev)
            )
        drop = tuple(
            sk.record_id(labitem.KIND_ITEM_TEXT, labitem.part_ref(item_id, n))
            for n in range(len(parts), old["text_parts"] if old else 0)
        )
        blobs = tuple(a["blob_id"] for a in attachments)
        rec = SpaceRecord(labitem.KIND_ITEM, item_id, value, rev, drop, blobs=blobs)
        self.put_record(lab_id, sk, rec)
        self.roster.labcache.put_item(lab_id, value, item.text)
        return item_id

    def _item_value(
        self,
        state: labfmt.LabState,
        item: LabItemDraft,
        item_id: str,
        rev: int,
        now: datetime,
        old: dict | None,
        attachments: list[dict],
    ) -> dict:
        """The signed lab item value of a draft."""
        try:
            return labitem.make_lab_item(
                lab_id=state.lab_id,
                item_id=item_id,
                rev=rev,
                kind=item.kind,
                title=item.title,
                text=item.text,
                author=self.device.subject,
                key=self.device.device_key(),
                roster=labfmt.roster_ref(state),
                published_at=parse_time(old["published_at"]) if old else now,
                updated_at=now,
                origin=item.origin,
                type=item.type,
                facts=list(item.facts),
                finding=self._finding_ref(item.finding_root) if item.finding_root else None,
                attachments=attachments,
            )
        except FormatError as exc:
            raise LabError("This item has a field that the lab space does not accept.") from exc

    def _attach(self, lab_id: str, item_id: str, files: tuple[Path, ...]) -> list[dict]:
        """Encrypt each file with its own key and upload it as a blob. The
        key goes into the item, which only lab members open."""
        if len(files) > labitem.MAX_ATTACHMENTS:
            raise LabError(f"An item has at most {labitem.MAX_ATTACHMENTS} files.")
        root = labitem.attachment_root(lab_id, item_id)
        out = []
        for n, f in enumerate(files):
            path = Path(f)
            if not path.is_file():
                raise LabError("A file to attach is not on this computer now.")
            key, blob_id = aead.new_key(), secrets.token_hex(16)
            with tempfile.TemporaryFile() as tmp:
                with path.open("rb") as src:
                    size, _ = encrypt_stream(
                        src,
                        tmp,
                        content_key=key,
                        finding_root=root,
                        evidence_root=bytes(32),
                        slot=n,
                        chunk_size=DEFAULT_CHUNK_SIZE,
                    )
                tmp.seek(0)
                self.device.http.call("PUT", f"/blobs/{blob_id}", tmp.read(), auth=True)
            name = path.name[: labitem.MAX_TITLE]
            out.append(
                {
                    "blob_id": blob_id,
                    "chunk_size": DEFAULT_CHUNK_SIZE,
                    "content_key": key.hex(),
                    "evidence_root": None,
                    "media_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                    "name": name,
                    "size": size,
                    "slot": n,
                }
            )
        return out

    def lab_file(self, lab_id: str, item_id: str, n: int) -> tuple[str, str, bytes]:
        """(name, media type, bytes) of attachment `n` of a lab item. The
        blob is checked chunk by chunk (AEAD with the key of the item)."""
        lab_id = self.roster.check_lab_id(lab_id)
        value = self._cached_item(lab_id, item_id)
        atts = value.get("attachments") or []
        if not isinstance(n, int) or not 0 <= n < len(atts):
            raise LabError("This file is not in the lab item.")
        a = atts[n]
        data = self.device.http.call("GET", f"/blobs/{a['blob_id']}", auth=True)
        out = io.BytesIO()
        try:
            size = decrypt_stream(
                io.BytesIO(data),
                out,
                content_key=bytes.fromhex(a["content_key"]),
                finding_root=labitem.attachment_root(lab_id, item_id),
                evidence_root=bytes.fromhex(a["evidence_root"])
                if a["evidence_root"]
                else bytes(32),
                slot=a["slot"],
                chunk_size=a["chunk_size"],
            )
        except (BlobError, ValueError) as exc:
            raise LogMisbehaved("a lab file from the node does not decrypt") from exc
        if size != a["size"]:
            raise LogMisbehaved("a lab file from the node has the wrong size")
        return a["name"], a["media_type"], out.getvalue()

    def lab_unpublish(self, lab_id: str, item_id: str) -> None:
        """Remove an item: a new revision with `deleted` and no text. The
        author, the PI, or an admin can do it. The node deletes the text."""
        lab_id = self.roster.check_lab_id(lab_id)
        state, sk = self.writer(lab_id)
        old = self._cached_item(lab_id, item_id)
        if old["author"] != self.device.subject and not state.can(self.device.subject, "tombstone"):
            raise LabError("Your role in this lab does not permit this.")
        value = labitem.make_lab_item(
            lab_id=lab_id,
            item_id=item_id,
            rev=old["rev"] + 1,
            kind=old["kind"],
            title=old["title"],
            text="",
            author=self.device.subject,
            key=self.device.device_key(),
            roster=labfmt.roster_ref(state),
            published_at=parse_time(old["published_at"]),
            updated_at=self.device.now(),
            origin=old["origin"],
            type=old["type"],
            deleted=True,
        )
        drop = tuple(
            sk.record_id(labitem.KIND_ITEM_TEXT, labitem.part_ref(item_id, n))
            for n in range(old["text_parts"])
        )
        rec = SpaceRecord(labitem.KIND_ITEM, item_id, value, old["rev"] + 1, drop)
        self.put_record(lab_id, sk, rec)
        self.roster.labcache.put_item(lab_id, value, "")

    def lab_items(self, lab_id: str, after_rev: int = 0) -> list[dict]:
        """The live items of the lab space (from the cache, no network)."""
        lab_id = self.roster.check_lab_id(lab_id)
        return [v for v, _ in self.roster.labcache.items(lab_id) if v["rev"] > after_rev]

    def lab_item(self, lab_id: str, item_id: str) -> dict:
        """{"item": <value>, "text"} from the cache."""
        lab_id = self.roster.check_lab_id(lab_id)
        value = self._cached_item(lab_id, item_id)
        return {"item": value, "text": self.roster.labcache.item(lab_id, item_id)[1]}

    # --------------------------------------------------------------- sync

    def sync_space(self, lab_id: str, state: labfmt.LabState) -> dict:
        """Records after the cursor: items and the settings record."""
        return {"items": self._sync_records(lab_id, state), "settings": self.settings_rev(lab_id)}

    def _sync_records(self, lab_id: str, state: labfmt.LabState) -> int:
        """Read the records after the cursor. Return the number of new item
        revisions. A record that does not verify is dropped; a roster head
        that is not in the chain is a fork (`LogMisbehaved`)."""
        by_id = {sk.key_id: sk for sk in self.space_keys(lab_id).values()}
        cache = self.roster.labcache
        cursor, count = cache.cursor(lab_id), 0
        while True:
            data = self.device.http.call(
                "GET", f"/labs/{lab_id}/space/records?after={cursor}&limit=200", auth=True
            )
            try:
                recs, nxt, more = list(data["records"]), int(data["next"]), bool(data["more"])
            except (KeyError, TypeError, ValueError) as exc:
                raise LogMisbehaved("the node gave a damaged lab space answer") from exc
            for rec in recs:
                state, took = self._take_record(lab_id, state, by_id, rec)
                count += took
            if nxt > cursor:
                cursor = nxt
                cache.set_cursor(lab_id, cursor)
            if not more or not recs:
                return count

    def _take_record(
        self, lab_id: str, state: labfmt.LabState, by_id: dict, rec
    ) -> tuple[labfmt.LabState, bool]:
        """Open one record of the node and keep it if it verifies."""
        doc = rec.get("record") if isinstance(rec, dict) else None
        sk = by_id.get(doc.get("key_id")) if isinstance(doc, dict) else None
        if sk is None:
            return state, False  # an epoch that this device cannot read
        try:
            kind, ref, value = open_record(sk, doc)
        except FormatError:
            return state, False
        if kind == labitem.KIND_ITEM:
            return self._take_item(lab_id, state, by_id, ref, value)
        if kind == labsettings.KIND_SETTINGS and ref == labsettings.SETTINGS_REF:
            return self.take_settings(lab_id, state, value), False
        return state, False

    def _roster_check(self, lab_id: str, state: labfmt.LabState, ref: dict) -> labfmt.LabState:
        """The roster head that a writer saw must be in this device's chain."""
        if ref["seq"] > state.seq:
            state = self.roster.lab_state(lab_id)
            if ref["seq"] > state.seq:
                raise LogMisbehaved(
                    "a lab record names a roster that the node does not show (fork)"
                )
        if state.heads.get(ref["seq"]) != ref["head"]:
            raise LogMisbehaved("a lab record names a roster head that is not in the chain (fork)")
        return state

    def _take_item(
        self, lab_id: str, state: labfmt.LabState, by_id: dict, ref: str, value
    ) -> tuple[labfmt.LabState, bool]:
        try:
            labitem.verify_lab_item(value)
        except FormatError:
            return state, False
        if value["lab_id"] != lab_id or value["item_id"] != ref:
            return state, False
        state = self._roster_check(lab_id, state, value["roster"])
        author = value["author"]
        role = self.roster.state_at(lab_id, value["roster"]["seq"]).members.get(author)
        if role is None:
            return state, False  # not a member when it wrote the item
        if not self.roster.device_check()(
            author, value["author_device"], parse_time(value["updated_at"])
        ):
            return state, False
        got = self.roster.labcache.item(lab_id, ref)
        if not _may_take(got, value, role):
            return state, False
        text = "" if value["deleted"] else self._read_text(lab_id, by_id, value)
        if text is None:
            return state, False
        self.roster.labcache.put_item(lab_id, value, text)
        return state, True

    def _read_text(self, lab_id: str, by_id: dict, value: dict) -> str | None:
        """The text parts of an item, checked against its digest."""
        parts = []
        for n in range(value["text_parts"]):
            part = self._read_part(lab_id, by_id, labitem.part_ref(value["item_id"], n))
            if part is None:
                return None
            parts.append(part)
        text = "".join(parts)
        return text if labitem.text_digest(text) == value["text_digest"] else None

    def _read_part(self, lab_id: str, by_id: dict, ref: str) -> str | None:
        """One text part of an item, or None if it does not open."""
        ids = next(iter(by_id.values()))  # each epoch has the same record IDs
        rid = ids.record_id(labitem.KIND_ITEM_TEXT, ref)
        try:
            doc = self.device.http.call("GET", f"/labs/{lab_id}/space/records/{rid}", auth=True)[
                "record"
            ]
        except NodeHTTPError as exc:
            if exc.status == 404:
                return None
            raise
        sk = by_id.get(doc.get("key_id")) if isinstance(doc, dict) else None
        if sk is None:
            return None
        try:
            kind, got_ref, part = open_record(sk, doc)
        except FormatError:
            return None
        if kind != labitem.KIND_ITEM_TEXT or got_ref != ref or not isinstance(part, dict):
            return None
        text = part.get("text")
        return text if isinstance(text, str) else None

    # ----------------------------------------------------------- settings

    def settings_rev(self, lab_id: str) -> int:
        doc = self.roster.labcache.settings(lab_id)
        return int(doc["rev"]) if doc else 0

    def take_settings(self, lab_id: str, state: labfmt.LabState, value) -> labfmt.LabState:
        """Keep a settings record if it verifies: signature, roster head in
        the chain, monotonic `roster.seq >= max(prev_roster_seq, epoch_seq)`,
        the writer was PI or admin at `max(roster.seq, epoch_seq)`, the device
        was a key of the writer, and a higher `rev`. Else drop it."""
        try:
            labsettings.verify_settings(value)
        except FormatError:
            return state
        if value["lab_id"] != lab_id:
            return state
        state = self._roster_check(lab_id, state, value["roster"])
        prev = self.roster.labcache.settings(lab_id)
        prev_roster_seq = prev["roster"]["seq"] if prev else -1
        epoch_seq = self.roster.labcache.epoch_seq(lab_id)
        min_seq = max(prev_roster_seq, epoch_seq)
        if value["roster"]["seq"] < min_seq:
            return state
        check_seq = max(value["roster"]["seq"], epoch_seq)
        role = self.roster.state_at(lab_id, check_seq).members.get(value["updated_by"])
        if role not in (labfmt.PI, labfmt.ADMIN):
            return state
        at = parse_time(value["updated_at"])
        if not self.roster.device_check()(value["updated_by"], value["updated_device"], at):
            return state
        if value["rev"] > self.settings_rev(lab_id):
            self.roster.labcache.set_settings(lab_id, value)
        return state

    def lab_settings(self, lab_id: str) -> dict:
        """The settings of a lab from the cache, with the defaults of each
        absent section: {"rev", "updated_by", "updated_at", "sections"}."""
        lab_id = self.roster.check_lab_id(lab_id)
        self.roster.member_cache(lab_id)
        doc = self.roster.labcache.settings(lab_id)
        return {
            "rev": int(doc["rev"]) if doc else 0,
            "sections": labsettings.sections_of(doc),
            "updated_at": doc["updated_at"] if doc else None,
            "updated_by": doc["updated_by"] if doc else None,
        }

    def lab_set_settings(self, lab_id: str, changes: dict) -> dict:
        """Change one section or more (PI or admin). A section in `changes`
        replaces the old section. Return `lab_settings`."""
        lab_id = self.roster.check_lab_id(lab_id)
        if not isinstance(changes, dict) or not changes:
            raise LabError("Choose a setting to change.")
        if any(name not in labsettings.SECTIONS for name in changes):
            raise LabError("This is not a lab setting.")
        try:
            for name, value in changes.items():
                labsettings.validate_section(name, value)
        except FormatError as exc:
            raise LabError("A value of this setting is not valid.") from exc
        state, sk = self.writer(lab_id)
        if not state.can(self.device.subject, "settings"):
            raise LabError("Your role in this lab does not permit this.")
        self._sync_records(lab_id, state)
        state = self.roster.labcache.state(lab_id) or state
        old = self.roster.labcache.settings(lab_id) or {}
        sections = {n: old[n] for n in labsettings.SECTIONS if n in old}
        sections.update(changes)
        rev = self.settings_rev(lab_id) + 1
        ref = labsettings.SETTINGS_REF
        rid = sk.record_id(labsettings.KIND_SETTINGS, ref)
        for _ in range(2):
            doc = labsettings.make_settings(
                lab_id=lab_id,
                rev=rev,
                sections=sections,
                updated_by=self.device.subject,
                key=self.device.device_key(),
                roster=labfmt.roster_ref(state),
                updated_at=self.device.now(),
            )
            rec = SpaceRecord(labsettings.KIND_SETTINGS, ref, doc, rev, topic="settings")
            try:
                self.put_record(lab_id, sk, rec)
                break
            except LabError as exc:
                if not isinstance(exc.__cause__, NodeHTTPError) or exc.__cause__.status != 409:
                    raise
                try:
                    stored = self.device.http.call(
                        "GET", f"/labs/{lab_id}/space/records/{rid}", auth=True
                    ).get("record")
                except NodeHTTPError:
                    raise exc from None
                if not isinstance(stored, dict) or not isinstance(stored.get("version"), int):
                    raise
                if stored["version"] < rev:
                    raise
                rev = stored["version"] + 1
        self.roster.labcache.set_settings(lab_id, doc)
        return self.lab_settings(lab_id)

    def lab_policy(self, lab_id: str) -> LabPolicy:
        """The rules of the lab settings for sources, models, and matching
        (cache only). The client enforces them; they bind lab-space material
        only."""
        lab_id = self.roster.check_lab_id(lab_id)
        self.roster.member_cache(lab_id)
        return LabPolicy(lab_id, **labsettings.sections_of(self.roster.labcache.settings(lab_id)))


def _may_take(got: tuple | None, value: dict, role: str) -> bool:
    """The rules for a new revision of a cached item: a higher `rev`, no
    change after a removal, and only the author makes a new revision (the
    PI or an admin can also remove the item)."""
    if got is not None and (got[0]["rev"] >= value["rev"] or got[0]["deleted"]):
        return False
    if got is None or got[0]["author"] == value["author"]:
        return True
    return bool(value["deleted"]) and role in (labfmt.PI, labfmt.ADMIN)
