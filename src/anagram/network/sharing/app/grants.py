"""Grants: client vault sharing: encrypted upload, rings, grants, grant receipts,
public release, revocation, and the recipient side. See spec/vault.md.

Rules:

- Each finding version has its own random content key. Only the client sees it.
  The node gets ciphertext only.
- A grant wraps the payload (content key and opening data) to each device X25519
  key of the recipient (HPKE). The client takes device keys only from `lookup`,
  which checks log inclusion proofs. It never uses a key that the node gives
  without a proof.
- Each grant puts a salted, owner-signed receipt commitment into the log. The
  recipient gets the receipt and its log proof, so it can prove the date of the
  disclosure later.
- Access already given cannot be taken back. A revocation makes a new version
  with a new content key and grants it only to the remaining recipients.
"""

from __future__ import annotations

import io
import os
import re
import secrets
import tempfile
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from cryptography.exceptions import InvalidTag

from anagram.core.canonical import CanonicalError, canonical_json, loads_canonical
from anagram.core.crypto import aead, hpke, merkle
from anagram.core.crypto.blob import (
    DEFAULT_CHUNK_SIZE,
    BlobError,
    BlobParams,
    decrypt_bytes,
    decrypt_stream,
    encrypt_stream,
)
from anagram.core.crypto.chunked import ContentDigest, hash_bytes, hash_file
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.wraps import find_wrap, wrap_to_devices
from anagram.identity.api import Device, Directory, LogCheck, validate_lab_id, validate_subject
from anagram.local.api import Findings
from anagram.network.formats.vault import (
    GRANT_PAYLOAD_SCHEMA,
    GRANT_SCHEMA,
    PUBLIC,
    PUBLIC_RELEASE_SCHEMA,
    grant_info,
    make_grant_receipt,
    make_payload,
    receipt_commitment,
    receipt_log_entry,
    validate_payload,
    verify_grant_receipt,
)
from anagram.network.groups.app.labroster import LabRoster
from anagram.network.ports import FindingVault
from anagram.proofs.bundle import EvidenceOpening, ProofBundle
from anagram.proofs.proof import verify_bundle
from anagram.proofs.records import LINK_SUPERSEDES, Link, Opening, OpeningDocument, finding_links

if TYPE_CHECKING:
    from anagram.identity.api import SubjectKeys

COMMUNITY = "community"
_RING_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]")


class ThirdPartyWarning(ClientError):
    """Evidence holds other people's words. Grant again with an acknowledgement."""


def normalize_member(value: str, resolve: Callable[[str], str] | None = None) -> str:
    """A ring member: `community`, `public`, `lab:<lab id>`, a subject (`pid:`),
    or an ORCID iD. `resolve` maps an ORCID iD to the pid of a findable member."""
    v = value.strip()
    if v in (COMMUNITY, PUBLIC):
        return v
    try:
        if v.startswith("lab:") or v.startswith("lab-"):
            return "lab:" + validate_lab_id(v.removeprefix("lab:"))
        if v.startswith("pid:") or resolve is None:
            return validate_subject(v)
    except FormatError as exc:
        raise ClientError(f"not a ring member: {value!r} ({exc})") from exc
    return resolve(v)


def safe_name(slot: int, name: str | None) -> str:
    base = _SAFE.sub("_", Path(name or "").name)[:120] or "evidence"
    return f"{slot}-{base}"


class GrantHooks(Protocol):
    """What sharing adds to a grant (`anagram.network.sharing.app.reads.ShareHooks`).
    The composition root gives the hooks to `Grants`."""

    def extra_blobs(self, grant_id: bytes, plain: bytes) -> set[str]:
        """More blob IDs for the grant envelope. The same answer for a grant
        ID each time: the node refuses a changed blob list."""
        ...

    def read_gate(self, grant_id: str) -> str | None:
        """Called before a grant is fetched (a read receipt)."""
        ...

    def gated_call(self, grant_id: str, method: str, path: str) -> dict:
        """A receipt-gated call (retries once on 428 with a fresh receipt)."""
        ...

    def fetch_blob(self, blob_id: str, grant_id: str | None = None) -> bytes: ...


class Grants:
    """Vault sharing on this computer (layer L3): rings, upload, grants,
    public release, revocation, and the recipient side."""

    def __init__(
        self,
        device: Device,
        log: LogCheck,
        directory: Directory,
        findings: Findings,
        roster: LabRoster,
        hooks: GrantHooks,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.log = log
        self.directory = directory
        self.findings = findings
        self.roster = roster
        self.hooks = hooks

    def content_key(self, root: str) -> bytes:
        """The content key of one finding version. Made on first use."""
        key = self.device.unseal("content-key", root)
        if key is None:
            key = aead.new_key()
            self.device.seal("content-key", root, key)
        return key

    # ---------------------------------------------------------------- rings

    def ring_create(self, name: str) -> dict:
        """Add a ring outside all existing rings."""
        if not _RING_NAME.match(name) or name in (COMMUNITY, PUBLIC):
            raise ClientError("ring name: 1 to 64 letters, digits, space, _ . -")
        try:
            return self.vault.create_ring(name)
        except KeyError as exc:
            raise ClientError(str(exc)) from exc

    def ring_add(self, name: str, members: list[str]) -> dict:
        try:
            ring = self.vault.ring(name)
        except KeyError as exc:
            raise ClientError(str(exc)) from exc
        new = set(ring["members"]) | {
            normalize_member(m, self.directory.resolve_person) for m in members
        }
        self.vault.set_ring_members(name, sorted(new))
        return self.vault.ring(name)

    def ring_remove(self, name: str, members: list[str]) -> dict:
        try:
            ring = self.vault.ring(name)
        except KeyError as exc:
            raise ClientError(str(exc)) from exc
        new = set(ring["members"]) - {
            normalize_member(m, self.directory.resolve_person) for m in members
        }
        self.vault.set_ring_members(name, sorted(new))
        return self.vault.ring(name)

    def ring_list(self) -> list[dict]:
        return self.vault.rings()

    def ring_recipients(self, name: str) -> tuple[set[str], bool]:
        """Subjects of the ring and of all rings inside it, and whether `public`
        is in them. An outer ring covers the inner rings."""
        try:
            ring = self.vault.ring(name)
        except KeyError as exc:
            raise ClientError(str(exc)) from exc
        members: set[str] = set()
        for r in self.vault.rings():
            if r["position"] <= ring["position"]:
                members |= set(r["members"])
        subjects: set[str] = set()
        public = PUBLIC in members
        for m in members:
            if m == PUBLIC:
                continue
            if m == COMMUNITY:
                subjects |= set(self.device.http.call("GET", "/members", auth=True)["members"])
            elif m.startswith("lab:"):
                subjects |= self.roster.lab_members(m.removeprefix("lab:"))  # verified roster
            else:
                subjects.add(m)
        subjects.discard(self.device.subject)
        return subjects, public

    # --------------------------------------------------------------- upload

    def upload(self, ref: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> list[dict]:
        """Encrypt and upload each evidence file of a finding version that is not
        uploaded yet. Return the blob list. A file that is missing or changed since
        the commit is not uploaded (it can stay local)."""
        row = self.vault.find(ref)
        doc = self.findings.opening(row.root)
        meta = self.vault.evidence_meta(row.root)
        key = self.content_key(row.root)
        root = bytes.fromhex(row.root)
        blobs = []
        for slot, ev in enumerate(doc.evidence):
            m = meta.get(slot, {})
            if m.get("blob_id"):
                blobs.append(
                    {
                        "blob_id": m["blob_id"],
                        "chunk_size": m["chunk_size"],
                        "size": m["size"],
                        "slot": slot,
                    }
                )
                continue
            path = m.get("path")
            if not path or not Path(path).is_file():
                continue
            expected = ContentDigest.from_json(ev.fields["content"])
            if hash_file(path, expected.chunk_size).digest != expected.digest:
                continue  # the file changed after the commit
            blob_id = secrets.token_hex(16)
            with tempfile.TemporaryFile() as tmp:
                with open(path, "rb") as src:
                    size, _ = encrypt_stream(
                        src,
                        tmp,
                        content_key=key,
                        finding_root=root,
                        evidence_root=ev.root(),
                        slot=slot,
                        chunk_size=chunk_size,
                    )
                tmp.seek(0)
                self.device.http.call("PUT", f"/blobs/{blob_id}", tmp.read(), auth=True)
            self.vault.set_blob(row.root, slot, blob_id, chunk_size, size)
            blobs.append({"blob_id": blob_id, "chunk_size": chunk_size, "size": size, "slot": slot})
        return blobs

    def _uploaded(self, root: str) -> list[dict]:
        return [
            {"blob_id": m["blob_id"], "chunk_size": m["chunk_size"], "size": m["size"], "slot": s}
            for s, m in self.vault.evidence_meta(root).items()
            if m.get("blob_id")
        ]

    # ---------------------------------------------------------------- grant

    def third_party_items(self, ref: str) -> list[str]:
        row = self.vault.find(ref)
        doc = self.findings.opening(row.root)
        out = []
        for slot, m in self.vault.evidence_meta(row.root).items():
            if m["third_party"] and slot < len(doc.evidence):
                out.append(doc.evidence[slot].fields.get("name") or f"evidence {slot}")
        return out

    def third_party_gate(self, root: str, warnings_ack: bool) -> None:
        flagged = self.third_party_items(root)
        if flagged and not warnings_ack:
            raise ThirdPartyWarning(
                "this finding has evidence with other people's words (for example quoted"
                f" email): {', '.join(flagged)}. Make sure that you may share it, then"
                " try again with warnings_ack (CLI: --ack-third-party)."
            )

    def _receipt(self, root: bytes, grant_id: bytes, recipient: str) -> tuple[dict, dict]:
        """Make a grant receipt, log its commitment, and return (receipt, log proof)."""
        receipt = make_grant_receipt(
            finding_root=root,
            grant_id=grant_id,
            recipient=recipient,
            granted_at=self.device.now(),
            salt=secrets.token_bytes(32),
            key=self.device.device_key(),
        )
        entry = receipt_log_entry(receipt)
        result = self.device.node.submit(entry)
        self.log.logged(canonical_json(entry), result)
        log = {
            "checkpoint": result["checkpoint"],
            "entry": entry,
            "inclusion": result["inclusion"],
            "leaf_index": result["leaf_index"],
            "tree_size": result["tree_size"],
        }
        return receipt, log

    def _payload(self, row, blobs, recipient: str, receipt: dict, log: dict, schema: str):
        return make_payload(
            schema=schema,
            owner=self.device.subject,
            recipient=recipient,
            finding_id=row.finding_id,
            version=row.version,
            content_key=self.content_key(row.root),
            opening=self.findings.opening(row.root).to_json(),
            bundle=self.findings.public_bundle(row.root).to_json(),
            blobs=blobs,
            receipt=receipt,
            receipt_log=log,
        )

    def grant(
        self,
        ref: str,
        ring: str | None = None,
        recipients: list[str] | tuple = (),
        warnings_ack: bool = False,
        upload: bool = True,
    ) -> dict:
        """Grant one finding version to a ring (and the rings inside it) and to
        extra recipients. Return {"granted": [...], "skipped": [...], "public": id}.

        All device keys are looked up (with log proofs) before anything is sent.
        A key that the log does not prove stops the whole grant."""
        row = self.vault.find(ref)
        self.third_party_gate(row.root, warnings_ack)
        subjects: set[str] = {
            normalize_member(r, self.directory.resolve_person) for r in recipients
        }
        public = PUBLIC in subjects
        subjects.discard(PUBLIC)
        if ring is not None:
            ring_subjects, ring_public = self.ring_recipients(ring)
            subjects |= ring_subjects
            public = public or ring_public
        subjects.discard(self.device.subject)
        states: dict[str, SubjectKeys] = {}
        skipped = []
        for s in sorted(subjects):
            try:
                states[s] = self.directory.lookup(s)
            except LogMisbehaved:
                raise
            except ClientError:
                skipped.append(s)  # no active keys: the person has not joined
        blobs = self.upload(row.root) if upload else self._uploaded(row.root)
        granted = []
        for s, state in states.items():
            granted.append(self._grant_to(row, blobs, s, list(state.devices.values())))
        release = None
        if public:
            release = self.publish(row.root, upload=upload, warnings_ack=warnings_ack)
            release = release["release_id"]
        return {"granted": granted, "public": release, "skipped": skipped}

    def _grant_to(self, row, blobs: list[dict], recipient: str, devices: list[dict]) -> dict:
        grant_id = secrets.token_bytes(16)
        receipt, log = self._receipt(bytes.fromhex(row.root), grant_id, recipient)
        payload = self._payload(row, blobs, recipient, receipt, log, GRANT_PAYLOAD_SCHEMA)
        plain = canonical_json(payload)
        self.device.seal("grant-payload", grant_id.hex(), plain)
        self._post_grant(grant_id, recipient, blobs, devices, plain)
        self.vault.add_grant_sent(
            grant_id.hex(),
            row.root,
            recipient,
            [d["ed25519"] for d in devices],
            receipt["granted_at"],
        )
        return {"devices": len(devices), "grant_id": grant_id.hex(), "recipient": recipient}

    def _post_grant(self, grant_id, recipient, blobs, devices, plain: bytes) -> None:
        doc = {
            "blobs": sorted(
                {b["blob_id"] for b in blobs} | self.hooks.extra_blobs(grant_id, plain)
            ),
            "grant_id": grant_id.hex(),
            "recipient": recipient,
            "schema": GRANT_SCHEMA,
            "wraps": wrap_to_devices(plain, devices, lambda d: grant_info(grant_id, d)),
        }
        self.device.http.call("POST", "/grants", {"grant": doc}, auth=True)

    def sync_grants(self) -> list[str]:
        """Wrap each sent grant again for new devices of its recipient. Run it
        from time to time (the owner's device must be on). Return the grant IDs
        that changed."""
        changed = []
        for g in self.vault.grants_sent():
            try:
                state = self.directory.lookup(g["recipient"])
            except LogMisbehaved:
                raise
            except ClientError:
                continue
            devices = sorted(state.devices)
            if devices == g["devices"]:
                continue
            plain = self.device.unseal("grant-payload", g["grant_id"])
            if plain is None:
                continue
            blobs = loads_canonical(plain)["blobs"]
            gid = bytes.fromhex(g["grant_id"])
            self._post_grant(gid, g["recipient"], blobs, list(state.devices.values()), plain)
            self.vault.add_grant_sent(
                g["grant_id"], g["root"], g["recipient"], devices, g["created_at"]
            )
            changed.append(g["grant_id"])
        return changed

    def publish(self, ref: str, upload: bool = True, warnings_ack: bool = False) -> dict:
        """Publish the content key and the opening data of one finding version.
        Anyone can then read and verify it. This cannot be taken back."""
        row = self.vault.find(ref)
        self.third_party_gate(row.root, warnings_ack)
        blobs = self.upload(row.root) if upload else self._uploaded(row.root)
        grant_id = secrets.token_bytes(16)
        receipt, log = self._receipt(bytes.fromhex(row.root), grant_id, PUBLIC)
        release = self._payload(row, blobs, PUBLIC, receipt, log, PUBLIC_RELEASE_SCHEMA)
        self.device.http.call("POST", "/public", {"release": release}, auth=True)
        self.vault.add_grant_sent(grant_id.hex(), row.root, PUBLIC, [], receipt["granted_at"])
        return {"release_id": grant_id.hex()}

    def revoke(self, ref: str, ring: str | None = None, recipients=(), **kw) -> dict:
        """Make a new version (new content key) from the same files and grant it
        only to `ring` and `recipients`. Earlier versions stay readable by the
        people who got them: access already given cannot be taken back."""
        row = self.vault.find(ref)
        doc = self.findings.opening(row.root)
        meta = self.vault.evidence_meta(row.root)
        paths, flags = [], []
        for slot in range(len(doc.evidence)):
            m = meta.get(slot, {})
            if not m.get("path") or not Path(m["path"]).is_file():
                raise ClientError(f"evidence {slot} is not on this device; cannot re-version")
            paths.append(m["path"])
            flags.append(m.get("third_party", False))
        links = [link for link in finding_links(doc.finding.fields) if link.type != LINK_SUPERSEDES]
        links.append(Link(LINK_SUPERSEDES, bytes.fromhex(row.root)))
        bundle = self.findings.commit_finding(
            paths, claim=doc.finding.fields.get("claim"), links=links, third_party=flags
        )
        new_root = bundle.subject.root.hex()
        out = self.grant(new_root, ring=ring, recipients=list(recipients), **kw)
        out["root"] = new_root
        return out

    # ------------------------------------------------------------ recipient

    def inbox(self) -> list[dict]:
        """Grants for me that have a wrap for this device."""
        me = self.device.my_device()["ed25519"]
        out = []
        for g in self.device.http.call("GET", "/grants", auth=True)["grants"]:
            doc = g["grant"]
            out.append(
                {
                    "blobs": len(doc["blobs"]),
                    "for_this_device": find_wrap(doc["wraps"], me) is not None,
                    "grant_id": doc["grant_id"],
                    "received_at": g["created_at"],
                    "sender": g["sender"],
                }
            )
        return out

    def open_grant(self, grant_id: str, out_dir: str | Path) -> dict:
        """Decrypt a grant, check it, decrypt its files into `out_dir`, and verify
        the finding proof with the opened data."""
        return self.verify_payload(self.fetch_payload(grant_id)[0], out_dir)

    def fetch_payload(self, grant_id: str) -> tuple[dict, dict]:
        """Fetch (after a read receipt), decrypt, and check the payload of a
        grant to me. Return (payload, envelope)."""
        self.hooks.read_gate(grant_id)  # a read receipt before the fetch
        g = self.hooks.gated_call(
            grant_id, "GET", f"/grants/{urllib.parse.quote(grant_id, safe='')}"
        )["grant"]
        if not isinstance(g, dict) or g.get("grant_id") != grant_id:
            raise ClientError("grant envelope does not match the requested grant ID")
        me = self.device.my_device()["ed25519"]
        ct = find_wrap(g["wraps"], me)
        if ct is None:
            raise ClientError("this grant has no key for this device; ask the owner to sync")
        try:
            plain = hpke.open_sealed(
                hpke.private_from_bytes(self.device.x25519_key().private_bytes()),
                ct,
                grant_info(bytes.fromhex(g["grant_id"]), bytes.fromhex(me)),
            )
            payload = validate_payload(loads_canonical(plain), GRANT_PAYLOAD_SCHEMA)
        except (InvalidTag, CanonicalError, FormatError, ValueError) as exc:
            raise ClientError(f"grant does not open: {exc}") from exc
        if payload["recipient"] != self.device.subject:
            raise ClientError("grant payload is for another person")
        if payload["receipt"]["grant_id"] != g["grant_id"]:
            raise ClientError("grant payload does not match the grant")
        return payload, g

    def open_release(self, release_id: str, out_dir: str | Path) -> dict:
        """Read and verify a public release. It needs no grant."""
        doc = self.device.http.call("GET", f"/public/{urllib.parse.quote(release_id, safe='')}")
        try:
            payload = validate_payload(doc, PUBLIC_RELEASE_SCHEMA)
        except FormatError as exc:
            raise ClientError(f"bad public release: {exc}") from exc
        return self.verify_payload(payload, out_dir)

    def verify_payload(self, payload: dict, out_dir: str | Path | None, *, sink=None) -> dict:
        """Check a payload and its files. Without `sink`, write the files into
        `out_dir`. With `sink(slot, evidence, ciphertext, plaintext)`, write
        nothing to disk (the received store)."""
        bundle, doc = _opening_of(payload)
        root = doc.finding.root()
        fields = doc.finding.fields

        # The owner: the signing device keys must be (or have been) the owner's.
        owner_keys = self.directory.keys_ever(payload["owner"])
        if bundle.subject.owner_key.hex() not in owner_keys:
            raise ClientError("the finding is not signed by a device key of the owner")
        receipt, log = payload["receipt"], payload["receipt_log"]
        self._check_receipt(receipt, log, root, owner_keys)

        # Files: decrypt each blob and compare it with the committed digest.
        out = Path(out_dir) if out_dir is not None else None
        if sink is None:
            if out is None:
                raise ClientError("verify_payload needs out_dir or a sink")
            out.mkdir(parents=True, exist_ok=True)
        key = bytes.fromhex(payload["content_key"])
        files = []
        for b in payload["blobs"]:
            slot = b["slot"]
            if slot >= len(doc.evidence):
                raise ClientError("blob for an evidence slot that does not exist")
            ev = doc.evidence[slot]
            data = self.hooks.fetch_blob(b["blob_id"], receipt["grant_id"])
            blob = _Blob(data, key, root, ev, slot, b["chunk_size"])
            if sink is not None:
                sink(slot, ev, data, blob.plaintext())
            else:
                files.append(str(blob.write(out)))

        # Verify the finding proof with all fields opened and the files.
        full = _full_bundle(bundle, doc)
        report = verify_bundle(full, self.device.trust(), files=files)
        if not report.ok:
            raise ClientError("finding proof does not verify:\n" + report.summary())
        if sink is None:
            (out / "proof.json").write_text(full.dumps() + "\n")
            (out / "receipt.json").write_text(
                canonical_json({"log": log, "receipt": receipt}).decode() + "\n"
            )
        return {
            "claim": fields.get("claim"),
            "files": files,
            "finding_id": payload["finding_id"],
            "granted_at": receipt["granted_at"],
            "not_after": report.not_after.isoformat() if report.not_after else None,
            "owner": payload["owner"],
            "receipt_commitment": receipt_commitment(receipt).hex(),
            "root": root.hex(),
            "verified": True,
            "version": payload["version"],
        }

    def _check_receipt(self, receipt: dict, log: dict, root: bytes, owner_keys: set) -> None:
        """Check the grant receipt: the owner signature, the commitment, and
        the inclusion in the log."""
        try:
            verify_grant_receipt(receipt)
        except FormatError as exc:
            raise ClientError(str(exc)) from exc
        if receipt["sender_key"] not in owner_keys or receipt["finding_root"] != root.hex():
            raise ClientError("grant receipt is not from the owner for this finding")
        entry = receipt_log_entry(receipt)
        if log.get("entry") != entry:
            raise ClientError("grant receipt log entry does not match")
        cp = self.log.old_checkpoint(log["checkpoint"])
        path = [bytes.fromhex(h) for h in log["inclusion"]]
        if log["tree_size"] != cp.size or not merkle.verify_inclusion(
            merkle.leaf_hash(canonical_json(entry)), log["leaf_index"], cp.size, path, cp.root
        ):
            raise LogMisbehaved("grant receipt is not in the log")


def _opening_of(payload: dict) -> tuple[ProofBundle, OpeningDocument]:
    """The proof bundle and the opening document of a grant payload. The
    opening must match the finding proof and give each evidence opening."""
    try:
        bundle = ProofBundle.from_json(payload["bundle"])
        doc = OpeningDocument.from_json(payload["opening"])
    except (FormatError, KeyError, TypeError, ValueError) as exc:
        raise ClientError(f"bad grant payload: {exc}") from exc
    fields = doc.finding.fields
    if (
        doc.finding.root() != bundle.subject.root
        or fields.get("finding_id") != payload["finding_id"]
        or fields.get("version") != payload["version"]
    ):
        raise ClientError("opening does not match the finding proof")
    for slot, ev in enumerate(doc.evidence):
        if fields.get(f"evidence.{slot}") != ev.root().hex():
            raise ClientError("evidence opening does not match the finding")
    if fields.get("evidence_count") != len(doc.evidence):
        raise ClientError("evidence openings are missing")
    return bundle, doc


def _full_bundle(bundle: ProofBundle, doc: OpeningDocument) -> ProofBundle:
    """The proof bundle with all fields of the finding and the evidence opened."""
    return ProofBundle(
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


class _Blob:
    """One encrypted evidence blob of a grant. Each read checks the plaintext
    against the committed digest."""

    def __init__(
        self, data: bytes, key: bytes, root: bytes, ev: Opening, slot: int, chunk_size: int
    ) -> None:
        self.data = data
        self.slot = slot
        self.ev = ev
        self.args: BlobParams = {
            "content_key": key,
            "finding_root": root,
            "evidence_root": ev.root(),
            "slot": slot,
            "chunk_size": chunk_size,
        }
        self.expected = ContentDigest.from_json(ev.fields["content"])

    def _mismatch(self) -> ClientError:
        return ClientError(f"evidence {self.slot}: decrypted file is not the committed file")

    def plaintext(self) -> bytes:
        """Decrypt the blob in memory."""
        try:
            plain = decrypt_bytes(self.data, **self.args)
        except BlobError as exc:
            raise ClientError(f"evidence {self.slot}: {exc}") from exc
        if hash_bytes(plain, self.expected.chunk_size).digest != self.expected.digest:
            raise self._mismatch()
        return plain

    def write(self, out: Path) -> Path:
        """Decrypt the blob into a file in `out` (atomic). Return its path."""
        target = out / safe_name(self.slot, self.ev.fields.get("name"))
        fd, tmp_name = tempfile.mkstemp(dir=out, prefix=".part-")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as dst:
                decrypt_stream(io.BytesIO(self.data), dst, **self.args)
            if hash_file(tmp, self.expected.chunk_size).digest != self.expected.digest:
                raise self._mismatch()
            os.replace(tmp, target)
        except BlobError as exc:
            raise ClientError(f"evidence {self.slot}: {exc}") from exc
        finally:
            if tmp.exists():
                tmp.unlink()
        return target
