"""The owner's read records and share history
(`ReadRecords`, `Client.read_records`, layer L3). See spec/vault.md
sections 13 and 16.

- `sync_reads` fetches the read receipts and the node fetch events of the
  grants of this person and checks each one on this computer (reader key
  history from the log, log inclusion, node signature, `seq` gaps);
- `history` gives one row for each finding and target;
- `share_record` is the "Export record" of one finding and one person.

The reader side of read receipts is `anagram.network.sharing.app.reads`.
"""

from __future__ import annotations

from anagram.core.canonical import canonical_json, loads_canonical
from anagram.core.crypto import merkle
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import format_time
from anagram.identity.api import Device, Directory, LogCheck, is_subject
from anagram.local.api import Findings
from anagram.network.formats.sharing import (
    read_receipt_id,
    read_receipt_log_entry,
    seq_gaps,
    verify_fetch_event,
    verify_read_receipt,
)
from anagram.network.formats.vault import receipt_commitment
from anagram.network.ports import FindingVault
from anagram.network.sharing.app.invites import invite_label
from anagram.network.sharing.app.received import TITLE_MAX
from anagram.network.sharing.app.tables import INVITE_TARGET, LAB_TARGET, ShareStore

HISTORY_STATES = ("waiting", "delivered", "read", "stopped")
SHARE_RECORD_SCHEMA = "anagram.share_record.v1"  # "Export record" (spec/vault.md section 16)


class ReadRecords:
    """Read records and the share history of the owner on this computer
    (layer L3)."""

    def __init__(
        self,
        device: Device,
        log: LogCheck,
        directory: Directory,
        findings: Findings,
        store: ShareStore,
        vault: FindingVault,
    ) -> None:
        self.device = device
        self.vault = vault
        self.store = store
        self.log = log
        self.directory = directory
        self.findings = findings

    # ------------------------------------------------------- read records

    def _check_receipt(self, item: dict, sent: dict) -> str | None:
        """Check one read receipt of a grant that this person sent. Return
        None if all checks pass, else a short reason (an anomaly)."""
        receipt, log = item.get("receipt"), item.get("log") or {}
        try:
            verify_read_receipt(receipt)
        except FormatError:
            return "bad_signature"
        g = sent.get(receipt["grant_id"])
        if g is None or g["recipient"] != receipt["reader"]:
            return "not_my_grant"
        if receipt["reader_key"] not in self.directory.keys_ever(receipt["reader"]):
            return "unknown_reader_key"
        entry = read_receipt_log_entry(receipt)
        if log.get("entry") != entry:
            return "log_entry_mismatch"
        try:
            cp = self.log.old_checkpoint(log["checkpoint"])
            path = [bytes.fromhex(h) for h in log["inclusion"]]
            ok = log["tree_size"] == cp.size and merkle.verify_inclusion(
                merkle.leaf_hash(canonical_json(entry)), log["leaf_index"], cp.size, path, cp.root
            )
        except (KeyError, TypeError, ValueError):
            ok = False
        return None if ok else "not_in_log"

    def sync_reads(self) -> list[dict]:
        """Fetch the read receipts and fetch events of my grants, check them,
        and store them. Return the changes:
        `{"kind": "read", "grant_id", "root", "reader", "read_at", "reads"}` and
        `{"kind": "anomaly", "grant_id", "root", "reader", "detail"}`."""
        cfg = self.device.identity_config()
        assertion_key = bytes.fromhex(cfg["assertion_key"])
        sent = {g["grant_id"]: g for g in self.vault.grants_sent()}
        cursor = int(self.store.reads_cursor.get() or 0)
        changes: list[dict] = []
        touched: set[str] = set()
        while True:
            try:
                page = self.device.http.call("GET", f"/grants/sent/reads?since={cursor}", auth=True)
            except NodeHTTPError as exc:
                if exc.status == 404:
                    return changes  # the node has no read ledger
                raise
            for item in page["receipts"]:
                changes.extend(self._store_receipt(item, sent))
            for ev in page["events"]:
                try:
                    verify_fetch_event(ev, assertion_key, cfg["node_key"])
                except FormatError:
                    changes.append(self._anomaly(sent, ev.get("grant_id"), None, "bad_event"))
                    continue
                if ev["grant_id"] not in sent:
                    continue
                self.store.add_fetch_event(ev)
                touched.add(ev["grant_id"])
            cursor = int(page["cursor"])
            self.store.reads_cursor.set("", str(cursor))
            if not page.get("more"):
                break
        for gid in sorted(touched):
            gaps = seq_gaps([e["seq"] for e in self.store.fetch_events_of(gid)])
            if gaps:
                changes.append(self._anomaly(sent, gid, None, "event_gap", missing=gaps))
        return changes

    def _anomaly(self, sent, grant_id, reader, detail, **extra) -> dict:
        g = sent.get(grant_id) or {}
        root = g.get("root")
        row = self.vault.get(root) if root else None
        if row is not None:
            self.store.add_share_event(
                finding_id=row.finding_id,
                root=root,
                person=reader or g.get("recipient"),
                target=g.get("recipient") or "unknown",
                kind="anomaly",
                at=format_time(self.device.now()),
                detail={"grant_id": grant_id, "reason": detail, **extra},
            )
        return {
            "detail": detail,
            "grant_id": grant_id,
            "kind": "anomaly",
            "reader": reader or g.get("recipient"),
            "root": root,
            **extra,
        }

    def _store_receipt(self, item: dict, sent: dict) -> list[dict]:
        receipt = item.get("receipt") or {}
        try:
            rid = read_receipt_id(receipt)
        except (TypeError, ValueError):
            return [self._anomaly(sent, None, None, "bad_receipt")]
        if self.store.has_read(rid):
            return []
        try:
            reason = self._check_receipt(item, sent)
        except LogMisbehaved:
            reason = "log_misbehaved"
        except ClientError:
            reason = "unknown_reader_key"
        gid = receipt.get("grant_id")
        if reason is not None:
            return [self._anomaly(sent, gid, receipt.get("reader"), reason)]
        g = sent[gid]
        self.store.add_read(rid, g["root"], receipt, item["log"])
        row = self.vault.get(g["root"])
        if row is not None:
            self.store.add_share_event(
                finding_id=row.finding_id,
                root=g["root"],
                person=receipt["reader"],
                target=receipt["reader"],
                kind="read",
                at=receipt["read_at"],
                detail={"grant_id": gid, "receipt_id": rid},
            )
        count = len(self.store.reads_of(grant_id=gid))
        return [
            {
                "grant_id": gid,
                "kind": "read",
                "read_at": receipt["read_at"],
                "reader": receipt["reader"],
                "reads": count,
                "root": g["root"],
            }
        ]

    # ------------------------------------------------- history (section 8.4)

    def _finding_title(self, root: str) -> str:
        claim = (self.findings.opening(root).finding.fields.get("claim") or "").strip()
        first = claim.splitlines()[0][:TITLE_MAX] if claim else ""
        return first or f"Finding {root[:12]}"

    def history(self, *, finding_id: str | None = None, person: str | None = None) -> list[dict]:
        """One row for each finding and target (a person, my lab, or an
        invited person): state, reads, events, evidence. A person who got a
        grant with no share row (a ring or CLI grant) has a row too.
        Plan section 8.4; the label of a member is for the UI to add."""
        versions: dict[str, list] = {}
        for r in self.vault.list():
            versions.setdefault(r.finding_id, []).append(r)
        fid_of = {r.root: f for f, rows in versions.items() for r in rows}
        sent = self.vault.grants_sent()
        pairs: dict[tuple[str, str], dict | None] = {}
        for sh in self.store.shares_of():
            pairs[(sh["finding_id"], sh["target"])] = sh
        for g in sent:
            fid = fid_of.get(g["root"])
            if fid and is_subject(g["recipient"]):
                pairs.setdefault((fid, g["recipient"]), None)
        reads = self.store.reads_of()
        out, titles = [], {}
        for (fid, target), sh in pairs.items():
            if fid not in versions or (finding_id is not None and fid != finding_id):
                continue
            if person is not None and target != person:
                continue
            rows = sorted(versions[fid], key=lambda r: r.version)
            if fid not in titles:
                titles[fid] = self._finding_title(rows[-1].root)
            out.append(self._history_row(fid, target, sh, rows, sent, reads, titles[fid]))
        return sorted(out, key=lambda h: (h["shared_at"] or "", h["target"]), reverse=True)

    def _target_kind(self, target: str) -> tuple[str, str | None]:
        """(kind, label) of a share target: "lab", "invite" (label: the
        contact, if this computer made the invite), or "member"."""
        if target.startswith(LAB_TARGET):
            return "lab", None
        if target.startswith(INVITE_TARGET):
            got = invite_label(self.device, target.removeprefix(INVITE_TARGET))
            return "invite", got["contact"]["value"] if got else None
        return "member", None

    def _grant_receipt(self, grants: list[dict]) -> str | None:
        """The commitment of the grant receipt of the last grant."""
        if not grants:
            return None
        plain = self.device.unseal("grant-payload", grants[-1]["grant_id"])
        if plain is None:
            return None
        return receipt_commitment(loads_canonical(plain)["receipt"]).hex()

    def _history_row(self, fid, target, sh, rows, sent, all_reads, title) -> dict:
        roots = {r.root for r in rows}
        grants = [g for g in sent if g["root"] in roots and g["recipient"] == target]
        reads = sorted(
            (rd for rd in all_reads if rd["root"] in roots and rd["reader"] == target),
            key=lambda rd: rd["read_at"],
        )
        events = [
            {"at": e["at"], "detail": e["detail"], "kind": e["kind"]}
            for e in self.store.share_events(finding_id=fid)
            if e["target"] == target or e["person"] == target
        ]
        kind, label = self._target_kind(target)
        latest = rows[-1]
        return {
            "devices": len({rd["reader_key"] for rd in reads}),
            "events": events,
            "evidence": {
                "grant_receipt": self._grant_receipt(grants),
                "read_receipts": [rd["receipt_id"] for rd in reads],
            },
            "finding": {"id": fid, "root": latest.root, "title": title, "version": latest.version},
            "first_read_at": reads[0]["read_at"] if reads else None,
            "last_read_at": reads[-1]["read_at"] if reads else None,
            "person": {
                "kind": kind,
                "label": label,
                "subject": target if is_subject(target) else None,
            },  # fmt: skip
            "reads": len(reads),
            "shared_at": sh["created_at"] if sh else (grants[0]["created_at"] if grants else None),
            "state": _history_state(sh, kind, reads, grants),
            "target": target,
        }

    def share_record(self, finding_id: str, subject: str) -> dict:
        """ "Export record": the grant receipts, the read receipts with their
        log proofs, and the node fetch events of one finding and one person
        (spec/vault.md section 16). A person can check it against the log."""
        roots = {r.root for r in self.vault.list() if r.finding_id == finding_id}
        if not roots:
            raise ClientError("unknown finding")
        reads = [rd for rd in self.store.reads_of()
                 if rd["root"] in roots and rd["reader"] == subject]  # fmt: skip
        gids = {g["grant_id"] for g in self.vault.grants_sent()
                if g["root"] in roots and g["recipient"] == subject}  # fmt: skip
        gids |= {rd["grant_id"] for rd in reads}
        grants = []
        for gid in sorted(gids):
            plain = self.device.unseal("grant-payload", gid)
            if plain is None:
                continue
            p = loads_canonical(plain)
            grants.append({"grant_id": gid, "log": p["receipt_log"], "receipt": p["receipt"],
                           "root": p["receipt"]["finding_root"]})  # fmt: skip
        return {
            "fetch_events": [ev for gid in sorted(gids) for ev in self.store.fetch_events_of(gid)],
            "finding_id": finding_id,
            "grants": grants,
            "person": subject,
            "reads": [{"log": rd["log"], "receipt": rd["receipt"]} for rd in reads],
            "schema": SHARE_RECORD_SCHEMA,
        }


def _history_state(sh: dict | None, kind: str, reads: list, grants: list) -> str:
    """One of `HISTORY_STATES`."""
    if sh is not None and sh["state"] == "stopped":
        return "stopped"
    if kind == "lab":
        return "delivered"
    if reads:
        return "read"
    if grants:
        return "delivered"
    return "waiting"
