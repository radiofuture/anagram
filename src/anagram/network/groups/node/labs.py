"""Lab unit on the node.

The node stores and orders the signed roster of each lab (`formats.lab`). It
applies each new entry with the same function as the clients, so it refuses
an entry that a client would refuse. It cannot make an entry: it has no
member device key and no invite seed.

Access to a lab comes only from the roster (the state in memory, built from
the table `lab_roster`). `LabDirectory` (`labdirectory`, tables `labs` and
`lab_members`) is a cache for counts, `labs_of`, and the matching operator.
A row in the cache gives no access. `LabService` writes it from the verified
roster.

Each refusal for a person who is not in the lab is `404` (the same answer as
for a lab that does not exist).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.errors import Conflict, Forbidden, FormatError, NodeError, NotFound
from anagram.core.shared_db import SharedDB
from anagram.core.timefmt import parse_time
from anagram.identity.api import (
    IdentityDirectory,
    QuotaExceeded,
    record_size,
    validate_lab_id,
    validate_record,
)
from anagram.network.formats import lab as labfmt
from anagram.network.formats import labkey
from anagram.network.groups.node.labdirectory import LabDirectory
from anagram.network.ports import AdmissionCheck

DEFAULT_LAB_QUOTA = 2048 << 20  # 2 GiB of ciphertext for each lab
MAX_LAB_RECORDS = 100_000
TOPICS = ("members", "invites", "keys", "space", "settings")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_roster (lab_id TEXT NOT NULL, seq INTEGER NOT NULL,
    entry TEXT NOT NULL, hash TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (lab_id, seq));
CREATE TABLE IF NOT EXISTS lab_invites (invite_id TEXT PRIMARY KEY, lab_id TEXT NOT NULL,
    auth TEXT NOT NULL, expires_at INTEGER NOT NULL, max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS lab_keys (lab_id TEXT NOT NULL, epoch INTEGER NOT NULL,
    recipient TEXT NOT NULL, doc TEXT NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY (lab_id, epoch, recipient));
CREATE TABLE IF NOT EXISTS lab_records (lab_id TEXT NOT NULL, record_id TEXT NOT NULL,
    version INTEGER NOT NULL, size INTEGER NOT NULL, doc TEXT NOT NULL, author TEXT NOT NULL,
    change INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (lab_id, record_id));
CREATE TABLE IF NOT EXISTS lab_blobs (lab_id TEXT NOT NULL, blob_id TEXT NOT NULL,
    record_id TEXT NOT NULL, PRIMARY KEY (lab_id, blob_id));
CREATE TABLE IF NOT EXISTS lab_changes (change INTEGER PRIMARY KEY AUTOINCREMENT,
    lab_id TEXT NOT NULL, topic TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS lab_host (lab_id TEXT PRIMARY KEY, quota INTEGER NOT NULL,
    suspended INTEGER NOT NULL DEFAULT 0);
-- `lab_roles` was a second cache of the members that nothing read.
DROP TABLE IF EXISTS lab_roles;
"""


class LabService:
    """The labs of this node (layer L3): the roster chains, the key
    packages, the lab space records, and the changes that clients wait for."""

    def __init__(
        self,
        db_path: str | Path,
        identity: IdentityDirectory,
        directory: LabDirectory,
        may_create: Callable[[str], bool],
        admission_check: AdmissionCheck,
        vault=None,
        quota: int = DEFAULT_LAB_QUOTA,
    ) -> None:
        """`directory`: the cache of lab names and members that this service
        writes. `may_create(subject)`: may this node member start a lab? The
        admission policy of the node gives it (L4,
        `anagram.admission.node.service.group_creation`). `admission_check`: the
        checks of the `invite` and `join` roster entries (L4,
        `anagram.admission.check.GroupAdmission`)."""
        self.identity = identity
        self.directory = directory
        self.admission_check = admission_check
        self.vault = vault
        self.quota = quota
        self.may_create = may_create
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)
        self._states: dict[str, labfmt.LabState] = {}
        self._load()

    # ------------------------------------------------------------ helpers

    def _one(self, sql: str, *args):
        return self._db.execute(sql, args).fetchone()

    def now(self) -> int:
        return self.identity.now()

    def _device_ok(self, subject: str, device: str, at: datetime) -> bool:
        """A new entry needs a device that is active now (the node view)."""
        return device in self.identity.active_devices(subject)

    def _auths(self, lab_id: str) -> dict[str, dict]:
        return {
            iid: json.loads(auth)
            for iid, auth in self._db.execute(
                "SELECT invite_id, auth FROM lab_invites WHERE lab_id = ?", (lab_id,)
            )
        }

    def _load(self) -> None:
        """Build the state of each lab from the stored chain. Each entry was
        checked when the node took it, so the device check is not run again
        (a device that was removed later signed it when it was active)."""
        labs = [r[0] for r in self._db.execute("SELECT DISTINCT lab_id FROM lab_roster")]
        for lab_id in labs:
            entries = [
                json.loads(e)
                for (e,) in self._db.execute(
                    "SELECT entry FROM lab_roster WHERE lab_id = ? ORDER BY seq", (lab_id,)
                )
            ]
            self._states[lab_id] = labfmt.replay(
                lab_id,
                entries,
                lambda *_: True,
                self._auths(lab_id),
                admission=self.admission_check,
            )

    def state(self, lab_id: str) -> labfmt.LabState:
        try:
            validate_lab_id(lab_id)
        except FormatError as exc:
            raise NotFound("unknown lab") from exc
        state = self._states.get(lab_id)
        if state is None:
            raise NotFound("unknown lab")
        return state

    def member_state(self, subject: str, lab_id: str) -> labfmt.LabState:
        """The state of a lab for a person in it. A person outside the lab
        gets the answer of an unknown lab."""
        self.identity.require_member(subject)
        state = self.state(lab_id)
        if subject not in state.members:
            raise NotFound("unknown lab")
        return state

    def _change(self, lab_id: str, topic: str) -> int:
        cur = self._db.execute(
            "INSERT INTO lab_changes (lab_id, topic, at) VALUES (?, ?, ?)",
            (lab_id, topic, self.now()),
        )
        self._changed.notify_all()
        return int(cur.lastrowid)

    def _store_entry(self, state: labfmt.LabState, entry: dict, old_members: dict) -> None:
        """Write one applied entry, the caches, and the change rows."""
        lab_id = state.lab_id
        self._db.execute(
            "INSERT INTO lab_roster (lab_id, seq, entry, hash, at) VALUES (?, ?, ?, ?, ?)",
            (lab_id, entry["seq"], canonical_json(entry).decode(), state.head, self.now()),
        )
        self.directory.put(lab_id, state.name, state.pi(), list(state.members), self.now())
        if entry["op"] in ("invite", "revoke_invite", "join", "remove"):
            self._sync_invites(state)
            self._change(lab_id, "invites")
        if state.members != old_members or entry["op"] in ("rename", "create", "close"):
            self._change(lab_id, "members")

    def _sync_invites(self, state: labfmt.LabState) -> None:
        for iid, inv in state.invites.items():
            self._db.execute(
                "UPDATE lab_invites SET uses = ?, revoked = ? WHERE invite_id = ?",
                (inv["uses"], int(inv["revoked"]), iid),
            )

    def apply(self, state: labfmt.LabState, entry: dict, auths=None) -> labfmt.LabState:
        """Apply on a copy. A stale `seq` or `prev` is a conflict (the client
        pulls and tries again); each other fault is a bad request."""
        if not isinstance(entry, dict):
            raise NodeError("entry: expected an object")
        if entry.get("seq") != state.seq + 1 or entry.get("prev") != state.head:
            raise Conflict("the roster has a newer entry; read the roster and try again")
        trial = state.copy()
        try:
            trial.apply(entry, self._device_ok, auths)
        except (FormatError, KeyError, TypeError, ValueError) as exc:
            raise NodeError(f"roster entry refused: {exc}") from exc
        return trial

    # ------------------------------------------------------------- create

    def create(self, subject: str, entry: dict) -> dict:
        self.identity.require_member(subject)
        if not self.may_create(subject):
            raise Forbidden("To start a lab on this node, ask the node organizer for an invite.")
        try:
            labfmt.validate_roster_entry(entry, self.admission_check)
        except FormatError as exc:
            raise NodeError(f"roster entry refused: {exc}") from exc
        if entry["op"] != "create" or entry["actor"] != subject:
            raise NodeError("a new lab starts with your own create entry")
        lab_id = entry["lab_id"]
        with self._lock:
            if lab_id in self._states:
                raise Conflict("a lab with this ID exists")
            # A lab from before the roster has a row in the cache only.
            if self.directory.pi(lab_id) not in (None, subject):
                raise Conflict("a lab with this ID exists")
            state = self.apply(labfmt.LabState(lab_id, admission=self.admission_check), entry)
            self._states[lab_id] = state
            self._db.execute(
                "INSERT OR IGNORE INTO lab_host (lab_id, quota) VALUES (?, ?)", (lab_id, self.quota)
            )
            self._store_entry(state, entry, {})
        return {"head": state.head, "lab_id": lab_id, "name": state.name, "seq": state.seq}

    # ------------------------------------------------------------- roster

    def submit_entry(self, subject: str, lab_id: str, entry: dict) -> dict:
        """A signed entry of a member (each op except `create`, `join`, and
        `invite`; an invite comes with its authorisation, through
        `AdmissionService.put_lab_invite`)."""
        with self._lock:
            state = self.member_state(subject, lab_id)
            if not isinstance(entry, dict) or entry.get("actor") != subject:
                raise Forbidden("you can send only your own roster entries")
            if entry.get("op") in ("create", "join", "invite"):
                raise NodeError("this op has its own route")
            if entry.get("op") == "add" and not self.identity.is_member(entry.get("subject")):
                raise NotFound("that person is not a member of this node")
            new = self.apply(state, entry)
            old = dict(state.members)
            self._states[lab_id] = new
            self._store_entry(new, entry, old)
            return {"head": new.head, "seq": new.seq}

    def roster(self, subject: str, lab_id: str, after: int = -1) -> dict:
        with self._lock:
            state = self.member_state(subject, lab_id)
            rows = self._db.execute(
                "SELECT entry FROM lab_roster WHERE lab_id = ? AND seq > ? ORDER BY seq",
                (lab_id, int(after)),
            ).fetchall()
            return {
                "entries": [json.loads(e) for (e,) in rows],
                "head": state.head,
                "invites": self._auths(lab_id),
                "seq": state.seq,
            }

    def get_lab(self, subject: str, lab_id: str) -> dict:
        """A lab member gets the roster view. Another node member gets the
        ID and the name only (a node can have many labs)."""
        self.identity.require_member(subject)
        with self._lock:
            state = self.state(lab_id)
            if subject not in state.members:
                return {"lab_id": lab_id, "name": state.name}
            return {
                "head": state.head,
                "lab_id": lab_id,
                "members": sorted(state.members),
                "name": state.name,
                "pi": state.pi(),
                "roles": dict(sorted(state.members.items())),
                "seq": state.seq,
            }

    # ------------------------------------------------------- for admission

    @property
    def lock(self):
        """The lock of the lab states. Admission (L4) holds it to check an
        invite and append its entry in one action."""
        return self._lock

    def commit(self, lab_id: str, new: labfmt.LabState, entry: dict, old_members: dict) -> None:
        """Keep a state that `apply` made, and store its entry (hold `lock`)."""
        self._states[lab_id] = new
        self._store_entry(new, entry, old_members)

    def add_invite(self, lab_id: str, iid: str, auth: dict) -> None:
        """Store the authorisation of an invite; the chain needs it to replay
        the `invite` entry (hold `lock`)."""
        self._db.execute(
            "INSERT INTO lab_invites (invite_id, lab_id, auth, expires_at, max_uses)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                iid,
                lab_id,
                canonical_json(auth).decode(),
                int(parse_time(auth["expires_at"]).timestamp()),
                auth["max_uses"],
            ),
        )

    def check_invite_package(
        self, state: labfmt.LabState, subject: str, iid: str, package: dict | None
    ) -> None:
        if package is None:
            return
        try:
            labkey.validate_key_package(package)
        except FormatError as exc:
            raise NodeError(f"key package refused: {exc}") from exc
        if (
            package["lab_id"] != state.lab_id
            or package["recipient"] != labkey.invite_recipient(iid)
            or package["sender"] != subject
        ):
            raise NodeError("the key package is for another lab, invite, or sender")
        if package["epoch"] != self._epoch(state.lab_id):
            raise Conflict("the lab key has a newer epoch; read the keys and try again")

    def _epoch(self, lab_id: str) -> int:
        """The current lab key epoch: the highest epoch with a package (0
        before the first package)."""
        row = self._one("SELECT MAX(epoch) FROM lab_keys WHERE lab_id = ?", lab_id)
        return int(row[0] or 0)

    def put_package(self, lab_id: str, package: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO lab_keys (lab_id, epoch, recipient, doc, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                lab_id,
                package["epoch"],
                package["recipient"],
                canonical_json(package).decode(),
                self.now(),
            ),
        )

    def invite_auth(self, invite_id: str) -> tuple[str, dict]:
        """(lab ID, authorisation) of a lab invite. `NotFound` if unknown."""
        if not isinstance(invite_id, str) or len(invite_id) != 32:
            raise NotFound("unknown invite")
        row = self._one("SELECT lab_id, auth FROM lab_invites WHERE invite_id = ?", invite_id)
        if row is None:
            raise NotFound("unknown invite")
        return row[0], json.loads(row[1])

    def newest_package(self, lab_id: str, recipient: str) -> dict | None:
        """The key package of the newest epoch for `recipient`, or None."""
        row = self._one(
            "SELECT doc FROM lab_keys WHERE lab_id = ? AND recipient = ?"
            " ORDER BY epoch DESC LIMIT 1",
            lab_id,
            recipient,
        )
        return json.loads(row[0]) if row else None

    # ---------------------------------------------------------------- keys

    def put_keys(self, subject: str, lab_id: str, epoch: int, packages: list) -> dict:
        """A PI or admin stores key packages. The node checks
        the form only; it has no key. Epoch `current + 1` starts a new epoch
        (a rotation): the first request wins. At the current epoch a request
        adds recipients (a new member); it is a conflict if one recipient has
        a package at that epoch already, so a second rotation of the same
        epoch never mixes two keys. Each other epoch is a conflict."""
        with self._lock:
            state = self.member_state(subject, lab_id)
            if not state.can(subject, "rotate"):
                raise Forbidden("only a PI or admin gives lab keys")
            if not isinstance(packages, list) or not packages or len(packages) > 1000:
                raise NodeError("packages: expected a list of 1 to 1000 packages")
            recipients = _package_recipients(state, subject, epoch, packages)
            current = self._epoch(lab_id)
            if epoch == current and current > 0:
                taken = {
                    r
                    for (r,) in self._db.execute(
                        "SELECT recipient FROM lab_keys WHERE lab_id = ? AND epoch = ?",
                        (lab_id, epoch),
                    )
                }
                if taken & recipients:
                    raise Conflict("this epoch has a key for one of these recipients")
            elif epoch != current + 1:
                raise Conflict("the lab key has a newer epoch; read the keys and try again")
            self._db.execute("BEGIN")
            try:
                for p in packages:
                    self.put_package(lab_id, p)
                self._change(lab_id, "keys")
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return {"epoch": epoch}

    def get_keys(self, subject: str, lab_id: str) -> dict:
        """The packages for this person (all epochs) and the current epoch.
        A PI or admin also gets the packages of the current epoch for each
        recipient (`current`): their wraps name device keys (public), so
        the client can see a device that is not active now."""
        with self._lock:
            state = self.member_state(subject, lab_id)
            mine = [
                json.loads(d)
                for (d,) in self._db.execute(
                    "SELECT doc FROM lab_keys WHERE lab_id = ? AND recipient = ? ORDER BY epoch",
                    (lab_id, subject),
                )
            ]
            epoch = self._epoch(lab_id)
            out = {"epoch": epoch, "packages": mine}
            if state.can(subject, "rotate"):
                out["current"] = [
                    json.loads(d)
                    for (d,) in self._db.execute(
                        "SELECT doc FROM lab_keys WHERE lab_id = ? AND epoch = ?"
                        " ORDER BY recipient",
                        (lab_id, epoch),
                    )
                ]
            return out

    # -------------------------------------------------------------- space

    def _quota(self, lab_id: str) -> tuple[int, bool]:
        row = self._one("SELECT quota, suspended FROM lab_host WHERE lab_id = ?", lab_id)
        return (int(row[0]), bool(row[1])) if row else (self.quota, False)

    def _used(self, lab_id: str) -> int:
        return int(
            self._one("SELECT COALESCE(SUM(size), 0) FROM lab_records WHERE lab_id = ?", lab_id)[0]
        )

    def put_record(
        self,
        subject: str,
        lab_id: str,
        record_id: str,
        doc: dict,
        blobs: list | None = None,
        topic: str = "space",
        drop: list | None = None,
    ) -> dict:
        """Store one lab space record (ciphertext). The node
        checks the form, the size, and the quota; it cannot read the content.
        Only the first writer of a record, the PI, or an admin replaces it.
        `drop`: record IDs to delete in the same action (the text parts of a
        removed or shorter item), with the same rule. `topic` is `space` or
        `settings` (the client says it; the node learns only that a settings
        change happened)."""
        drop, blobs = _record_args(record_id, doc, blobs, topic, drop)
        size = record_size(doc)
        with self._lock:
            state = self.member_state(subject, lab_id)
            quota, suspended = self._quota(lab_id)
            if suspended:
                raise Forbidden("This lab is read-only now. Ask the node organizer.")
            keeper = state.can(subject, "tombstone")

            def owned(rid: str):
                row = self._one(
                    "SELECT version, size, doc, author FROM lab_records"
                    " WHERE lab_id = ? AND record_id = ?",
                    lab_id,
                    rid,
                )
                if row is not None and row[3] != subject and not keeper:
                    raise Forbidden("only the author, the PI, or an admin changes this item")
                return row

            old = owned(record_id)
            gone = [r for r in (owned(rid) for rid in drop if isinstance(rid, str)) if r]
            touched = [record_id, *[rid for rid in drop if isinstance(rid, str)]]
            before = self._record_blobs(lab_id, touched)
            for b in blobs:
                # A writer lists only its own blobs (or the blobs of this
                # record): a lab record must not open the blob of another person.
                if b not in before and (self.vault is None or self.vault.blob_owner(b) != subject):
                    raise NodeError("blobs: list only blobs that you uploaded")
            if old is not None:
                if old[2] == canonical_json(doc).decode() and not drop:
                    return {"change": None, "record_id": record_id, "version": old[0]}
                if doc["version"] <= old[0]:
                    raise Conflict(f"the node has version {old[0]}; send a newer version")
            elif self._one("SELECT COUNT(*) FROM lab_records WHERE lab_id = ?", lab_id)[0] >= (
                MAX_LAB_RECORDS
            ):
                raise QuotaExceeded("too many records in this lab space")
            freed = (old[1] if old else 0) + sum(r[1] for r in gone)
            if self._used(lab_id) - freed + size > quota:
                raise QuotaExceeded("The lab space is full. Ask the node organizer.")
            author = old[3] if old else subject
            change = self._write_record(lab_id, doc, author, blobs, topic, drop)
            self._drop_orphans(before - set(blobs))
            return {"change": change, "record_id": record_id, "version": doc["version"]}

    def _write_record(
        self, lab_id: str, doc: dict, author: str, blobs: list, topic: str, drop: list
    ) -> int:
        """Write a checked record, its blob rows, and the drops in one
        transaction (hold `lock`). Return the change number."""
        record_id = doc["record_id"]
        self._db.execute("BEGIN")
        try:
            for rid in drop:
                self._db.execute(
                    "DELETE FROM lab_records WHERE lab_id = ? AND record_id = ?", (lab_id, rid)
                )
                self._db.execute(
                    "DELETE FROM lab_blobs WHERE lab_id = ? AND record_id = ?", (lab_id, rid)
                )
            change = self._change(lab_id, topic)
            self._db.execute(
                "INSERT OR REPLACE INTO lab_records (lab_id, record_id, version, size, doc,"
                " author, change, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    lab_id,
                    record_id,
                    doc["version"],
                    record_size(doc),
                    canonical_json(doc).decode(),
                    author,
                    change,
                    self.now(),
                ),
            )
            self._db.execute(
                "DELETE FROM lab_blobs WHERE lab_id = ? AND record_id = ?", (lab_id, record_id)
            )
            self._db.executemany(
                "INSERT OR REPLACE INTO lab_blobs (lab_id, blob_id, record_id) VALUES (?, ?, ?)",
                [(lab_id, b, record_id) for b in blobs],
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        return change

    def _record_blobs(self, lab_id: str, record_ids: list[str]) -> set[str]:
        out: set[str] = set()
        for rid in record_ids:
            out |= {
                r[0]
                for r in self._db.execute(
                    "SELECT blob_id FROM lab_blobs WHERE lab_id = ? AND record_id = ?",
                    (lab_id, rid),
                )
            }
        return out

    def _drop_orphans(self, blob_ids: set[str]) -> None:
        """Delete the blobs that no lab record lists now (a removed item, or
        a revision with other files). A blob that a public release lists
        stays."""
        if self.vault is None:
            return
        for b in sorted(blob_ids):
            if self._one("SELECT 1 FROM lab_blobs WHERE blob_id = ?", b) is not None:
                continue
            owner = self.vault.blob_owner(b)
            if owner is None:
                continue
            try:
                self.vault.delete_blob(owner, b)
            except (Conflict, Forbidden, NotFound, NodeError):
                continue

    def can_read_blob(self, subject: str, blob_id: str) -> bool:
        """The `readers` hook of `NodeVault.blob_path`: a member of a lab
        whose space lists the blob reads it (no read receipt in a lab)."""
        with self._lock:
            labs = [
                r[0]
                for r in self._db.execute(
                    "SELECT DISTINCT lab_id FROM lab_blobs WHERE blob_id = ?", (blob_id,)
                )
            ]
            return any(lid in self._states and subject in self._states[lid].members for lid in labs)

    def records(self, subject: str, lab_id: str, after: int = 0, limit: int = 200) -> dict:
        """Records changed after `after` (a change number), oldest first."""
        limit = max(1, min(int(limit), 500))
        with self._lock:
            self.member_state(subject, lab_id)
            rows = self._db.execute(
                "SELECT doc, author, change FROM lab_records WHERE lab_id = ? AND change > ?"
                " ORDER BY change LIMIT ?",
                (lab_id, int(after), limit + 1),
            ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        return {
            "more": more,
            "next": rows[-1][2] if rows else int(after),
            "records": [{"author": a, "change": c, "record": json.loads(d)} for d, a, c in rows],
        }

    def get_record(self, subject: str, lab_id: str, record_id: str) -> dict:
        with self._lock:
            self.member_state(subject, lab_id)
            row = self._one(
                "SELECT doc, author, change FROM lab_records WHERE lab_id = ? AND record_id = ?",
                lab_id,
                record_id,
            )
        if row is None:
            raise NotFound("no such record")
        return {"author": row[1], "change": row[2], "record": json.loads(row[0])}

    # ------------------------------------------------------------ changes

    def changes(self, subject: str, after: int = 0, wait: float = 0) -> dict:
        """Changes of the labs of this person after `after`. With `wait`
        (0 to 25 seconds), hold the request until a change exists or the time
        ends."""
        self.identity.require_member(subject)
        wait = max(0.0, min(float(wait), 25.0))
        deadline = time.monotonic() + wait
        with self._lock:
            while True:
                labs = [lid for lid, st in self._states.items() if subject in st.members]
                rows = []
                for lid in labs:
                    rows += self._db.execute(
                        "SELECT change, lab_id, topic FROM lab_changes WHERE change > ?"
                        " AND lab_id = ? ORDER BY change LIMIT 500",
                        (int(after), lid),
                    ).fetchall()
                rows = sorted(rows)[:500]
                left = deadline - time.monotonic()
                if rows or left <= 0:
                    break
                self._changed.wait(left)
        return {
            "changes": [{"change": c, "lab_id": lid, "topic": t} for c, lid, t in rows],
            "next": rows[-1][0] if rows else int(after),
        }

    # ---------------------------------------------------------- organizer

    def node_stats(self) -> list[dict]:
        """Counts and sizes of each lab for the organizer page.
        No title, no text, no setting, no key, no person."""
        now = datetime.fromtimestamp(self.now(), UTC)
        out = []
        with self._lock:
            for lab_id, st in sorted(self._states.items(), key=lambda kv: kv[1].name.lower()):
                quota, suspended = self._quota(lab_id)
                records, size = self._one(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM lab_records WHERE lab_id = ?",
                    lab_id,
                )
                epoch = self._one("SELECT MAX(epoch) FROM lab_keys WHERE lab_id = ?", lab_id)[0]
                created = self._one(
                    "SELECT at FROM lab_roster WHERE lab_id = ? AND seq = 0", lab_id
                )
                last = self._one("SELECT MAX(at) FROM lab_changes WHERE lab_id = ?", lab_id)[0]
                out.append(
                    {
                        "admins": sum(1 for r in st.members.values() if r != labfmt.MEMBER),
                        "bytes": int(size),
                        "created_at": int(created[0]) if created else None,
                        "epoch": int(epoch or 0),
                        "lab_id": lab_id,
                        "last_change_at": int(last) if last is not None else None,
                        "members": len(st.members),
                        "name": st.name,
                        "open_invites": len(st.open_invites(now)),
                        "quota": quota,
                        "records": int(records),
                        "suspended": suspended,
                    }
                )
        return out

    def set_node_limits(
        self, lab_id: str, quota: int | None = None, suspended: bool | None = None
    ) -> dict:
        """The organizer sets the quota (bytes) or suspends a lab (members
        read; nobody writes to the lab space)."""
        if quota is not None and (
            isinstance(quota, bool) or not isinstance(quota, int) or quota < 1 << 20
        ):
            raise NodeError("quota: a whole number of bytes, 1 MiB or more")
        if suspended is not None and not isinstance(suspended, bool):
            raise NodeError("suspended: true or false")
        with self._lock:
            self.state(lab_id)
            self._db.execute(
                "INSERT OR IGNORE INTO lab_host (lab_id, quota) VALUES (?, ?)", (lab_id, self.quota)
            )
            if quota is not None:
                self._db.execute("UPDATE lab_host SET quota = ? WHERE lab_id = ?", (quota, lab_id))
            if suspended is not None:
                self._db.execute(
                    "UPDATE lab_host SET suspended = ? WHERE lab_id = ?", (int(suspended), lab_id)
                )
        return next(r for r in self.node_stats() if r["lab_id"] == lab_id)


def _package_recipients(
    state: labfmt.LabState, subject: str, epoch: int, packages: list
) -> set[str]:
    """Check the form of each key package of `put_keys` and its recipient
    (a member, or an invite of the lab that is not revoked). Return the
    recipients."""
    recipients: set[str] = set()
    for p in packages:
        try:
            labkey.validate_key_package(p)
        except FormatError as exc:
            raise NodeError(f"key package refused: {exc}") from exc
        if p["lab_id"] != state.lab_id or p["epoch"] != epoch or p["sender"] != subject:
            raise NodeError("a key package is for another lab, epoch, or sender")
        r = p["recipient"]
        if r in recipients:
            raise NodeError("two key packages for one recipient")
        if r.startswith("invite:"):
            inv = state.invites.get(r.removeprefix("invite:"))
            if inv is None:
                raise NodeError("a key package is for an invite of another lab")
            if inv["revoked"]:
                raise NodeError("a key package is for a revoked invite")
        elif r not in state.members:
            raise NodeError("a key package is for a person who is not in the lab")
        recipients.add(r)
    return recipients


def _record_args(
    record_id: str, doc: dict, blobs: list | None, topic: str, drop: list | None
) -> tuple[list, list]:
    """Check the arguments of `put_record` that need no lab state. Return
    (drop, blobs)."""
    if topic not in ("space", "settings"):
        raise NodeError("topic: space or settings")
    try:
        validate_record(doc)
    except FormatError as exc:
        raise NodeError(str(exc)) from exc
    if doc["record_id"] != record_id:
        raise NodeError("record_id in the path and in the record differ")
    drop = drop or []
    if not isinstance(drop, list) or len(drop) > 1000 or record_id in drop:
        raise NodeError("drop: expected a list of other record IDs")
    blobs = blobs or []
    if not isinstance(blobs, list) or any(not isinstance(b, str) for b in blobs):
        raise NodeError("blobs: expected a list of blob IDs")
    return drop, blobs


def lab_policy_from_env(env) -> tuple[int, str]:
    """(quota in bytes, create policy) from `ANAGRAM_LAB_QUOTA_MB` and
    `ANAGRAM_LAB_CREATE`. Raise ValueError for a bad value. The create policy
    is a part of the admission policy of the node (`NodePolicy`)."""
    raw = (env.get("ANAGRAM_LAB_QUOTA_MB") or "").strip()
    quota = DEFAULT_LAB_QUOTA
    if raw:
        if not raw.isdigit() or int(raw) < 1:
            raise ValueError("ANAGRAM_LAB_QUOTA_MB must be a whole number of MB, 1 or more")
        quota = int(raw) << 20
    policy = (env.get("ANAGRAM_LAB_CREATE") or "organizer_invite").strip()
    if policy == "organizer":
        policy = "organizer_invite"
    if policy not in ("member", "organizer_invite"):
        raise ValueError("ANAGRAM_LAB_CREATE must be member or organizer_invite")
    return quota, policy
