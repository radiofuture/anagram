"""Node identity service (layer L1): members, sessions, identity records, the
key directory, and the log submissions. `IdentityService` is also the
composition root of the identity parts of the node: the sign-in methods
(`orcid_signin`, `email_signin`, `passkeys`, `device_signin`, `vouch`), the
people lookup (`people`), and the key backups (`backups`).

L1 does not decide who may register. The registration gate (L4,
`anagram.admission.node.service.AdmissionService`) checks the invites and gives an
`Admission`; `add_member` applies it. A person needs no ORCID iD.
A person can link one later (purpose `link`); it shows only when linked.

The node stores only public data, hashes of secrets (tokens, codes), and
ciphertext (key backups). It never receives a private key or a recovery secret.

Person IDs (v2): the public subject of a person is `pid:<32 hex>`. The node keeps
a private map ORCID iD -> pid (`orcid_accounts`) and never publishes it. The log
and the public directory show only the pid and a salted ORCID commitment. A
signed-in member can look up a pid by ORCID iD only if that person turned on
"findable by ORCID" (rate limit, audit log).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import (
    Conflict,
    Forbidden,
    FormatError,
    NodeError,
    NotFound,
    RateLimited,
    Unauthorized,
)
from anagram.core.shared_db import SharedDB
from anagram.core.timefmt import parse_time
from anagram.identity.formats.documents import (
    KIND_KEY_BINDING,
    BindingError,
    SubjectKeys,
    make_assertion,
    new_pid,
    validate_subject,
    verify_identity_record,
)
from anagram.identity.node.backups import KeyBackups
from anagram.identity.node.challenges import Challenges, secret_hash
from anagram.identity.node.checks import NOT_A_MEMBER, person_pid
from anagram.identity.node.device_signin import DeviceSignIn
from anagram.identity.node.email_signin import EmailSignIn
from anagram.identity.node.mailer import Mailer
from anagram.identity.node.orcid import OrcidAdapter
from anagram.identity.node.orcid_signin import OrcidSignIn
from anagram.identity.node.passkeys import PasskeySignIn
from anagram.identity.node.people import PeopleLookup
from anagram.identity.node.schema import ACCOUNT_TABLES, one, open_db
from anagram.identity.node.vouch import VouchSignIn
from anagram.identity.ports import Admission
from anagram.proofs.node.service import EntryRejected, NodeService

ASSERTION_TTL = timedelta(minutes=10)


class IdentityDirectory(Protocol):
    """What the node services of the higher layers (labs, matching) read from
    L1 (port `IdentityDirectory`, layers plan section 4). `IdentityService`
    gives it; a higher layer never reads the identity database."""

    def now(self) -> int: ...

    def is_member(self, subject: str) -> bool: ...

    def require_member(self, subject: str) -> None: ...

    def active_devices(self, subject: str) -> dict[str, dict]: ...

    def keys_of(self, subject: str) -> SubjectKeys | None: ...

    def orcid_account(self, orcid: str) -> dict | None: ...

    def identity_record(self, subject: str) -> dict | None: ...


@dataclass
class IdentityConfig:
    community: str
    public_url: str
    node_key: str  # fingerprint of the log key
    organizers: set[str] = field(default_factory=set)  # ORCID iDs
    submit_per_minute: int = 60
    session_days: int = 7

    @property
    def rp_id(self) -> str:
        return urllib.parse.urlsplit(self.public_url).hostname or "localhost"

    @property
    def callback_url(self) -> str:
        return self.public_url.rstrip("/") + "/auth/orcid/callback"


class IdentityService:
    def __init__(
        self,
        db_path: str | Path,
        cfg: IdentityConfig,
        assertion_key: SigningKey,
        log: NodeService,
        orcid: OrcidAdapter,
        mailer: Mailer,
        trust: dict,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.key = assertion_key
        self.log = log
        self.trust = trust
        self.clock = clock
        self._lock = threading.RLock()
        self._db = open_db(db_path)
        self._submits: dict[str, deque] = {}
        self._dir: dict[str, SubjectKeys] = {}
        for (entry,) in self._db.execute("SELECT entry FROM directory ORDER BY leaf_index"):
            e = json.loads(entry)
            self._dir.setdefault(e["subject"], SubjectKeys(e["subject"])).apply(
                e, assertion_key=self.key.public_bytes(), node_key=cfg.node_key
            )
        # The parts. Each gets this service (sessions, assertions, members).
        challenges = Challenges(self._db, self.now)
        self.orcid_signin = OrcidSignIn(self, orcid)
        self.email_signin = EmailSignIn(self, challenges, mailer)
        self.passkeys = PasskeySignIn(self, challenges)
        self.device_signin = DeviceSignIn(self, challenges)
        self.vouch = VouchSignIn(self)
        self.people = PeopleLookup(self)
        self.backups = KeyBackups(self)

    # ------------------------------------------------------------ helpers

    def now(self) -> int:
        return int(self.clock())

    def now_dt(self) -> datetime:
        return datetime.fromtimestamp(self.now(), UTC)

    def _one(self, sql: str, *args):
        return one(self._db, sql, *args)

    @property
    def db(self) -> SharedDB:
        """The connection of `identity.sqlite`. The admission tables (L4) are
        in this file too, so that a claim and its member row are one action."""
        return self._db

    @property
    def lock(self):
        return self._lock

    def key_state(self, subject: str) -> SubjectKeys:
        """The key directory state of a person (a new empty one if none)."""
        return self._dir.get(subject) or SubjectKeys(subject)

    def assertion(
        self, subject: str, commitment: str | None, method: str, device: str, nonce: str
    ) -> dict:
        """A sign-in assertion for the device key `device`."""
        now = self.now_dt()
        return make_assertion(
            subject=subject,
            orcid_commitment=commitment,
            method=method,
            audience=bytes.fromhex(device),
            nonce=nonce,
            community=self.cfg.community,
            node_key=self.cfg.node_key,
            issued_at=now,
            expires_at=now + ASSERTION_TTL,
            key=self.key,
        )

    def new_session(self, subject: str, method: str, device: str | None) -> dict:
        """A new session. `device` is the device key of the sign-in assertion
        (None for a passkey). The session ends when that device stops being
        active (see `authenticate`) and at each reset or remove."""
        token = secrets.token_urlsafe(32)
        expires = self.now() + self.cfg.session_days * 86400
        self._db.execute(
            "INSERT INTO sessions (token_hash, subject, method, expires_at, device)"
            " VALUES (?, ?, ?, ?, ?)",
            (secret_hash("session", token), subject, method, expires, device),
        )
        return {"expires_at": expires, "subject": subject, "token": token}

    def check_login(self, subject: str, device: str) -> None:
        """Purpose "login" (sign in again without an invite): the subject must be
        a member, and the device must be active or not bound yet (a new device
        then follows the key-binding rules). A removed device gets no session."""
        if not self.is_member(subject):
            raise Forbidden(NOT_A_MEMBER)
        if self._removed(subject, device):
            raise Forbidden("this device was removed; recover your keys or use another device")

    def _removed(self, subject: str, device: str) -> bool:
        """The device was bound and is not active now (reset or remove)."""
        state = self.key_state(subject)
        bound = {e["device"]["ed25519"] for e in state.history}
        return device in bound and device not in state.devices

    def new_subject(self, pid: str | None) -> str:
        """The person ID that the client made, or a new one if it is not
        valid or another account has it."""
        subject = person_pid(pid)
        taken = any(
            self._one(f"SELECT 1 FROM {table} WHERE subject = ?", subject) is not None  # noqa: S608
            for table in ACCOUNT_TABLES
        )
        return new_pid() if taken else subject

    # ----------------------------------------------------------- accounts

    def orcid_account(self, orcid: str) -> dict | None:
        """Private: the account of an ORCID iD, or None."""
        row = self._one(
            "SELECT subject, salt, commitment, findable, linked FROM orcid_accounts"
            " WHERE orcid = ?",
            orcid,
        )
        if row is None:
            return None
        return {
            "commitment": row[2],
            "findable": bool(row[3]),
            "linked": bool(row[4]),
            "salt": row[1],
            "subject": row[0],
        }

    def subject_for_orcid(self, orcid: str) -> str | None:
        """Private map ORCID iD -> pid (node-internal use only)."""
        acct = self.orcid_account(orcid)
        return acct["subject"] if acct else None

    def orcid_of(self, subject: str) -> str | None:
        """Private map pid -> ORCID iD (node-internal use only)."""
        row = self._one("SELECT orcid FROM orcid_accounts WHERE subject = ?", subject)
        return row[0] if row else None

    def email_of(self, subject: str) -> str | None:
        """Private: the proved address of the person, else the stated one."""
        row = self._one("SELECT email FROM email_accounts WHERE subject = ?", subject)
        if row is None:
            row = self._one("SELECT email FROM invite_accounts WHERE subject = ?", subject)
        return row[0] if row else None

    def proved_contact(self, subject: str, kind: str, contact: str) -> bool:
        """The person signed in with this email address or ORCID iD."""
        if kind == "email":
            sql = "SELECT 1 FROM email_accounts WHERE email = ? AND subject = ?"
        else:
            sql = "SELECT 1 FROM orcid_accounts WHERE orcid = ? AND subject = ?"
        return self._one(sql, contact, subject) is not None

    def findable(self, subject: str) -> bool:
        """True if one of the addresses or iDs of the person is findable."""
        return any(
            (row := self._one(f"SELECT findable FROM {table} WHERE subject = ?", subject))  # noqa: S608
            and row[0]
            for table in ACCOUNT_TABLES
        )

    # ----------------------------------------------------------- sessions

    def authenticate(self, token: str | None) -> str:
        if not token:
            raise Unauthorized("sign in first")
        row = self._one(
            "SELECT subject, expires_at, device FROM sessions WHERE token_hash = ?",
            secret_hash("session", token),
        )
        if row is None or row[1] < self.now():
            raise Unauthorized("session is not valid")
        subject, _, device = row
        # A device that was bound and is not active now (reset or remove) has
        # no session. A device that is not bound yet (join) has one.
        if device is not None and self._removed(subject, device):
            raise Unauthorized("session is not valid")
        return subject

    def session_device(self, token: str | None) -> tuple[str, str | None]:
        """(subject, device key) of a valid session. The device is None for
        a passkey session. A member credential request names the device
        (spec/network.md 6.6), and the node checks it against this one."""
        subject = self.authenticate(token)
        row = self._one(
            "SELECT device FROM sessions WHERE token_hash = ?", secret_hash("session", token)
        )
        return subject, row[0] if row else None

    def logout(self, token: str | None) -> dict:
        if not token:
            raise Unauthorized("sign in first")
        self._db.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (secret_hash("session", token),)
        )
        return {"status": "signed_out"}

    def _end_sessions(self, subject: str, active: dict) -> None:
        """After a reset or remove: end each session of `subject` that is not
        bound to an active device. This includes passkey sessions."""
        rows = self._db.execute(
            "SELECT token_hash, device FROM sessions WHERE subject = ?", (subject,)
        ).fetchall()
        for token_hash, device in rows:
            if device is None or device not in active:
                self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    # ------------------------------------------------------------ members

    def is_member(self, subject: str) -> bool:
        return self._one("SELECT 1 FROM members WHERE subject = ?", subject) is not None

    def require_member(self, subject: str) -> None:
        if not self.is_member(subject):
            raise Forbidden("join the community first (claim an invite)")

    def require_organizer(self, subject: str) -> None:
        row = self._one("SELECT role FROM members WHERE subject = ?", subject)
        if row is None or row[0] != "organizer":
            raise Forbidden("only an organizer can do this")

    def add_member(self, admission: Admission) -> bool:
        """Registration: make a person a node member. Only the registration
        gate (L4, `AdmissionService`) gives an `Admission`; L1 does not decide
        who may register. The member row keeps the vouch reference. At most
        `admission.limit` members come in with one reference. Return True if
        a row was made. An organizer admission makes a member an organizer."""
        validate_subject(admission.subject)
        subject = admission.subject
        with self._lock:
            if self.is_member(subject):
                if admission.role == "organizer":
                    self._db.execute(
                        "UPDATE members SET role = 'organizer' WHERE subject = ?", (subject,)
                    )
                return False
            if admission.limit is not None:
                n = self._one("SELECT COUNT(*) FROM members WHERE invite = ?", admission.ref)[0]
                if n >= admission.limit:
                    raise Conflict(
                        "This invite link was used. Ask the person who sent it for a new link."
                    )
            organizer = (
                admission.role == "organizer" or self.orcid_of(subject) in self.cfg.organizers
            )
            self._db.execute(
                "INSERT INTO members (subject, role, joined_at, invite) VALUES (?, ?, ?, ?)",
                (subject, "organizer" if organizer else "member", self.now(), admission.ref),
            )
            self.vouch.claim_pending_email(subject)
            return True

    def member_ref(self, subject: str) -> tuple[str, str | None] | None:
        """(role, vouch reference) of a member, or None."""
        row = self._one("SELECT role, invite FROM members WHERE subject = ?", subject)
        return (row[0], row[1]) if row else None

    def members_by_join(self) -> list[tuple[str, int]]:
        """(subject, joined_at) of each member, oldest first."""
        return [
            (r[0], r[1])
            for r in self._db.execute(
                "SELECT subject, joined_at FROM members ORDER BY joined_at, subject"
            )
        ]

    def members(self, viewer: str) -> list[str]:
        """All member subjects (for the "community" ring). Members only."""
        self.require_member(viewer)
        return [r[0] for r in self._db.execute("SELECT subject FROM members ORDER BY subject")]

    def community_stats(self) -> dict:
        """Member counts for the organizer page. No user content."""
        roles = dict(self._db.execute("SELECT role, COUNT(*) FROM members GROUP BY role"))
        return {
            "members": sum(roles.values()),
            "organizers": int(roles.get("organizer", 0)),
        }

    def keys_of(self, subject: str) -> SubjectKeys | None:
        """The key directory state of a person (None: not in the directory)."""
        return self._dir.get(subject)

    def active_devices(self, subject: str) -> dict[str, dict]:
        state = self._dir.get(subject)
        return dict(state.devices) if state else {}

    def identity_record(self, subject: str) -> dict | None:
        row = self._one("SELECT record FROM identities WHERE subject = ?", subject)
        return json.loads(row[0]) if row else None

    # ------------------------------------------------------ identity record

    def put_identity(self, subject: str, record: dict, labs: Collection[str]) -> dict:
        """Store the identity record of `subject`. `labs`: the labs of the
        person (L3 gives them); the record can name only one of them."""
        self.require_member(subject)
        try:
            verify_identity_record(record, self.key_state(subject))
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if record["lab_id"] is not None and record["lab_id"] not in labs:
            raise Forbidden("you are not a member of that lab")
        self._db.execute(
            "INSERT OR REPLACE INTO identities (subject, record) VALUES (?, ?)",
            (subject, json.dumps(record)),
        )
        return record

    def get_identity(self, viewer: str, subject: str) -> dict:
        self.require_member(viewer)
        row = self._one("SELECT record FROM identities WHERE subject = ?", subject)
        if row is None:
            raise NotFound("no identity record")
        return json.loads(row[0])

    def me(self, subject: str) -> dict:
        row = self._one("SELECT role FROM members WHERE subject = ?", subject)
        ident = self._one("SELECT record FROM identities WHERE subject = ?", subject)
        acct = self._one("SELECT findable, linked FROM orcid_accounts WHERE subject = ?", subject)
        return {
            "community": self.cfg.community,
            "devices": sorted(self.key_state(subject).devices),
            "email": self.email_of(subject),
            "findable": self.findable(subject),
            "findable_by_orcid": bool(acct and acct[0]),
            "orcid_linked": bool(acct and acct[1]),
            "identity": json.loads(ident[0]) if ident else None,
            "role": row[0] if row else None,
            "subject": subject,
        }

    # ---------------------------------------------------- log submissions

    def _rate_limit(self, subject: str) -> None:
        q = self._submits.setdefault(subject, deque())
        now = self.clock()
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.cfg.submit_per_minute:
            raise RateLimited("too many submissions; wait one minute")
        q.append(now)

    def submit(self, subject: str, entry: dict) -> dict:
        """Accept a log entry from a member. Key bindings must follow the chain rules."""
        self.require_member(subject)
        with self._lock:
            self._rate_limit(subject)
            if not isinstance(entry, dict) or entry.get("kind") != KIND_KEY_BINDING:
                return self.log.submit(entry)
            if entry.get("subject") != subject:
                raise Forbidden("you can bind keys only for your own subject")
            trial = self._trial_binding(subject, entry)
            result = self.log.submit(entry)
            self._db.execute(
                "INSERT INTO directory (leaf_index, subject, seq, entry) VALUES (?, ?, ?, ?)",
                (result["leaf_index"], subject, entry["seq"], canonical_json(entry).decode()),
            )
            self._dir[subject] = trial
            if entry["op"] in ("reset", "remove"):
                self._end_sessions(subject, trial.devices)
            return result

    def _trial_binding(self, subject: str, entry: dict) -> SubjectKeys:
        """The key state of `subject` after `entry`, on a copy. Raise
        `EntryRejected` if the entry breaks the chain rules."""
        state = self.key_state(subject)
        trial = SubjectKeys(
            subject,
            state.seq,
            state.head,
            dict(state.devices),
            list(state.history),
            state.orcid_commitment,
        )
        try:
            trial.apply(entry, assertion_key=self.key.public_bytes(), node_key=self.cfg.node_key)
            auth = entry["authority"]
            if "assertion" in auth and parse_time(auth["assertion"]["expires_at"]) < self.now_dt():
                raise BindingError("assertion has expired")
        except (FormatError, KeyError, TypeError) as exc:
            raise EntryRejected(str(exc)) from exc
        return trial

    def directory(self, subject: str) -> dict:
        """All binding entries of a subject, with inclusion proofs at one checkpoint."""
        try:
            validate_subject(subject)
        except FormatError as exc:
            raise NotFound("unknown subject") from exc
        with self._lock:
            cp = self.log.checkpoint()
            size = cp["tree_size"]
            rows = self._db.execute(
                "SELECT leaf_index, entry FROM directory WHERE subject = ? AND leaf_index < ?"
                " ORDER BY leaf_index",
                (subject, size),
            ).fetchall()
            entries = [
                {"entry": json.loads(e), "inclusion": self.log.inclusion(i, size), "leaf_index": i}
                for i, e in rows
            ]
        return {"checkpoint": cp["checkpoint"], "entries": entries, "tree_size": size}
