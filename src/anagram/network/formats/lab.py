"""Lab unit formats: the signed lab roster. See spec/lab.md.
The other lab formats are in `labkey` (the key package), `labitem` (the lab
item), and `labsettings` (the lab settings).

The membership of a lab is a hash chain of roster entries. Member devices
sign the entries. The node stores and orders the chain, but it cannot add an
entry: it has no member device key, and a `join` entry needs a request that
the joiner signed with the key of the invite. The node and each client apply
the chain with one function (`LabState.apply`).

    entry_hash = sha256(tagged_message(TAG_LAB_ROSTER, canonical_json(entry)))
    signature  = Ed25519(actor device, tagged_message(TAG_SIGN_LAB_ROSTER,
                 canonical_json(entry without "signature")))

The lab invite and the join request are admission formats (layer L4,
`anagram.admission.formats`, spec/admission.md). The roster applies an
`invite` or `join` entry only with the checks of the port `AdmissionCheck`
(`anagram.network.ports`). The caller gives the checks to each state
(`LabState(lab_id, admission=...)`, `replay(..., admission=...)`); the
composition root makes them. With no check, the roster refuses these entries.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import TAG_LAB_ROSTER, TAG_SIGN_LAB_ROSTER, tagged_message
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, hex_field, int_at_least
from anagram.identity.api import validate_lab_id, validate_subject
from anagram.network.ports import AdmissionCheck

ROSTER_SCHEMA = "anagram.lab_roster.v1"

PI, ADMIN, MEMBER = "pi", "admin", "member"
ROLES = (PI, ADMIN, MEMBER)
OPS = (
    "create",
    "add",
    "join",
    "remove",
    "leave",
    "role",
    "transfer",
    "rename",
    "invite",
    "revoke_invite",
    "close",
)
ZERO_HEAD = "00" * 32
MAX_NAME = 200


_ENTRY_FIELDS = {
    "schema",
    "lab_id",
    "seq",
    "prev",
    "op",
    "at",
    "actor",
    "actor_device",
    "subject",
    "role",
    "name",
    "invite",
    "request",
    "signature",
}
# `device_ok(subject, device_ed25519_hex, at)`: is this device key a key of
# this subject at time `at`? The node answers with the active devices of now.
# A client answers from the key directory with log proofs.
DeviceCheck = Callable[[str, str, datetime], bool]

# The words of each refusal of the admission policy, for a `join` entry.
_JOIN_REFUSED = {
    "revoked": "join: the invite was revoked",
    "used": "join: the invite was used",
    "expired": "join: the invite had expired",
    "endorser": "join: the person who made the invite cannot invite now",
}


def given(admission: AdmissionCheck | None) -> AdmissionCheck:
    """The admission checks that the caller gave. Raise `FormatError` for
    None: with no check, an `invite` or `join` entry is refused."""
    if admission is None:
        raise FormatError("the roster has no admission check; invite and join entries are refused")
    return admission


# ------------------------------------------------------------------ helpers


def check_name(value: Any, what: str = "lab name") -> str:
    """A lab name: 1 to 200 characters, no control character, no space at
    the start or the end."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_NAME:
        raise FormatError(f"{what}: expected 1..{MAX_NAME} characters")
    if value != value.strip() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise FormatError(f"{what}: bad characters")
    return value


def entry_hash(entry: JsonObject) -> str:
    """The hash of a full roster entry (with its signature or request)."""
    return hashlib.sha256(tagged_message(TAG_LAB_ROSTER, canonical_json(entry))).hexdigest()


# ------------------------------------------------------------ roster entry


def validate_roster_entry(doc: Any, admission: AdmissionCheck | None) -> JsonObject:
    """Check the form of a roster entry. The chain rules are in `LabState.apply`.
    A `join` entry needs `admission` (it checks the form of the request)."""
    if not isinstance(doc, dict) or set(doc) != _ENTRY_FIELDS:
        raise FormatError("roster entry: fields do not match the schema")
    if doc["schema"] != ROSTER_SCHEMA:
        raise FormatError("roster entry: unknown schema")
    validate_lab_id(doc["lab_id"])
    int_at_least(doc["seq"], "roster entry seq")
    hex_field(doc["prev"], HEX32, "roster entry prev")
    op = doc["op"]
    if op not in OPS:
        raise FormatError("roster entry: unknown op")
    parse_time(doc["at"])
    validate_subject(doc["actor"])
    hex_field(doc["actor_device"], HEX32, "roster entry actor_device")
    if doc["role"] is not None and doc["role"] not in ROLES:
        raise FormatError("roster entry: unknown role")
    if doc["name"] is not None:
        check_name(doc["name"])
    if doc["invite"] is not None:
        hex_field(doc["invite"], HEX16, "roster entry invite")
    needs = {
        "create": ("subject", "role", "name"),
        "add": ("subject", "role"),
        "join": ("subject", "role", "invite", "request"),
        "remove": ("subject",),
        "leave": ("subject",),
        "role": ("subject", "role"),
        "transfer": ("subject",),
        "rename": ("name",),
        "invite": ("invite",),
        "revoke_invite": ("invite",),
        "close": (),
    }[op]
    for name in ("subject", "role", "name", "invite", "request"):
        if (doc[name] is not None) != (name in needs):
            raise FormatError(
                f"roster entry: op {op} {'needs' if name in needs else 'has no'} {name}"
            )
    if doc["subject"] is not None:
        validate_subject(doc["subject"])
    if op == "join":
        if doc["signature"] is not None:
            raise FormatError(
                "roster entry: a join entry has no signature (the request is the proof)"
            )
        given(admission).check_request_form(doc["request"])
    else:
        hex_field(doc["signature"], HEX64, "roster entry signature")
    return doc


def make_roster_entry(
    *,
    state: LabState,
    op: str,
    actor: str,
    key: SigningKey,
    at: datetime,
    subject: str | None = None,
    role: str | None = None,
    name: str | None = None,
    invite: str | None = None,
) -> JsonObject:
    """A signed entry that comes next after `state`. `op` is each op except
    `join` (see `make_join_entry`). For `leave`, the subject is the actor."""
    if op == "join":
        raise FormatError("a join entry comes from a join request")
    if op == "leave":
        subject = actor
    entry = {
        "actor": actor,
        "actor_device": key.public_bytes().hex(),
        "at": format_time(at),
        "invite": invite,
        "lab_id": state.lab_id,
        "name": name,
        "op": op,
        "prev": state.head,
        "request": None,
        "role": role,
        "schema": ROSTER_SCHEMA,
        "seq": state.seq + 1,
        "subject": subject,
    }
    entry["signature"] = sign_doc(entry, TAG_SIGN_LAB_ROSTER, key)
    return validate_roster_entry(entry, state.admission)


def make_join_entry(*, state: LabState, request: JsonObject, role: str, at: datetime) -> JsonObject:
    """The entry that the node makes from a join request. It has no signature;
    the request holds the two signatures of the joiner."""
    given(state.admission).check_request_form(request)
    entry = {
        "actor": request["subject"],
        "actor_device": request["device"],
        "at": format_time(at),
        "invite": request["invite"],
        "lab_id": state.lab_id,
        "name": None,
        "op": "join",
        "prev": state.head,
        "request": request,
        "role": role,
        "schema": ROSTER_SCHEMA,
        "seq": state.seq + 1,
        "signature": None,
        "subject": request["subject"],
    }
    return validate_roster_entry(entry, state.admission)


# ----------------------------------------------------------------- state

# Permission table. `target` is the role of the other person,
# or the role that an action gives.
_ACTIONS = {
    "read": (PI, ADMIN, MEMBER),
    "publish": (PI, ADMIN, MEMBER),
    "invite": (PI, ADMIN),
    "invite_admin": (PI,),
    "revoke_invite": (PI, ADMIN),
    "add": (PI, ADMIN),
    "remove": (PI, ADMIN),
    "tombstone": (PI, ADMIN),
    "settings": (PI, ADMIN),
    "rename": (PI, ADMIN),
    "role": (PI,),
    "transfer": (PI,),
    "close": (PI,),
    "rotate": (PI, ADMIN),
    "leave": (ADMIN, MEMBER),
}


@dataclass
class LabState:
    """The state of one lab after a chain of roster entries."""

    lab_id: str
    seq: int = -1
    head: str = ZERO_HEAD
    name: str = ""
    members: dict[str, str] = field(default_factory=dict)  # pid -> role
    # invite id -> {"auth": authorisation, "uses": int, "revoked": bool,
    #               "actor": pid, "joined": tuple of the pids that joined with it}
    invites: dict[str, JsonObject] = field(default_factory=dict)
    genesis: str | None = None
    closed: bool = False
    removed_at: int = -1  # seq of the last remove or leave (drives key rotation)
    joined_at: dict[str, int] = field(default_factory=dict)  # pid -> seq of the entry
    times: dict[str, str] = field(default_factory=dict)  # pid -> "at" of that entry
    requests: set[str] = field(default_factory=set)  # hashes of used join requests
    heads: dict[int, str] = field(default_factory=dict)  # seq -> entry hash
    # Rules v2 (removal is final): pid -> seq of the `remove` entry. A removed
    # person cannot join with an invite until a PI or admin adds the person
    # again (`add`).
    removed: dict[str, int] = field(default_factory=dict)
    devices: dict[str, frozenset[str]] = field(default_factory=dict)  # pid -> devices in the chain
    barred: dict[str, str] = field(default_factory=dict)  # device of a removed person -> pid
    # pid -> the person who vouched (the creator of the invite)
    invited_by: dict[str, str] = field(default_factory=dict)
    # The checks of the `invite` and `join` entries (port `AdmissionCheck`;
    # L4 gives them). None: the state refuses these entries.
    admission: AdmissionCheck | None = field(default=None, repr=False, compare=False)

    def copy(self) -> LabState:
        return LabState(
            self.lab_id,
            self.seq,
            self.head,
            self.name,
            dict(self.members),
            {k: dict(v) for k, v in self.invites.items()},
            self.genesis,
            self.closed,
            self.removed_at,
            dict(self.joined_at),
            dict(self.times),
            set(self.requests),
            dict(self.heads),
            dict(self.removed),
            dict(self.devices),
            dict(self.barred),
            dict(self.invited_by),
            self.admission,
        )

    def pi(self) -> str:
        for pid, role in self.members.items():
            if role == PI:
                return pid
        raise FormatError("lab has no PI")

    def can(self, subject: str, action: str, target_role: str | None = None) -> bool:
        """The permission table (`_ACTIONS`). `target_role` is the
        role of the person that the action changes, or the role that it gives."""
        role = self.members.get(subject)
        if role is None or self.closed or action not in _ACTIONS:
            return False
        if role not in _ACTIONS[action]:
            return False
        if role == ADMIN and action in ("add", "remove") and target_role not in (None, MEMBER):
            return False
        if action == "remove" and target_role == PI:
            return False
        if action == "invite" and target_role == ADMIN:
            return role == PI
        return True

    def open_invites(self, now: datetime) -> list[str]:
        """IDs of the invites that a person can still use at `now`."""
        check = given(self.admission)
        return [
            iid
            for iid, inv in sorted(self.invites.items())
            if check.refusal(inv, self.creator_may_invite(inv["auth"]), now) is None
        ]

    def creator_may_invite(self, auth: JsonObject) -> bool:
        """The rule of the lab for an invite: the person who made it can still
        make it (a PI; or an admin, for a member invite)."""
        role = self.members.get(auth["created_by"])
        if auth["role"] == ADMIN:
            return role == PI
        return role in (PI, ADMIN)

    def apply(
        self,
        entry: JsonObject,
        device_ok: DeviceCheck,
        auths: Mapping[str, JsonObject] | None = None,
    ) -> None:
        """Check `entry` against the chain rules, then apply it. `auths` gives
        the invite authorisations (invite id -> authorisation) for `invite`
        entries. Raise `FormatError` on each rule that fails; the state does
        not change then."""
        validate_roster_entry(entry, self.admission)
        trial = self.copy()
        trial.advance(entry, device_ok, auths or {})
        self.__dict__.update(trial.__dict__)

    def advance(
        self, e: JsonObject, device_ok: DeviceCheck, auths: Mapping[str, JsonObject]
    ) -> None:
        """Apply the entry `e` (its form is checked) to this state in place.
        On a failure, a part of the change can stay: callers use `apply`,
        which applies to a copy."""
        op, actor, subject = e["op"], e["actor"], e["subject"]
        if e["lab_id"] != self.lab_id:
            raise FormatError("roster entry is for another lab")
        if e["seq"] != self.seq + 1:
            raise FormatError("roster entry seq is not next in the chain")
        if e["prev"] != self.head:
            raise FormatError("roster entry prev does not match the chain head")
        if self.closed:
            raise FormatError("the lab is closed")
        at = parse_time(e["at"])
        if op == "join":
            self._apply_join(e, device_ok)
        else:
            if not doc_signature_ok(e, TAG_SIGN_LAB_ROSTER, bytes.fromhex(e["actor_device"])):
                raise FormatError("roster entry has a bad signature")
            if not device_ok(actor, e["actor_device"], at):
                raise FormatError("roster entry device is not a key of the actor")
            if op == "create":
                if e["seq"] != 0 or subject != actor or e["role"] != PI:
                    raise FormatError("create: seq 0, the actor is the PI")
                self.name = e["name"]
                self.members = {actor: PI}
                self.joined_at[actor] = 0
                self.times[actor] = e["at"]
            else:
                if e["seq"] == 0:
                    raise FormatError("the first roster entry must be create")
                if actor not in self.members:
                    raise FormatError("the actor is not in the lab")
                self._apply_op(e, auths)
        self.devices[actor] = self.devices.get(actor, frozenset()) | {e["actor_device"]}
        h = entry_hash(e)
        if e["seq"] == 0:
            self.genesis = h
        self.seq = e["seq"]
        self.head = h
        self.heads[e["seq"]] = h

    def _apply_op(self, e: JsonObject, auths: Mapping[str, JsonObject]) -> None:
        if e["op"] == "invite":
            self._apply_invite(e, auths)
            return
        steps = {
            "add": self._op_add,
            "remove": self._op_remove,
            "leave": self._op_leave,
            "role": self._op_role,
            "transfer": self._op_transfer,
            "rename": self._op_rename,
            "revoke_invite": self._op_revoke_invite,
            "close": self._op_close,
        }
        steps[e["op"]](e)

    def _op_add(self, e: JsonObject) -> None:
        actor, subject, role = e["actor"], e["subject"], e["role"]
        if role not in (ADMIN, MEMBER) or subject in self.members:
            raise FormatError("add: role admin or member, for a person not in the lab")
        if not self.can(actor, "add", role):
            raise FormatError("add: not permitted for this role")
        self._readmit(subject)
        self.members[subject] = role
        self.joined_at[subject] = e["seq"]
        self.times[subject] = e["at"]

    def _op_remove(self, e: JsonObject) -> None:
        actor, subject = e["actor"], e["subject"]
        target = self.members.get(subject)
        if target is None or subject == actor:
            raise FormatError("remove: the person must be in the lab, and not the actor")
        if not self.can(actor, "remove", target):
            raise FormatError("remove: not permitted for this role")
        self._drop(subject, e["seq"])
        self._bar(subject, e["seq"])

    def _op_leave(self, e: JsonObject) -> None:
        actor = e["actor"]
        if e["subject"] != actor:
            raise FormatError("leave: only the actor leaves")
        if self.members[actor] == PI:
            raise FormatError("leave: the PI gives the PI role to another member first")
        self._drop(actor, e["seq"])
        self._revoke_member_invites(actor)

    def _op_role(self, e: JsonObject) -> None:
        subject, role = e["subject"], e["role"]
        if not self.can(e["actor"], "role") or role not in (ADMIN, MEMBER):
            raise FormatError("role: only the PI sets the role admin or member")
        target = self.members.get(subject)
        if target is None or target == PI:
            raise FormatError("role: the person must be in the lab, and not the PI")
        self.members[subject] = role

    def _op_transfer(self, e: JsonObject) -> None:
        actor, subject = e["actor"], e["subject"]
        if not self.can(actor, "transfer") or subject not in self.members or subject == actor:
            raise FormatError("transfer: the PI gives the role to another member")
        self.members[subject] = PI
        self.members[actor] = ADMIN

    def _op_rename(self, e: JsonObject) -> None:
        if not self.can(e["actor"], "rename"):
            raise FormatError("rename: not permitted for this role")
        self.name = e["name"]

    def _op_revoke_invite(self, e: JsonObject) -> None:
        inv = self.invites.get(e["invite"])
        if inv is None or inv["revoked"]:
            raise FormatError("revoke_invite: no open invite with this ID")
        need = "invite_admin" if inv["auth"]["role"] == ADMIN else "revoke_invite"
        if not self.can(e["actor"], need):
            raise FormatError("revoke_invite: not permitted for this role")
        inv["revoked"] = True

    def _op_close(self, e: JsonObject) -> None:
        if not self.can(e["actor"], "close"):
            raise FormatError("close: only the PI closes the lab")
        self.closed = True

    def _drop(self, subject: str, seq: int) -> None:
        del self.members[subject]
        self.joined_at.pop(subject, None)
        self.times.pop(subject, None)
        self.removed_at = seq

    def _revoke_member_invites(self, subject: str) -> None:
        for inv in self.invites.values():
            if inv["actor"] == subject or subject in inv["joined"]:
                inv["revoked"] = True

    def _bar(self, subject: str, seq: int) -> None:
        """Rules v2: a removal is final. Record the person and the devices of
        the person in the chain, and revoke each invite that the person made
        or joined with (so no rotation wraps a new key to it)."""
        self.removed[subject] = seq
        for device in self.devices.get(subject, ()):
            self.barred[device] = subject
        self._revoke_member_invites(subject)

    def _readmit(self, subject: str) -> None:
        """An explicit `add` by a PI or admin ends the bar of a removed person."""
        self.removed.pop(subject, None)
        self.barred = {d: p for d, p in self.barred.items() if p != subject}

    def _apply_invite(self, e: JsonObject, auths: Mapping[str, JsonObject]) -> None:
        iid = e["invite"]
        auth = auths.get(iid)
        if auth is None:
            raise FormatError("invite: the authorisation is missing")
        check = given(self.admission)
        check.check_invite(auth)
        if check.invite_id(auth) != iid or iid in self.invites:
            raise FormatError("invite: the ID does not match its authorisation, or it is used")
        if auth["created_by"] != e["actor"] or auth["creator_device"] != e["actor_device"]:
            raise FormatError("invite: the authorisation is from another person or device")
        if auth["lab_id"] != self.lab_id or auth["genesis"] != self.genesis:
            raise FormatError("invite: the authorisation is for another lab")
        if not self.can(e["actor"], "invite", auth["role"]):
            raise FormatError("invite: not permitted for this role")
        self.invites[iid] = {
            "actor": e["actor"],
            "auth": auth,
            "joined": (),
            "revoked": False,
            "uses": 0,
        }

    def _apply_join(self, e: JsonObject, device_ok: DeviceCheck) -> None:
        req = e["request"]
        inv = self.invites.get(e["invite"])
        if inv is None:
            raise FormatError("join: unknown invite")
        auth = inv["auth"]
        if req["lab_id"] != self.lab_id or req["invite"] != e["invite"]:
            raise FormatError("join: the request is for another lab or invite")
        if e["actor"] != req["subject"] or e["actor_device"] != req["device"]:
            raise FormatError("join: the entry does not match its request")
        if e["role"] != auth["role"]:
            raise FormatError("join: the role is not the role of the invite")
        check = given(self.admission)
        why = check.refusal(inv, self.creator_may_invite(auth), parse_time(req["at"]))
        if why is not None:
            raise FormatError(_JOIN_REFUSED[why])
        rh = check.request_hash(req)
        if rh in self.requests:
            raise FormatError("join: this request was used")
        if req["subject"] in self.members:
            raise FormatError("join: the person is in the lab")
        if req["subject"] in self.removed or req["device"] in self.barred:
            raise FormatError(
                "join: the person was removed from the lab; a PI or admin must add the person"
            )
        check.check_request(req, auth)
        if not device_ok(req["subject"], req["device"], parse_time(req["at"])):
            raise FormatError("join: the device is not a key of the person")
        inv["uses"] += 1
        inv["joined"] = (*inv["joined"], req["subject"])
        self.requests.add(rh)
        self.members[req["subject"]] = auth["role"]
        self.joined_at[req["subject"]] = e["seq"]
        self.times[req["subject"]] = e["at"]
        self.invited_by[req["subject"]] = auth["created_by"]


def replay(
    lab_id: str,
    entries: list[JsonObject],
    device_ok: DeviceCheck,
    auths: Mapping[str, JsonObject] | None = None,
    *,
    admission: AdmissionCheck | None,
) -> LabState:
    """Apply entries in order to a new state with the checks `admission`."""
    state = LabState(lab_id, admission=admission)
    for e in entries:
        state.apply(e, device_ok, auths)
    return state


# ------------------------------------------------- shared by items and settings


def roster_ref(state: LabState) -> JsonObject:
    """The roster point (seq and head) that a lab item or the settings name."""
    return {"head": state.head, "seq": state.seq}


def check_roster_ref(value: Any, what: str) -> None:
    """Check the form of a roster reference (see `roster_ref`)."""
    if not isinstance(value, dict) or set(value) != {"head", "seq"}:
        raise FormatError(f"{what}: bad roster reference")
    int_at_least(value["seq"], f"{what} roster seq")
    hex_field(value["head"], HEX32, f"{what} roster head")


def check_text(value: Any, what: str, limit: int = MAX_NAME, optional: bool = True) -> None:
    """Text of at most `limit` characters, with no control character. None
    is correct when `optional`."""
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 0x20 for c in value):
        raise FormatError(f"{what}: expected text of at most {limit} characters")
