"""The verified lab roster on the client: `LabRoster`.

Rules:

- The client trusts only a roster that it verified. It keeps the head that it
  verified (the pin, in `labspace.sqlite`) and applies each new entry from the
  node with `formats.lab.LabState.apply`. A device key must be a key of the
  actor at the time of the entry, from `lookup` (log proofs). A chain that
  does not extend the pin, a shorter chain, or an entry that does not apply
  is a node fault: `LogMisbehaved`, and the client stores nothing.
- A node cannot add a person: an entry needs a member device signature, and
  a join needs the key of the invite.

The lab keys are in `labkeys`, the lab space in `labrecords`, and the
actions that change the roster in `labs`.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import Device, Directory, validate_lab_id
from anagram.network.formats import lab as labfmt
from anagram.network.groups.app.labcache import LabCache
from anagram.network.ports import AdmissionCheck

# A device signs an entry with its own clock. The key binding of the device
# has a time from the same clock; this is the margin for other clocks.
CLOCK_SKEW = timedelta(minutes=5)
RETRIES = 3


class LabError(ClientError):
    """A lab action is not possible (a rule, a role, or the person is not in
    the lab). The text is for the person."""


class LabRoster:
    """The verified roster of each lab of this person (layer L3), and the
    local lab cache that holds it."""

    def __init__(self, device: Device, directory: Directory, admission_check: AdmissionCheck):
        self.device = device
        self.directory = directory
        # The checks of the `invite` and `join` roster entries (port
        # `AdmissionCheck`, L4). The composition root (`Client`) gives them.
        self.admission_check = admission_check
        self._labcache: LabCache | None = None

    @property
    def labcache(self) -> LabCache:
        if self._labcache is None:
            self._labcache = LabCache(self.device.home, self.device.keystore, self.admission_check)
        return self._labcache

    def new_state(self, lab_id: str) -> labfmt.LabState:
        """An empty roster state with the admission checks of this client."""
        return labfmt.LabState(lab_id, admission=self.admission_check)

    def device_check(self) -> labfmt.DeviceCheck:
        """A `DeviceCheck` from the key directory (log proofs). It reads the
        device windows of each person one time."""
        windows: dict[str, list] = {}

        def ok(subject: str, device: str, at: datetime) -> bool:
            if subject not in windows:
                try:
                    windows[subject] = self.directory.device_windows(subject)
                except LogMisbehaved:
                    raise
                except ClientError:
                    windows[subject] = []
            return any(
                d == device and start - CLOCK_SKEW <= at and (end is None or at < end)
                for d, start, end in windows[subject]
            )

        return ok

    def check_lab_id(self, lab_id: str) -> str:
        try:
            return validate_lab_id(lab_id)
        except FormatError as exc:
            raise LabError("This is not a lab.") from exc

    def lab_state(self, lab_id: str) -> labfmt.LabState:
        """Pull the roster after the pinned head and verify it. Return the
        verified state. The pin moves only after the full check."""
        lab_id = self.check_lab_id(lab_id)
        pinned = self.labcache.state(lab_id)
        after = pinned.seq if pinned else -1
        try:
            data = self.device.http.call("GET", f"/labs/{lab_id}/roster?after={after}", auth=True)
        except NodeHTTPError as exc:
            if exc.status == 404:
                if pinned is not None:
                    self.labcache.set_left(lab_id)
                raise LabError("You are not in this lab.") from exc
            raise
        state = pinned.copy() if pinned else self.new_state(lab_id)
        try:
            entries, auths = list(data["entries"]), dict(data["invites"])
            seq, head = int(data["seq"]), data["head"]
        except (KeyError, TypeError, ValueError) as exc:
            raise LogMisbehaved("the node gave a damaged lab roster") from exc
        if seq < state.seq:
            raise LogMisbehaved("the node shows a shorter lab roster than this device saw")
        check = self.device_check()
        used: dict[str, dict] = {}
        try:
            for e in entries:
                state.apply(e, check, auths)
                if isinstance(e, dict) and e.get("op") == "invite":
                    used[e["invite"]] = auths[e["invite"]]
        except (FormatError, KeyError, TypeError) as exc:
            raise LogMisbehaved(f"a lab roster entry from the node does not verify: {exc}") from exc
        if state.seq != seq or state.head != head:
            raise LogMisbehaved("the lab roster of the node does not match its head")
        if entries:
            self.labcache.append(state, entries, used)
        if self.device.subject in state.members and self.labcache.left(lab_id):
            self.labcache.set_left(lab_id, False)
        return state

    def submit(self, lab_id: str, op: str, **kw) -> labfmt.LabState:
        """Sign one entry on the newest verified state and send it. On a
        conflict (another entry came first), pull and try again."""
        for _ in range(RETRIES):
            state = self.lab_state(lab_id)
            entry = labfmt.make_roster_entry(
                state=state,
                op=op,
                actor=self.device.subject,
                key=self.device.device_key(),
                at=self.device.now(),
                **kw,
            )
            trial = state.copy()
            try:
                trial.apply(entry, lambda *_: True)
            except FormatError as exc:
                raise LabError(_rule_text(op, str(exc))) from exc
            try:
                self.device.http.call("POST", f"/labs/{lab_id}/roster", {"entry": entry}, auth=True)
            except NodeHTTPError as exc:
                if exc.status == 409:
                    continue
                raise
            self.labcache.append(trial, [entry], {})
            return trial
        raise LabError("The lab changed while you worked. Try again.")

    def view(self, state: labfmt.LabState) -> dict:
        """The roster as the person sees it, with the role of this person."""
        return {
            "head": state.head,
            "lab_id": state.lab_id,
            "members": sorted(state.members),
            "name": state.name,
            "pi": state.pi(),
            "role": state.members.get(self.device.subject),
            "roles": dict(sorted(state.members.items())),
            "seq": state.seq,
        }

    def lab_members(self, lab_id: str) -> set[str]:
        """Members of the verified roster; an empty set if this person is not
        in the lab. A node fault still raises `LogMisbehaved`."""
        try:
            return set(self.lab_state(lab_id).members)
        except LabError:
            return set()

    def member_cache(self, lab_id: str) -> labfmt.LabState:
        """The cached verified state of a lab that this person is in (no
        network). A lab that is not in the cache, or that the person left,
        raises `LabError`."""
        state = self.labcache.state(lab_id)
        if state is None or self.labcache.left(lab_id) or self.device.subject not in state.members:
            raise LabError("You are not in this lab.")
        return state

    def state_at(self, lab_id: str, seq: int) -> labfmt.LabState:
        """The verified state after the entry `seq` (from the cache)."""
        entries = [e for e in self.labcache.entries(lab_id) if e["seq"] <= seq]
        return labfmt.replay(
            lab_id,
            entries,
            lambda *_: True,
            self.labcache.auths(lab_id),
            admission=self.admission_check,
        )

    def was_keeper(self, lab_id: str, sender: str, from_seq: int) -> bool:
        """True if `sender` had the role PI or admin specifically at roster seq
        `from_seq` (the verified chain in the cache)."""
        if from_seq < 0:
            return False
        st = self.state_at(lab_id, from_seq)
        return st.seq == from_seq and st.members.get(sender) in (labfmt.PI, labfmt.ADMIN)


def _rule_text(op: str, detail: str) -> str:
    """One sentence for a refused action (experience rule 8)."""
    if op == "leave" and "PI" in detail:
        return "You are the PI. Give the PI role to another member, then leave."
    if "not permitted" in detail or "only the PI" in detail:
        return "Your role in this lab does not permit this."
    if "in the lab" in detail:
        return "This person is not in the lab, or is in it already."
    return "This lab change is not possible."
