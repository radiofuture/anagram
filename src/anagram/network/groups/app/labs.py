"""Lab unit on the client: `Labs`.

`Labs` has the actions that change the roster of a lab (make, add, remove,
leave, role, transfer, rename), the list of the labs of this person, the
sync of all parts, and the removal of a device. It uses three parts that the
composition root (`Client`) makes:

- `LabRoster` (`labroster`): the verified roster and the local lab cache.
- `LabKeys` (`labkeys`): the epoch keys, the key packages, and rotation.
- `LabSpace` (`labrecords`): the items, files, and settings of the lab space.
"""

from __future__ import annotations

import secrets

from anagram.core.errors import FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import Account, Device, Directory, new_lab_id
from anagram.network.formats import lab as labfmt
from anagram.network.groups.app.labkeys import LabKeys
from anagram.network.groups.app.labrecords import LabSpace
from anagram.network.groups.app.labroster import LabError, LabRoster


class Labs:
    """The labs of this person (layer L3): the roster actions and the sync."""

    def __init__(
        self,
        device: Device,
        directory: Directory,
        account: Account,
        roster: LabRoster,
        keys: LabKeys,
        space: LabSpace,
    ) -> None:
        self.device = device
        self.directory = directory
        self.account = account
        self.roster = roster
        self.keys = keys
        self.space = space

    # ------------------------------------------------------------ actions

    def lab_create(self, name: str) -> dict:
        """Start a lab with this person as PI. Return {"lab_id", "name"}."""
        name = _lab_name(name)
        lab_id = new_lab_id(secrets.token_bytes(8))
        state = self.roster.new_state(lab_id)
        entry = labfmt.make_roster_entry(
            state=state,
            op="create",
            actor=self.device.subject,
            key=self.device.device_key(),
            at=self.device.now(),
            subject=self.device.subject,
            role=labfmt.PI,
            name=name,
        )
        self.device.http.call("POST", "/labs", {"entry": entry}, auth=True)
        state.apply(entry, lambda *_: True)
        self.roster.labcache.append(state, [entry], {})
        self.keys.first_epoch(state)
        return {"lab_id": lab_id, "name": name}

    def lab_add(self, lab_id: str, who: str, role: str = labfmt.MEMBER) -> dict:
        """Add a node member directly (PI; admin for role member)."""
        subject = self.directory.resolve_person(who)
        state = self.roster.submit(lab_id, "add", subject=subject, role=role)
        self.keys.give_keys(state, subject)
        return self.roster.view(state)

    def lab_remove(self, lab_id: str, who: str) -> dict:
        """Remove a member. A remove starts a new epoch in the same action."""
        subject = self.directory.resolve_person(who)
        state = self.roster.submit(lab_id, "remove", subject=subject)
        self.keys.lab_rotate(state.lab_id)
        return self.roster.view(state)

    def lab_leave(self, lab_id: str) -> None:
        """Leave the lab. The lab keys that this device has stay as sealed
        vault items (they open only what the person read before); the cache
        marks the lab as left, so no scope reads it."""
        self.roster.submit(lab_id, "leave")
        self.roster.labcache.set_left(lab_id)

    def lab_set_role(self, lab_id: str, who: str, role: str) -> dict:
        subject = self.directory.resolve_person(who)
        return self.roster.view(self.roster.submit(lab_id, "role", subject=subject, role=role))

    def lab_transfer(self, lab_id: str, who: str) -> dict:
        subject = self.directory.resolve_person(who)
        return self.roster.view(self.roster.submit(lab_id, "transfer", subject=subject))

    def lab_rename(self, lab_id: str, name: str) -> dict:
        name = _lab_name(name)
        return self.roster.view(self.roster.submit(lab_id, "rename", name=name))

    def lab_list(self) -> list[dict]:
        """The labs of this person from the local cache (no network):
        [{"lab_id", "name", "role", "members", "rotation_due"}]."""
        cache = self.roster.labcache
        out = []
        for lab_id in cache.labs():
            state = cache.state(lab_id)
            if state is None or self.device.subject not in state.members:
                continue
            out.append(
                {
                    "lab_id": lab_id,
                    "members": len(state.members),
                    "name": state.name,
                    "role": state.members[self.device.subject],
                    "rotation_due": self.keys.rotation_due(state),
                }
            )
        return out

    # --------------------------------------------------------------- sync

    def _sync_ids(self) -> list[str]:
        """The labs to sync: the labs in the cache and the labs that the node
        lists for this person (a second device has no cache yet)."""
        ids = set(self.roster.labcache.labs())
        try:
            ids |= {x for x in self.account.whoami().get("labs") or [] if isinstance(x, str)}
        except NodeHTTPError:
            pass
        return sorted(ids)

    def lab_sync(self, lab_id: str | None = None) -> dict:
        """Roster, key packages, rotation if due (PI or admin), records,
        settings. Safe to run again. Return {"labs": {lab_id: {...}}}."""
        ids = [self.roster.check_lab_id(lab_id)] if lab_id else self._sync_ids()
        out: dict[str, dict] = {}
        for lid in ids:
            try:
                state = self.roster.lab_state(lid)
            except LabError:
                out[lid] = {"removed": True}
                continue
            _, current = self.keys.pull_keys(lid, state)
            rotated = False
            if state.can(self.device.subject, "rotate"):
                self.keys.check_devices(state, current)
                if self.keys.rotation_due(state):
                    self.keys.lab_rotate(lid)
                    rotated = True
            out[lid] = {
                "epoch": self.roster.labcache.epoch(lid),
                "rotated": rotated,
                "roster": state.seq,
                **self.space.sync_space(lid, state),
            }
        return {"labs": out}

    # -------------------------------------------------------------- devices

    def remove_device(self, device: str) -> dict:
        """Remove one other device of this person from the key directory (a
        `remove` key binding that this device signs), then start a new epoch
        of each lab where this person is PI or admin. In other labs a
        PI or admin rotates at the next sync (the device trigger). Return
        {"device", "rotated": [lab_id], "due": [lab_id]}."""
        state = self.directory.lookup(self.device.subject)
        mine = self.device.device_key().public_bytes().hex()
        if device == mine:
            raise LabError("This computer cannot remove itself. Use another device.")
        if device not in state.devices:
            raise LabError("This device is not one of your devices.")
        self.directory.bind(
            state,
            op="remove",
            device=state.devices[device],
            authority={"device": mine},
            pop=None,
            authority_key=self.device.device_key(),
        )
        rotated, due = [], []
        cache = self.roster.labcache
        for lab_id in cache.labs():
            cached = cache.state(lab_id)
            if cached is None or self.device.subject not in cached.members:
                continue
            if cached.can(self.device.subject, "rotate"):
                try:
                    self.keys.lab_rotate(lab_id)
                    rotated.append(lab_id)
                    continue
                except (LabError, NodeHTTPError):
                    pass
            due.append(lab_id)
        return {"device": device, "due": due, "rotated": rotated}


def _lab_name(name: str) -> str:
    """The name of a lab without spaces at the ends. A bad name raises
    `LabError`."""
    name = name.strip() if isinstance(name, str) else name
    try:
        return labfmt.check_name(name)
    except FormatError as exc:
        raise LabError("A lab name has 1 to 200 characters.") from exc
