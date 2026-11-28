"""The lab keys on the client: `LabKeys`.

The lab key has epochs. This device keeps the key of each epoch as a sealed
vault item (kind `lab-key`). A key package from the node is checked against
the verified roster (`LabRoster`) before it opens: the roster head that it
names is in the chain, the sender was PI or admin, and the sender device was
a key of the sender. Each fault is a node fault (`LogMisbehaved`). A remove,
or a device that is not active now, makes a new epoch due.
"""

from __future__ import annotations

from anagram.core.crypto import aead
from anagram.core.crypto.hashing import TAG_SIGN_LAB_KEY
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.signed import doc_signature_ok
from anagram.core.timefmt import parse_time
from anagram.core.wraps import find_wrap
from anagram.identity.api import Device, Directory
from anagram.network.formats import lab as labfmt
from anagram.network.formats import labkey
from anagram.network.groups.app.labroster import RETRIES, LabError, LabRoster

LAB_KEY_KIND = "lab-key"  # sealed vault item; ref "<lab_id>:<epoch>"


class LabKeys:
    """The epoch keys of the labs of this person (layer L3): key packages,
    rotation, and the labs whose space this device can read."""

    def __init__(self, device: Device, directory: Directory, roster: LabRoster) -> None:
        self.device = device
        self.directory = directory
        self.roster = roster

    # ------------------------------------------------------------ the keys

    def epoch_keys(self, lab_id: str) -> dict[int, bytes]:
        """The lab keys that this device holds (sealed vault items; they come
        to the other devices of the person through the personal store)."""
        prefix = f"{lab_id}:"
        out: dict[int, bytes] = {}
        for kind, ref, _, _ in self.device.vault.sealed_items():
            if kind != LAB_KEY_KIND or not ref.startswith(prefix):
                continue
            n = ref.removeprefix(prefix)
            try:
                key = self.device.unseal(kind, ref)
            except Exception:  # noqa: S112 - sealed with another vault key: not usable
                continue
            if n.isdigit() and key is not None and len(key) == 32:
                out[int(n)] = key
        return out

    def keep_lab_keys(self, lab_id: str, keys: dict[int, bytes], epoch_seq: int) -> None:
        """Seal new epoch keys. A package that gives another key for an epoch
        that this device has is a node fault (two keys for one epoch)."""
        known = self.epoch_keys(lab_id)
        for n, key in sorted(keys.items()):
            if n in known and known[n] != key:
                raise LogMisbehaved("a lab key package gives a second key for one epoch")
            if n not in known:
                self.device.seal(LAB_KEY_KIND, f"{lab_id}:{n}", key)
        cache = self.roster.labcache
        top = max(keys)
        if top > cache.epoch(lab_id) or cache.epoch_seq(lab_id) < 0:
            cache.set_epoch(lab_id, top)
            cache.set_epoch_seq(lab_id, epoch_seq)
            cache.set_due(lab_id, False)

    def lab_key(self, lab_id: str, epoch: int | None = None) -> tuple[int, bytes]:
        """(epoch, key). With no epoch: the newest key on this device. Pull
        the packages from the node if the key is not here."""
        lab_id = self.roster.check_lab_id(lab_id)
        keys = self.epoch_keys(lab_id)
        if (epoch is None and not keys) or (epoch is not None and epoch not in keys):
            self.pull_keys(lab_id, self.roster.lab_state(lab_id))
            keys = self.epoch_keys(lab_id)
        n = max(keys, default=0) if epoch is None else epoch
        if n not in keys:
            raise LabError("This computer has no key for this part of the lab space.")
        return n, keys[n]

    def readable_labs(self) -> list[str]:
        """Labs whose space this device can read now (for
        `index.spaces.readable_spaces`): the lab is not left, the verified
        roster (cache) has this person, and the key of the current epoch
        opens. Old keys alone do not make a lab readable."""
        cache = self.roster.labcache
        out = []
        for lab_id in cache.labs():
            state = cache.state(lab_id)
            if state is None or self.device.subject not in state.members:
                continue
            epoch = cache.epoch(lab_id)
            if epoch and epoch in self.epoch_keys(lab_id):
                out.append(lab_id)
        return out

    # ------------------------------------------------------------ packages

    def package(
        self,
        state: labfmt.LabState,
        epoch: int,
        keys: dict[int, bytes],
        recipient: str,
        devices: list[dict],
        epoch_seq: int,
    ) -> dict:
        """One key package. `roster_seq` is the roster seq at the start of
        the epoch, so that each package of an epoch names the same start
        (the rotation rule reads it)."""
        if (
            epoch_seq < 0
            or epoch_seq not in state.heads
            or not self.roster.was_keeper(state.lab_id, self.device.subject, epoch_seq)
        ):
            epoch_seq = state.seq
        return labkey.make_key_package(
            lab_id=state.lab_id,
            epoch=epoch,
            keys={n: keys[n] for n in range(1, epoch + 1)},
            recipient=recipient,
            devices=devices,
            roster_seq=epoch_seq,
            roster_head=state.heads[epoch_seq],
            sender=self.device.subject,
            key=self.device.device_key(),
            created_at=self.device.now(),
        )

    def member_package(
        self, state: labfmt.LabState, epoch: int, keys: dict[int, bytes], subject: str, seq: int
    ) -> dict | None:
        """A package for each active device of a member, with device keys
        from `lookup` (log proofs; a failed proof stops the action). None if
        the person has no active device."""
        if subject not in state.members:
            return None
        try:
            devices = list(self.directory.lookup(subject).devices.values())
        except LogMisbehaved:
            raise
        except ClientError:
            return None
        return self.package(state, epoch, keys, subject, devices, seq)

    def open_package(
        self, state: labfmt.LabState, doc: dict, device: str, private_x25519: bytes
    ) -> dict[int, bytes]:
        """Check a package (`check_package`), then open the wrap of `device`."""
        self.check_package(state, doc)
        try:
            return labkey.open_key_package(doc, device=device, private_x25519=private_x25519)
        except FormatError as exc:
            raise LogMisbehaved(f"a lab key package does not open: {exc}") from exc

    def check_package(self, state: labfmt.LabState, doc: dict) -> None:
        """The checks of a key package: the roster head that the package
        names is in the verified chain; the sender was PI or admin; the
        sender device was a key of the sender; the signature verifies. Each
        fault is a node fault."""
        try:
            labkey.validate_key_package(doc)
        except FormatError as exc:
            raise LogMisbehaved(f"the node gave a damaged lab key package: {exc}") from exc
        if doc["lab_id"] != state.lab_id:
            raise LogMisbehaved("the node gave the key package of another lab")
        if state.heads.get(doc["roster_seq"]) != doc["roster_head"]:
            raise LogMisbehaved("a lab key package names a roster head that is not in the chain")
        if not self.roster.was_keeper(state.lab_id, doc["sender"], doc["roster_seq"]):
            raise LogMisbehaved("a lab key package comes from a person who cannot give keys")
        check = self.roster.device_check()
        if not check(doc["sender"], doc["sender_device"], parse_time(doc["created_at"])):
            raise LogMisbehaved("a lab key package comes from a device that is not the sender's")
        if not doc_signature_ok(doc, TAG_SIGN_LAB_KEY, bytes.fromhex(doc["sender_device"])):
            raise LogMisbehaved("a lab key package has a bad signature")

    def pull_keys(self, lab_id: str, state: labfmt.LabState) -> tuple[int, list[dict] | None]:
        """Read my packages and open the newest one that has a wrap for this
        device (it holds the keys of all earlier epochs). Return the current
        epoch of the node and, for a PI or admin, the packages of that epoch."""
        data = self.device.http.call("GET", f"/labs/{lab_id}/keys", auth=True)
        try:
            epoch, packages = int(data["epoch"]), list(data["packages"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LogMisbehaved("the node gave a damaged lab key answer") from exc
        me = self.device.my_device()["ed25519"]
        if any(
            not isinstance(d, dict) or d.get("recipient") != self.device.subject for d in packages
        ):
            raise LogMisbehaved("the node gave the lab key package of another person")
        packages.sort(key=lambda d: -int(d.get("epoch", 0)))
        for doc in packages:
            if find_wrap(doc.get("wraps") or [], me) is not None:
                keys = self.open_package(state, doc, me, self.device.x25519_key().private_bytes())
                self.keep_lab_keys(lab_id, keys, doc["roster_seq"])
                break
            known = self.epoch_keys(lab_id)
            if known and doc.get("epoch") == max(known):
                # A device made after this package: the keys came through the
                # personal store. The package gives the start of the epoch.
                self.check_package(state, doc)
                self.keep_lab_keys(lab_id, known, doc["roster_seq"])
                break
        current = data.get("current")
        return epoch, current if isinstance(current, list) else None

    # ------------------------------------------------- the epochs of a lab

    def first_epoch(self, state: labfmt.LabState) -> None:
        """Epoch 1 of a new lab: a new key, wrapped to the devices of the PI."""
        keys = {1: aead.new_key()}
        mine = self.member_package(state, 1, keys, self.device.subject, state.seq)
        if mine is None:
            raise LabError("This computer has no active device key. Sign in again.")
        self.device.http.call(
            "PUT", f"/labs/{state.lab_id}/keys/1", {"packages": [mine]}, auth=True
        )
        self.keep_lab_keys(state.lab_id, keys, state.seq)

    def give_keys(self, state: labfmt.LabState, subject: str) -> None:
        """Give a new member the keys of epochs 1 to now. If a rotation came
        first, the package is for the newest epoch (pull, then again)."""
        for _ in range(RETRIES):
            self.pull_keys(state.lab_id, state)
            keys = self.epoch_keys(state.lab_id)
            if not keys:
                return  # no key on this device: the next rotation gives one
            n = max(keys)
            pkg = self.member_package(
                state, n, keys, subject, self.roster.labcache.epoch_seq(state.lab_id)
            )
            if pkg is None:
                return  # no active device yet: the next rotation gives one
            try:
                self.device.http.call(
                    "PUT", f"/labs/{state.lab_id}/keys/{n}", {"packages": [pkg]}, auth=True
                )
                return
            except NodeHTTPError as exc:
                if exc.status != 409:
                    raise
            state = self.roster.lab_state(state.lab_id)
            if subject not in state.members:
                return

    def rotation_due(self, state: labfmt.LabState) -> bool:
        """A new epoch is due (cache only, no network): a member went after
        the start of the current epoch, or a device in the wraps of the
        current epoch is not active now."""
        cache, lab_id = self.roster.labcache, state.lab_id
        if cache.epoch(lab_id) == 0:
            return False
        return state.removed_at > cache.epoch_seq(lab_id) or cache.due(lab_id)

    def lab_rotate(self, lab_id: str) -> int:
        """Start a new epoch (PI or admin): a new key, with the keys of all
        earlier epochs, wrapped to each member and each open invite. If
        another rotation wins the race, take its key. Return the epoch."""
        lab_id = self.roster.check_lab_id(lab_id)
        for _ in range(RETRIES):
            state = self.roster.lab_state(lab_id)
            if not state.can(self.device.subject, "rotate"):
                raise LabError("Your role in this lab does not permit this.")
            current, _ = self.pull_keys(lab_id, state)
            keys = self.epoch_keys(lab_id)
            if sorted(keys) != list(range(1, current + 1)):
                raise LabError("This computer does not have all keys of this lab. Sync first.")
            n = current + 1
            keys = {**keys, n: aead.new_key()}
            packages = self.epoch_packages(state, n, keys)
            try:
                self.device.http.call(
                    "PUT", f"/labs/{lab_id}/keys/{n}", {"packages": packages}, auth=True
                )
            except NodeHTTPError as exc:
                if exc.status != 409:
                    raise
                state = self.roster.lab_state(lab_id)
                self.pull_keys(lab_id, state)
                if not self.rotation_due(state):
                    return self.roster.labcache.epoch(lab_id)
                continue
            self.keep_lab_keys(lab_id, keys, state.seq)
            return n
        raise LabError("The lab changed while you worked. Try again.")

    def epoch_packages(self, state: labfmt.LabState, n: int, keys: dict[int, bytes]) -> list:
        """The packages of epoch `n`: one for each member with an active
        device, and one for each open invite."""
        packages = []
        for subject in sorted(state.members):
            pkg = self.member_package(state, n, keys, subject, state.seq)
            if pkg is not None:
                packages.append(pkg)
        for iid in state.open_invites(self.device.now()):
            auth = state.invites[iid]["auth"]
            packages.append(
                self.package(
                    state, n, keys, labkey.invite_recipient(iid), [invite_device(auth)], state.seq
                )
            )
        return packages

    def check_devices(self, state: labfmt.LabState, current: list[dict] | None) -> None:
        """Set `due` if a device in the wraps of the current epoch is not an
        active device of its member now (a removed or reset device)."""
        if not current:
            return
        for doc in current:
            subject = doc.get("recipient") if isinstance(doc, dict) else None
            if subject not in state.members:
                continue  # an invite, or a person who went (removed_at covers it)
            try:
                active = set(self.directory.lookup(subject, allow_empty=True).devices)
            except LogMisbehaved:
                raise
            except ClientError:
                continue
            wrapped = {w.get("device") for w in doc.get("wraps") or [] if isinstance(w, dict)}
            if wrapped - active:
                self.roster.labcache.set_due(state.lab_id, True)
                return


def invite_device(auth: dict) -> dict:
    """The one "device" of an invite package: the keys from the seed."""
    return {"ed25519": auth["invite_pub"], "x25519": auth["invite_x25519"]}
