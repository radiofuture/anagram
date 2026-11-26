"""The key directory on this computer (layer L1): `Directory`.

The client takes the device keys of a person only from the key directory of
the node, and only with log proofs: each key binding must be in a checkpoint
that is consistent with the last checkpoint that this client saw, and the
answer must list all key bindings of the person in the log (so a node cannot
hide a reset). The client keeps a copy of the key bindings in the vault, and
`monitor` checks each new binding of this person.
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime

from anagram.core.canonical import CanonicalError, canonical_json, loads
from anagram.core.crypto import merkle
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.timefmt import parse_time
from anagram.identity.app.device import Device
from anagram.identity.app.logcheck import LogCheck
from anagram.identity.formats.documents import (
    KIND_KEY_BINDING,
    SubjectKeys,
    is_subject,
    make_binding,
    validate_orcid,
    validate_subject,
)


class Directory:
    def __init__(self, device: Device, log: LogCheck) -> None:
        self.device = device
        self.log = log

    def _apply(self, state: SubjectKeys, entry: dict) -> None:
        cfg = self.device.identity_config()
        state.apply(
            entry, assertion_key=bytes.fromhex(cfg["assertion_key"]), node_key=cfg["node_key"]
        )

    def lookup(self, who: str, allow_empty: bool = False) -> SubjectKeys:
        """Keys of a person (ORCID iD or subject). Each binding entry must have a
        valid inclusion proof in a checkpoint that is consistent with the last
        checkpoint this client saw. The answer must also be complete: the client
        reads the log up to that checkpoint, and the node answer must list all
        key bindings of the subject in it. Thus a node cannot hide a reset."""
        subject = self.resolve_person(who)
        vault = self.device.vault
        data = self.device.http.call("GET", f"/directory/{urllib.parse.quote(subject, safe=':')}")
        state = SubjectKeys(subject)
        if data["checkpoint"] is None:
            if data["entries"]:
                raise LogMisbehaved("directory entries without a checkpoint")
        else:
            cp = self.log.checkpoint(data["checkpoint"])
            if data["tree_size"] != cp.size:
                raise LogMisbehaved("directory answer does not match its checkpoint")
            for item in data["entries"]:
                leaf = merkle.leaf_hash(canonical_json(item["entry"]))
                path = [bytes.fromhex(h) for h in item["inclusion"]]
                if not merkle.verify_inclusion(leaf, item["leaf_index"], cp.size, path, cp.root):
                    raise LogMisbehaved("directory entry is not in the log")
                try:
                    self._apply(state, item["entry"])
                except FormatError as exc:
                    raise LogMisbehaved(f"directory entry breaks the chain rules: {exc}") from exc
            for a in self._sync_log(cp):
                vault.add_alert(None, a)
            local = [
                (i, canonical_json(e)) for i, e in vault.directory_entries(subject) if i < cp.size
            ]
            given = [(it["leaf_index"], canonical_json(it["entry"])) for it in data["entries"]]
            if given != local:
                raise LogMisbehaved("directory answer omits or changes key bindings in the log")
        if not state.devices and not allow_empty:
            raise ClientError(f"no active keys for {subject}")
        return state

    def resolve_person(self, who: str) -> str:
        """A subject (`pid:...`), or the pid of a member who is findable by this
        ORCID iD (`GET /resolve/orcid`, members only)."""
        who = who.strip()
        if is_subject(who):
            return who
        try:
            orcid = validate_orcid(who.removeprefix("orcid:"))
        except FormatError as exc:
            raise ClientError(f"not a person ID or ORCID iD: {who!r}") from exc
        try:
            found = self.device.http.call("GET", f"/resolve/orcid/{orcid}", auth=True)
        except NodeHTTPError as exc:
            if exc.status == 404:
                raise ClientError(
                    f"no member is findable by ORCID iD {orcid}; ask the person to turn on"
                    " 'findable by ORCID', or use their person ID"
                ) from exc
            raise
        try:
            return validate_subject(found.get("subject"))
        except FormatError as exc:
            raise LogMisbehaved("node gave a bad person ID") from exc

    def keys_ever(self, who: str) -> set[str]:
        """Each device key that the key directory bound to the person at some
        time (also removed keys): a signature of an old object stays valid."""
        state = self.lookup(who, allow_empty=True)
        return {e["device"]["ed25519"] for e in state.history if e["op"] in ("add", "reset")}

    def device_windows(self, subject: str) -> list[tuple[str, datetime, datetime | None]]:
        """(device, from, to) for each device that the key directory bound to
        this person (log proofs). `to` is None for an active device."""
        state = self.lookup(subject, allow_empty=True)
        active: dict[str, datetime] = {}
        out: list[tuple[str, datetime, datetime | None]] = []
        for e in state.history:
            at, dev = parse_time(e["created_at"]), e["device"]["ed25519"]
            if e["op"] == "reset":
                out += [(d, t, at) for d, t in active.items()]
                active = {}
            if e["op"] in ("add", "reset"):
                active[dev] = at
            elif e["op"] == "remove" and dev in active:
                out.append((dev, active.pop(dev), at))
        return out + [(d, t, None) for d, t in active.items()]

    def bind(self, state: SubjectKeys, **kw) -> dict:
        """Sign (with `authority_key`, if given) and submit the next key
        binding of `state`, and check that the log took it."""
        signer = kw.pop("authority_key", None)
        kw.setdefault("orcid_commitment", state.orcid_commitment)
        entry = make_binding(
            subject=state.subject,
            seq=state.seq + 1,
            prev=state.head,
            created_at=self.device.now(),
            authority_key=signer,
            **kw,
        )
        result = self.device.http.submit(entry)
        self.log.logged(canonical_json(entry), result)
        return entry

    def _sync_log(self, cp) -> list[str]:
        """Read the log entries up to the verified checkpoint `cp`, check that
        they make its root, and keep each valid key binding in the vault. Return
        alerts for invalid key bindings. `lookup` and `monitor` use this local
        copy as the reference."""
        vault = self.device.vault
        size, frontier = vault.monitor_state(cp.origin)
        if size > cp.size:
            raise LogMisbehaved("log went backwards")
        if size == cp.size:
            return []
        new_entries: list[tuple[int, dict]] = []
        i = size
        while i < cp.size:
            batch = self.device.node.entries(i, min(cp.size, i + 1000))
            if not batch:
                raise LogMisbehaved("node returned no entries")
            for text in batch:
                data = text.encode("utf-8")
                frontier = merkle.frontier_append(frontier, i, merkle.leaf_hash(data))
                try:
                    entry = loads(data)
                except (CanonicalError, ValueError):
                    entry = None
                if isinstance(entry, dict) and entry.get("kind") == KIND_KEY_BINDING:
                    new_entries.append((i, entry))
                i += 1
        if merkle.frontier_root(frontier) != cp.root:
            raise LogMisbehaved("log entries do not match the checkpoint")
        states: dict[str, SubjectKeys] = {}
        for _, e in vault.directory_entries():
            st = states.setdefault(e["subject"], SubjectKeys(e["subject"]))
            self._apply(st, e)
        alerts: list[str] = []
        for idx, entry in new_entries:
            st = states.setdefault(entry["subject"], SubjectKeys(entry["subject"]))
            try:
                self._apply(st, entry)
            except FormatError as exc:
                alerts.append(f"entry {idx}: invalid key binding in the log: {exc}")
                continue
            vault.add_directory_entry(idx, entry["subject"], entry)
        vault.set_monitor_state(cp.origin, cp.size, frontier)
        return alerts

    def monitor(self) -> list[str]:
        """Read all new log entries, check that they make the checkpoint root, and
        check each key binding. Return new alerts (unexpected keys for me).

        `lookup` also reads the log. A separate cursor makes sure that the checks
        below see each of my key bindings one time."""
        doc = self.device.node.checkpoint()
        if doc.get("checkpoint") is None:
            return []
        cp = self.log.checkpoint(doc["checkpoint"])
        vault = self.device.vault
        alerts = self._sync_log(cp)
        me = self.device.config.get("identity", {}).get("subject")
        start = int(self.device.keys.monitor_cursor.get(cp.origin) or 0)
        expected = vault.expected_devices()
        mine = self.device.my_device()["ed25519"]
        for idx, entry in vault.directory_entries(me) if me else []:
            if idx < start or idx >= cp.size:
                continue
            key = entry["device"]["ed25519"]
            if entry["op"] in ("add", "reset") and key not in expected:
                alerts.append(
                    f"entry {idx}: an unknown device key {key[:16]}... was bound to you"
                    f" ({entry['op']}). If you did not do this, your account is at risk."
                )
            if (entry["op"] == "reset" and key != mine) or (
                entry["op"] == "remove" and key == mine
            ):
                alerts.append(f"entry {idx}: this device was removed ({entry['op']})")
        for a in alerts:
            vault.add_alert(None, a)
        self.device.keys.monitor_cursor.set(cp.origin, str(cp.size))
        return alerts
