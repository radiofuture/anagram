"""The handoff part of an enclave instance: restart, the state-key handoff
and the takeover (spec/enclave-trust.md 5.3, 5.7, 6.2).

The state key moves only by the signed handoff message (`trust/handoff.py`).
A writer gives it to a successor of the same release, or to the named
successor release (an upgrade), or to a standby that only joins the
holders. A holder writes when the cosigned log names it: the latest epoch
names it `next_writer`, or a failover entry names it.

`HandoffSteps` is the part of `EnclaveInstance` that does these steps; it
reads the instance's line state and keys, which `EnclaveInstance` holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from anagram.core.canonical import JsonObject, loads_canonical
from anagram.core.crypto import hpke
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.instance_keys import InstanceKeys
from anagram.network.matching.enclave.journal import Journal
from anagram.network.matching.enclave.ledger import Ledger
from anagram.network.matching.enclave.state import Host, LogPort, Release, Role
from anagram.network.matching.trust import handoff as ho
from anagram.network.matching.trust import snapshot as snap
from anagram.network.matching.trust.attestation import verify_successor
from anagram.network.matching.trust.bundle import attestation_digest
from anagram.network.matching.trust.clock import SignedClock
from anagram.network.matching.trust.lines import latest_epoch, line_writer, writer_of
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.release import APP_VERSION, accept_release, check_successor
from anagram.network.matching.trust.roots import Roots


@dataclass
class Handoff:
    """A handoff in progress at the writer, and the message that a holder
    got."""

    successor: str | None = None  # the instance ID that a handoff names
    standby: bool = False  # the handoff adds a holder and keeps this writer
    received: tuple[str, int, str] | None = None  # (me, counter, digest) of the message I got
    sent: JsonObject | None = None  # the message of the handoff in progress
    successor_key: str | None = None  # the output key of its successor
    standbys: dict[str, tuple[JsonObject, str]] = field(default_factory=dict)  # sid -> (msg, key)


class HandoffSteps:
    """Restart, handoff and takeover. The attributes below are fields of
    `EnclaveInstance`; the methods it calls are its own."""

    release: Release
    roots: Roots
    host: Host
    line_id: str
    keys: InstanceKeys
    role: Role
    state_key: bytes | None
    journal: Journal | None
    signed: SignedClock
    last_epoch: int
    last_digest: str | None
    pending_epoch: JsonObject | None
    handoff: Handoff

    @property
    def log(self) -> LogPort:
        raise NotImplementedError

    def observe(self) -> int | None:
        raise NotImplementedError

    def _write_epoch(self, next_writer: str | None, holders: list[str] | None = None) -> None:
        raise NotImplementedError

    def _journal(self, ledger: Ledger) -> Journal:
        raise NotImplementedError

    def _signed_epoch(self) -> int:
        raise NotImplementedError

    def _count(self, name: str) -> None:
        raise NotImplementedError

    def _restored(self) -> None:
        raise NotImplementedError

    # ---- restart (6.2) ----------------------------------------------------------

    def _load(self, view: LogView, latest: JsonObject) -> bytes:
        sealed = self.host.disk.get(latest["counter"], b"")
        received = self.handoff.received if latest["next_writer"] == self.keys.instance_id else None
        digest = snap.digest(sealed).hex()
        snap.check_load(view, self.roots, self.line_id, latest["counter"], digest, received)
        return sealed

    def restart(self) -> None:
        """The matching worker restarts inside the live instance: work since
        the last cosigned epoch is lost and that epoch loads. No receipt or
        batch of the lost work was released (6.3)."""
        if self.journal is None:
            return
        view = self.log.view()
        latest = latest_epoch(view, self.line_id)
        if latest is None:
            raise Refused("snapshot_unknown", "the line has no cosigned epoch")
        self._load(view, latest)
        self.journal.cosigned = latest["counter"]
        self.journal.restart(keep_pending=True)
        self.signed.max_seen = max(self.signed.max_seen, self.journal.ledger.max_seen)
        if (
            self.pending_epoch is not None
            and self.pending_epoch["counter"] <= self.journal.cosigned
        ):
            self.pending_epoch = None
        self.last_digest = view.digests[view.entries.index(latest)].hex()
        self.last_epoch = self._signed_epoch()
        self._restored()

    def _retire(self) -> None:
        """Stop for good: the state key and the line state leave memory."""
        self.role, self.state_key, self.journal = Role.RETIRED, None, None

    # ---- the handoff (5.3) --------------------------------------------------------

    def hand_off(
        self,
        successor_doc: JsonObject,
        successor_release: JsonObject,
        standby: bool = False,
    ) -> JsonObject:
        """Steps 2 and 3 at the writer: check the successor and send the
        state key for the latest cosigned epoch. An upgrade stops opening
        requests; a `standby` handoff only adds a holder, which can take
        over by failover if this writer stops (5.7)."""
        if self.role != Role.WRITER or self.state_key is None or self.journal is None:
            raise Refused("handoff_not_successor", "not the writer")
        now = self.observe()
        view = self.log.view()
        epoch = latest_epoch(view, self.line_id)
        try:
            if now is None:
                raise Refused("clock_unsafe")
            if isinstance(successor_doc, dict) and (
                successor_doc.get("instance_id") == self.keys.instance_id
                or successor_doc.get("line_id") != self.line_id
            ):
                raise Refused("handoff_not_successor", "self or cross-line handoff")
            accept_release(successor_release, view, self.roots, APP_VERSION, now)
            check_successor(self.release.entry, successor_release)
            verify_successor(successor_doc, successor_release, view, self.roots, now)
            if epoch is None or epoch["counter"] != self.journal.counter - 1:
                raise Refused("snapshot_unknown", "the latest epoch is not cosigned yet")
            holders = set(epoch["holders"]) | {successor_doc["instance_id"]}
            if len(holders) > successor_release["max_instances"]:
                raise Refused("instance_limit")
            if successor_doc["key_epoch"] != self.keys.key_epoch:
                raise Refused("handoff_not_successor", "key epoch")
        except Refused as exc:
            self._count(f"handoff_{exc.code}")
            raise
        target = attestation_digest(successor_doc)
        counter, digest = epoch["counter"], epoch["snapshot_digest"]
        secret = ho.secret(self.state_key, self.line_id, counter, digest)
        sealed = hpke.seal(bytes.fromhex(successor_doc["intake_key"]), secret, ho.info(target))
        self.role = Role.WRITER if standby else Role.DRAINING
        msg = ho.make(sealed, self.line_id, counter, digest, target, self.keys.output)
        h = self.handoff
        sid = successor_doc["instance_id"]
        if standby:
            h.standbys[sid] = (msg, successor_doc["output_key"])
            h.successor, h.standby = sid, True
            h.sent, h.successor_key = msg, successor_doc["output_key"]
        else:
            h.successor, h.standby = sid, False
            h.sent, h.successor_key = msg, successor_doc["output_key"]
        return msg

    def check_ready(self, doc: object) -> str:
        """The successor's `ready` note for the handoff in progress (the
        host asks for it before `finish_hand_off`). Return the successor ID."""
        h = self.handoff
        if self.role == Role.DRAINING:
            if h.sent is None or h.successor_key is None or h.successor is None:
                raise Refused("handoff_not_successor", "no handoff in progress")
            ho.check_ready(doc, h.sent, h.successor_key)
            return h.successor
        if h.standbys:
            signer = doc.get("signer") if isinstance(doc, dict) else None
            for sid, (sent, key) in h.standbys.items():
                if signer == key:
                    ho.check_ready(doc, sent, key)
                    return sid
            raise Refused("handoff_not_successor", "not the successor of this handoff")
        raise Refused("handoff_not_successor", "no handoff in progress")

    def ready(self, msg: JsonObject) -> JsonObject:
        """The note that this successor accepted `msg` (`accept_hand_off`)."""
        return ho.ready(msg, self.keys.output)

    def finish_hand_off(self, successor_id: str | None = None) -> None:
        """Step 5: the epoch that adds the successor to the holders. For an
        upgrade it names the successor the next writer, and after it this
        instance opens nothing."""
        h = self.handoff
        if self.role == Role.DRAINING:
            if h.successor is None or h.standby:
                raise Refused("handoff_not_successor", "no handoff in progress")
            sid = h.successor
            latest = latest_epoch(self.log.view(), self.line_id)
            holders = sorted({*(latest["holders"] if latest else []), sid})
            self._write_epoch(next_writer=sid, holders=holders)
            self._retire()
            h.successor, h.standby, h.sent, h.successor_key = None, False, None, None
            h.standbys.clear()
            return
        if self.role != Role.WRITER:
            raise Refused("handoff_not_successor", "no handoff in progress")
        target_id = successor_id if successor_id is not None else h.successor
        if target_id is None or target_id not in h.standbys:
            raise Refused("handoff_not_successor", "no handoff in progress")
        latest = latest_epoch(self.log.view(), self.line_id)
        holders = sorted({*(latest["holders"] if latest else []), target_id})
        self._write_epoch(next_writer=None, holders=holders)
        h.standbys.pop(target_id, None)
        if h.successor == target_id:
            h.successor, h.standby, h.sent, h.successor_key = None, False, None, None

    def accept_hand_off(self, msg: JsonObject) -> None:
        """Step 4 at the successor."""
        try:
            if self.role != Role.NEW:
                raise Refused("handoff_bad_sender", "instance is not new")
            if not isinstance(msg, dict) or msg.get("line_id") != self.line_id:
                raise Refused("handoff_bad_sender", "handoff is for another line")
            key = ho.accept(
                msg,
                self.log.view(),
                self.keys.attestation_digest(),
                hpke.private_bytes(self.keys.intake),
            )
        except Refused as exc:
            self._count(f"handoff_{exc.code}")
            raise
        self.state_key = key
        self.handoff.received = (self.keys.instance_id, msg["counter"], msg["snapshot_digest"])
        self.role = Role.HOLDER

    # ---- the takeover (5.7, 6.2) --------------------------------------------------

    def _take_over(self) -> None:
        """A holder becomes the writer when the cosigned log says so: the
        latest epoch names it `next_writer` (an upgrade; that epoch is the
        one after the handoff message, 6.2), or a failover entry names it
        (5.7). It loads the latest epoch's snapshot and writes from then
        on. After a failover the old writer leaves the holders."""
        view = self.log.view()
        latest = latest_epoch(view, self.line_id)
        if (
            latest is None
            or self.state_key is None
            or line_writer(view, self.line_id, self.roots) != self.keys.instance_id
        ):
            return
        _, body = snap.open_snapshot(self.state_key, self._load(view, latest))
        self.journal = self._journal(Ledger.from_json(loads_canonical(body)))
        self.signed.max_seen = max(self.signed.max_seen, self.journal.ledger.max_seen)
        self.journal.counter = latest["counter"] + 1
        self.journal.cosigned = latest["counter"]
        self.pending_epoch = None
        self.last_digest = view.digests[view.entries.index(latest)].hex()
        self.role = Role.WRITER
        self._restored()
        holders = latest["holders"]
        if latest["next_writer"] != self.keys.instance_id:
            holders = [h for h in holders if h != writer_of(latest)]
        self._write_epoch(next_writer=None, holders=holders)
