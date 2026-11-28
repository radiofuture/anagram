"""One instance of the matching enclave (spec/enclave-trust.md 1, 5, 6).

An `EnclaveInstance` is one confidential VM of a release. Its keys
(`InstanceKeys`) come from inside and never leave; the state key of its
line seals snapshots and moves only by the signed handoff (`HandoffSteps`).
The live packs, the sweep, the reveal and the day batch are `Matching`.
Its roles (`Role`):

- `new`: logged its instance key; holds no state key;
- `writer`: the one instance of the line that opens requests and keeps
  state. It writes a state epoch at each 10-minute boundary and releases
  receipts and day batches only after a cosigned checkpoint holds an epoch
  that holds them (6.3);
- `holder`: holds the state key after a handoff; it writes when the latest
  cosigned epoch names it `next_writer`, or when a cosigned failover entry
  names it after the writer's lease ended (enclave-trust.md 5.7);
- `draining`: sent the state key to a successor; opens nothing;
- `retired`: wrote the epoch that hands the line over, or saw a failover
  to another holder; it holds no state key.

The instance reads only signed inputs: the log checkpoints (signed time,
epochs), the roster and node control chains, and the sealed requests. It
trusts the host for storage and transport only.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import aead
from anagram.core.crypto.signing import verify
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import ROSTER, Network, check_checkpoint
from anagram.network.formats.strict import (
    DAY,
    NONCE_MEMORY,
    REQUEST_SKEW,
    Refused,
    need,
    parse_time,
)
from anagram.network.matching.enclave import intake
from anagram.network.matching.enclave.funnel import EngineFactory, PackMatch, Rules
from anagram.network.matching.enclave.handoff_steps import Handoff, HandoffSteps
from anagram.network.matching.enclave.instance_keys import InstanceKeys
from anagram.network.matching.enclave.journal import Journal
from anagram.network.matching.enclave.ledger import Ledger, cut
from anagram.network.matching.enclave.pairs import Matching
from anagram.network.matching.enclave.state import (
    EPOCH,
    RENEW,
    SNAPSHOT_SIZES,
    Forbidden,
    Host,
    LogPort,
    NotReady,
    Release,
    Role,
)
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust import snapshot as snap
from anagram.network.matching.trust.bundle import make_bundle
from anagram.network.matching.trust.clock import SignedClock
from anagram.network.matching.trust.entries import entry_digest, sign_entry
from anagram.network.matching.trust.issuance import Issuance, policy_limit
from anagram.network.matching.trust.lines import latest_epoch, line_writer
from anagram.network.matching.trust.platform import Platform
from anagram.network.matching.trust.roots import Roots, quorum_times


@dataclass
class EnclaveInstance(HandoffSteps):
    release: Release
    platform: Platform
    roots: Roots
    host: Host
    line_id: str
    engines: EngineFactory  # the host's engines for the release's models
    keys: InstanceKeys = field(default_factory=InstanceKeys)
    new_id: Callable[[], str] = field(default=lambda: secrets.token_hex(16))  # proposal IDs
    role: Role = Role.NEW
    state_key: bytes | None = None
    journal: Journal | None = None
    signed: SignedClock = field(default_factory=SignedClock)
    last_epoch: int = -1  # the 10-minute index of the last epoch written
    last_digest: str | None = None  # digest of the line's latest epoch entry
    pending_epoch: JsonObject | None = None  # latest uncosigned epoch emitted by this writer
    handoff: Handoff = field(default_factory=Handoff)
    refusals: dict[str, int] = field(default_factory=dict)  # counted without line state
    nonces: dict[tuple[str, str], int] = field(default_factory=dict)  # (node, nonce) -> time
    issuance: Issuance = field(default_factory=Issuance)  # from the public log, not state
    net: Network = field(init=False)
    matching: Matching = field(init=False)

    def __post_init__(self) -> None:
        body = self.release.matching
        self.net = Network(body["network"], body["roster_key"])
        rules = Rules.of(self.release.kind("matching")[0])
        match = PackMatch(self.engines(self.release.kind("model")), rules)
        self.matching = Matching(self.net, match, self.new_id, self._count)

    @property
    def log(self) -> LogPort:
        return self.host.log

    @property
    def instance_id(self) -> str:
        return self.keys.instance_id

    @property
    def document(self) -> JsonObject | None:
        return self.keys.document

    @property
    def ledger(self) -> Ledger:
        if self.journal is None:
            raise Refused("unavailable", "the instance holds no line state")
        return self.journal.ledger

    # ---- keys and the line (sections 3.3, 5.4, 5.5) -------------------------

    def register(self) -> None:
        """Make a new attestation document and log the instance key with a
        lease of 24 hours. Called at start and every 12 hours."""
        note = self.log.checkpoint()
        now = self.host.clock()
        self.keys.register(
            self.line_id, self.release, self.platform, self.roots, self.log, note, now
        )

    def start_line(self) -> None:
        """The first instance of an authorised line: a new state key and the
        epoch at counter 0 (section 5.5)."""
        self.state_key = aead.new_key()
        self.journal = self._journal(Ledger())
        self.role = Role.WRITER
        self._write_epoch(next_writer=None, holders=[self.instance_id])

    def _journal(self, ledger: Ledger) -> Journal:
        key = self.state_key
        if key is None:
            raise Refused("unavailable", "no state key")

        def seal(counter: int, body: bytes) -> bytes:
            size = next((s for s in SNAPSHOT_SIZES if s >= len(body) + 4), None)
            if size is None:
                raise Refused("too_large", f"state of {len(body)} bytes is over the largest bucket")
            return snap.seal(key, self.line_id, counter, size, body)

        def unseal(counter: int, sealed: bytes) -> bytes:
            head, body = snap.open_snapshot(key, sealed)
            if head["counter"] != counter or head["line_id"] != self.line_id:
                raise Refused("snapshot_unknown", "header")
            return body

        return Journal(ledger=ledger, snapshots=self.host.disk, seal=seal, unseal=unseal)

    def _restored(self) -> None:
        """The line state came back from a snapshot: run the removal pass
        again, because the restored epoch may be older than an erasure."""
        self.matching.removals_at = -1

    # ---- signed time, the log and the network ----------------------------

    def observe(self) -> int | None:
        """Read the newest checkpoint and the control events. Return the
        signed time, or None in `clock_unsafe` (6.4)."""
        host = self.host.clock()
        _, _, lower, upper, _ = quorum_times(self.log.checkpoint(), self.roots)
        self.signed.observe(lower, upper, host)
        now = self.signed.now(host)
        if now is None:
            self._count("clock_unsafe")
            return None
        self._follow_network()
        if self.journal is not None:
            self.journal.ledger.max_seen = max(self.journal.ledger.max_seen, self.signed.max_seen)
        if self.role == Role.WRITER and self.journal is not None:
            self.matching.erase_removed(self.journal.ledger, now)
        latest = latest_epoch(self.log.view(), self.line_id)
        j = self.journal
        if j is not None and latest is not None:
            if j.cosigned < latest["counter"] < j.counter:
                j.cosign(latest["counter"])
                if self.pending_epoch is not None and self.pending_epoch["counter"] <= j.cosigned:
                    self.pending_epoch = None
            elif latest["counter"] >= j.counter and self.role == Role.WRITER:
                try:
                    self.restart()
                except Refused:
                    pass
        return now

    def _signed_epoch(self) -> int:
        """The 10-minute index of the signed time, which the tick compares
        with signed time (6.4). In `clock_unsafe` it keeps the last value."""
        now = self.signed.now(self.host.clock())
        return self.last_epoch if now is None else now // EPOCH

    def _follow_network(self) -> None:
        """Apply new roster and node events in order (spec/network.md 8.6).
        A bad event stops its chain, and the chain then refuses credentials."""
        for chain in [ROSTER, *sorted(self.net.nodes)]:
            for event in self.host.feed.events(chain, self.net.chain(chain).count):
                try:
                    self.net.receive(event)
                except Refused:
                    self._count("bad_control_event")

    def _roster_fresh(self, now: int) -> bool:
        found = [
            e
            for _, e in self.log.view().of_kind("roster_checkpoint")
            if e["signer"] == self.net.roster_key
        ]
        if not found:
            return False
        try:
            check_checkpoint(found[-1], self.net, now)
        except Refused:
            return False
        return True

    def _count(self, name: str) -> None:
        if self.journal is not None and self.role == Role.WRITER:
            self.journal.ledger.count(name)
        else:
            self.refusals[name] = self.refusals.get(name, 0) + 1

    # ---- the tick ----------------------------------------------------------

    def tick(self) -> None:
        """The work that time drives: lease renewal, expiry, waiting reveals,
        the cut (sweep and day batch) and the 10-minute epoch."""
        now = self.observe()
        if now is None:
            return
        writer = line_writer(self.log.view(), self.line_id, self.roots)
        if self.role == Role.WRITER and writer not in (self.instance_id, None):
            self._retire()  # a failover named another holder (5.7)
            return
        renew = self.keys.lease_until - self.host.clock() < RENEW
        if self.role in (Role.WRITER, Role.HOLDER) and renew:
            self.register()
        if self.role == Role.HOLDER:
            self._take_over()
        elif self.role == Role.WRITER:
            self._writer_tick(now)

    def _writer_tick(self, now: int) -> None:
        if self.journal is None:
            raise Refused("unavailable", "no line state")
        ledger = self.journal.ledger
        ledger.expire(now)
        for pair_id in ledger.ready_pairs(now):
            self.matching.try_reveal(ledger, pair_id, now)
        day = now // DAY + 1
        if now >= cut(day) and str(day) not in ledger.batches:
            self.matching.sweep(ledger, now)
            self.matching.make_batch(ledger, day, self.journal.counter, self.keys.output)
        if now // EPOCH > self.last_epoch:
            try:
                self._write_epoch(next_writer=None)
            except Refused:
                self._count("pending_epoch_conflict")

    def _write_epoch(self, next_writer: str | None, holders: list[str] | None = None) -> None:
        if self.journal is None:
            raise Refused("unavailable", "no line state")
        latest = latest_epoch(self.log.view(), self.line_id)
        if latest is not None and self.journal.cosigned < latest["counter"] < self.journal.counter:
            self.journal.cosign(latest["counter"])
        if (
            self.pending_epoch is not None
            and self.pending_epoch["counter"] <= self.journal.cosigned
        ):
            self.pending_epoch = None
        if self.pending_epoch is not None and self.pending_epoch["counter"] > self.journal.cosigned:
            self.log.append(self.pending_epoch)
            self.journal.counter = max(self.journal.counter, self.pending_epoch["counter"] + 1)
            self.last_digest = entry_digest(self.pending_epoch).hex()
            self.last_epoch = self._signed_epoch()
            return
        self.journal.ledger.max_seen = max(self.journal.ledger.max_seen, self.signed.max_seen)
        counter = self.journal.counter
        sealed = self.journal.seal(counter, canonical_json(self.journal.ledger.to_json()))
        if holders is None:
            holders = latest["holders"] if latest else [self.instance_id]
        fields = {
            "checkpoint": quorum_times(self.log.checkpoint(), self.roots)[0].hex(),
            "counter": counter,
            "holders": sorted(holders),
            "instance_id": self.instance_id,
            "line_id": self.line_id,
            "next_writer": next_writer,
            "prev": self.last_digest,
            "rekey": False,
            "snapshot_digest": snap.digest(sealed).hex(),
            "snapshot_size": len(sealed),
        }
        entry = sign_entry("enclave_state_epoch", fields, self.keys.output)
        existed = counter in self.host.disk
        if not existed:
            self.host.disk[counter] = sealed
        try:
            self.log.append(entry)
        except Refused:
            if not existed:
                self.host.disk.pop(counter, None)
            raise
        if existed:
            self.host.disk[counter] = sealed
        self.journal.counter = counter + 1
        self.pending_epoch = entry
        self.last_digest = entry_digest(entry).hex()
        self.last_epoch = self._signed_epoch()

    # ---- requests (enclave-messages.md 3, 9) -----------------------------

    def check_node(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> str:
        """The node request signature (9.3). Return the node ID, or raise
        Forbidden."""
        self._follow_network()
        now = self.host.clock()
        node = headers.get("anagram-node", "")
        rec = self.net.nodes.get(node)
        if rec is None or node in self.net.removed:
            raise Forbidden("node not in the roster")
        try:
            t = parse_time(headers.get("anagram-time"), "time")
            sig = bytes.fromhex(headers.get("anagram-signature", ""))
            nonce = bytes.fromhex(headers.get("anagram-nonce", ""))
            payload = m.node_request_payload(node, self.log.origin, method, path, t, body, nonce)
        except (Refused, ValueError) as exc:
            raise Forbidden("headers") from exc
        if abs(t - now) > REQUEST_SKEW:
            raise Forbidden("time")
        if not verify(bytes.fromhex(rec["key"]), m.TAG_SIGN_NODE_REQUEST, payload, sig):
            raise Forbidden("signature")
        self.nonces = {k: v for k, v in self.nonces.items() if v > now - NONCE_MEMORY}
        if (node, nonce.hex()) in self.nonces:
            raise Forbidden("replay")
        self.nonces[(node, nonce.hex())] = now
        return node

    def take(self, cls: int, node: str, raw: bytes) -> None:
        """Open one request and keep its receipt (released per 4.4). Only
        the writer takes requests (enclave-trust.md 3.7); the front end
        sends every request to it. `raw` has the length of its route's
        class (the front end checks it), so the response key is at bytes
        69 to 101 and a step-1 failure also gets a receipt (3.3)."""
        if self.role != Role.WRITER or self.journal is None:
            raise NotReady
        ledger = self.journal.ledger
        digest = m.request_digest(raw)
        if digest.hex() in ledger.receipts:
            return  # the same bytes again: the same receipt, no change (8.5)
        now = self.observe()
        try:
            req = m.parse_header(raw)
            need(req.cls == cls, "bad_envelope", "class of the route")
        except Refused as exc:
            reason: str | None = exc.code
        else:
            reason = self._process(raw, node, now)
        stamp = now if now is not None else ledger.max_seen
        status = "accepted" if reason is None else "rejected"
        doc = m.receipt(status, reason, digest, stamp, self.keys.output)
        try:
            sealed = m.seal_receipt(raw[m.RESPONSE], digest, doc)
        except ValueError:
            self._count("bad_envelope")
            return
        encoded = base64.b64encode(sealed).decode("ascii")
        ledger.add_receipt(digest.hex(), node, self.journal.counter, encoded, stamp)

    def _process(self, raw: bytes, node: str, now: int | None) -> str | None:
        k = self.keys
        keys = intake.Keys(k.intake_public, k.intake, k.attestation_digest())
        try:
            req, body = intake.open_sealed(raw, keys, now)
            if now is None:  # open_sealed refused already; this narrows the type
                return "clock_unsafe"
            entries = self.log.view().entries
            self.issuance.update(entries[self.issuance.seen :], self.issuance.seen)
            gate = intake.Gate(
                ledger=self.ledger,
                net=self.net,
                ctx=self._context(now),
                node=node,
                shard=(0, 1),
                roster_fresh=self._roster_fresh(now),
                issuance=self.issuance,
                issuance_limit=policy_limit(self.net.policy_at(now)),
            )
            if req.cls == m.CLASS_UPLOAD:
                intake.take_upload(body, gate)
            elif req.cls == m.CLASS_KNOWN:
                intake.take_known(body, gate)
            else:
                pair = intake.take_answer(body, gate)
                if pair is not None and pair in self.ledger.ready_pairs(now):
                    self.matching.try_reveal(self.ledger, pair, now)
        except Refused as exc:
            return exc.code
        return None

    def _context(self, now: int) -> packs.Context:
        body = self.release.matching
        nodes = {k: v["key"] for k, v in self.net.nodes.items() if k not in self.net.removed}
        size = len(self.log.view().entries)
        return packs.Context(
            now=now,
            network=body["network"],
            node_keys=nodes,
            log_roots=intake.LogRoots(self.log.root_at, size),
            descriptor_set=self.release.descriptor_set.hex(),
            statement=dsc.statement_hash(self.release.kind("matching")[0]),
            teasers_allowed=body["card_option"] == "b",
            schemas=tuple(s for s in body["accepted_schemas"] if s.startswith("anagram.pack.")),
        )

    # ---- relay reads ---------------------------------------------------------

    def receipt(self, node: str, digest: str) -> bytes:
        if self.role != Role.WRITER or self.journal is None or self.observe() is None:
            raise NotReady
        found = self.journal.ledger.receipt(digest, node, self.journal.cosigned)
        if found is None:
            raise NotReady
        return base64.b64decode(found)

    def slots(self, node: str, day: int) -> bytes:
        if self.role != Role.WRITER or self.journal is None or self.observe() is None:
            raise NotReady
        nodes = self.journal.ledger.batch(day, self.journal.cosigned)
        if nodes is None:
            raise NotReady
        found = {bytes.fromhex(a): base64.b64decode(v) for a, v in nodes.get(node, [])}
        return m.slot_batch(day, found)

    # ---- the sealed record (6.2) -------------------------------------------

    def sealed_record(self) -> JsonObject:
        """What the instance keeps across a restart of its process: its keys,
        its role and its document, and the state key. The platform seals
        this record (the simulated host keeps it in a file that it encrypts
        with a host key; a TEE seals it to the measurement). The line state
        itself is in the sealed snapshots on the host disk."""
        received = self.handoff.received
        return {
            **self.keys.record(),
            "handoff": list(received) if received else None,
            "line_id": self.line_id,
            "pending_epoch": self.pending_epoch,
            "role": self.role.value,
            "state_key": self.state_key.hex() if self.state_key else None,
        }

    @classmethod
    def resume(
        cls,
        record: JsonObject,
        release: Release,
        platform: Platform,
        roots: Roots,
        host: Host,
        engines: EngineFactory,
    ) -> EnclaveInstance:
        """The instance of a `sealed_record` after a restart. A writer loads
        the latest cosigned epoch from the host disk (6.2), as `restart`
        does; work after that epoch is lost and no output of it was
        released (6.3). A writer whose snapshot does not load (a failover
        happened while it was down, or the disk lost it) opens nothing."""
        inst = cls(
            release=release,
            platform=platform,
            roots=roots,
            host=host,
            line_id=record["line_id"],
            engines=engines,
            keys=InstanceKeys.from_record(record),
            role=Role(record["role"]),
        )
        inst.load_state(record)
        return inst

    def load_state(self, record: JsonObject) -> None:
        if record["state_key"]:
            self.state_key = bytes.fromhex(record["state_key"])
        if record["handoff"]:
            me, counter, digest = record["handoff"]
            self.handoff.received = (me, counter, digest)
        pending = record.get("pending_epoch")
        if isinstance(pending, dict):
            self.pending_epoch = pending
        if self.role in (Role.WRITER, Role.DRAINING) and self.state_key is not None:
            self.journal = self._journal(Ledger())
            try:
                self.restart()
            except Refused:
                self._retire()


def bundle(log: LogPort, release: Release, instances: list[EnclaveInstance]) -> JsonObject:
    """The attestation bundle (enclave-trust.md 3.7): the latest checkpoint,
    the descriptors and the document of the writer of each line."""
    docs = [i.document for i in instances if i.role == Role.WRITER and i.document is not None]
    return make_bundle(log.checkpoint(), list(release.descriptors), docs)
