"""Network roster, control events, node IDs (spec/network.md)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import tagged_hash
from anagram.core.crypto.signing import SigningKey, verify
from anagram.network.formats import credential as cred
from anagram.network.formats.strict import (
    DOMAIN,
    HEX16,
    HEX32,
    MAX_SAFE,
    NODE_ID,
    ROR,
    Refused,
    enum,
    exact,
    fmt_time,
    hexval,
    intval,
    need,
    parse_time,
    sig_ok,
    sign,
    text,
)

TAG_NODE_ID = "anagram/v1/net/node-id"
TAG_SUBJECT = "anagram/v1/net/subject"
TAG_EVENT = "anagram/v1/net/control-event"
TAG_SIGN_EVENT = "anagram/v1/net/sign/control-event"
TAG_SIGN_CHECKPOINT = "anagram/v1/net/sign/roster-checkpoint"
TAG_SIGN_KEY_PROOF = "anagram/v1/net/sign/key-proof"
TAG_SIGN_ENDORSEMENT = "anagram/v1/net/sign/endorsement"
TAG_SIGN_CREDENTIAL_REQUEST = "anagram/v1/net/sign/credential-request"
ROSTER = "roster"
ROSTER_MAX_AGE = 3_600
ZERO = bytes(32)
NETWORK_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
URL = re.compile(r"^https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
NODE_KINDS = ("individual", "lab", "university")
ROSTER_KINDS = (
    "roster_created",
    "node_admitted",
    "node_updated",
    "node_key_rotated",
    "node_removed",
    "roster_key_rotated",
    "ban",
    "unban",
    "policy_updated",
)
NODE_KINDS_EVENTS = ("member_removed", "member_left", "credential_revoked")
REASONS = {
    "node_removed": ("abuse", "compromised", "left", "other"),
    "ban": ("abuse", "other"),
    "member_removed": ("group_handover", "other", "removed"),
    "member_left": ("key_changed", "left", "moved"),
    "credential_revoked": ("compromised", "other", "superseded"),
}


def node_id(initial_key: bytes) -> str:
    return "node-" + tagged_hash(TAG_NODE_ID, initial_key)[:16].hex()


def subject_hash(subject: bytes) -> str:
    return tagged_hash(TAG_SUBJECT, subject).hex()


def event_hash(event: JsonObject) -> bytes:
    return tagged_hash(TAG_EVENT, canonical_json(event))


def make_event(
    chain: str, seq: int, prev: bytes, kind: str, body: JsonObject, time: int, key: SigningKey
) -> JsonObject:
    doc = {
        "body": body,
        "chain": chain,
        "kind": kind,
        "prev": prev.hex(),
        "schema": "anagram.control_event.v1",
        "seq": seq,
        "signer": key.public_bytes().hex(),
        "time": fmt_time(time),
    }
    return sign(doc, TAG_SIGN_EVENT, key)


def check_node_record(rec: Any) -> JsonObject:
    names = {"admin", "affiliation", "domain", "id", "key", "kind", "ror", "url"}
    checked = exact(rec, names, "node record")
    hexval(rec["id"], NODE_ID, "node id")
    hexval(rec["key"], HEX32, "node key")
    text(rec["affiliation"], 200, "affiliation")
    hexval(rec["domain"], DOMAIN, "domain")
    need(rec["ror"] is None or bool(ROR.match(str(rec["ror"]))), "bad_message", "ror")
    enum(rec["kind"], NODE_KINDS, "node kind")
    need(isinstance(rec["url"], str) and bool(URL.match(rec["url"])), "bad_message", "url")
    need(isinstance(rec["admin"], str) and 3 <= len(rec["admin"]) <= 254, "bad_message", "admin")
    return checked


def check_policy(p: Any) -> JsonObject:
    names = {"credential_formats", "credential_max_life", "node_invites_per_quarter"}
    names |= {"new_members_per_month", "roster_max_age", "schema"}
    checked = exact(p, names, "policy")
    need(p["schema"] == "anagram.net.policy.v1", "bad_message", "policy schema")
    formats = p["credential_formats"]
    need(isinstance(formats, list) and formats == sorted(set(formats)), "bad_message", "formats")
    need(len(formats) >= 1 and set(formats) <= set(cred.FORMATS), "bad_message", "formats")
    intval(p["credential_max_life"], 3_600, 86_400, "credential_max_life")
    intval(p["roster_max_age"], 300, 3_600, "roster_max_age")
    intval(p["node_invites_per_quarter"], 0, 100, "node_invites_per_quarter")
    intval(p["new_members_per_month"], 1, 100_000, "new_members_per_month")
    return checked


@dataclass
class Chain:
    """One control chain (the roster, or one node), applied in order."""

    name: str
    count: int = 0
    head: bytes = ZERO
    last_time: int = 0
    pending: dict[int, JsonObject] = field(default_factory=dict)
    stopped: str | None = None  # "gap" or "fork"


@dataclass
class Network:
    """The state that the roster chain and the node chains give."""

    network: str
    roster_key: str
    nodes: dict[str, JsonObject] = field(default_factory=dict)
    removed: set[str] = field(default_factory=set)
    old_keys: dict[str, tuple[str, int]] = field(default_factory=dict)  # node -> (key, last seq)
    bans: set[str] = field(default_factory=set)
    policy: JsonObject | None = None  # the newest policy received
    policies: list[tuple[int, JsonObject]] = field(default_factory=list)  # (effective, policy)
    revoked_credentials: set[str] = field(default_factory=set)
    gone_subjects: dict[str, tuple[str, int]] = field(default_factory=dict)  # hash -> (node, time)
    moved: set[str] = field(default_factory=set)  # subject hashes whose last exit was `moved`
    chains: dict[str, Chain] = field(default_factory=dict)
    seen: dict[tuple[str, int], bytes] = field(default_factory=dict)

    def chain(self, name: str) -> Chain:
        return self.chains.setdefault(name, Chain(name))

    def receive(self, event: JsonObject) -> None:
        """Take one event in any order. Apply it and any events that it unblocks."""
        exact(
            event,
            {"body", "chain", "kind", "prev", "schema", "seq", "signature", "signer", "time"},
            "event",
        )
        need(event["schema"] == "anagram.control_event.v1", "unsupported_schema", "event")
        seq = intval(event["seq"], 0, MAX_SAFE, "seq")
        ch = self.chain(event["chain"])
        key = (ch.name, seq)
        digest = event_hash(event)
        if key in self.seen and self.seen[key] != digest:
            ch.stopped = "fork"
            raise Refused("stale_roster", f"fork in chain {ch.name} at {seq}")
        self.seen.setdefault(key, digest)
        if seq < ch.count:
            return
        ch.pending[seq] = event
        while ch.count in ch.pending and ch.stopped != "fork":
            self._apply(ch, ch.pending.pop(ch.count))
        ch.stopped = "gap" if ch.pending and ch.stopped != "fork" else ch.stopped
        if not ch.pending and ch.stopped == "gap":
            ch.stopped = None

    def _apply(self, ch: Chain, ev: JsonObject) -> None:
        need(bytes.fromhex(hexval(ev["prev"], HEX32, "prev")) == ch.head, "bad_message", "prev")
        t = parse_time(ev["time"], "time")
        need(t >= ch.last_time, "bad_message", "time goes back")
        signer = self._signer(ch, ev)
        need(ev["signer"] == signer, "bad_signature", "signer")
        need(sig_ok(ev, TAG_SIGN_EVENT, signer), "bad_signature", "event")
        if ch.name == ROSTER:
            self._roster_event(ev, t)
        else:
            self._node_event(ch.name, ev, t)
        ch.count += 1
        ch.head = event_hash(ev)
        ch.last_time = t

    def _signer(self, ch: Chain, ev: JsonObject) -> str:
        if ch.name == ROSTER:
            return self.roster_key
        node = self.nodes.get(ch.name)
        if node is None:
            raise Refused("stale_roster", "node chain before admission")
        old = self.old_keys.get(ch.name)
        if old is not None and ev["seq"] <= old[1]:
            return old[0]
        key: str = node["key"]  # checked by `check_node_record`
        return key

    def _roster_event(self, ev: JsonObject, t: int) -> None:
        kind, body = enum(ev["kind"], ROSTER_KINDS, "kind"), ev["body"]
        if kind == "roster_created":
            need(ev["seq"] == 0, "bad_message", "roster_created first")
            exact(body, {"network", "roster_key"}, "body")
            need(
                body["network"] == self.network and body["roster_key"] == self.roster_key,
                "bad_message",
                "pin",
            )
        elif kind in ("node_admitted", "node_updated"):
            self._admit(kind, body)
        elif kind == "node_key_rotated":
            self._rotate(body)
        elif kind == "node_removed":
            exact(body, {"node", "reason"}, "body")
            enum(body["reason"], REASONS[kind], "reason")
            need(body["node"] in self.nodes, "bad_message", "unknown node")
            self.removed.add(body["node"])
        elif kind == "roster_key_rotated":
            exact(body, {"new_key"}, "body")
            self.roster_key = hexval(body["new_key"], HEX32, "new_key")
        elif kind in ("ban", "unban"):
            self._ban(kind, body)
        else:
            exact(body, {"effective", "policy"}, "body")
            effective = parse_time(body["effective"], "effective")
            self.policy = check_policy(body["policy"])
            self.policies.append((effective, self.policy))

    def policy_at(self, now: int) -> JsonObject | None:
        """The newest policy whose `effective` time has passed (section 9)."""
        live = [p for effective, p in self.policies if effective <= now]
        return live[-1] if live else None

    def _admit(self, kind: str, body: JsonObject) -> None:
        exact(body, {"endorsement", "endorser", "node"}, "body")
        rec = check_node_record(body["node"])
        if kind == "node_admitted":
            need(rec["id"] not in self.nodes, "bad_message", "node exists")
            need(rec["id"] == node_id(bytes.fromhex(rec["key"])), "bad_message", "node id")
        else:
            need(
                rec["id"] in self.nodes and rec["key"] == self.nodes[rec["id"]]["key"],
                "bad_message",
                "update",
            )
        if body["endorser"] == ROSTER:
            need(body["endorsement"] is None, "bad_message", "endorsement")
        else:
            inviter = self.nodes.get(body["endorser"])
            if inviter is None or body["endorser"] in self.removed:
                raise Refused("bad_message", "endorser")
            sig = bytes.fromhex(str(body["endorsement"]))
            ok = verify(
                bytes.fromhex(inviter["key"]), TAG_SIGN_ENDORSEMENT, canonical_json(rec), sig
            )
            need(ok, "bad_signature", "endorsement")
        self.nodes[rec["id"]] = rec

    def _rotate(self, body: JsonObject) -> None:
        exact(body, {"chain_seq", "new_key", "node", "proof"}, "body")
        node = self.nodes.get(body["node"])
        if node is None:
            raise Refused("bad_message", "unknown node")
        new_key = hexval(body["new_key"], HEX32, "new_key")
        proof = canonical_json({"new_key": new_key, "node": body["node"]})
        ok = verify(
            bytes.fromhex(node["key"]), TAG_SIGN_KEY_PROOF, proof, bytes.fromhex(body["proof"])
        )
        need(ok, "bad_signature", "key proof")
        seq = intval(body["chain_seq"], -1, MAX_SAFE, "chain_seq")
        self.old_keys[body["node"]] = (node["key"], seq)
        self.nodes[body["node"]] = {**node, "key": new_key}

    def _ban(self, kind: str, body: JsonObject) -> None:
        if kind == "ban":
            exact(body, {"reason", "subject"}, "body")
            enum(body["reason"], REASONS["ban"], "reason")
            self.bans.add(hexval(body["subject"], HEX32, "subject"))
        else:
            exact(body, {"subject"}, "body")
            self.bans.discard(hexval(body["subject"], HEX32, "subject"))

    def _node_event(self, node: str, ev: JsonObject, t: int) -> None:
        kind, body = enum(ev["kind"], NODE_KINDS_EVENTS, "kind"), ev["body"]
        if kind == "credential_revoked":
            exact(body, {"credential", "reason"}, "body")
            enum(body["reason"], REASONS[kind], "reason")
            self.revoked_credentials.add(hexval(body["credential"], HEX32, "credential"))
            return
        exact(body, {"reason", "subject"}, "body")
        enum(body["reason"], REASONS[kind], "reason")
        subj = hexval(body["subject"], HEX32, "subject")
        self.gone_subjects[subj] = (node, t)
        if kind == "member_left" and body["reason"] == "moved":
            self.moved.add(subj)
        else:
            self.moved.discard(subj)

    def credential_usable(self, facts: cred.MemberFacts, raw: bytes) -> None:
        """Network checks of a member credential (spec/network.md section 6.4)."""
        roster = self.chain(ROSTER)
        need(roster.stopped is None, "stale_roster", "roster")
        need(facts.node in self.nodes and facts.node not in self.removed, "revoked", "node")
        ch = self.chain(facts.node)
        need(ch.stopped is None and ch.count >= facts.control_head, "stale_roster", "node chain")
        need(
            cred.credential_hash(raw).hex() not in self.revoked_credentials, "revoked", "credential"
        )
        subj = subject_hash(bytes.fromhex(facts.subject))
        need(subj not in self.bans, "revoked", "banned")
        gone = self.gone_subjects.get(subj)
        need(gone is None or gone[0] != facts.node or facts.issued > gone[1], "revoked", "member")

    def removes(self, facts: cred.MemberFacts, raw: bytes) -> bool:
        """True when a control event removed the member of this credential
        for good: the node was removed, the credential revoked, the subject
        banned, or the member removed or left (not `moved`). The enclave
        then erases the subject at once (spec/enclave-trust.md 7.1). A gap
        or a fork (`stale_roster`) only pauses the credential, and a member
        who moved is dormant (section 8.4)."""
        try:
            self.credential_usable(facts, raw)
        except Refused as exc:
            moved = subject_hash(bytes.fromhex(facts.subject)) in self.moved
            return exc.code == "revoked" and not moved
        return False


def roster_checkpoint(
    network: str, seq: int, head: bytes, time: int, key: SigningKey
) -> JsonObject:
    """A roster checkpoint. It is also a `roster_checkpoint` entry of the
    enclave transparency log, so it has a `kind`."""
    doc = {
        "head": head.hex(),
        "kind": "roster_checkpoint",
        "network": network,
        "schema": "anagram.net.roster_checkpoint.v1",
        "seq": seq,
        "signer": key.public_bytes().hex(),
        "time": fmt_time(time),
    }
    return sign(doc, TAG_SIGN_CHECKPOINT, key)


def check_checkpoint(doc: Any, net: Network, now: int) -> None:
    names = {"head", "kind", "network", "schema", "seq", "signature", "signer", "time"}
    exact(doc, names, "roster checkpoint")
    need(doc["kind"] == "roster_checkpoint", "bad_message", "kind")
    need(doc["network"] == net.network, "bad_message", "network")
    need(doc["signer"] == net.roster_key, "bad_signature", "signer")
    need(sig_ok(doc, TAG_SIGN_CHECKPOINT, net.roster_key), "bad_signature", "checkpoint")
    age = now - parse_time(doc["time"], "time")
    need(-300 <= age <= ROSTER_MAX_AGE, "stale_roster", "checkpoint age")
    ch = net.chain(ROSTER)
    need(ch.count == doc["seq"] + 1 and ch.head.hex() == doc["head"], "stale_roster", "head")


def credential_request(
    person: SigningKey, device: str, node: str, nonce: str, time: int
) -> JsonObject:
    hexval(nonce, HEX16, "nonce")
    doc = {
        "device": device,
        "node": node,
        "nonce": nonce,
        "person_key": person.public_bytes().hex(),
        "schema": "anagram.net.credential_request.v1",
        "time": fmt_time(time),
    }
    return sign(doc, TAG_SIGN_CREDENTIAL_REQUEST, person)


def check_credential_request(obj: object) -> JsonObject:
    """The form and the person-key signature of a credential request
    (section 6.6). The node checks the rest against its own state."""
    doc = exact(
        obj, {"device", "node", "nonce", "person_key", "schema", "signature", "time"}, "request"
    )
    need(doc["schema"] == "anagram.net.credential_request.v1", "unsupported_schema", "request")
    hexval(doc["device"], HEX32, "device")
    hexval(doc["nonce"], HEX16, "nonce")
    key = hexval(doc["person_key"], HEX32, "person_key")
    need(isinstance(doc["node"], str), "bad_message", "node")
    parse_time(doc["time"], "time")
    need(sig_ok(doc, TAG_SIGN_CREDENTIAL_REQUEST, key), "bad_signature", "request")
    return doc
