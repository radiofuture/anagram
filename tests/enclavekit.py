"""A whole simulated network for the enclave slice (plan net 14b step 11).

It runs the real code end to end in one process, with real HTTP routes
through `TestClient`: the `simulated` log and witnesses, the roster, two
nodes with the relay, one enclave line, and the app client of each person.
All keys and IDs come from labels, so two runs with the same inputs give
the same bytes (the non-interference test compares runs).

Time moves only by `World.advance`. It ticks at least every 6 hours and in
each cut window (23:10 and 23:40 UTC), then publishes a checkpoint, so the
signed clock stays fresh and no day batch is missed.
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import (
    ROSTER,
    ZERO,
    event_hash,
    make_event,
    node_id,
    roster_checkpoint,
)
from anagram.network.formats.strict import DAY
from anagram.network.matching.app.enclave_client import EnclaveClient, pack_doc
from anagram.network.matching.enclave.http import FrontEnd, relay_router
from anagram.network.matching.enclave.instance import EnclaveInstance
from anagram.network.matching.enclave.instance_keys import InstanceKeys
from anagram.network.matching.enclave.ledger import cut
from anagram.network.matching.enclave.simulated_engines import simulated_engines
from anagram.network.matching.enclave.state import Host, Release
from anagram.network.matching.hosting.tools.operator import model_weights, simulated_descriptors
from anagram.network.matching.node.credentials import (
    CredentialIssuer,
    Member,
    credential_router,
)
from anagram.network.matching.node.enclave_relay import EnclaveRelay, enclave_router
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.devtrust import DevTrust
from anagram.network.matching.trust.entries import entry_digest
from anagram.network.matching.trust.log_routes import log_read_router
from anagram.network.matching.trust.release import NOTICE

HOUR = 3_600
SEED = "anagram enclavekit"
START = 1_793_000_000 // DAY * DAY + 6 * HOUR  # 06:00 UTC, 2026-10
NETWORK = "net.anagram.example"
LINE = hashlib.sha256(f"{SEED}: line".encode()).hexdigest()[:32]
REFERENCE = {"gpu": False, "image_digest": "sha256:" + "1" * 64}
REFERENCE_2 = {"gpu": False, "image_digest": "sha256:" + "2" * 64}
FLOOR = {"svn": 3}
TYPE = "research_fit"
STATEMENT = "Anagram matches you inside a sealed service; names go out only after two yes answers."


def seed(label: str) -> bytes:
    return hashlib.sha256(f"{SEED}: {label}".encode()).digest()


def key(label: str) -> SigningKey:
    return SigningKey.from_seed(seed(label))


def descriptors(answer_day: int, min_people: int, min_nodes: int) -> list[dict]:
    roster = key("roster").public_bytes().hex()
    return simulated_descriptors(NETWORK, roster, answer_day, min_people, min_nodes, STATEMENT)


class Feed:
    """The roster and node control chains (spec/network.md 8)."""

    def __init__(self) -> None:
        self.chains: dict[str, list[dict]] = {}

    def events(self, chain: str, after: int) -> list[dict]:
        return self.chains.get(chain, [])[after:]

    def add(self, chain: str, kind: str, body: dict, time: int, signer: SigningKey) -> dict:
        events = self.chains.setdefault(chain, [])
        prev = event_hash(events[-1]) if events else ZERO
        event = make_event(chain, len(events), prev, kind, body, time, signer)
        events.append(event)
        return event


class Recording(TestClient):
    """A client that keeps every request body and response body: what a
    node (or the network) sees."""

    def __init__(self, app: FastAPI, base_url: str) -> None:
        super().__init__(app, base_url=base_url)
        self.seen: list[tuple[str, str, bytes, bytes]] = []  # (method, path, request, response)

    def request(self, method: str, url: httpx.URL | str, **kwargs) -> httpx.Response:  # type: ignore[override]
        r = super().request(method, url, **kwargs)
        self.seen.append((method, r.request.url.path, r.request.content, r.content))
        return r


@dataclass
class Node:
    label: str
    key: SigningKey
    record: dict
    relay: EnclaveRelay
    issuer: CredentialIssuer  # POST /net/credential (network.md 6.6)
    sessions: dict[str, Member]  # bearer token -> member: the member sessions of the node
    http: Recording  # the app-facing node routes

    @property
    def id(self) -> str:
        return self.record["id"]


@dataclass
class Person:
    name: str
    node: Node
    key: SigningKey
    client: EnclaveClient
    lines: dict
    email: str
    deny: dict = field(default_factory=lambda: {"domains": [], "nodes": [], "rors": []})
    version: int = 0
    approved_at: int = START
    items: list[tuple[int, dict]] = field(default_factory=list)  # (day, opened item)
    receipts: list[dict] = field(default_factory=list)
    join: dict | None = None  # {"index", "salt"} of the person's join entry (network.md 6.7)

    @property
    def subject(self) -> str:
        return self.key.public_bytes().hex()

    @property
    def pid(self) -> str:
        return "pid:" + hashlib.sha256(self.name.encode()).hexdigest()[:32]

    @property
    def card(self) -> dict:
        return {
            "email": self.email,
            "institution": self.node.record["affiliation"],
            "lab": None,
            "name": self.name,
            "orcid": None,
        }

    def secrets(self) -> list[bytes]:
        """Bytes that must not reach a node or a peer before mutual yes."""
        texts = [line["text"] for side in self.lines.values() for line in side]
        return [t.encode() for t in [*texts, self.name, self.email, self.subject, self.pid]]


def line(lid: str, text: str, scope: str = "both", cls: str | None = None) -> dict:
    return {
        "class": cls or ("method" if lid.startswith("o") else "skill"),
        "concepts": [],
        "id": lid,
        "scope": scope,
        "text": text,
        "types": [TYPE],
    }


@dataclass
class LogService:
    """The log's write API as a node uses it: the log publishes a checkpoint
    after each entry (enclave-trust.md 2.1)."""

    world: World

    def append(self, entry: dict) -> int:
        index = self.world.log.append(entry)
        self.world.publish()
        return index

    def checkpoint(self) -> str:
        return self.world.log.checkpoint()

    def inclusion(self, index: int, size: int) -> list[str]:
        return self.world.log.inclusion(index, size)


class World:
    def __init__(self, answer_day: int = 2, min_people: int = 2, min_nodes: int = 1) -> None:
        self.t = START
        self.trust = DevTrust(clock=self.now, key=key)
        self.log = self.trust.log
        self.feed = Feed()
        self.roster_key = key("roster")
        self.descriptors = descriptors(answer_day, min_people, min_nodes)
        hashes = sorted(dsc.descriptor_hash(d).hex() for d in self.descriptors)
        weights = model_weights(self.descriptors)
        not_before = START + NOTICE + HOUR
        self.rel = self.trust.release(hashes, REFERENCE, FLOOR, not_before, weights=weights)
        self.rel2 = self.trust.release(
            hashes,
            REFERENCE_2,
            FLOOR,
            not_before,
            successor_of=entry_digest(self.rel).hex(),
            weights=weights,
            commit="1" * 40,
        )
        self.trust.authorise_line(self.rel, LINE)
        self.feed.add(
            ROSTER,
            "roster_created",
            {"network": NETWORK, "roster_key": self.roster_key.public_bytes().hex()},
            self.t,
            self.roster_key,
        )
        records = {label: self._admit(label) for label in ("A", "B")}
        self.last_roster = 0
        self.publish()
        self.t = not_before + HOUR
        self.publish()
        self.host = Host(self.log, self.feed, self.now)
        self.ids = (f"{n:032x}" for n in itertools.count(1))
        self.instances: list[EnclaveInstance] = []
        first = self.instance("one", self.rel)
        first.register()
        self.publish()
        first.start_line()
        self.publish()
        self.front = FrontEnd(Release(self.rel, tuple(self.descriptors)), self.instances)
        app = FastAPI()
        app.include_router(relay_router(self.front))
        self.enclave_http = Recording(app, "http://enclave.test")
        log_app = FastAPI()
        log_app.include_router(log_read_router(self.log))
        self.log_http = Recording(log_app, f"https://{self.log.origin.split('/')[0]}")
        self.nodes = {label: self._node(label, rec) for label, rec in records.items()}
        self.people: dict[str, Person] = {}

    def now(self) -> int:
        return self.t

    # ---- set-up ------------------------------------------------------------

    def _admit(self, label: str) -> dict:
        k = key(f"node {label}")
        domain = f"lab-{label.lower()}.example.org"
        rec = {
            "admin": f"admin@{domain}",
            "affiliation": f"Laboratory {label}",
            "domain": domain,
            "id": node_id(k.public_bytes()),
            "key": k.public_bytes().hex(),
            "kind": "lab",
            "ror": f"0abcde{label.lower()}12",
            "url": f"https://{domain}",
        }
        body = {"endorsement": None, "endorser": ROSTER, "node": rec}
        self.feed.add(ROSTER, "node_admitted", body, self.t, self.roster_key)
        return rec

    def _node(self, label: str, rec: dict) -> Node:
        k = key(f"node {label}")
        relay = EnclaveRelay(
            rec["id"], k, self.log.origin, self.enclave_http, self.now, seed(f"slots {label}")
        )
        issuer = CredentialIssuer(rec["id"], k, NETWORK, LogService(self), self.now)
        sessions: dict[str, Member] = {}

        def member_of(authorization: str | None = Header(default=None)) -> Member:
            """The member session of identity.md, reduced to a bearer token."""
            token = (authorization or "").removeprefix("Bearer ")
            if not authorization:
                raise HTTPException(401, "no session")
            if token not in sessions:
                raise HTTPException(403, "not a member")
            return sessions[token]

        app = FastAPI()
        app.include_router(enclave_router(relay))
        app.include_router(credential_router(issuer, member_of))
        http = Recording(app, f"https://{rec['domain']}")
        return Node(label, k, rec, relay, issuer, sessions, http)

    def member_session(self, label: str, name: str, pid: str, email: str) -> tuple[str, SigningKey]:
        """A member of node `label` signs in (identity.md device sign-in, out
        of scope here): the session token and the device key."""
        node = self.nodes[label]
        device = key(f"device {label} {name}")
        token = hashlib.sha256(seed(f"session {label} {name}")).hexdigest()
        tags = (packs.known_tag(packs.email_id(email)).hex(),)
        node.sessions[token] = Member(name, device.public_bytes().hex(), pid, tags)
        return token, device

    def instance(self, name: str, release: dict) -> EnclaveInstance:
        inst = EnclaveInstance(
            release=Release(release, tuple(self.descriptors)),
            platform=self.trust.platform(release["profiles"]["simulated"]["reference"]),
            roots=self.trust.roots,
            host=self.host,
            line_id=LINE,
            engines=simulated_engines,
            keys=InstanceKeys(
                output=key(f"instance {name} output"),
                intake=hpke.private_from_bytes(seed(f"instance {name} intake")),
                instance_id=hashlib.sha256(seed(f"instance {name} id")).hexdigest()[:32],
            ),
            new_id=lambda: next(self.ids),
        )
        self.instances.append(inst)
        return inst

    def person(self, name: str, node: str, lines: dict, deny_nodes: tuple[str, ...] = ()) -> Person:
        k = key(f"person {name}")
        n = self.nodes[node]
        client = EnclaveClient(
            subject=k,
            reply=hpke.private_from_bytes(seed(f"reply {name}")),
            node=n.http,
            roots=self.trust.roots,
            log=self.log,
            clock=self.now,
        )
        email = f"{name.split()[0].lower()}@{n.record['domain']}"
        p = Person(name, n, k, client, lines, email)
        p.deny["nodes"] = sorted(self.nodes[x].id for x in deny_nodes)
        self.people[name] = p
        return p

    # ---- the log and time -----------------------------------------------------

    def publish(self) -> None:
        """A roster checkpoint every 30 minutes, then a log checkpoint."""
        if self.t - self.last_roster >= 1_800:
            chain = self.feed.chains[ROSTER]
            rc = roster_checkpoint(
                NETWORK, len(chain) - 1, event_hash(chain[-1]), self.t, self.roster_key
            )
            self.log.append(rc)
            self.last_roster = self.t
        self.log.publish()

    def tick(self) -> None:
        """A fresh checkpoint (the signed clock), the instances' work, then a
        checkpoint that cosigns the epochs they wrote."""
        self.publish()
        for inst in list(self.instances):
            inst.tick()
        self.publish()
        for node in self.nodes.values():
            node.relay.tick()  # the node timer: day batches, then expiry

    def advance(self, seconds: int) -> None:
        end = self.t + seconds
        stops = set(range((self.t // (6 * HOUR) + 1) * 6 * HOUR, end, 6 * HOUR))
        for d in range(self.t // DAY, end // DAY + 2):
            stops |= {cut(d + 1) + 600, cut(d + 1) + 2_400}
        for stop in sorted(s for s in stops if self.t < s <= end):
            self.t = stop
            self.tick()
        if self.t < end:
            self.t = end
            self.tick()

    def to_day(self, day: int, hour: int = 8) -> None:
        self.advance(day * DAY + hour * HOUR - self.t)

    # ---- people ------------------------------------------------------------------

    def credential(self, p: Person) -> dict:
        """A member credential of the person's node, logged and cosigned."""
        facts = cred.MemberFacts(
            network=NETWORK,
            node=p.node.id,
            subject=p.subject,
            kind="person",
            issued=self.t - 60,
            expires=self.t - 60 + DAY,
            control_head=0,
            pid=p.pid,
            email_tags=(packs.known_tag(packs.email_id(p.email)).hex(),),
        )
        raw = cred.make_biscuit(facts, p.node.key)
        if p.join is None:  # the first credential: a join entry
            salt = f"{len(self.log.entries):032x}"
            entry = cred.log_entry(facts, raw, p.node.key, cred.member_commit(p.subject, salt))
            index = self.log.append(entry)
            p.join = {"index": index, "salt": salt}
        else:
            entry = cred.log_entry(facts, raw, p.node.key)
            index = self.log.append(entry)
        self.publish()
        size = len(self.log.view().entries)
        proof = {
            "entry_signature": entry["signature"],
            "hashes": self.log.inclusion(index, size),
            "index": index,
            "join": p.join,
            "tree_size": size,
        }
        return {"format": cred.FORMAT_BISCUIT, "log": proof, "token": b64url(raw)}

    def upload(self, p: Person) -> str:
        target = p.client.refresh()
        p.version += 1
        charter = {"disclosure": "d0", "protocols": [TYPE], "rules": {TYPE: "any"}, "weekly_cap": 3}
        doc = pack_doc(
            p.key,
            p.client.reply_key,
            self.credential(p),
            target,
            p.lines,
            charter,
            p.version,
            self.t,
            p.approved_at,
            deny=p.deny,
        )
        return p.client.upload_pack(doc)

    def withdraw(self, p: Person) -> str:
        p.client.refresh()
        p.version += 1
        return p.client.withdraw(p.version)

    def read_slots(self, p: Person) -> dict | None:
        """The person's item of today (None for a filler)."""
        day = self.t // DAY
        p.client.refresh()
        item = p.client.slot(day)
        if item is not None:
            p.items.append((day, item))
        return item

    def receipt(self, p: Person, digest: str) -> dict | None:
        r = p.client.receipt(digest)
        if r is not None:
            p.receipts.append(r)
        return r

    def send_answers(self, p: Person) -> list[str]:
        p.client.refresh()
        return p.client.send_due()

    def node_traffic(self) -> list[tuple[str, str, bytes, bytes]]:
        """Every exchange that crossed a node: app <-> node and node <-> enclave."""
        out = list(self.enclave_http.seen)
        for n in self.nodes.values():
            out += n.http.seen
        return out

    def writer(self) -> EnclaveInstance:
        return self.front.writer

    def slot_plain(self, p: Person, day: int) -> bytes:
        """The opened slot document of a day, as canonical bytes."""
        address = m.slot_address(day, p.client.reply_key).hex()
        raw = p.node.relay.slot(address)
        doc = m.open_slot(p.client.reply, day, raw, set(p.client.refresh().output_keys))
        return canonical_json(doc) if doc is not None else b""
