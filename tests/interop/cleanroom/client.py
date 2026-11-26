"""The clean-room app (enclave-messages.md 9.1) over plain HTTP, with its
member credential from the node (network.md 6.6: `POST /net/credential`,
`GET /net/credential/{hash}/proof`, member session).

`http` is any client with `get(path, headers=...)` and
`post(path, content=..., headers=...)` that returns objects with
`status_code`, `content` and `json()` (httpx). `log` is the enclave log read
API: `entries(start, end)` and `covering(index)` (enclave-trust.md 2.1, 2.4).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol

from . import messages as m
from . import trust as t
from .core import Refused, Signer, cjson, day_of, fmt_time, parse_time, x25519_public
from .pack import build_pack, statement_hash


class LogReader(Protocol):
    def entries(self, start: int, end: int) -> list[dict]: ...
    def covering(self, index: int) -> str: ...


TIMED = ("enclave_release", "enclave_rebuild", "enclave_line", "enclave_instance_key")


@dataclass
class Target:
    """The instance that passed every check, and what the app read with it."""

    doc: dict
    digest: str
    intake: bytes
    release: dict
    matching: dict
    vocab: str
    descriptor_set: str
    output_keys: set[str]


class Trust:
    """The app's view of the enclave log and the bundle checks of 3.7."""

    def __init__(self, pins: t.Pins, reader: LogReader, clock, app_version: str = "1.2.0") -> None:
        self.pins = pins
        self.reader = reader
        self.clock = clock
        self.app_version = app_version
        self.log = t.Log(pins, [])
        self.covered: set[str] = set()

    def _read(self, note: str) -> None:
        size = int(note.split("\n")[1])
        have = len(self.log.entries)
        if size > have:
            new = self.reader.entries(have, size)
            self.log.entries.extend(new)
        self.log.accept(note)

    def _cover(self) -> None:
        for i, e in enumerate(self.log.entries[: self.log.latest.size]):
            if e.get("kind") in TIMED and t.entry_ok(e):
                note = self.reader.covering(i)
                if note not in self.covered:
                    self.covered.add(note)
                    self.log.accept(note)

    def check_bundle(self, bundle: dict, subject: str) -> Target:
        if set(bundle) != {"checkpoint", "descriptors", "documents", "schema"}:
            raise Refused("bad_attestation", "bundle fields")
        if bundle["schema"] != "anagram.enclave.attestation_bundle.v1":
            raise Refused("bad_attestation", "bundle schema")
        if len(bundle["documents"]) > 64 or len(cjson(bundle)) > 1 << 20:
            raise Refused("bad_attestation", "bundle size")
        self._read(bundle["checkpoint"])
        self._cover()
        now = self.log.now(self.clock())
        errors = []
        for doc in bundle["documents"]:
            lines = [
                e for _i, e in self.log.of_kind("enclave_line") if e["line_id"] == doc["line_id"]
            ]
            if lines and t.shard(subject, lines[0]["shard"]["n"]) != lines[0]["shard"]["k"]:
                continue
            try:
                release = t.verify_attestation(self.log, doc, subject, now, self.app_version)
                bodies = t.check_descriptors(bundle["descriptors"], release["descriptor_hashes"])
            except Refused as r:
                errors.append(r.code)
                continue
            outputs = {
                e["signer"]
                for _i, e in self.log.of_kind("enclave_instance_key")
                if e["release"] == doc["release"]
            }
            return Target(
                doc,
                t.attestation_digest(doc),
                bytes.fromhex(doc["intake_key"]),
                release,
                bodies["matching"],
                bodies["vocabulary"]["id"],
                t.descriptor_set(release["descriptor_hashes"]),
                outputs,
            )
        raise Refused(errors[0] if errors else "no_instance", "no document passed")


@dataclass(eq=False)
class App:
    """One person's app."""

    subject: Signer
    http: object
    trust: Trust
    node: str  # the node ID of the person's node
    session: str  # bearer token of the member session (identity.md)
    device: str  # hex device key of the session
    pid: str
    email: str
    card: dict
    clock: object
    reply: bytes = field(default_factory=lambda: os.urandom(32))
    version: int = 0
    approved_at: int = 0
    sent: dict[str, m.Sealed] = field(default_factory=dict)
    receipts: dict[str, dict] = field(default_factory=dict)
    proposals: dict[str, tuple[int, dict]] = field(default_factory=dict)  # id -> (slot day, item)
    choices: dict[str, tuple[str, dict | None]] = field(default_factory=dict)
    answered: set[str] = field(default_factory=set)
    done: dict[str, int] = field(default_factory=dict)  # id -> checkpoints already sent
    fillers: list[str] = field(default_factory=list)  # digests of the answer fillers sent
    target: Target | None = None

    @property
    def reply_public(self) -> bytes:
        return x25519_public(self.reply)

    def refresh(self) -> Target:
        r = self.http.get("/enclave/attestation")
        if r.status_code != 200:
            raise Refused("node", f"attestation {r.status_code}")
        self.target = self.trust.check_bundle(r.json(), self.subject.hex)
        return self.target

    def _send(self, cls: int, body: bytes, path: str) -> str:
        target = self.refresh()
        s = m.seal_request(cls, body, target.digest, target.intake)
        return self.post(path, s)

    def post(self, path: str, s: m.Sealed) -> str:
        r = self.http.post(
            path, content=s.request, headers={"content-type": "application/octet-stream"}
        )
        if r.status_code != 202:
            raise Refused("node", f"{path} {r.status_code}")
        self.sent[s.digest] = s
        return s.digest

    def pack_body(self, lines: dict, deny: dict | None = None, version: int | None = None) -> bytes:
        target = self.refresh()
        now = self.clock()
        # pack.md 8: version = max(last + 1, unix milliseconds of created)
        self.version = version if version is not None else max(self.version + 1, now * 1000)
        cred = self.credential(now)
        # pack.md 3.2: one standing consent; `approved_at` changes only when
        # the person approves again.
        self.approved_at = self.approved_at or now
        charter = {
            "disclosure": "d0",
            "protocols": sorted({ty for side in lines.values() for x in side for ty in x["types"]}),
            "rules": {},
            "weekly_cap": 3,
        }
        charter["rules"] = {p: "any" for p in charter["protocols"]}
        doc = build_pack(
            subject=self.subject,
            reply_key=self.reply_public,
            credential=cred,
            lines=lines,
            charter=charter,
            version=self.version,
            created=now,
            approved_at=self.approved_at,
            descriptor_set=target.descriptor_set,
            statement=statement_hash(target.matching["consent_statement"]),
            vocab=target.vocab,
            deny=deny,
        )
        return cjson(doc)

    def credential(self, now: int) -> dict:
        """network.md 6.6: a request signed by the person key, the
        credential, then its log proof (`404` until a cosigned checkpoint
        holds the entry)."""
        auth = {"authorization": f"Bearer {self.session}"}
        request = self.subject.sign_doc(
            "anagram/v1/net/sign/credential-request",
            {
                "device": self.device,
                "node": self.node,
                "nonce": os.urandom(16).hex(),
                "person_key": self.subject.hex,
                "schema": "anagram.net.credential_request.v1",
                "time": fmt_time(now),
            },
        )
        r = self.http.post("/net/credential", content=cjson(request), headers=auth)
        if r.status_code != 200:
            raise Refused("node", f"credential {r.status_code}")
        got = r.json()
        r = self.http.get(f"/net/credential/{got['hash']}/proof", headers=auth)
        if r.status_code != 200:
            raise Refused("node", f"credential proof {r.status_code}")
        return {**got["credential"], "log": r.json()["log"]}

    def upload(self, lines: dict, deny: dict | None = None) -> str:
        return self._send(m.UPLOAD, self.pack_body(lines, deny), "/enclave/uploads")

    def withdraw(self) -> str:
        self.refresh()
        self.version = max(self.version + 1, self.clock() * 1000)
        doc = m.withdrawal(self.subject, self.reply_public, self.version, self.clock())
        return self._send(m.UPLOAD, cjson(doc), "/enclave/uploads")

    def receipt(self, digest: str) -> dict | None:
        r = self.http.get(f"/enclave/receipts/{digest}")
        if r.status_code != 200 or len(r.content) != m.RECEIPT_SIZE:
            raise Refused("node", f"receipt {r.status_code} {len(r.content)}")
        doc = m.open_receipt(self.sent[digest], r.content, self.trust_outputs())
        if doc is not None:
            self.receipts[digest] = doc
        return doc

    def trust_outputs(self) -> set[str]:
        return {e["signer"] for _i, e in self.trust.log.of_kind("enclave_instance_key")}

    def slot(self, day: int | None = None) -> dict | None:
        d = day if day is not None else day_of(self.clock())
        address = m.slot_address(d, self.reply_public).hex()
        r = self.http.get(f"/enclave/slots/{address}")
        if r.status_code != 200 or len(r.content) != m.SLOT_SIZE:
            raise Refused("node", f"slot {r.status_code} {len(r.content)}")
        doc = m.open_slot(self.reply, d, r.content, self.trust_outputs())
        if doc is None:
            return None
        item = doc["item"]
        if item["kind"] == "proposal":
            self.proposals[item["id"]] = (d, item)
        return item

    def choose(self, proposal: str, choice: str) -> None:
        self.choices[proposal] = (choice, self.card if choice == "yes" else None)

    def due(self) -> list[tuple[str, int]]:
        """5.3: (proposal, checkpoint index) for each checkpoint whose day
        has come and that got no object yet, before the expiry."""
        now = self.clock()
        out = []
        for p, (_d, item) in self.proposals.items():
            if now >= parse_time(item["expires"]):
                continue
            passed = sum(1 for c in item["checkpoints"] if parse_time(c) <= now)
            out += [(p, i) for i in range(self.done.get(p, 0), passed)]
        return out

    def send_due(self) -> list[str]:
        """One sealed object for each due checkpoint: the answer once there is
        a choice, `not_now` at the last checkpoint with no choice, else a
        filler. Returns the digests of the answers (not of the fillers)."""
        out = []
        for p, i in self.due():
            self.done[p] = i + 1
            if p not in self.answered and (p in self.choices or i == 2):
                choice, card = self.choices.get(p, ("not_now", None))
                doc = m.answer(self.subject, p, choice, card, self.clock())
                out.append(self._send(m.ANSWER, cjson(doc), "/enclave/answers"))
                self.answered.add(p)
            else:
                self.fillers.append(
                    self._send(m.ANSWER, cjson(m.answer_filler()), "/enclave/answers")
                )
        return out

    def resend(self, digest: str) -> None:
        """8.5: the same request bytes again."""
        s = self.sent[digest]
        r = self.http.post("/enclave/answers" if s.request[4] == m.ANSWER else "/enclave/uploads",
                           content=s.request)  # fmt: skip
        if r.status_code != 202:
            raise Refused("node", f"resend {r.status_code}")
