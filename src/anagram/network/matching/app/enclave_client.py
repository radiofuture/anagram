"""The app side of the matching enclave: a small client library.

The app trusts only its pinned roots (spec/enclave-trust.md 2.6) and its
own checks. It:

1. fetches the attestation bundle through its node, reads the log under
   the bundle's checkpoint, checks the release (2.5), the descriptors (3.6)
   and the writer's document (3.4), and seals only to a document that
   passes for its subject (3.7);
2. builds and signs its pack, known object, answers, withdrawal or cover,
   and seals each in a fixed-size envelope with a fresh response key
   (enclave-messages.md 3);
3. fetches each receipt (`202` then a 1,024-byte fetch, 4.4) and each day
   slot (4,096 bytes, 6.3); bytes that do not open are "nothing yet";
4. sends one answer object at each of the three answer checkpoints of a
   proposal: the answer at the first checkpoint after the person chose (or
   `not_now` at the last one), and a filler of the same size at the others
   (5.3). So the node sees the same three objects for every
   proposal, whatever the person did and when.

The node and the network transport see only ciphertext of fixed sizes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.strict import DAY, Refused, fmt_time, parse_time
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.binding import descriptor_set_hash
from anagram.network.matching.trust.bundle import Target, check_bundle
from anagram.network.matching.trust.follow import LogFollower, LogReader
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

RESEAL = frozenset({"stale_attestation", "unknown_instance_key"})  # enclave-messages.md 8.5


@dataclass
class Pending:
    """A delivered proposal and its answer checkpoints (5.3)."""

    proposal: str
    checkpoints: list[int]  # UTC days, from the proposal item
    expires: int  # Unix time: the end of the last checkpoint day
    choice: str | None = None  # None until the person chooses
    card: JsonObject | None = None
    answered: bool = False  # the answer itself went out
    done: int = 0  # checkpoints served so far (the answer or a filler)

    @property
    def next_day(self) -> int | None:
        """The day of the next checkpoint, or None after the last one."""
        return self.checkpoints[self.done] if self.done < len(self.checkpoints) else None

    @classmethod
    def of(cls, item: JsonObject) -> Pending:
        days = [parse_time(t, "checkpoint") // DAY for t in item["checkpoints"]]
        return cls(item["id"], days, parse_time(item["expires"], "expires"))


@dataclass
class EnclaveClient:
    subject: SigningKey
    reply: Any  # X25519 private key: slots are sealed to it
    node: httpx.Client  # a member session at the person's node
    roots: Roots
    log: LogReader  # the enclave transparency log (public)
    clock: Callable[[], int]
    target: Target | None = None
    responses: dict[str, Any] = field(default_factory=dict)  # digest -> response key
    pending: dict[str, Pending] = field(default_factory=dict)
    unconfirmed: dict[str, tuple[str, bytes]] = field(default_factory=dict)  # digest -> request
    bodies: dict[str, tuple[str, int, bytes]] = field(default_factory=dict)  # digest -> body
    follower: LogFollower = field(init=False)

    def __post_init__(self) -> None:
        self.follower = LogFollower(self.log, self.roots)

    @property
    def subject_hex(self) -> str:
        return self.subject.public_bytes().hex()

    @property
    def reply_key(self) -> bytes:
        return hpke.public_bytes(self.reply)

    # ---- attestation ---------------------------------------------------------

    def refresh(self) -> Target:
        r = self.node.get("/enclave/attestation")
        r.raise_for_status()
        self.target = self.check_bundle(r.json())
        return self.target

    @property
    def view(self) -> LogView | None:
        """What the app checked so far; it only grows."""
        return self.follower.view

    def check_bundle(self, bundle: JsonObject) -> Target:
        """3.7 steps 1 to 4 (`trust.bundle.check_bundle`) for this subject."""
        subject = self.subject.public_bytes()
        return check_bundle(bundle, self.follower, self.roots, self.clock(), subject)

    def _target(self) -> Target:
        return self.target if self.target is not None else self.refresh()

    # ---- requests --------------------------------------------------------------

    def _send(self, route: str, cls: int, body: bytes) -> str:
        target = self._target()
        response = hpke.generate()
        raw = m.seal_request(cls, target.digest, target.intake, hpke.public_bytes(response), body)
        digest = m.request_digest(raw).hex()
        self.responses[digest] = response
        self.unconfirmed[digest] = (route, raw)
        self.bodies[digest] = (route, cls, body)
        self._post(route, raw)
        return digest

    def _post(self, route: str, raw: bytes) -> None:
        r = self.node.post(f"/enclave/{route}", content=raw)
        if r.status_code != 202:
            raise httpx.HTTPStatusError("relay refused", request=r.request, response=r)

    def resend(self, digests: Iterable[str] | None = None) -> list[str]:
        """Send again the same bytes of each request with no receipt (or of
        those in `digests`). A restart can lose a request whose receipt was
        never released (4.4); the same bytes then get one receipt (8.5)."""
        chosen = sorted(
            self.unconfirmed if digests is None else set(digests) & set(self.unconfirmed)
        )
        for digest in chosen:
            route, raw = self.unconfirmed[digest]
            self._post(route, raw)
        return chosen

    def receipt(self, digest: str) -> JsonObject | None:
        """The receipt, or None while the node serves the filler."""
        r = self.node.get(f"/enclave/receipts/{digest}")
        r.raise_for_status()
        try:
            doc = m.open_receipt(
                self.responses[digest],
                bytes.fromhex(digest),
                r.content,
                set(self._target().output_keys),
            )
        except Refused:
            return None
        self.unconfirmed.pop(digest, None)
        if not (doc["status"] == "rejected" and doc.get("reason") in RESEAL):
            self.bodies.pop(digest, None)
        return doc

    def reseal(self, digest: str) -> str:
        """After `stale_attestation` or `unknown_instance_key` (a failover,
        or a key that is not the writer's): fetch the bundle again and seal
        the same body to the current writer (8.5). A new request digest."""
        route, cls, body = self.bodies.pop(digest)
        self.refresh()
        return self._send(route, cls, body)

    def upload_pack(self, doc: JsonObject) -> str:
        return self._send(
            "uploads", m.CLASS_UPLOAD, canonical_json(packs.sign_pack(doc, self.subject))
        )

    def upload_known(self, version: int, tags: list[bytes]) -> str:
        body = packs.encode_known(
            self.subject,
            version,
            self.clock(),
            self._target().descriptors["vocabulary"][0]["body"]["id"],
            [(t, []) for t in tags],
        )
        return self._send("known", m.CLASS_KNOWN, body)

    def withdraw(self, version: int) -> str:
        """Matching off (7.1). The enclave deletes the open proposals, so the
        remaining checkpoints of each get a filler: the node sees the same
        answer objects as if nothing changed (5.3)."""
        for p in self.pending.values():
            p.answered = True
        doc = m.withdrawal(self.subject, version, self.reply_key, self.clock())
        return self._send("uploads", m.CLASS_UPLOAD, canonical_json(doc))

    def cover(self, credential: JsonObject) -> str:
        doc = m.cover(self.subject, "person", credential, self.reply_key, self.clock())
        return self._send("uploads", m.CLASS_UPLOAD, canonical_json(doc))

    # ---- slots and answers -------------------------------------------------------

    def slot(self, day: int) -> JsonObject | None:
        """The item of day `day`, or None for a filler (no slot)."""
        address = m.slot_address(day, self.reply_key).hex()
        r = self.node.get(f"/enclave/slots/{address}")
        r.raise_for_status()
        doc = m.open_slot(self.reply, day, r.content, set(self._target().output_keys))
        if doc is None:
            return None
        item: JsonObject = doc["item"]  # `m.open_slot` checked the slot
        if item["kind"] == "proposal":
            self.pending.setdefault(item["id"], Pending.of(item))
        return item

    def choose(self, proposal: str, choice: str, card: JsonObject | None = None) -> None:
        """Record the person's choice. It goes out at the next checkpoint
        (5.3); a choice after the answer went out changes nothing."""
        p = self.pending[proposal]
        if not p.answered:
            p.choice, p.card = choice, card if choice == "yes" else None

    def send_due(self) -> list[str]:
        """Serve each checkpoint whose day has come: the answer once the
        person chose (`not_now` at the last checkpoint if not), else a
        filler. A proposal leaves the list after its last checkpoint or its
        expiry. Return the request digests."""
        now = self.clock()
        sent = []
        for pid, p in sorted(self.pending.items()):
            while p.next_day is not None and p.next_day <= now // DAY and now < p.expires:
                last = p.done == len(p.checkpoints) - 1
                if not p.answered and (p.choice is not None or last):
                    doc = m.answer(self.subject, pid, p.choice or "not_now", now, p.card)
                    p.answered = True
                else:
                    doc = m.answer_filler()
                sent.append(self._send("answers", m.CLASS_ANSWER, canonical_json(doc)))
                p.done += 1
            if p.next_day is None or now >= p.expires:
                del self.pending[pid]
        return sent


def pack_doc(
    subject: SigningKey,
    reply_key: bytes,
    credential: JsonObject,
    target: Target,
    lines: dict[str, list[JsonObject]],
    charter: JsonObject,
    version: int,
    created: int,
    approved_at: int,
    deny: JsonObject | None = None,
    block: JsonObject | None = None,
) -> JsonObject:
    """A lines-only person pack (spec/pack.md 3) for the target's release.
    The caller signs it (`EnclaveClient.upload_pack`)."""
    return {
        "block": block or {"hide": [], "people": []},
        "charter": charter,
        "consent": {
            "approved_at": fmt_time(approved_at),
            "descriptor_set": descriptor_set_hash(
                [bytes.fromhex(h) for h in target.release["descriptor_hashes"]]
            ).hex(),
            "statement": dsc.statement_hash(target.descriptors["matching"][0]),
        },
        "created": fmt_time(created),
        "credential": credential,
        "deny": deny or {"domains": [], "nodes": [], "rors": []},
        "expires": fmt_time(created + packs.MAX_LIFE),
        "facts": [],
        "kind": "person",
        "lines": lines,
        "readings": [],
        "reply_key": reply_key.hex(),
        "schema": packs.SCHEMA,
        "subject": subject.public_bytes().hex(),
        "teasers": [],
        "topics": [],
        "version": version,
        "vocab": target.descriptors["vocabulary"][0]["body"]["id"],
    }
