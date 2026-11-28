"""Member credentials at the node (spec/network.md 6.5 and 6.6).

    POST /net/credential               a signed credential request -> the credential
    GET  /net/credential/{hash}/proof  the log proof, after a cosigned checkpoint

The app proves that it holds the person key (the request signature); the
member session proves the device. The node issues a credential of at most
24 hours, writes its `member_credential` entry to the enclave log, and
gives the log proof when a checkpoint that the witnesses cosigned holds the
entry. The app puts the credential and the proof in its next pack.

The first credential of a member (and the first after the member's removal
or exit at this node) is a join entry: it commits to the person key under a
random salt, and every later proof names it (`join`), so the log counts new
members of the node, not renewals (6.7).

Only the member that a credential was issued to gets its proof; any other
member gets `404`. The proof holds the salt and the index of the join entry,
so another member could link each renewal to its join entry (6.6).

`CredentialIssuer` has no HTTP and no sessions: `credential_router` takes a
dependency that gives the member of the session (`401` without a session,
`403` for a person who is not a member), so the node shell and the test
network each give their own. The node keeps its state (bindings, joins,
entries, the nonces of the last 10 minutes and the counts of the day) in
`JsonTable`s, so a restart does not reset the nonce check or the daily limit.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from anagram.core.canonical import CanonicalError, JsonObject, loads_canonical
from anagram.core.crypto.signing import SigningKey
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats.roster import check_credential_request
from anagram.network.formats.strict import (
    DAY,
    HEX32,
    NONCE_MEMORY,
    REQUEST_SKEW,
    Refused,
    parse_time,
)
from anagram.network.matching.trust.follow import checkpoint_size

DAILY_LIMIT = 4  # 6.6: at most 4 credentials for each member in a day


class IssueLog(Protocol):
    """The enclave log as the node uses it: the write API and the reads that
    a proof needs (spec/enclave-trust.md 2.1)."""

    def append(self, entry: JsonObject) -> int: ...

    def checkpoint(self) -> str: ...

    def inclusion(self, index: int, size: int) -> list[str]: ...


@dataclass(frozen=True)
class Member:
    """The member of a session, as the node's member records give it."""

    id: str  # the node's own member ID
    device: str  # hex device key of the session
    pid: str | None
    email_tags: tuple[str, ...]


class IssueRefused(Refused):
    """A credential request that the node refuses, with its HTTP status."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__("issue_refused", detail)
        self.status = status


@dataclass
class CredentialIssuer:
    node: str
    key: SigningKey
    network: str
    log: IssueLog
    clock: Callable[[], int]
    control_head: Callable[[], int] = lambda: 0  # events of this node's chain so far
    bindings: MutableMapping[str, str] = field(default_factory=dict)  # member ID -> person key (4)
    seen: MutableMapping[str, int] = field(default_factory=dict)  # nonce -> time
    issued: MutableMapping[str, int] = field(default_factory=dict)  # "member/day" -> count
    # hash -> [index, entry, join, member ID]: the member is the only one that gets the proof
    entries: MutableMapping[str, Any] = field(default_factory=dict)
    joins: MutableMapping[str, JsonObject] = field(default_factory=dict)  # member ID -> join
    # The time of the person key's last removal or exit at this node (8.4), or 0.
    left: Callable[[str], int] = lambda _person_key: 0
    # One request at a time: the nonce check and the daily count read, then write.
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def issue(self, body: bytes, member: Member) -> JsonObject:
        """The checks of 6.6 in order, then the credential and its log entry."""
        with self._lock:
            return self._issue(body, member)

    def _prune(self, now: int) -> None:
        """Forget the nonces older than 10 minutes and the counts of past days."""
        for nonce in [n for n, t in self.seen.items() if t <= now - NONCE_MEMORY]:
            del self.seen[nonce]
        today = now // DAY
        for key in [k for k in self.issued if int(k.rsplit("/", 1)[1]) < today]:
            del self.issued[key]

    def _issue(self, body: bytes, member: Member) -> JsonObject:
        now = self.clock()
        try:
            req = check_credential_request(loads_canonical(body))
        except (CanonicalError, ValueError, Refused) as exc:
            raise IssueRefused(400, f"credential request: {exc}") from exc
        if req["device"] != member.device:
            raise IssueRefused(403, "the session's device is not `device`")
        if req["node"] != self.node:
            raise IssueRefused(400, "the request names another node")
        if abs(parse_time(req["time"], "time") - now) > REQUEST_SKEW:
            raise IssueRefused(400, "request time")
        self._prune(now)
        if req["nonce"] in self.seen:
            raise IssueRefused(400, "nonce seen in the last 10 minutes")
        bound = self.bindings.setdefault(member.id, req["person_key"])
        if bound != req["person_key"]:
            raise IssueRefused(403, "the person key differs from the recorded binding")
        day = f"{member.id}/{now // DAY}"
        if self.issued.get(day, 0) >= DAILY_LIMIT:
            raise IssueRefused(429, "credential limit for today")
        self.seen[req["nonce"]] = now
        self.issued[day] = self.issued.get(day, 0) + 1
        facts = cred.MemberFacts(
            network=self.network,
            node=self.node,
            subject=req["person_key"],
            kind="person",
            issued=now,
            expires=now + cred.MAX_LIFE,
            control_head=self.control_head(),
            pid=member.pid,
            email_tags=tuple(sorted(member.email_tags)),
        )
        raw = cred.make_biscuit(facts, self.key)
        join = self.joins.get(member.id)
        if join is not None and join["time"] > self.left(req["person_key"]):
            entry = cred.log_entry(facts, raw, self.key)
            index = self.log.append(entry)
        else:  # a new member, or a member who came back after a removal
            salt = secrets.token_hex(16)
            entry = cred.log_entry(facts, raw, self.key, cred.member_commit(facts.subject, salt))
            index = self.log.append(entry)
            join = {"index": index, "salt": salt, "time": now}
            self.joins[member.id] = join
        digest = cred.credential_hash(raw).hex()
        self.entries[digest] = [
            index,
            entry,
            {"index": join["index"], "salt": join["salt"]},
            member.id,
        ]
        token = {"format": cred.FORMAT_BISCUIT, "token": b64url(raw)}
        return {"credential": token, "hash": digest}

    def proof(self, digest: str, member: Member) -> JsonObject | None:
        """The log proof against the latest cosigned checkpoint, or None
        (`404`) while no cosigned checkpoint holds the entry, and for a
        credential of another member (6.6)."""
        found = self.entries.get(digest)
        if found is None or found[-1] != member.id:
            return None
        index, entry, join, _ = found
        size = checkpoint_size(self.log.checkpoint())
        if index >= size:
            return None
        return {
            "log": {
                "entry_signature": entry["signature"],
                "hashes": self.log.inclusion(index, size),
                "index": index,
                "join": join,
                "tree_size": size,
            }
        }


def credential_router(issuer: CredentialIssuer, member_of: Callable[..., Member]) -> APIRouter:
    """The app-facing routes of 6.6. `member_of` is a route dependency that
    gives the member of the session or raises `401`/`403`."""
    router = APIRouter(prefix="/net")

    @router.post("/credential")
    async def issue(request: Request, member: Any = Depends(member_of)) -> JsonObject:
        body = await request.body()
        try:
            # In a worker thread: the issue writes to the log over HTTP.
            return await run_in_threadpool(issuer.issue, body, member)
        except IssueRefused as exc:
            raise HTTPException(exc.status, exc.detail) from exc

    @router.get("/credential/{digest}/proof")
    def proof(digest: str, member: Any = Depends(member_of)) -> JsonObject:
        if not HEX32.match(digest):
            raise HTTPException(400)
        found = issuer.proof(digest, member)
        if found is None:
            raise HTTPException(404)
        return found

    return router
