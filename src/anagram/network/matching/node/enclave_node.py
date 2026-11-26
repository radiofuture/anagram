"""The matching enclave at a node: config, parts and status.

node.json "enclave" (default: off, so a node without it is unchanged):

    {"enabled": true,
     "profile": "simulated",                 a profile that this build verifies
     "urls": ["http://enclave-a:8790", ...], the instances of the line (writer, standby)
     "log_url": "http://log:8780",           the enclave log (read and write API)
     "pins": {...},                          devnet.json: network, roster key, log key and
                                             origin, witnesses, release key, development root
     "record": {"affiliation", "admin", "kind", "ror"},   the node record (network.md 2.3)
     "tick_seconds": 60}                     the relay timer (day batches, expiry)

With it, the node holds its network key (`keys/network-ed25519`, the node
key of spec/network.md 1), and serves:

    /enclave/*                    the relay (member session; `EnclaveRelay`)
    /net/credential, .../proof    member credentials (member session; `CredentialIssuer`)
    /net/control                  the node's control chain (public; `ControlChain`)

`node serve` also runs the relay timer. The node pins the log key and the
witnesses: a credential proof uses only a cosigned checkpoint that it
checked. `NodeEnclave.status` checks the enclave's attestation bundle under
the pins, as an app does, so an operator sees at once if the enclave or
the log is wrong.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx
from fastapi import Header

from anagram.core.canonical import JsonObject
from anagram.core.crypto.signing import SigningKey
from anagram.core.http import bearer
from anagram.core.jsontable import JsonTable
from anagram.core.shared_db import SharedDB
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import check_node_record, node_id
from anagram.network.formats.strict import Refused
from anagram.network.matching.hosting.clients import HttpLog
from anagram.network.matching.node.control import ControlChain
from anagram.network.matching.node.credentials import CredentialIssuer, Member
from anagram.network.matching.node.enclave_relay import (
    TICK_SECONDS,
    EnclaveRelay,
    EnclaveUnavailable,
    FailoverLink,
)
from anagram.network.matching.trust.bundle import check_bundle
from anagram.network.matching.trust.follow import LogFollower
from anagram.network.matching.trust.pins import Pins
from anagram.network.matching.trust.platform import available_profiles

if TYPE_CHECKING:
    from anagram.identity.api import IdentityService

DEFAULT_ENCLAVE: JsonObject = {
    "enabled": False,
    "log_url": "",
    "pins": None,
    "profile": "simulated",
    "record": {"admin": "", "affiliation": "", "kind": "lab", "ror": None},
    "tick_seconds": TICK_SECONDS,
    "urls": [],
}
_PID = re.compile(r"^pid:[0-9a-f]{32}$")
TIMEOUT = 15.0
KEEPALIVE = 2.0  # seconds; less than the keep-alive timeout of the services


def default_connect(base_url: str) -> httpx.Client:
    """An idle connection is closed after `KEEPALIVE` seconds, before the
    server closes it (uvicorn: 5 s). So the node does not send a request on
    a connection that the server closes at the same time."""
    return httpx.Client(
        base_url=base_url, timeout=TIMEOUT, limits=httpx.Limits(keepalive_expiry=KEEPALIVE)
    )


def enclave_config(raw: JsonObject | None) -> JsonObject:
    """The "enclave" config with defaults. Raise ValueError for a config that
    is on and not complete."""
    cfg = {**DEFAULT_ENCLAVE, **(raw or {})}
    cfg["record"] = {**DEFAULT_ENCLAVE["record"], **(cfg.get("record") or {})}
    if not cfg["enabled"]:
        return cfg
    if cfg["profile"] not in available_profiles():
        raise ValueError(f"enclave profile must be one of {available_profiles()}")
    urls = cfg["urls"]
    if not urls or not all(
        isinstance(u, str) and u.startswith(("http://", "https://")) for u in urls
    ):
        raise ValueError("enclave.urls must list the http(s) URLs of the enclave instances")
    if not str(cfg["log_url"]).startswith(("http://", "https://")):
        raise ValueError("enclave.log_url must be the http(s) URL of the enclave log")
    if not isinstance(cfg["pins"], dict):
        raise ValueError("enclave.pins must hold the network pins (devnet.json)")
    Pins.from_json(cfg["pins"])
    if not isinstance(cfg["tick_seconds"], int | float) or cfg["tick_seconds"] <= 0:
        raise ValueError("enclave.tick_seconds must be a positive number")
    if not cfg["record"]["affiliation"] or not cfg["record"]["admin"]:
        raise ValueError("enclave.record needs affiliation and admin")
    return cfg


def node_record(cfg: JsonObject, key: SigningKey, public_url: str) -> JsonObject:
    """The node record of spec/network.md 2.3, for the roster operator."""
    rec = {
        "admin": cfg["record"]["admin"],
        "affiliation": cfg["record"]["affiliation"],
        "domain": urlsplit(public_url).hostname or "",
        "id": node_id(key.public_bytes()),
        "key": key.public_bytes().hex(),
        "kind": cfg["record"]["kind"],
        "ror": cfg["record"]["ror"],
        "url": public_url,
    }
    try:
        check_node_record(rec)
    except Refused as exc:
        raise ValueError(f"node record: {exc} (the public URL must be https://)") from exc
    return rec


def member_session(identity: IdentityService) -> Callable[..., Member]:
    """The route dependency of the credential routes (network.md 6.6): the
    member of the session, with its device, person ID and email tag.
    `401` without a session, `403` for a person who is not a member."""

    def member_of(authorization: str | None = Header(default=None)) -> Member:
        subject, device = identity.session_device(bearer(authorization))
        identity.require_member(subject)
        email = identity.email_of(subject)
        tags = (packs.known_tag(packs.email_id(email)).hex(),) if email else ()
        pid = subject if _PID.match(subject) else None
        return Member(subject, device or "", pid, tags)

    return member_of


@dataclass
class NodeEnclave:
    """The enclave parts of one node."""

    pins: Pins
    relay: EnclaveRelay
    issuer: CredentialIssuer
    chain: ControlChain
    log: HttpLog
    clock: Callable[[], int]
    tick_seconds: float = TICK_SECONDS

    @classmethod
    def build(
        cls,
        cfg: JsonObject,
        key: SigningKey,
        state_dir: Path,
        clock: Callable[[], int],
        connect: Callable[[str], httpx.Client] = default_connect,
    ) -> NodeEnclave:
        """`connect` gives the HTTP client of a base URL (the log, each
        enclave instance)."""
        pins = Pins.from_json(cfg["pins"])
        nid = node_id(key.public_bytes())
        log = HttpLog(pins.origin, pins.roots, connect(cfg["log_url"]))
        link = FailoverLink([connect(u) for u in cfg["urls"]])
        state_dir.mkdir(parents=True, exist_ok=True)
        relay = EnclaveRelay.persistent(
            SharedDB(state_dir / "relay.sqlite"), nid, key, pins.origin, link, clock
        )
        chain = ControlChain(state_dir / "control.sqlite", nid, key, clock)
        db = SharedDB(state_dir / "credentials.sqlite")
        issuer = CredentialIssuer(
            nid,
            key,
            pins.network,
            log,
            clock,
            control_head=lambda: chain.count,
            bindings=JsonTable(db, "bindings"),
            entries=JsonTable(db, "entries"),
            joins=JsonTable(db, "joins"),
            seen=JsonTable(db, "nonces"),
            issued=JsonTable(db, "issued"),
            left=chain.left,
        )
        return cls(pins, relay, issuer, chain, log, clock, cfg["tick_seconds"])

    def close(self) -> None:
        """Close the HTTP clients of the log and of the enclave instances."""
        self.log.http.close()
        link = self.relay.link
        if isinstance(link, FailoverLink):
            link.close()

    def status(self) -> JsonObject:
        """What an operator checks: the node ID, the log (a checkpoint with a
        witness quorum under the pins), and the enclave (an attestation
        bundle that passes the app's checks under the pins)."""
        out: JsonObject = {
            "network": self.pins.network,
            "node": self.relay.node,
            "profile": self.pins.profile,
        }
        try:
            out["log_size"] = len(self.log.view().entries)
            out["log"] = "ok"
        except Refused as exc:
            out["log"] = f"not ok: {exc.code}"
        try:
            bundle = self.relay.attestation(wait=False)
            roots = self.pins.roots
            probe = SigningKey.generate().public_bytes()  # any subject: the app's checks
            target = check_bundle(bundle, LogFollower(self.log, roots), roots, self.clock(), probe)
            out["enclave"] = "attested"
            out["instance_id"] = target.document["instance_id"]
        except EnclaveUnavailable:
            out["enclave"] = "unreachable"
        except Refused as exc:  # NotSealable is a refusal too
            out["enclave"] = f"not attested: {type(exc).__name__}"
        return out
