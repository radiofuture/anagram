"""Node data directory: keys, log database, local witness, anchors.

Layout of <dir>:

    node.json        origin, anchors, community, public URL, ORCID mode and client ID,
                     organizers, submission rate limit (no secrets)
    keys/            log-ed25519, witness-ed25519, fake-anchor-ed25519,
                     assertion-ed25519, network-ed25519 (the node key of
                     spec/network.md: member credentials, control events, node
                     requests to the enclave), orcid-client-secret (FileKeystore)
    log.sqlite       the Merkle log
    witness.sqlite   state of the local witness
    identity.sqlite  invites, members, sessions, directory index, key backups
                     (hashes of secrets and ciphertext only)
    vault.sqlite     grants, public releases, guardian sets, recovery requests
    store.sqlite     personal store records and person-key packages (ciphertext only)
    labs.sqlite      lab rosters, invite authorisations, lab key packages and lab space
                     records (ciphertext only), lab names and members
    blobs/           encrypted evidence blobs (ciphertext only)
    enclave/         with node.json "enclave" on: the control chain (control.sqlite),
                     the person-key bindings and credential log entries (credentials.sqlite),
                     and the relay's sealed receipts and slots

Anchors (node.json "anchors"): "fake", "rfc3161:<URL>", "opentimestamps", or
"opentimestamps:<URL>,<URL>" (calendars). A node with real ORCID (production or
sandbox) never uses "fake": `create` refuses it and the default is
`anagram.proofs.anchors.defaults.DEFAULT_ANCHORS`. node.json "anchor_mode":

- "inline" (default; a local client node): each checkpoint is stamped during the
  commit.
- "background" (`anagram node init` and `anagram node start`): only the fake
  anchor is inline. Network anchors run in `anagram.proofs.node.anchoring`, so a
  commit never waits for a TSA or a calendar. node.json "anchor_batch_seconds"
  sets the batch interval (default 600).

node.json "enclave" (optional, default off): the matching enclave of the
network, `simulated` profile. Matching runs only there: the node holds no
matching key and only relays sealed messages. See
`anagram.network.matching.node.enclave_node` and docs/enclave.md.

Environment variables override node.json: ANAGRAM_ORCID_CLIENT_ID,
ANAGRAM_ORCID_CLIENT_SECRET, ANAGRAM_PUBLIC_URL.

The local witness runs with the node. This is enough to test the protocol. It
does not stop a dishonest operator, because the operator holds both keys. A real
deployment uses a witness that another party runs.
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import NodeError
from anagram.identity.api import (
    ORCID_MODES,
    PUBLIC_LOG_KINDS,
    FileKeystore,
    make_node_trust,
    node_key_fingerprint,
    validate_orcid,
)
from anagram.proofs.anchors.base import Anchor
from anagram.proofs.anchors.defaults import DEFAULT_ANCHORS, anchor_kind
from anagram.proofs.anchors.fake import FakeAnchor
from anagram.proofs.anchors.ots import OpenTimestampsAnchor
from anagram.proofs.anchors.rfc3161 import RFC3161Anchor
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner
from anagram.proofs.log.store import SQLiteLog
from anagram.proofs.log.witness import Witness
from anagram.proofs.node.service import NodeService

# Log origins name the log format generation. v2 (2026-10-27): person IDs
# (`pid:`) and ORCID commitments in key bindings. A node made before v2 has an
# old origin; its log is not read by this version (no field users, no migration).
LOG_ORIGIN_PATH = "log-v2"
DEFAULT_ORIGIN = f"local.anagram/{LOG_ORIGIN_PATH}"
DEFAULT_COMMUNITY = "Local Anagram community"
DEFAULT_PUBLIC_URL = "http://127.0.0.1:8787"
NODE_KEYS = (
    "log-ed25519",
    "witness-ed25519",
    "fake-anchor-ed25519",
    "assertion-ed25519",
    "network-ed25519",
)
ORCID_SECRET_KEY = "orcid-client-secret"  # noqa: S105 - a key name, not a secret


@dataclass
class NodeHome:
    dir: Path

    @property
    def config_path(self) -> Path:
        return self.dir / "node.json"

    def exists(self) -> bool:
        return self.config_path.exists()

    def create(
        self,
        origin: str = DEFAULT_ORIGIN,
        anchors: list[str] | None = None,
        *,
        community: str = DEFAULT_COMMUNITY,
        public_url: str = DEFAULT_PUBLIC_URL,
        orcid_mode: str = "fake",
        orcid_client_id: str = "",
        orcid_client_secret: str = "",
        organizers: list[str] | tuple = (),
        submit_per_minute: int = 60,
        anchor_mode: str = "inline",
        anchor_batch_seconds: int = 600,
    ) -> None:
        if orcid_mode not in ORCID_MODES:
            raise ValueError(f"ORCID mode must be one of {ORCID_MODES}")
        if anchors is None:
            anchors = ["fake"] if orcid_mode == "fake" else list(DEFAULT_ANCHORS)
        check_anchor_policy(orcid_mode, anchors)
        if anchor_mode not in ("inline", "background"):
            raise ValueError("anchor mode must be inline or background")
        parsed = urllib.parse.urlsplit(public_url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("public URL must be http(s) with a host")
        self.dir.mkdir(parents=True, exist_ok=True)
        ks = FileKeystore(self.dir / "keys")
        for name in NODE_KEYS:
            ks.get_or_create(name, lambda: secrets.token_bytes(32))
        if orcid_client_secret:
            ks.put(ORCID_SECRET_KEY, orcid_client_secret.encode())
        cfg = {
            "anchor_batch_seconds": int(anchor_batch_seconds),
            "anchor_mode": anchor_mode,
            "anchors": list(anchors),
            "community": community,
            "orcid": {"client_id": orcid_client_id, "mode": orcid_mode},
            "organizers": [organizer_orcid(o) for o in organizers],
            "origin": origin,
            "public_url": public_url.rstrip("/"),
            "submit_per_minute": submit_per_minute,
        }
        self.config_path.write_text(json.dumps(cfg, indent=2) + "\n")

    def config(self) -> dict:
        cfg = json.loads(self.config_path.read_text())
        cfg.setdefault("community", DEFAULT_COMMUNITY)
        cfg.setdefault("orcid", {"client_id": "", "mode": "fake"})
        cfg["organizers"] = [organizer_orcid(o) for o in cfg.get("organizers", [])]
        cfg.setdefault("public_url", DEFAULT_PUBLIC_URL)
        cfg.setdefault("submit_per_minute", 60)
        cfg.setdefault("anchor_mode", "inline")
        cfg.setdefault("anchor_batch_seconds", 600)
        if os.environ.get("ANAGRAM_PUBLIC_URL"):
            cfg["public_url"] = os.environ["ANAGRAM_PUBLIC_URL"].rstrip("/")
        if os.environ.get("ANAGRAM_ORCID_CLIENT_ID"):
            cfg["orcid"]["client_id"] = os.environ["ANAGRAM_ORCID_CLIENT_ID"]
        return cfg

    def orcid_client_secret(self) -> str:
        if os.environ.get("ANAGRAM_ORCID_CLIENT_SECRET"):
            return os.environ["ANAGRAM_ORCID_CLIENT_SECRET"]
        raw = FileKeystore(self.dir / "keys").get(ORCID_SECRET_KEY)
        return raw.decode() if raw else ""

    def callback_url(self) -> str:
        return self.config()["public_url"] + "/auth/orcid/callback"

    def _key(self, name: str) -> SigningKey:
        seed = FileKeystore(self.dir / "keys").get(name)
        if seed is None:
            raise FileNotFoundError(f"node key missing: {name}")
        return SigningKey.from_seed(seed)

    def log_signer(self) -> NoteSigner:
        return NoteSigner(self.config()["origin"], self._key("log-ed25519"))

    def witness_signer(self) -> NoteSigner:
        name = self.config()["origin"].split("/")[0] + "/witness"
        return NoteSigner(name, self._key("witness-ed25519"), alg=ALG_COSIGNATURE_V1)

    def fake_anchor_key(self) -> SigningKey:
        return self._key("fake-anchor-ed25519")

    def assertion_key(self) -> SigningKey:
        ks = FileKeystore(self.dir / "keys")
        ks.get_or_create("assertion-ed25519", lambda: secrets.token_bytes(32))  # older homes
        return self._key("assertion-ed25519")

    def network_key(self) -> SigningKey:
        """The node key of the network (spec/network.md 1). An older home
        gets it at its first use."""
        ks = FileKeystore(self.dir / "keys")
        ks.get_or_create("network-ed25519", lambda: secrets.token_bytes(32))
        return self._key("network-ed25519")

    def enclave_config(self) -> dict:
        """node.json "enclave" with defaults; ValueError if it is on and not complete."""
        from anagram.network.api import enclave_config

        return enclave_config(self.config().get("enclave"))

    def node_record(self) -> dict:
        """The node record (spec/network.md 2.3) to give the roster operator."""
        from anagram.network.api import node_record

        return node_record(self.enclave_config(), self.network_key(), self.config()["public_url"])

    def enclave(self, clock=None, connect=None):
        """The enclave parts (relay, credentials, control chain), or None when
        node.json "enclave" is off."""
        from anagram.core.devclock import clock_from_env
        from anagram.network.api import NodeEnclave

        cfg = self.enclave_config()
        if not cfg["enabled"]:
            return None
        clock = clock or clock_from_env()
        extra = {"connect": connect} if connect is not None else {}
        return NodeEnclave.build(
            cfg, self.network_key(), self.dir / "enclave", lambda: int(clock()), **extra
        )

    def set_enclave(self, enclave: dict) -> None:
        """Write node.json "enclave" after the checks of `enclave_config`."""
        from anagram.network.api import enclave_config

        cfg = json.loads(self.config_path.read_text())
        cfg["enclave"] = enclave_config(enclave)
        self.config_path.write_text(json.dumps(cfg, indent=2) + "\n")

    def fingerprint(self) -> str:
        return node_key_fingerprint(self.log_signer().vkey())

    def trust_document(self) -> dict:
        """The signed trust document. An invite pins the log key fingerprint."""
        cfg = self.config()
        fake = [self.fake_anchor_key().public_bytes().hex()] if "fake" in cfg["anchors"] else []
        return make_node_trust(
            log_key=self._key("log-ed25519"),
            log_vkey=self.log_signer().vkey(),
            witness_vkeys=[self.witness_signer().vkey()],
            fake_anchor_keys=fake,
            assertion_key=self.assertion_key().public_bytes(),
            community=cfg["community"],
            node_url=cfg["public_url"],
            orcid_mode=cfg["orcid"]["mode"],
        )

    def orcid_adapter(self):
        from anagram.identity.api import FakeOrcid, OrcidOAuth

        cfg = self.config()
        mode = cfg["orcid"]["mode"]
        if mode == "fake":
            return FakeOrcid(cfg["public_url"])
        client_id = cfg["orcid"]["client_id"]
        secret = self.orcid_client_secret()
        if not client_id or not secret:
            return _DisabledOrcid(mode)
        return OrcidOAuth(client_id, secret, mode)

    def identity(self, service: NodeService, orcid=None, mailer=None, clock=None):
        from anagram.identity.api import FakeMailer, IdentityConfig, IdentityService

        cfg = self.config()
        icfg = IdentityConfig(
            community=cfg["community"],
            public_url=cfg["public_url"],
            node_key=self.fingerprint(),
            organizers=set(cfg["organizers"]),
            submit_per_minute=cfg["submit_per_minute"],
        )
        kwargs = {"clock": clock} if clock else {}
        return IdentityService(
            self.dir / "identity.sqlite",
            icfg,
            self.assertion_key(),
            service,
            orcid or self.orcid_adapter(),
            mailer or FakeMailer(),
            self.trust_document(),
            **kwargs,
        )

    def admin(self, identity, admission, anchoring=None, service=None, clock=None):
        """The organizer page (`/admin`). `admission`: the `AdmissionService`
        (invites, invite chain), for example `self.admission(...)`."""
        from anagram.shell.node.admin import Admin

        kwargs = {"clock": clock} if clock else {}
        return Admin(
            self.dir / "admin.sqlite",
            identity,
            anchoring,
            log=service,
            admission=admission,
            labs=self.lab_directory(),
            **kwargs,
        )

    def vault(self, identity):
        from anagram.network.api import NodeVault

        return NodeVault(self.dir / "vault.sqlite", self.dir / "blobs", identity)

    def reads(self, identity, vault):
        """The read ledger, and its receipt gate on `vault`."""
        from anagram.network.api import ReadLedger

        hours = self.config().get("sharing", {}).get("read_window_hours", 24)
        reads = ReadLedger(self.dir / "reads.sqlite", identity, vault, window_s=int(hours * 3600))
        vault.read_gate = reads.serve
        return reads

    def verify(self, identity):
        """The public verify page and published proofs, or None when
        the node config has `verify.public_page` false."""
        from anagram.proofs.node.verify_page import VerifyPages

        cfg = self.config()
        if not cfg.get("verify", {}).get("public_page", True):
            return None
        return VerifyPages(
            self.dir / "proofs.sqlite", identity, self.trust_info(), public_url=cfg["public_url"]
        )

    def node_policy(self):
        """The admission policy of this node (L4, `NodePolicy`): invite only,
        and the lab create rule from `ANAGRAM_LAB_CREATE`
        (read at each start)."""
        from anagram.admission.api import NodePolicy
        from anagram.network.api import lab_policy_from_env

        return NodePolicy(create_group=lab_policy_from_env(os.environ)[1])

    def admission_store(self, identity):
        """The admission tables (L4) on the connection and the store lock of
        the identity service (see the lock contract in
        `anagram.admission.node.store`)."""
        from anagram.admission.api import AdmissionStore

        return AdmissionStore(identity.db, identity.lock)

    def reader_invites(self, identity):
        """Reader invites (layer L4)."""
        from anagram.admission.api import ReaderInvites

        return ReaderInvites(identity, self.admission_store(identity), self.node_policy())

    def admission(self, identity, labs=None, readers=None):
        """The registration gate of the node (L4): node invites, lab invites,
        reader invites, and the invite chain."""
        from anagram.admission.api import AdmissionService

        return AdmissionService(
            identity, self.admission_store(identity), labs, self.node_policy(), readers
        )

    def store(self, identity):
        """The personal store on the node (ciphertext records of each person)."""
        from anagram.identity.api import NodePersonalStore

        return NodePersonalStore(self.dir / "store.sqlite", identity)

    def lab_directory(self):
        """The lab names and members (L3, `LabDirectory`, in labs.sqlite)."""
        from anagram.network.api import LabDirectory

        return LabDirectory(self.dir / "labs.sqlite")

    def labs(self, identity, vault=None):
        """The lab unit (rosters, invites, lab keys, lab space records).
        `ANAGRAM_LAB_QUOTA_MB` and `ANAGRAM_LAB_CREATE` are read at each start."""
        from anagram.admission.api import GroupAdmission, group_creation
        from anagram.network.api import LabService, lab_policy_from_env

        quota, _ = lab_policy_from_env(os.environ)
        policy = self.node_policy()
        labs = LabService(
            self.dir / "labs.sqlite",
            identity,
            self.lab_directory(),
            group_creation(identity, policy),
            GroupAdmission(policy),  # the roster checks of L4 (port `AdmissionCheck`)
            vault,
            quota,
        )
        if vault is not None:  # a lab member reads the lab blobs
            vault.readers.append(labs.can_read_blob)
        return labs

    def app(self, orcid=None, mailer=None, clock=None):
        return self.app_parts(orcid, mailer, clock)[0]

    def app_parts(self, orcid=None, mailer=None, clock=None):
        """The FastAPI app and the identity service behind it: (app, identity).
        A server uses `app.state.enclave` (or None) to run the relay timer."""
        from anagram.shell.node.app import create_app

        service = self.service()
        identity = self.identity(service, orcid, mailer, clock)
        anchoring = self.anchoring(service, clock)
        vault = self.vault(identity)
        labs = self.labs(identity, vault)
        readers = self.reader_invites(identity)
        admission = self.admission(identity, labs, readers)
        enclave = self.enclave()
        app = create_app(
            service,
            self.trust_info(),
            identity,
            vault=vault,
            anchoring=anchoring,
            admin=self.admin(identity, admission, anchoring, service, clock),
            store=self.store(identity),
            labs=labs,
            reads=self.reads(identity, vault),
            reader_invites=readers,
            admission=admission,
            verify=self.verify(identity),
            enclave_parts=enclave,
        )
        app.state.enclave = enclave
        app.state.anchoring = anchoring  # `node serve` starts its thread
        app.state.admission = admission
        app.state.labs = labs
        return app, identity

    def anchor(self, spec: str) -> Anchor:
        kind = anchor_kind(spec)
        if kind == "fake":
            return FakeAnchor(self.fake_anchor_key())
        if kind == "rfc3161":
            return RFC3161Anchor(spec.removeprefix("rfc3161:"))
        calendars = spec.removeprefix("opentimestamps").removeprefix(":")
        if calendars:
            return OpenTimestampsAnchor(tuple(u for u in calendars.split(",") if u))
        return OpenTimestampsAnchor()

    def _checked_specs(self) -> tuple[dict, list[str]]:
        cfg = self.config()
        check_anchor_policy(cfg["orcid"]["mode"], cfg["anchors"])
        return cfg, list(cfg["anchors"])

    def anchors(self) -> list[Anchor]:
        """The inline anchors (stamped during each commit)."""
        cfg, specs = self._checked_specs()
        if cfg["anchor_mode"] == "background":
            specs = [s for s in specs if anchor_kind(s) == "fake"]
        return [self.anchor(s) for s in specs]

    def background_anchors(self) -> dict[str, Anchor]:
        cfg, specs = self._checked_specs()
        if cfg["anchor_mode"] != "background":
            return {}
        return {s: self.anchor(s) for s in specs if anchor_kind(s) != "fake"}

    def anchoring(self, service: NodeService, clock=None):
        """The background anchor scheduler, or None (no network anchors)."""
        from anagram.proofs.node.anchoring import AnchorScheduler

        anchors = self.background_anchors()
        if not anchors:
            return None
        kwargs = {"clock": clock} if clock else {}
        return AnchorScheduler(
            service.store,
            service.origin,
            anchors,
            self.dir / "anchors.sqlite",
            batch_seconds=int(self.config()["anchor_batch_seconds"]),
            **kwargs,
        )

    def trust_info(self) -> dict:
        """Public keys that a client pins for this node."""
        fake = "fake" in self.config()["anchors"]
        return {
            "fake_anchor_keys": [self.fake_anchor_key().public_bytes().hex()] if fake else [],
            "log_keys": [self.log_signer().vkey()],
            "witness_keys": [self.witness_signer().vkey()],
        }

    def service(self) -> NodeService:
        signer = self.log_signer()
        witness = Witness(self.witness_signer(), self.dir / "witness.sqlite", [signer.verifier])
        return NodeService(
            SQLiteLog(self.dir / "log.sqlite"),
            signer,
            [witness],
            self.anchors(),
            public_kinds=PUBLIC_LOG_KINDS,
        )


class _OrcidUnavailable(NodeError):
    status = 503


class _DisabledOrcid:
    """Adapter used when a production/sandbox node runs without ORCID credentials."""

    enabled = False

    def __init__(self, mode: str) -> None:
        self.mode = mode

    def authorize_url(self, state: str, redirect_uri: str, login_hint: str | None = None) -> str:
        raise _OrcidUnavailable("ORCID is not configured on this node")

    def exchange(self, code: str, redirect_uri: str):
        raise _OrcidUnavailable("ORCID is not configured on this node")


def organizer_orcid(value: str) -> str:
    """Organizers are listed by ORCID iD (an old `orcid:` prefix is allowed)."""
    return validate_orcid(str(value).strip().removeprefix("orcid:"))


def check_anchor_policy(orcid_mode: str, anchors: list[str]) -> None:
    """A node with real ORCID never uses the fake anchor. Unknown specs fail."""
    kinds = [anchor_kind(s) for s in anchors]
    if orcid_mode != "fake" and "fake" in kinds:
        raise ValueError(
            "the fake anchor is for local development only; a node with real ORCID "
            "must use real anchors (rfc3161, opentimestamps)"
        )
