"""Recovery guardians (optional). See spec/vault.md section 6.

Set up (owner device):

1. Make a new 32-byte guardian recovery secret G. Seal a key backup with G
   (same format as the recovery kit backup) and store it on the node.
2. Split G with Shamir (k of n, default 2 of 3). HPKE-encrypt each share to
   each device of its guardian. The guardian keys come from `lookup` (log
   proofs). The node stores only ciphertext.

Recover (new device, no keys):

1. Sign in at the node (ORCID or email) with a new temporary device key. Send a
   recovery request: the node assertion for the temporary key, and the key.
2. Each guardian runs an explicit approve command. The guardian device checks
   the node assertion, decrypts its share, and encrypts it again to the
   temporary key of the request.
3. With k approvals, the new device combines the shares, gets G, opens the
   backup, and restores the keys. It then checks that the restored device key
   is still active in the key directory.

The guardians must confirm the request with the person by another channel
(for example a call), because the node holds the assertion key and can make an
assertion for anyone.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import os
import secrets
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from cryptography.exceptions import InvalidTag

from anagram.core.canonical import CanonicalError, canonical_json, loads_canonical
from anagram.core.crypto import hpke, shamir
from anagram.core.crypto.hashing import TAG_SIGN_KEY_POSSESSION
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.crypto.x25519 import X25519Key
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import HttpNode, NodeHTTPError, Transport
from anagram.core.timefmt import format_time, parse_time
from anagram.core.wraps import b64, find_wrap, wrap_to_devices
from anagram.identity.app.browsers import Browser
from anagram.identity.app.device import (
    DEVICE_ED25519,
    DEVICE_X25519,
    INDEX_KEY,
    VAULT_KEY,
    Device,
)
from anagram.identity.app.directory import Directory
from anagram.identity.app.identity import Home, OpenHome, SignInWith, fetch_trust, sign_in
from anagram.identity.app.keychain import destroy_keystore, open_keystore
from anagram.identity.app.kit import restore_keys, write_private
from anagram.identity.app.session import read_session, write_session
from anagram.identity.formats.backup import backup_id as derive_backup_id
from anagram.identity.formats.backup import open_backup, seal_backup
from anagram.identity.formats.documents import (
    device_json,
    possession_message,
    sign_possession,
    validate_subject,
    verify_assertion,
)
from anagram.identity.formats.recovery import (
    GUARDIAN_APPROVAL_SCHEMA,
    GUARDIAN_SET_SCHEMA,
    RECOVERY_REQUEST_MAX_AGE,
    guardian_info,
    make_recovery_request,
    make_share,
    recovery_info,
    recovery_request_id,
    validate_approval,
    validate_share,
)

PENDING_DIR = "guardian-recovery"
DEFAULT_THRESHOLD = 2


class Guardians:
    """Recovery guardians of this person and the requests of other people
    (layer L1)."""

    def __init__(self, device: Device, directory: Directory) -> None:
        self.device = device
        self.directory = directory

    def guardians_set(self, who: list[str], threshold: int = DEFAULT_THRESHOLD) -> dict:
        """Choose guardians (k of n). Replaces an earlier set and its backup."""
        subjects = [self.directory.resolve_person(w) for w in who]
        if len(set(subjects)) != len(subjects) or self.device.subject in subjects:
            raise ClientError("guardians must be distinct other people")
        n = len(subjects)
        if not 2 <= threshold <= n <= shamir.MAX_SHARES:
            raise ClientError(f"need 2 <= threshold <= guardians <= {shamir.MAX_SHARES}")
        # Look up every guardian first (log proofs). A key that the log does not
        # prove stops the setup before anything is sent.
        states = [self.directory.lookup(s) for s in subjects]
        try:
            old = self.device.http.call("GET", "/guardians", auth=True)
        except NodeHTTPError as exc:
            if exc.status != 404:
                raise
            old = None

        secret = secrets.token_bytes(shamir.SECRET_LEN)
        keys = {
            DEVICE_ED25519: self.device.device_key().seed(),
            DEVICE_X25519: self.device.x25519_key().private_bytes(),
            VAULT_KEY: self.device.keystore.get(VAULT_KEY),
            INDEX_KEY: self.device.index_key(),
        }
        backup = seal_backup(secret, self.device.subject, keys)
        self.device.http.call("PUT", "/recovery/backup", {"backup": backup}, auth=True)
        set_id = secrets.token_bytes(16)
        guardians = []
        for (index, share), subject, state in zip(
            shamir.split(secret, threshold, n), subjects, states, strict=True
        ):
            doc = make_share(
                owner=self.device.subject,
                set_id=set_id,
                index=index,
                threshold=threshold,
                backup_id=backup["backup_id"],
                share=share,
            )
            wraps = wrap_to_devices(
                canonical_json(doc),
                list(state.devices.values()),
                partial(guardian_info, set_id, index),
            )
            guardians.append({"index": index, "subject": subject, "wraps": wraps})
        gset = {
            "backup_id": backup["backup_id"],
            "created_at": format_time(self.device.now()),
            "guardians": guardians,
            "schema": GUARDIAN_SET_SCHEMA,
            "set_id": set_id.hex(),
            "subject": self.device.subject,
            "threshold": threshold,
        }
        self.device.http.call("PUT", "/guardians", {"set": gset}, auth=True)
        if old is not None and old["backup_id"] != backup["backup_id"]:
            # The old shares now open nothing.
            self.device.http.call("DELETE", f"/recovery/backup/{old['backup_id']}", auth=True)
        return {"guardians": subjects, "set_id": set_id.hex(), "threshold": threshold}

    def guardian_requests(self) -> list[dict]:
        """Recovery requests of people for whom I am a guardian. Each item has
        `check`: "ok" if the node assertion and the key proof are valid."""
        out = []
        for r in self.device.http.call("GET", "/recovery/requests", auth=True)["requests"]:
            item = {**r, "check": "ok"}
            try:
                self._check_request(r["request_id"], r["request"])
            except ClientError as exc:
                item["check"] = str(exc)
            out.append(item)
        return out

    def _check_request(self, request_id: str, req: dict) -> None:
        cfg = self.device.config["identity"]
        try:
            if recovery_request_id(req) != request_id:
                raise FormatError("request ID does not match the request")
            a = verify_assertion(
                req["assertion"],
                assertion_key=bytes.fromhex(cfg["assertion_key"]),
                node_key=cfg["node_key"],
                audience=bytes.fromhex(req["device"]["ed25519"]),
            )
            if a["subject"] != req["subject"]:
                raise FormatError("assertion is for another person")
            # The assertion time comes from the node signature, not the client.
            age = (self.device.now() - parse_time(a["issued_at"])).total_seconds()
            if age > RECOVERY_REQUEST_MAX_AGE:
                raise FormatError("request is too old (more than 7 days); ask for a new one")
            if age < -600:
                raise FormatError("request is from the future")
            if not verify(
                bytes.fromhex(req["device"]["ed25519"]),
                TAG_SIGN_KEY_POSSESSION,
                possession_message(req["subject"], req["device"]),
                bytes.fromhex(req["pop"]),
            ):
                raise FormatError("bad proof of possession")
        except (FormatError, KeyError, TypeError, ValueError) as exc:
            raise ClientError(f"recovery request is not valid: {exc}") from exc

    def guardian_approve(self, request_id: str) -> dict:
        """Explicit approval: decrypt my share for the person of the request and
        encrypt it again to the new device key of the request. Confirm the
        request with the person (another channel) before you run this."""
        mine = [
            r
            for r in self.device.http.call("GET", "/recovery/requests", auth=True)["requests"]
            if r["request_id"] == request_id
        ]
        if not mine:
            raise ClientError("no recovery request with this ID for which you are a guardian")
        req, index = mine[0]["request"], mine[0]["index"]
        self._check_request(request_id, req)
        held = [
            s
            for s in self.device.http.call("GET", "/guardians/shares", auth=True)["shares"]
            if s["owner"] == req["subject"] and s["index"] == index
        ]
        if not held:
            raise ClientError("you hold no share for this person")
        me = self.device.my_device()["ed25519"]
        ct = find_wrap(held[0]["wraps"], me)
        if ct is None:
            raise ClientError("your share is not encrypted to this device")
        set_id = bytes.fromhex(held[0]["set_id"])
        try:
            plain = hpke.open_sealed(
                hpke.private_from_bytes(self.device.x25519_key().private_bytes()),
                ct,
                guardian_info(set_id, index, bytes.fromhex(me)),
            )
            share = validate_share(loads_canonical(plain))
        except (InvalidTag, CanonicalError, FormatError, ValueError) as exc:
            raise ClientError(f"share does not open: {exc}") from exc
        if share["owner"] != req["subject"] or share["index"] != index:
            raise ClientError("share is for another person or slot")
        sealed = hpke.seal(
            bytes.fromhex(req["device"]["x25519"]),
            canonical_json(share),
            recovery_info(bytes.fromhex(request_id), index),
        )
        approval = {
            "ciphertext": b64(sealed),
            "guardian": self.device.subject,
            "index": index,
            "request_id": request_id,
            "schema": GUARDIAN_APPROVAL_SCHEMA,
        }
        self.device.http.call(
            "POST", f"/recovery/requests/{request_id}/approvals", {"approval": approval}, auth=True
        )
        return {"index": index, "request_id": request_id, "subject": req["subject"]}


# ------------------------------------------------------------ new device


def _node_from(node_url: str | None, node_key: str | None):
    if not node_url or not node_key:
        raise ClientError("give an invite link, or the node URL and the node key fingerprint")
    return node_url, node_key


def start_guardian_recovery(
    home: str | Path,
    *,
    node_url: str | None = None,
    node_key: str | None = None,
    transport: Transport | None = None,
    browser: Browser | None = None,
    login_hint: str | None = None,
    email: str | None = None,
    email_code: Callable[[], str] | None = None,
    clock: Callable[[], float] | None = None,
) -> str:
    """Sign in with a temporary device key and send a recovery request. Return the
    request ID. Give it to your guardians. The node URL and key come from an
    invite link too (`anagram.admission.app.join.node_of`)."""
    home = Path(home)
    if (home / "config.json").exists():
        raise ClientError(f"{home} already has Anagram data; use an empty --home")
    url, fp = _node_from(node_url, node_key)
    node = HttpNode(url, transport)
    trust = fetch_trust(node, fp)
    pending = home / PENDING_DIR
    pending.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(pending, 0o700)
    ks = open_keystore(pending)
    key = SigningKey.from_seed(ks.get_or_create("temp-ed25519", lambda: secrets.token_bytes(32)))
    xkey = X25519Key.from_private_bytes(
        ks.get_or_create("temp-x25519", lambda: X25519Key.generate().private_bytes())
    )
    now = datetime.fromtimestamp(int(clock() if clock else datetime.now(UTC).timestamp()), UTC)
    via = SignInWith(browser=browser, login_hint=login_hint, email=email, email_code=email_code)
    assertion, signed = sign_in(node, trust, fp, key.public_bytes(), via, now=now)
    subject = assertion["subject"]
    node.token = signed["session"]["token"]
    device = device_json(key.public_bytes(), xkey.public_bytes())
    request = make_recovery_request(
        subject=subject,
        device=device,
        assertion=assertion,
        pop=sign_possession(subject, device, key),
        created_at=now,
    )
    rid = node.call("POST", "/recovery/requests", {"request": request}, auth=True)["request_id"]
    if rid != recovery_request_id(request):
        raise LogMisbehaved("node gave a wrong request ID")
    state = {"node_key": fp, "node_url": url, "request_id": rid, "subject": subject}
    write_private(pending / "state.json", json.dumps(state) + "\n")
    write_session(ks, signed["session"])
    return rid


def pending_recovery(home: str | Path) -> dict | None:
    p = Path(home) / PENDING_DIR / "state.json"
    return json.loads(p.read_text()) if p.exists() else None


def _collect_shares(
    approvals: list[dict],
    xkey,
    rid: bytes,
    subject: str,
    backup_id: str,
    k: int,
) -> list[tuple[int, bytes]]:
    shares: list[tuple[int, bytes]] = []
    seen: set[tuple[int, bytes]] = set()
    for a in approvals:
        try:
            validate_approval(a)
            ct = base64.b64decode(a["ciphertext"], validate=True)
            plain = hpke.open_sealed(xkey, ct, recovery_info(rid, a["index"]))
            share = validate_share(loads_canonical(plain))
        except (InvalidTag, CanonicalError, FormatError, ValueError, binascii.Error):
            continue  # a bad approval: skip it
        if (
            share["owner"] == subject
            and share["index"] == a["index"]
            and share["backup_id"] == backup_id
            and share["threshold"] == k
        ):
            pair = (share["index"], bytes.fromhex(share["share"]))
            if pair not in seen:
                seen.add(pair)
                shares.append(pair)
    return shares


def _combine_shares(shares: list[tuple[int, bytes]], k: int, backup_id: str) -> bytes | None:
    for combo in itertools.combinations(shares, k):
        if len({idx for idx, _ in combo}) < k:
            continue
        try:
            candidate = shamir.combine(list(combo), k)
        except ValueError:
            continue
        if derive_backup_id(candidate) == backup_id:
            return candidate
    return None


def finish_guardian_recovery(
    home: str | Path,
    *,
    open_home: OpenHome,
    transport: Transport | None = None,
    clock: Callable[[], float] | None = None,
) -> Home:
    """With k guardian approvals, restore the keys. Raise ClientError if there are
    not enough approvals yet."""
    home = Path(home)
    state = pending_recovery(home)
    if state is None:
        raise ClientError("no recovery request on this device; start one first")
    pending = home / PENDING_DIR
    ks = open_keystore(pending)
    session = read_session(ks)
    if session is None:
        raise ClientError("the recovery request on this device has no session; start again")
    node = HttpNode(state["node_url"], transport, token=session["token"])
    trust = fetch_trust(node, state["node_key"])
    subject = validate_subject(state["subject"])
    try:
        info = node.call("GET", f"/recovery/requests/{state['request_id']}", auth=True)
    except NodeHTTPError as exc:
        if exc.status == 404:
            raise ClientError(
                "the node has no such request (requests end after 7 days); start again"
            ) from exc
        raise
    k = info["threshold"]
    if k is None:
        raise ClientError("the guardian set changed after the request; start again")
    approvals = info["approvals"]
    if len(approvals) < k:
        raise ClientError(f"{len(approvals)} of {k} guardian approvals so far; ask your guardians")
    raw_xkey = ks.get("temp-x25519")
    if raw_xkey is None:
        raise ClientError("the recovery request on this device has no temporary key; start again")
    xkey = hpke.private_from_bytes(raw_xkey)
    shares = _collect_shares(
        approvals, xkey, bytes.fromhex(state["request_id"]), subject, info["backup_id"], k
    )
    secret = _combine_shares(shares, k, info["backup_id"])
    if secret is None:
        raise ClientError(f"the approvals do not give the secret (need {k} valid shares)")
    doc = node.call("GET", f"/recovery/backup/{info['backup_id']}")
    try:
        keys = open_backup(secret, doc)
    except FormatError as exc:
        raise ClientError(str(exc)) from exc
    if doc["subject"] != subject:
        raise ClientError("backup is for another person")
    # restore_keys signs in with the restored device key (a new session).
    client = restore_keys(
        home, node, trust, state["node_key"], subject, keys, open_home=open_home, clock=clock
    )
    destroy_keystore(pending)
    shutil.rmtree(pending)
    return client
