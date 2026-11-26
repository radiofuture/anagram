"""The account of this person on the node, from the device (layer L1):
findability, the ORCID link, second devices, the identity record, the
session, and the recovery kit."""

from __future__ import annotations

import secrets
from pathlib import Path

from anagram.core.canonical import CanonicalError, canonical_json, loads
from anagram.core.crypto.hashing import TAG_SIGN_KEY_POSSESSION, new_salt
from anagram.core.crypto.signing import verify
from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.signed import b64url, unb64url
from anagram.identity.app.browsers import Browser, LoopbackBrowser, pkce
from anagram.identity.app.device import (
    DEVICE_ED25519,
    DEVICE_X25519,
    INDEX_KEY,
    VAULT_KEY,
    Device,
)
from anagram.identity.app.directory import Directory
from anagram.identity.app.kit import (
    RecoveryKit,
    kit_file_path,
    parse_kit,
    write_kit_file,
)
from anagram.identity.app.personal import PersonalStore
from anagram.identity.app.session import clear_session
from anagram.identity.formats.backup import encode_secret, new_recovery_secret, seal_backup
from anagram.identity.formats.documents import (
    check_orcid_opening,
    make_identity_record,
    possession_message,
    sign_possession,
    validate_orcid,
)

DEVICE_REQUEST_SCHEMA = "anagram.device_request.v1"


class Account:
    """The account of this person on the node (layer L1): findability, the
    ORCID link, second devices, the identity record, the session, and the
    recovery kit. It needs an HTTP node."""

    def __init__(self, device: Device, directory: Directory, personal: PersonalStore) -> None:
        self.device = device
        self.directory = directory
        self.personal = personal

    def set_findable(self, on: bool) -> dict:
        """Turn "findable by ORCID" on or off (default off)."""
        return self.device.http.call("PUT", "/me/findable", {"on": bool(on)}, auth=True)

    @property
    def orcid(self) -> str | None:
        """My ORCID iD (from the sign-in or a link; never in the log). None
        when the person has none: that is normal."""
        return self.device.config.get("identity", {}).get("orcid")

    def link_orcid(self, browser: Browser | None = None, login_hint: str | None = None) -> str:
        """Link an ORCID iD to this account (optional). The node proves
        the iD with ORCID and keeps it in its private map. The key directory
        does not change. This device keeps the iD and the opening (salt) of
        the link commitment, and the personal store keeps a copy."""
        browser = browser or LoopbackBrowser()
        verifier, challenge = pkce()
        salt = new_salt().hex()
        body = {
            "code_challenge": challenge,
            "device_key": self.device.device_key().public_bytes().hex(),
            "nonce": secrets.token_hex(16),
            "orcid_salt": salt,
            "purpose": "link",
            "return_to": browser.return_to,
        }
        if login_hint:
            body["login_hint"] = login_hint
        start = self.device.http.call("POST", "/auth/orcid/start", body, auth=True)
        back = browser.open(start["authorize_url"])
        if back.get("state", start["flow_id"]) != start["flow_id"]:
            raise ClientError("sign-in answer is for another flow")
        out = self.device.http.call(
            "POST",
            "/auth/orcid/exchange",
            {"code": back.get("code", ""), "code_verifier": verifier, "flow_id": start["flow_id"]},
        )
        profile = out.get("profile") or {}
        try:
            orcid = validate_orcid(profile.get("orcid"))
            got_salt = bytes.fromhex(profile.get("orcid_salt") or "")
        except (FormatError, ValueError) as exc:
            raise ClientError("the node answer has no valid ORCID iD") from exc
        commitment = profile.get("orcid_commitment") or ""
        if not out.get("linked") or not check_orcid_opening(commitment, orcid, got_salt):
            raise ClientError("the node ORCID link does not match the ORCID iD and salt")
        ident = self.device.identity_config()
        ident.update(
            {"orcid": orcid, "orcid_link_commitment": commitment, "orcid_salt": got_salt.hex()}
        )
        self.device.save_config()
        self.personal.auto_sync()
        return orcid

    # ------------------------------------------------------ second device

    def device_request(self) -> str:
        """A short text that an existing device uses to add this device."""
        dev = self.device.my_device()
        doc = {
            "device": dev,
            "pop": sign_possession(self.device.subject, dev, self.device.device_key()),
            "schema": DEVICE_REQUEST_SCHEMA,
            "subject": self.device.subject,
        }
        return b64url(canonical_json(doc))

    def add_device(self, request: str) -> dict:
        """Approve a new device of the same person (from its device request)."""

        try:
            doc = loads(unb64url(request.strip()))
            dev, pop = doc["device"], doc["pop"]
            ok = doc["schema"] == DEVICE_REQUEST_SCHEMA and verify(
                bytes.fromhex(dev["ed25519"]),
                TAG_SIGN_KEY_POSSESSION,
                possession_message(self.device.subject, dev),
                bytes.fromhex(pop),
            )
        except (CanonicalError, FormatError, KeyError, TypeError, ValueError) as exc:
            raise ClientError("device request is damaged") from exc
        if not ok or doc["subject"] != self.device.subject:
            raise ClientError("device request is not for this person or has a bad signature")
        state = self.directory.lookup(self.device.subject)
        mine = self.device.device_key().public_bytes().hex()
        entry = self.directory.bind(
            state,
            op="add",
            device=dev,
            authority={"device": mine},
            pop=pop,
            authority_key=self.device.device_key(),
        )
        self.device.vault.expect_device(dev)
        self.directory.monitor()
        # The new device gets the person keys (vault key, index key) by HPKE.
        try:
            self.personal.send_person_keys(dev)
        except NodeHTTPError as exc:
            if exc.status != 404:  # 404: this node has no personal store
                raise
        self.personal.auto_sync()
        return entry

    # ------------------------------------------------- identity and labs

    def set_identity(
        self, display_name: str, institution: str | None = None, lab_id: str | None = None
    ) -> dict:
        state = self.directory.lookup(self.device.subject)
        record = make_identity_record(
            subject=self.device.subject,
            display_name=display_name,
            institution=institution,
            lab_id=lab_id,
            devices=list(state.devices.values()),
            updated_at=self.device.now(),
            key=self.device.device_key(),
            orcid_commitment=state.orcid_commitment,
        )
        return self.device.http.call("PUT", "/me/identity", {"record": record}, auth=True)

    def logout(self) -> None:
        """End the session on the node and remove it from this device."""
        try:
            if self.device.http.token:
                self.device.http.call("POST", "/auth/logout", {}, auth=True)
        finally:
            clear_session(self.device.keystore)
            self.device.http.token = None

    def whoami(self) -> dict:
        info = self.device.http.call("GET", "/me", auth=True)
        info["node"] = self.device.config["node"]["url"]
        info["node_key"] = self.device.identity_config()["node_key"]
        info["this_device"] = self.device.my_device()
        return info

    # ---------------------------------------------------- recovery kit

    def make_recovery_kit(self) -> RecoveryKit:
        """Make a new recovery secret, store the encrypted key backup on the node,
        and return a printable kit. The node receives only ciphertext. This
        method writes no file."""
        secret = new_recovery_secret()
        keys = {
            DEVICE_ED25519: self.device.device_key().seed(),
            DEVICE_X25519: self.device.x25519_key().private_bytes(),
            VAULT_KEY: self.device.keystore.get(VAULT_KEY),
            INDEX_KEY: self.device.index_key(),
        }
        backup = seal_backup(secret, self.device.subject, keys)
        self.device.http.call("PUT", "/recovery/backup", {"backup": backup}, auth=True)
        code = encode_secret(secret)
        cfg = self.device.identity_config()
        text = (
            f"# Anagram recovery kit\n\n"
            f"Community: {cfg['community']}\n\n"
            "Print this page or keep it offline. With this kit you can restore your keys\n"
            "on a new computer: `anagram recover recovery-kit.md`. Anyone with this kit\n"
            "can do the same, so keep it safe. The community server cannot read your keys.\n\n"
            "```\n"
            f"Node: {self.device.config['node']['url']}\n"
            f"Node key: {cfg['node_key']}\n"
            f"Subject: {self.device.subject}\n"
            f"Recovery code: {code}\n"
            "```\n\n"
            f"Device key: {self.device.device_key().public_bytes().hex()}\n"
            f"Made: {self.device.now().strftime('%Y-%m-%d')}\n"
        )
        return RecoveryKit(text, code)

    def write_recovery_kit(self, path: str | Path) -> tuple[Path, str]:
        """Make a new recovery kit and write it to `path` (mode 0600). The
        path must be outside the data directory."""
        path = kit_file_path(self.device.home, path)
        kit = self.make_recovery_kit()
        return write_kit_file(self.device.home, path, kit.text), kit.code

    def keep_pending_kit(self, kit: RecoveryKit) -> None:
        """Keep the kit in the encrypted local vault until the person saved
        it. It is a device-local value: it does not go to the personal store."""
        self.device.keys.pending_kit.set("", kit.text)

    def pending_kit(self) -> RecoveryKit | None:
        text = self.device.keys.pending_kit.get()
        if text is None:
            return None
        return RecoveryKit(text, parse_kit(text)["recovery code"])

    def drop_pending_kit(self) -> None:
        self.device.keys.pending_kit.delete()
