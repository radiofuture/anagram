"""Sign-in with ORCID on the node (layer L1): the OAuth flow with PKCE and a
one-time code to the loopback URL of the client (or out of band), and the
link of an ORCID iD to a member (purpose `link`)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING

from anagram.core.crypto.hashing import SALT_LEN
from anagram.core.errors import Conflict, Forbidden, FormatError, NodeError, Unauthorized
from anagram.identity.formats.documents import is_subject, orcid_commitment, validate_orcid
from anagram.identity.node.challenges import MAX_ATTEMPTS, secret_hash
from anagram.identity.node.checks import (
    NOT_A_MEMBER,
    check_device_nonce,
    person_salt,
    sign_in_purpose,
)
from anagram.identity.node.orcid import FakeOrcid, OrcidAdapter, OrcidError
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService

FLOW_TTL = 600
OOB = "urn:anagram:oob"
# The words of a sign-in that the device key or the kit must do.
USE_DEVICE = "Sign in on a computer where you use Anagram, or restore with your recovery kit."


def _b64url_sha256(text: str) -> str:
    d = hashlib.sha256(text.encode()).digest()
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def check_return_to(url: str) -> str:
    """The node sends the one-time code only to a loopback URL or out of band."""
    if url == OOB:
        return url
    p = urllib.parse.urlsplit(url)
    if p.scheme != "http" or p.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise NodeError("return_to must be an http loopback URL or " + OOB)
    if p.query or p.fragment:
        raise NodeError("return_to must not have a query or fragment")
    return url


def _check_start(code_challenge, pid, orcid_salt) -> None:
    if not isinstance(code_challenge, str) or len(code_challenge) != 43:
        raise NodeError("code_challenge must be base64url SHA-256 (43 chars)")
    if pid is not None and not is_subject(pid):
        raise NodeError("pid must be pid:<32 hex>")
    if orcid_salt is not None and (
        not isinstance(orcid_salt, str) or len(orcid_salt) != 2 * SALT_LEN
    ):
        raise NodeError("orcid_salt must be 32 bytes hex")


@dataclass(frozen=True)
class FlowStart:
    """The fields of a request to start an ORCID flow. `pid` and `orcid_salt`
    (optional): the person ID and the 32-byte ORCID salt that a new person
    made. The node uses them only when it makes a new account (first join)."""

    device_key: str
    nonce: str
    code_challenge: str
    return_to: str
    login_hint: str | None = None
    purpose: str | None = None
    pid: str | None = None
    orcid_salt: str | None = None


class OrcidSignIn:
    """The ORCID flow (table `flows`) and the ORCID accounts that it makes."""

    def __init__(self, identity: IdentityService, orcid: OrcidAdapter) -> None:
        self.identity = identity
        self.orcid = orcid

    @property
    def method(self) -> str:
        return {"fake": "orcid-fake", "sandbox": "orcid-sandbox"}.get(self.orcid.mode, "orcid")

    def start(self, req: FlowStart, link_subject: str | None = None) -> dict:
        """Start a flow. Purpose `link`: `link_subject` is the member of
        the session that links an ORCID iD; `req.orcid_salt` is the new salt."""
        purpose = sign_in_purpose(req.purpose)
        if purpose == "link":
            if link_subject is None:
                raise Unauthorized("sign in first")
            self.identity.require_member(link_subject)
        elif link_subject is not None:
            raise NodeError("only a link flow has a member")
        check_device_nonce(req.device_key, req.nonce)
        check_return_to(req.return_to)
        _check_start(req.code_challenge, req.pid, req.orcid_salt)
        flow_id = secrets.token_urlsafe(24)
        self.identity.db.execute(
            "INSERT INTO flows (id, device_key, nonce, code_challenge, return_to, expires_at,"
            " purpose, pid, orcid_salt, link_subject) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                flow_id,
                req.device_key,
                req.nonce,
                req.code_challenge,
                req.return_to,
                self.identity.now() + FLOW_TTL,
                purpose,
                req.pid,
                req.orcid_salt,
                link_subject,
            ),
        )
        hint = req.login_hint if isinstance(self.orcid, FakeOrcid) else None
        url = self.orcid.authorize_url(flow_id, self.identity.cfg.callback_url, hint)
        return {"authorize_url": url, "flow_id": flow_id}

    def callback(self, state: str, code: str) -> tuple[str, str | None]:
        """Return (redirect URL, one-time code). The redirect URL is the client's
        loopback URL, or None for out of band (show the code on a page)."""
        db = self.identity.db
        with self.identity.lock:
            row = one(db, "SELECT return_to, expires_at, orcid FROM flows WHERE id = ?", state)
            if row is None or row[1] < self.identity.now() or row[2] is not None:
                raise NodeError("sign-in flow is unknown, used, or expired")
            try:
                user = self.orcid.exchange(code, self.identity.cfg.callback_url)
                orcid = validate_orcid(user.orcid)
            except (OrcidError, FormatError) as exc:
                raise Unauthorized(str(exc)) from exc
            one_time = secrets.token_urlsafe(24)
            db.execute(
                "UPDATE flows SET orcid = ?, name = ?, code_hash = ? WHERE id = ?",
                (orcid, user.name, secret_hash("flow", state, one_time), state),
            )
        if row[0] == OOB:
            return "", one_time
        q = urllib.parse.urlencode({"code": one_time, "state": state})
        return f"{row[0]}?{q}", one_time

    def exchange(self, flow_id: str, code: str, code_verifier: str) -> dict:
        idt = self.identity
        with idt.lock:
            flow = self._use_flow(flow_id, code, code_verifier)
            device, nonce, orcid, name, purpose = (flow[k] for k in (0, 1, 4, 5, 9))
            acct = idt.orcid_account(orcid)
            if purpose == "link":
                return self._link(flow[12], orcid, flow[11], acct)
            if acct is not None and acct["linked"]:
                # A linked iD is not in the key directory, so it cannot make an
                # assertion that binds a device.
                raise Forbidden(USE_DEVICE)
            if purpose == "login":
                if acct is None:  # no account is made for a login
                    raise Forbidden(NOT_A_MEMBER)
                idt.check_login(acct["subject"], device)
            elif acct is None:
                acct = self._new_account(orcid, flow[10], flow[11])
            subject = acct["subject"]
            return {
                "assertion": idt.assertion(subject, acct["commitment"], self.method, device, nonce),
                # Only for this device. It is not in the assertion (the log).
                "profile": {"name": name, "orcid": orcid, "orcid_salt": acct["salt"]},
                "session": idt.new_session(subject, self.method, device),
            }

    def _use_flow(self, flow_id: str, code: str, code_verifier: str) -> tuple:
        """Check the one-time code and the PKCE verifier and mark the flow as
        used. Return the row of the flow."""
        db = self.identity.db
        row = one(
            db,
            "SELECT device_key, nonce, code_challenge, expires_at, orcid, name, code_hash,"
            " attempts, used, purpose, pid, orcid_salt, link_subject FROM flows WHERE id = ?",
            flow_id,
        )
        if row is None:
            raise Unauthorized("unknown sign-in flow")
        challenge, expires, orcid, code_hash, attempts, used = (row[k] for k in (2, 3, 4, 6, 7, 8))
        if used or expires < self.identity.now() or attempts >= MAX_ATTEMPTS or orcid is None:
            raise Unauthorized("sign-in flow is used, expired, or not finished")
        db.execute("UPDATE flows SET attempts = attempts + 1 WHERE id = ?", (flow_id,))
        ok_code = hmac.compare_digest(code_hash, secret_hash("flow", flow_id, str(code)))
        ok_pkce = hmac.compare_digest(challenge, _b64url_sha256(str(code_verifier)))
        if not (ok_code and ok_pkce):
            raise Unauthorized("wrong one-time code or verifier")
        db.execute("UPDATE flows SET used = 1 WHERE id = ?", (flow_id,))
        return row

    def _new_account(self, orcid: str, pid: str | None, salt: str | None) -> dict:
        subject = self.identity.new_subject(pid)
        raw = person_salt(salt)
        self.identity.db.execute(
            "INSERT INTO orcid_accounts (orcid, subject, salt, commitment) VALUES (?, ?, ?, ?)",
            (orcid, subject, raw.hex(), orcid_commitment(orcid, raw)),
        )
        return self.identity.orcid_account(orcid)

    def _link(self, subject: str, orcid: str, salt: str | None, acct: dict | None) -> dict:
        """Link an ORCID iD to a member. The key directory does not
        change: the commitment of a subject never changes (spec/identity.md
        section 7, rule 6). The node keeps the iD in its private map."""
        idt = self.identity
        if acct is not None and acct["subject"] != subject:
            raise Conflict("This ORCID iD is linked to another member.")
        if acct is None:
            if idt.orcid_of(subject) is not None:
                raise Conflict("Your account has another ORCID iD.")
            raw = person_salt(salt)
            idt.db.execute(
                "INSERT INTO orcid_accounts (orcid, subject, salt, commitment, findable, linked)"
                " VALUES (?, ?, ?, ?, ?, 1)",
                (
                    orcid,
                    subject,
                    raw.hex(),
                    orcid_commitment(orcid, raw),
                    int(idt.findable(subject)),
                ),
            )
            acct = idt.orcid_account(orcid)
        return {
            "linked": True,
            "profile": {
                "orcid": orcid,
                "orcid_commitment": acct["commitment"],
                "orcid_salt": acct["salt"],
            },
        }
