"""Client identity: the sign-in at the node, the end of a join, and sign in
again (login). The browsers of the ORCID step are in `browsers.py`, the
recovery kit in `kit.py`, and the account of the person in `account.py`.

The main path needs no ORCID iD: the invite is the proof of a
person (`POST /auth/invite`), and sign in again uses the device key. ORCID
stays as an option: a join with ORCID, and "Link your ORCID iD".

Trust: the invite pins the fingerprint of the node log key. The client checks the
node trust document against it. All other node keys (witness, assertion) come
from that signed document. The client never sends a private key to the node.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from anagram.core.crypto.hashing import new_salt
from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import HttpNode, NodeHTTPError, Transport
from anagram.identity.app.browsers import Browser, LoopbackBrowser, pkce
from anagram.identity.app.device import CONFIG_SCHEMA, Device
from anagram.identity.app.directory import Directory
from anagram.identity.app.personal import PersonalStore
from anagram.identity.app.session import write_session
from anagram.identity.formats.documents import (
    check_orcid_opening,
    new_pid,
    sign_device_signin,
    sign_possession,
    validate_orcid,
    verify_assertion,
    verify_node_trust,
)

if TYPE_CHECKING:
    from anagram.identity.app.account import Account

# ------------------------------------------------------------- results


class Home(Protocol):
    """An opened home, as the sign-in functions of L1 use it. The composition
    root gives the opener (`OpenHome`, for example `Client.open`), so that L1
    does not make the composition."""

    device: Device
    directory: Directory
    account: Account
    personal: PersonalStore

    def close(self) -> None: ...


# Open a home with this node connection: (home, node, clock or None) -> Home.
OpenHome = Callable[[Path, HttpNode, Callable[[], float] | None], Home]


@dataclass
class JoinResult:
    status: str  # "joined", "signed_in" (login), or "pending_device"
    client: Home
    subject: str
    receipt: dict | None  # None for a login (no invite)
    device_request: str | None = None
    kit_path: Path | None = None  # only when the caller wrote the kit to a file
    recovery_code: str | None = None
    kit_text: str | None = None  # the new recovery kit; None if no kit was made


def fetch_trust(node: HttpNode, pinned_fp: str) -> dict:
    try:
        trust = node.call("GET", "/node/trust")
        verify_node_trust(trust, pinned_fp)
    except FormatError as exc:
        raise ClientError(f"node is not the node in the invite: {exc}") from exc
    if trust["node_url"].rstrip("/") != node.base_url:
        raise ClientError("node trust document names a different URL")
    return trust


def config_from_trust(trust: dict, node_key: str, subject: str | None) -> dict:
    return {
        "identity": {
            "assertion_key": trust["assertion_key"],
            "community": trust["community"],
            "node_key": node_key,
            "orcid_mode": trust["orcid_mode"],
            "subject": subject,
        },
        "node": {"mode": "http", "url": trust["node_url"]},
        "schema": CONFIG_SCHEMA,
        "trust": {
            "fake_anchor_keys": trust["fake_anchor_keys"],
            "log_keys": trust["log_keys"],
            "min_anchors": 1 if trust["fake_anchor_keys"] else 0,
            "witness_keys": trust["witness_keys"],
        },
    }


# --------------------------------------------------------------- sign-in


@dataclass(frozen=True)
class SignInWith:
    """How a person signs in. `invite`: the token of a node invite, or
    `lab:<invite id>`; `stated_email` is the address that the person gives. A
    reader invite asks for the email code (`email_code`) or for the ORCID step
    (`browser`). Else `email` with `email_code`, else the ORCID step with
    `browser` (default: the system browser) and `login_hint` (fake ORCID)."""

    browser: Browser | None = None
    login_hint: str | None = None
    email: str | None = None
    email_code: Callable[[], str] | None = None
    invite: str | None = None
    stated_email: str | None = None
    on_code_sent: Callable[[str], None] | None = None


def sign_in(
    node: HttpNode,
    trust: dict,
    node_key: str,
    me: bytes,
    via: SignInWith,
    *,
    now: datetime,
    purpose: str = "join",
    person: dict | None = None,
) -> tuple[dict, dict]:
    """Sign in at the node for the device key `me`. Return (checked assertion,
    node answer with the session and the private profile). The assertion is
    bound to `me` and a nonce. Purpose "login": the node answers only for a
    member (no invite). `person` ({"pid", "orcid_salt"}): the person ID and ORCID
    salt that this device made for a first join; the node uses them only for a
    new account."""
    nonce = secrets.token_hex(16)
    person = person or {}
    signed = _invite_answer(node, via, me, nonce, person) if via.invite else None
    if signed is not None:
        pass  # the invite answered
    elif via.email:
        signed = _email_answer(node, via, me, nonce, purpose, person)
    else:
        signed = _orcid_answer(node, via, me, nonce, purpose, person)
    return _check_answer(signed, trust, node_key, me, nonce, now), signed


def _invite_answer(
    node: HttpNode, via: SignInWith, me: bytes, nonce: str, person: dict
) -> dict | None:
    """The answer to a sign-in with an invite, or None if the invite asks for
    the ORCID step."""
    body = {"device_key": me.hex(), "invite": via.invite, "nonce": nonce}
    if person.get("pid"):
        body["pid"] = person["pid"]
    if via.stated_email:
        body["email"] = via.stated_email
    signed = node.call("POST", "/auth/invite", body)
    if signed.get("needs") == "email_code":
        if via.email_code is None:
            raise ClientError("this invite needs the code from the email")
        if via.on_code_sent is not None:
            via.on_code_sent(signed.get("email_hint") or "")
        return node.call(
            "POST",
            "/auth/email/verify",
            {"challenge_id": signed["challenge_id"], "code": via.email_code()},
        )
    if signed.get("needs") == "orcid":
        return None  # the owner named the person by ORCID iD: the ORCID step
    return signed


def _email_answer(
    node: HttpNode, via: SignInWith, me: bytes, nonce: str, purpose: str, person: dict
) -> dict:
    body = {"device_key": me.hex(), "email": via.email, "nonce": nonce, "purpose": purpose}
    if person.get("pid"):
        body["pid"] = person["pid"]
    start = node.call("POST", "/auth/email/start", body)
    if via.email_code is None:
        raise ClientError("email sign-in needs the code from the email")
    return node.call(
        "POST",
        "/auth/email/verify",
        {"challenge_id": start["challenge_id"], "code": via.email_code()},
    )


def _orcid_answer(
    node: HttpNode, via: SignInWith, me: bytes, nonce: str, purpose: str, person: dict
) -> dict:
    browser = via.browser or LoopbackBrowser()
    verifier, challenge = pkce()
    body = {
        "code_challenge": challenge,
        "device_key": me.hex(),
        "nonce": nonce,
        "purpose": purpose,
        "return_to": browser.return_to,
    }
    if via.login_hint:
        body["login_hint"] = via.login_hint
    for name in ("pid", "orcid_salt"):
        if person.get(name):
            body[name] = person[name]
    start = node.call("POST", "/auth/orcid/start", body)
    back = browser.open(start["authorize_url"])
    if back.get("state", start["flow_id"]) != start["flow_id"]:
        raise ClientError("sign-in answer is for another flow")
    return node.call(
        "POST",
        "/auth/orcid/exchange",
        {"code": back.get("code", ""), "code_verifier": verifier, "flow_id": start["flow_id"]},
    )


def _check_answer(
    signed: dict, trust: dict, node_key: str, me: bytes, nonce: str, now: datetime
) -> dict:
    """Check the assertion and the ORCID opening of a sign-in answer. Return
    the checked assertion."""
    try:
        assertion = verify_assertion(
            signed["assertion"],
            assertion_key=bytes.fromhex(trust["assertion_key"]),
            node_key=node_key,
            audience=me,
            nonce=nonce,
            now=now,
        )
    except FormatError as exc:
        raise ClientError(f"node sign-in answer is not valid: {exc}") from exc
    if trust["orcid_mode"] != "fake" and assertion["method"] == "orcid-fake":
        raise ClientError("node used fake ORCID but says it uses real ORCID")
    profile = signed.get("profile") or {}
    if assertion["orcid_commitment"] is not None:
        try:
            orcid = validate_orcid(profile.get("orcid"))
            salt = bytes.fromhex(profile.get("orcid_salt") or "")
        except (FormatError, ValueError) as exc:
            raise ClientError("node sign-in answer has no valid ORCID opening") from exc
        if not check_orcid_opening(assertion["orcid_commitment"], orcid, salt):
            raise ClientError("node ORCID commitment does not match the ORCID iD and salt")
    return assertion


def new_person() -> dict:
    """A person ID and an ORCID salt for a first join (the node keeps them only
    if this is a new account)."""
    return {"orcid_salt": new_salt().hex(), "pid": new_pid()}


def remember_person(cfg: dict, assertion: dict, signed: dict) -> None:
    """Keep the subject, the ORCID iD, and the ORCID salt (the opening of the
    public commitment) in the client config. Only this device sees them."""
    ident = cfg["identity"]
    ident["subject"] = assertion["subject"]
    profile = signed.get("profile") or {}
    ident["orcid"] = profile.get("orcid") if assertion["orcid_commitment"] else None
    ident["orcid_salt"] = profile.get("orcid_salt") if assertion["orcid_commitment"] else None
    ident["orcid_commitment"] = assertion["orcid_commitment"]
    if profile.get("name"):
        ident["profile_name"] = profile["name"]


def device_sign_in(node: HttpNode, subject: str, key, node_key: str) -> dict:
    """Get a session with an active device key (no ORCID or email step)."""
    start = node.call(
        "POST",
        "/auth/device/start",
        {"device_key": key.public_bytes().hex(), "subject": subject},
    )
    if start.get("node_key") != node_key:
        raise ClientError("device sign-in answer is from another node")
    sig = sign_device_signin(subject, start["challenge"], node_key, key)
    return node.call(
        "POST",
        "/auth/device/verify",
        {"challenge_id": start["challenge_id"], "signature": sig},
    )["session"]


def bind_this_device(client: Home, subject: str, assertion: dict, reset: bool) -> bool | None:
    """Bind this device if it is not active (key-binding rules: `add` for the
    first device, `reset` to replace all devices). Return True if it bound,
    False if the device was active, None if another device must approve it."""
    state = client.directory.lookup(subject, allow_empty=True)
    mine = client.device.my_device()
    did_bind = False
    if mine["ed25519"] not in state.devices:
        if state.devices and not reset:
            return None
        client.directory.bind(
            state,
            # Seq 0 is an `add`. Later, an assertion can only `reset` (rule 4).
            op="reset" if state.history else "add",
            device=mine,
            authority={"assertion": assertion},
            orcid_commitment=assertion["orcid_commitment"],
            pop=sign_possession(subject, mine, client.device.device_key()),
        )
        state = client.directory.lookup(subject)
        did_bind = True
    for d in state.devices.values():
        client.device.vault.expect_device(d)
    client.directory.monitor()
    return did_bind


def finish_join(
    client: Home,
    subject: str,
    assertion: dict,
    receipt: dict | None,
    display_name: str | None,
    institution: str | None,
    status: str,
    lab_id: str | None = None,
) -> JoinResult:
    """Sign the identity record for the current devices and make a new
    recovery kit (the kit holds this device key). The kit stays in the
    encrypted local vault until the person saved it; no kit file is written.
    `lab_id`: the lab of a lab invite; the record takes it if it has none."""
    # Keep the lab and institution of an existing record (for example when a
    # second device joins). The new record lists the current devices.
    old = client.device.http.call("GET", "/me", auth=True).get("identity") or {}
    profile_name = (client.device.config.get("identity") or {}).get("profile_name")
    client.account.set_identity(
        display_name or old.get("display_name") or profile_name or "Member",
        institution=institution or old.get("institution"),
        lab_id=old.get("lab_id") or lab_id,
    )
    kit = client.account.make_recovery_kit()
    client.account.keep_pending_kit(kit)
    return JoinResult(status, client, subject, receipt, recovery_code=kit.code, kit_text=kit.text)


# ----------------------------------------------------------------- login


def login(
    home: str | Path,
    *,
    open_home: OpenHome,
    transport: Transport | None = None,
    browser: Browser | None = None,
    login_hint: str | None = None,
    email: str | None = None,
    email_code: Callable[[], str] | None = None,
    reset: bool = False,
    clock: Callable[[], float] | None = None,
    method: str | None = None,
) -> JoinResult:
    """Sign in again without an invite. The home must hold the config of an
    earlier join or recovery: the node URL and the pinned node key fingerprint.
    The node answers only for a member whose device is active, or not bound yet
    (a new device then needs approval, or `reset`). Status "signed_in" or
    "pending_device".

    `method`: "device" (the device key of this computer; no ORCID and no
    email), "orcid", or "email". Default: "email" with `email`, "orcid" with
    `browser` or `login_hint`, else "device". `open_home`: the opener of
    the composition root (`Client.open`)."""
    if method is None:
        method = "email" if email else ("orcid" if browser or login_hint else "device")
    home = Path(home)
    if not (home / "config.json").exists():
        raise ClientError(f"{home} has no Anagram identity; join with an invite link first")
    cfg = json.loads((home / "config.json").read_text())
    ident = cfg.get("identity") or {}
    if not ident.get("node_key") or cfg.get("node", {}).get("mode") != "http":
        raise ClientError("this home is not joined to a community; join with an invite link")
    now_ts = clock() if clock else datetime.now(UTC).timestamp()
    now = datetime.fromtimestamp(int(now_ts), UTC)
    node = HttpNode(cfg["node"]["url"], transport)
    trust = fetch_trust(node, ident["node_key"])
    if trust["assertion_key"] != ident.get("assertion_key"):
        raise ClientError("node assertion key changed; this is not the node you joined")
    client = open_home(home, node, clock)
    me = client.device.device_key().public_bytes()
    if method == "device":
        return _device_login(client, node, ident)
    via = SignInWith(browser=browser, login_hint=login_hint, email=email, email_code=email_code)
    assertion, signed = sign_in(node, trust, ident["node_key"], me, via, now=now, purpose="login")
    subject = assertion["subject"]
    node.token = signed["session"]["token"]
    if ident.get("subject") not in (None, subject):
        node.call("POST", "/auth/logout", {}, auth=True)  # end the new session
        client.device.vault.close()
        raise ClientError("this home belongs to another person")
    write_session(client.device.keystore, signed["session"])
    if (
        ident.get("subject") is None
        or ident.get("orcid_commitment") != (assertion["orcid_commitment"])
    ):
        remember_person(cfg, assertion, signed)
        client.device.save_config(cfg)
    bound = bind_this_device(client, subject, assertion, reset)
    if bound is None:
        return JoinResult(
            "pending_device", client, subject, None, device_request=client.account.device_request()
        )
    if not bound:
        if client.personal.adopt_person_keys():
            # New person keys: the old recovery kit of this device is out of date.
            return finish_join(client, subject, assertion, None, None, None, "signed_in")
        return JoinResult("signed_in", client, subject, None)
    return finish_join(client, subject, assertion, None, None, None, "signed_in")


def _device_login(client: Home, node: HttpNode, ident: dict) -> JoinResult:
    """Sign in again with the device key of this computer."""
    subject = ident.get("subject")
    if not subject:
        client.device.vault.close()
        raise ClientError("this home has no person yet; join with an invite link")
    try:
        session = device_sign_in(node, subject, client.device.device_key(), ident["node_key"])
    except NodeHTTPError as exc:
        client.device.vault.close()
        if exc.status in (401, 403):
            raise ClientError(
                "the key of this computer is not active; restore with your recovery kit"
            ) from exc
        raise
    write_session(client.device.keystore, session)
    node.token = session["token"]
    for d in client.directory.lookup(subject).devices.values():
        client.device.vault.expect_device(d)
    client.directory.monitor()
    return JoinResult("signed_in", client, subject, None)
