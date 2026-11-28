"""Join by invite in the app (layer L4; spec/admission.md).

- `join`: join a community from a node invite link or a lab invite link. It
  signs in with the invite (L1 `sign_in`), claims a node invite (and checks
  the receipt), or sends the lab join request.
- `invite_preview`, `node_of`: read a link before the join.
- `GroupInvites`: the lab invites of `Client.admission` (make, revoke,
  check, and use a lab invite link). They use the verified roster
  (`LabRoster`) and the lab keys (`LabKeys`) of L3.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from anagram.admission.formats import (
    DEFAULT_INVITE_DAYS,
    MAX_INVITE_DAYS,
    MAX_INVITE_USES,
    invite_keys,
    lab_invite_id,
    lab_invite_url,
    make_join_request,
    make_lab_invite,
    parse_invite_url,
    parse_lab_invite_link,
    sign_lab_invite_signin,
    verify_invite,
    verify_receipt,
)
from anagram.core.crypto.x25519 import X25519Key
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import HttpNode, NodeHTTPError, Transport
from anagram.core.timefmt import parse_time
from anagram.identity.api import (
    DEVICE_ED25519,
    DEVICE_X25519,
    VAULT_KEY,
    Browser,
    Device,
    Directory,
    Home,
    JoinResult,
    Keystore,
    SignInWith,
    bind_this_device,
    config_from_trust,
    device_sign_in,
    fetch_trust,
    finish_join,
    new_person,
    open_keystore,
    remember_person,
    sign_in,
    write_config,
    write_session,
)
from anagram.network.api import (
    ADMIN,
    CLOCK_SKEW,
    MEMBER,
    RETRIES,
    LabError,
    LabKeys,
    LabRoster,
    LabState,
    invite_device,
    invite_recipient,
    make_roster_entry,
)


def node_of(invite_link: str) -> dict:
    """`{"node_url", "node_key"}` of a node invite link (for a recovery on a
    new computer)."""
    invite = parse_invite_url(invite_link)
    return {"node_key": invite["node_key"], "node_url": invite["node_url"]}


def invite_preview(invite_link: str, transport: Transport | None = None) -> dict:
    """What the join screen asks for: `{"contact": "email" | "orcid" | None,
    "email_hint"}`. A lab invite has no contact. The node pin is not checked
    here: this is a hint for the screen, and the join checks it."""
    try:
        invite = parse_invite_url(invite_link)
    except FormatError:
        return {"contact": None, "email_hint": None}
    node = HttpNode(invite["node_url"], transport)
    return node.call("POST", "/auth/invite/preview", {"invite": invite["token"]})


class JoinHome(Home, Protocol):
    """An opened home, as `join` uses it: the sign-in parts and the lab
    invites (`GroupInvites`)."""

    admission: GroupInvites


def _read_invite(invite_link: str) -> tuple[dict, dict | None]:
    """The auth invite and the lab invite link (None for a node invite) of an
    invite link."""
    try:
        return parse_invite_url(invite_link), None
    except FormatError:
        # A lab invite link: the creator device signed it, not
        # the node. The node pin is the same; the lab join replaces the claim.
        lab_link = parse_lab_invite_link(invite_link)
        return lab_link["auth"], lab_link


def _home_config(home: Path, trust: dict, node_key: str) -> dict:
    """The config of the home. Make it from the trust if it does not exist.
    A home of another node is an error."""
    if (home / "config.json").exists():
        cfg = json.loads((home / "config.json").read_text())
        if cfg.get("identity", {}).get("node_key") != node_key:
            raise ClientError(f"{home} already belongs to another node; use another --home")
        return cfg
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)
    cfg = config_from_trust(trust, node_key, None)
    write_config(home, cfg)
    return cfg


def _device_keystore(home: Path) -> Keystore:
    """The keystore of the home, with the device keys and the vault key."""
    ks = open_keystore(home)
    ks.get_or_create(DEVICE_ED25519, lambda: secrets.token_bytes(32))
    ks.get_or_create(DEVICE_X25519, lambda: X25519Key.generate().private_bytes())
    ks.get_or_create(VAULT_KEY, lambda: secrets.token_bytes(32))
    return ks


def _claim_invite(node: HttpNode, trust: dict, token: str, subject: str) -> dict:
    """Claim a node invite and check the receipt of the node."""
    receipt = node.call("POST", "/invites/claim", {"token": token}, auth=True)
    try:
        verify_receipt(receipt, bytes.fromhex(trust["assertion_key"]), subject)
    except FormatError as exc:
        raise ClientError(str(exc)) from exc
    return receipt


def _join_sign_in(
    client: JoinHome,
    node: HttpNode,
    trust: dict,
    cfg: dict,
    ks: Keystore,
    invite: dict,
    lab_link: dict | None,
    *,
    method: str,
    now: datetime,
    browser: Browser | None,
    login_hint: str | None,
    email: str | None,
    email_code: Callable[[], str] | None,
    stated_email: str | None,
    on_code_sent: Callable[[str], None] | None,
) -> tuple[str, dict | None]:
    """Authenticate for `join`: use device sign-in if this device is already
    bound, else sign in via invite / email / ORCID."""
    dev_key = client.device.device_key()
    me = dev_key.public_bytes()
    existing_subject = cfg["identity"].get("subject")
    if method == "invite" and existing_subject:
        state = client.directory.lookup(existing_subject, allow_empty=True)
        if me.hex() in state.devices:
            session = device_sign_in(node, existing_subject, dev_key, invite["node_key"])
            write_session(ks, session)
            node.token = session["token"]
            return existing_subject, None
    invite_ref = None
    sign_invite = None
    if method == "invite":
        if lab_link is not None:
            invite_ref = "lab:" + lab_invite_id(invite)
            inv_sign_key, _ = invite_keys(bytes.fromhex(lab_link["seed"]))

            def sign_invite(inv: str, dk: str, nonce: str) -> str:
                return sign_lab_invite_signin(inv, dk, nonce, inv_sign_key)
        else:
            invite_ref = invite["token"]
    via = SignInWith(
        browser=browser,
        login_hint=login_hint,
        email=email,
        email_code=email_code,
        invite=invite_ref,
        stated_email=stated_email,
        on_code_sent=on_code_sent,
        device_key=dev_key if method == "invite" else None,
        sign_invite=sign_invite,
    )
    assertion, signed = sign_in(
        node,
        trust,
        invite["node_key"],
        me,
        via,
        now=now,
        person={"pid": existing_subject} if existing_subject else new_person(),
    )
    subject = assertion["subject"]
    if existing_subject not in (None, subject):
        node.token = signed["session"]["token"]
        try:
            node.call("POST", "/auth/logout", {}, auth=True)
        finally:
            node.token = None
            client.device.vault.close()
        raise ClientError("this home belongs to another person")
    write_session(ks, signed["session"])
    node.token = signed["session"]["token"]
    remember_person(cfg, assertion, signed)
    client.device.save_config(cfg)
    return subject, assertion


def join(
    home: str | Path,
    invite_link: str,
    *,
    open_home: Callable[[Path, HttpNode, Callable[[], float] | None], JoinHome],
    transport: Transport | None = None,
    browser: Browser | None = None,
    login_hint: str | None = None,
    email: str | None = None,
    email_code: Callable[[], str] | None = None,
    display_name: str | None = None,
    institution: str | None = None,
    reset: bool = False,
    clock: Callable[[], float] | None = None,
    method: str | None = None,
    stated_email: str | None = None,
    on_code_sent: Callable[[str], None] | None = None,
) -> JoinResult:
    """Join a community from an invite link. Safe to run again on the same home
    (for example after an existing device approved this one).

    `method`: "invite" (the main path: the invite is the proof, no ORCID
    and no email code), "orcid", or "email". Default: "email" with `email`,
    "orcid" with `browser` or `login_hint`, else "invite". `stated_email`: the
    address that the person gives with the invite method. `open_home`: the
    opener of the composition root (`Client.open`)."""
    if method is None:
        method = "email" if email else ("orcid" if browser or login_hint else "invite")
    if method not in ("invite", "orcid", "email"):
        raise ClientError("join method must be invite, orcid, or email")
    home = Path(home)
    invite, lab_link = _read_invite(invite_link)
    now_ts = clock() if clock else datetime.now(UTC).timestamp()
    now = datetime.fromtimestamp(int(now_ts), UTC)
    if parse_time(invite["expires_at"]) < now:
        raise ClientError("this invite has expired; ask the organizer for a new one")
    node = HttpNode(invite["node_url"], transport)
    trust = fetch_trust(node, invite["node_key"])
    try:
        if lab_link is None:
            verify_invite(invite, trust)
    except FormatError as exc:
        raise ClientError(str(exc)) from exc

    cfg = _home_config(home, trust, invite["node_key"])
    ks = _device_keystore(home)
    client = open_home(home, node, clock)
    if lab_link is not None:
        client.admission.check_lab_invite(invite)  # the creator device, with log proofs
    subject, assertion = _join_sign_in(
        client,
        node,
        trust,
        cfg,
        ks,
        invite,
        lab_link,
        method=method,
        now=now,
        browser=browser,
        login_hint=login_hint,
        email=email,
        email_code=email_code,
        stated_email=stated_email,
        on_code_sent=on_code_sent,
    )

    if lab_link is None:
        receipt = _claim_invite(node, trust, invite["token"], subject)
    else:
        # The first lab join request makes the person a node member; the node
        # answers `bind_device` until this device is bound. No receipt.
        receipt = None
        client.admission.lab_join(invite_link, bind_ok=True)

    bound = bind_this_device(client, subject, assertion, reset)
    if bound is None:
        return JoinResult(
            "pending_device",
            client,
            subject,
            receipt,
            device_request=client.account.device_request(),
        )
    if not bound:
        # An active device (an existing device approved it): take the person
        # keys and the personal store before the new recovery kit.
        client.personal.adopt_person_keys()
    lab_id = client.admission.lab_join(invite_link)["lab_id"] if lab_link is not None else None
    return finish_join(
        client, subject, assertion, receipt, display_name, institution, "joined", lab_id
    )


class GroupInvites:
    """Lab invites on this computer: make, revoke, check, and use a lab
    invite link. They use the verified roster and the lab keys (L3)."""

    def __init__(
        self, device: Device, directory: Directory, roster: LabRoster, keys: LabKeys
    ) -> None:
        self.device = device
        self.directory = directory
        self.roster = roster
        self.keys = keys

    # ------------------------------------------------------------ invites

    def lab_invite(
        self,
        lab_id: str,
        role: str = MEMBER,
        max_uses: int = 1,
        expires_days: float = DEFAULT_INVITE_DAYS,
    ) -> dict:
        """Make an invite link (PI or admin; PI only for role admin). The
        link holds the seed; the node gets the public authorisation only.
        Return {"invite_id", "url", "expires_at"}. Show `url` one time."""
        lab_id = self.roster.check_lab_id(lab_id)
        if role not in (ADMIN, MEMBER):
            raise LabError("An invite is for the role admin or member.")
        if isinstance(max_uses, bool) or not isinstance(max_uses, int):
            raise LabError(f"An invite link is for 1 to {MAX_INVITE_USES} people.")
        if not 1 <= max_uses <= MAX_INVITE_USES:
            raise LabError(f"An invite link is for 1 to {MAX_INVITE_USES} people.")
        if not isinstance(expires_days, int | float) or not 0 < expires_days <= MAX_INVITE_DAYS:
            raise LabError(f"An invite link is valid for at most {MAX_INVITE_DAYS} days.")
        ident = self.device.identity_config()
        for _ in range(RETRIES):
            state = self.roster.lab_state(lab_id)
            if not state.can(self.device.subject, "invite", role):
                raise LabError("Your role in this lab does not permit this.")
            seed = secrets.token_bytes(32)
            now = self.device.now()
            auth = make_lab_invite(
                seed=seed,
                node_url=self.device.config["node"]["url"],
                node_key=ident["node_key"],
                community=ident["community"],
                lab_id=lab_id,
                lab_name=state.name,
                genesis=state.genesis,
                role=role,
                max_uses=max_uses,
                expires_at=now + timedelta(days=expires_days),
                created_by=self.device.subject,
                created_at=now,
                key=self.device.device_key(),
            )
            iid = lab_invite_id(auth)
            entry = make_roster_entry(
                state=state,
                op="invite",
                actor=self.device.subject,
                key=self.device.device_key(),
                at=now,
                invite=iid,
            )
            trial = state.copy()
            trial.apply(entry, lambda *_: True, {iid: auth})
            body = {"auth": auth, "entry": entry, "package": self._invite_package(state, iid, auth)}
            try:
                self.device.http.call("POST", f"/labs/{lab_id}/invites", body, auth=True)
            except NodeHTTPError as exc:
                if exc.status == 409:
                    continue
                raise
            self.roster.labcache.append(trial, [entry], {iid: auth})
            return {
                "expires_at": auth["expires_at"],
                "invite_id": iid,
                "url": lab_invite_url(auth, seed),
            }
        raise LabError("The lab changed while you worked. Try again.")

    def _invite_package(self, state: LabState, iid: str, auth: dict) -> dict | None:
        """The keys of epochs 1 to now for the invite key (L3): a person who
        joins reads the lab space at once."""
        self.keys.pull_keys(state.lab_id, state)
        keys = self.keys.epoch_keys(state.lab_id)
        if not keys:
            return None
        return self.keys.package(
            state,
            max(keys),
            keys,
            invite_recipient(iid),
            [invite_device(auth)],
            self.roster.labcache.epoch_seq(state.lab_id),
        )

    def lab_revoke_invite(self, lab_id: str, invite_id: str) -> None:
        """Close an invite link. A person who joined with it stays (remove
        the person to end the access)."""
        self.roster.submit(lab_id, "revoke_invite", invite=invite_id)

    def check_lab_invite(self, auth: dict) -> None:
        """The creator device of a lab invite is a device of its creator (log
        proofs). This works before sign-in (`GET /directory` needs no
        session). The roster check after the join checks the rest."""
        try:
            windows = self.directory.device_windows(auth["created_by"])
        except LogMisbehaved:
            raise
        except ClientError as exc:
            raise LabError("This invite link is not from a member of this node.") from exc
        at = parse_time(auth["created_at"])
        if not any(
            d == auth["creator_device"] and start - CLOCK_SKEW <= at and (end is None or at < end)
            for d, start, end in windows
        ):
            raise LabError("This invite link is not from a member of this node.")

    def lab_join(self, url: str, bind_ok: bool = False) -> dict:
        """Join a lab with an invite link. Return {"lab_id", "name", "role"}.
        A person who is not a node member yet becomes one with the first
        request; the node then asks for a bound device (`bind_ok`: the join
        flow binds it and calls again). Safe to run again."""
        try:
            link = parse_lab_invite_link(url)
        except FormatError as exc:
            raise LabError("This is not a lab invite link. Copy the full link.") from exc
        auth, seed = link["auth"], bytes.fromhex(link["seed"])
        if auth["node_key"] != self.device.identity_config().get("node_key"):
            raise LabError("This invite link is for another node.")
        lab_id = auth["lab_id"]
        request = make_join_request(
            auth=auth,
            seed=seed,
            subject=self.device.subject,
            device_key=self.device.device_key(),
            at=self.device.now(),
        )
        try:
            out = self.device.http.call(
                "POST", f"/labs/{lab_id}/join", {"request": request}, auth=True
            )
        except NodeHTTPError as exc:
            if exc.status == 409:
                raise LabError(
                    "This invite link was used. Ask the person who sent it for a new link."
                ) from exc
            if exc.status in (404, 410):
                raise LabError("This invite link is no longer valid. Ask for a new link.") from exc
            raise
        if out.get("status") == "bind_device":
            if bind_ok:
                return {"lab_id": lab_id, "name": auth["lab_name"], "role": None}
            raise LabError("Finish the sign-in on this computer, then open the link again.")
        state = self.roster.lab_state(lab_id)
        if state.genesis != auth["genesis"] or self.device.subject not in state.members:
            raise LogMisbehaved("the lab roster of the node does not match the invite")
        self._after_join(state, auth, seed)
        return {"lab_id": lab_id, "name": state.name, "role": state.members[self.device.subject]}

    def _after_join(self, state: LabState, auth: dict, seed: bytes) -> None:
        """Open the key package of the invite with the key from the seed."""
        iid = lab_invite_id(auth)
        pkg = self.device.http.call("GET", f"/labs/invites/{iid}", auth=True).get("package")
        if pkg is None:
            self.keys.pull_keys(state.lab_id, state)  # a package for me, if one exists
            return
        if not isinstance(pkg, dict) or pkg.get("recipient") != invite_recipient(iid):
            raise LogMisbehaved("the node gave the key package of another invite")
        _, kem = invite_keys(seed)
        keys = self.keys.open_package(state, pkg, auth["invite_pub"], kem)
        self.keys.keep_lab_keys(state.lab_id, keys, pkg["roster_seq"])
        self.keys.pull_keys(state.lab_id, state)
