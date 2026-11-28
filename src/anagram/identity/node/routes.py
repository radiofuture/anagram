"""Node routes of identity (layer L1; spec/identity.md).

Public (no session):

    GET  /node/trust                      signed trust document (pin by fingerprint)
    GET  /directory/{subject}             key bindings with inclusion proofs (subject is a
                                          pid; it does not identify the person)
    GET  /recovery/backup/{backup_id}     encrypted key backup (ciphertext)

Sign-in (the invite sign-in is admission, L4: `anagram.admission.node.routes`; the
ORCID pages are in `anagram.shell.node.orcid_pages`):

    POST /auth/orcid/start                {device_key, nonce, code_challenge, return_to,
                                           purpose?: join | login | link (link: member session)}
    POST /auth/orcid/exchange             {flow_id, code, code_verifier} -> assertion, session
    POST /auth/email/start                {email, device_key, nonce, purpose?}
    POST /auth/email/verify               {challenge_id, code} -> assertion, session
    POST /auth/device/start               {subject, device_key} -> challenge
    POST /auth/device/verify              {challenge_id, signature} -> session (active device)
    POST /auth/passkeys/login/options     {subject}
    POST /auth/passkeys/login/verify      {challenge_id, credential} -> session

Session (Authorization: Bearer <token>):

    POST /auth/passkeys/register/options, /auth/passkeys/register/verify
    POST /auth/logout                     end this session
    GET  /me                              PUT /me/identity {record}
    PUT  /me/findable {on}                "findable" (default off)
    GET  /resolve/orcid/{orcid}           pid of a findable member (rate limit, audit)
    GET  /resolve/email/{email}
    GET  /identity/{subject}
    PUT  /recovery/backup {backup}        DELETE /recovery/backup/{backup_id}
    GET  /members
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Body, Header

from anagram.core.http import bearer, field
from anagram.identity.node.orcid_signin import FlowStart

SubjectOf = Callable[[str | None], str]


def identity_router(
    identity,
    subject_of: SubjectOf,
    labs_of: Callable[[str], list[str]],
    invited_by: Callable[[str], object],
) -> APIRouter:
    """`identity` is the `IdentityService` (with its sign-in, lookup and
    backup parts). `labs_of(subject)` (L3) gives the labs of a person for
    `/me` and the identity record check; `invited_by(subject)` (L4) gives who
    vouched for the person."""
    router = APIRouter()

    @router.get("/node/trust")
    def trust() -> dict:
        return identity.trust

    @router.get("/directory/{subject}")
    def directory(subject: str) -> dict:
        return identity.directory(subject)

    @router.post("/auth/logout")
    def logout(authorization: str | None = Header(default=None)) -> dict:
        return identity.logout(bearer(authorization))

    _orcid_email_device_routes(router, identity, subject_of)
    _passkey_routes(router, identity.passkeys, subject_of)
    _member_routes(router, identity, subject_of, labs_of, invited_by)
    _people_and_backup_routes(router, identity.people, identity.backups, subject_of)
    return router


def _orcid_email_device_routes(router: APIRouter, identity, subject_of: SubjectOf) -> None:
    orcid, email, device = identity.orcid_signin, identity.email_signin, identity.device_signin

    @router.post("/auth/orcid/start")
    def orcid_start(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        link = subject_of(authorization) if body.get("purpose") == "link" else None
        req = FlowStart(
            field(body, "device_key"),
            field(body, "nonce"),
            field(body, "code_challenge"),
            field(body, "return_to"),
            body.get("login_hint"),
            body.get("purpose"),
            body.get("pid"),
            body.get("orcid_salt"),
        )
        return orcid.start(req, link)

    @router.post("/auth/orcid/exchange")
    def orcid_exchange(body: dict = Body(...)) -> dict:
        return orcid.exchange(
            field(body, "flow_id"), field(body, "code"), field(body, "code_verifier")
        )

    @router.post("/auth/email/start")
    def email_start(body: dict = Body(...)) -> dict:
        return email.start(
            field(body, "email"),
            field(body, "device_key"),
            field(body, "nonce"),
            body.get("purpose"),
            body.get("pid"),
        )

    @router.post("/auth/email/verify")
    def email_verify(body: dict = Body(...)) -> dict:
        return email.verify(field(body, "challenge_id"), field(body, "code"))

    @router.post("/auth/device/start")
    def device_start(body: dict = Body(...)) -> dict:
        return device.start(field(body, "subject"), field(body, "device_key"))

    @router.post("/auth/device/verify")
    def device_verify(body: dict = Body(...)) -> dict:
        return device.verify(field(body, "challenge_id"), field(body, "signature"))


def _passkey_routes(router: APIRouter, passkeys, subject_of: SubjectOf) -> None:
    @router.post("/auth/passkeys/register/options")
    def pk_reg_options(authorization: str | None = Header(default=None)) -> dict:
        return passkeys.register_options(subject_of(authorization))

    @router.post("/auth/passkeys/register/verify")
    def pk_reg_verify(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return passkeys.register_verify(
            subject_of(authorization), field(body, "challenge_id"), field(body, "credential")
        )

    @router.post("/auth/passkeys/login/options")
    def pk_login_options(body: dict = Body(...)) -> dict:
        return passkeys.login_options(field(body, "subject"))

    @router.post("/auth/passkeys/login/verify")
    def pk_login_verify(body: dict = Body(...)) -> dict:
        return passkeys.login_verify(field(body, "challenge_id"), field(body, "credential"))


def _member_routes(
    router: APIRouter,
    identity,
    subject_of: SubjectOf,
    labs_of: Callable[[str], list[str]],
    invited_by: Callable[[str], object],
) -> None:
    @router.get("/me")
    def me(authorization: str | None = Header(default=None)) -> dict:
        subject = subject_of(authorization)
        out = {
            **identity.me(subject),
            "invited_by": invited_by(subject),
            "labs": labs_of(subject),
        }
        return dict(sorted(out.items()))

    @router.put("/me/identity")
    def put_identity(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        subject = subject_of(authorization)
        return identity.put_identity(subject, field(body, "record"), labs=labs_of(subject))

    @router.get("/identity/{subject}")
    def get_identity(subject: str, authorization: str | None = Header(default=None)) -> dict:
        return identity.get_identity(subject_of(authorization), subject)

    @router.get("/members")
    def members(authorization: str | None = Header(default=None)) -> dict:
        return {"members": identity.members(subject_of(authorization))}


def _people_and_backup_routes(router: APIRouter, people, backups, subject_of: SubjectOf) -> None:
    @router.put("/me/findable")
    def put_findable(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return people.set_findable(subject_of(authorization), field(body, "on"))

    @router.get("/resolve/orcid/{orcid}")
    def resolve_orcid(orcid: str, authorization: str | None = Header(default=None)) -> dict:
        return people.resolve_orcid(subject_of(authorization), orcid)

    @router.get("/resolve/email/{email}")
    def resolve_email(email: str, authorization: str | None = Header(default=None)) -> dict:
        return people.resolve_email(subject_of(authorization), email)

    @router.get("/recovery/backup/{backup_id}")
    def get_backup(backup_id: str) -> dict:
        return backups.get(backup_id)

    @router.put("/recovery/backup")
    def put_backup(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return backups.put(subject_of(authorization), field(body, "backup"))

    @router.delete("/recovery/backup/{backup_id}")
    def delete_backup(backup_id: str, authorization: str | None = Header(default=None)) -> dict:
        return backups.delete(subject_of(authorization), backup_id)


def member_check(identity, subject_of: SubjectOf) -> Callable[..., str]:
    """A route dependency: the request has the session of a member."""

    def require_member(authorization: str | None = Header(default=None)) -> str:
        subject = subject_of(authorization)
        identity.require_member(subject)
        return subject

    return require_member
