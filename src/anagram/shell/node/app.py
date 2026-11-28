"""The node app (composition root). Each layer gives
its routes; `create_app` only composes them. The route lists are in the
router modules:

    proofs/node/routes.py         /log/*, /tile/* (proofs; public, except the submit)
    identity/node/routes.py    /node/trust, /directory, /auth/* sign-in, /me, /resolve,
                            /identity, /recovery/backup, /members (L1)
    shell/node/orcid_pages.py     /auth/orcid/callback, /fake-orcid/authorize (shell)
    shell/node/join_page.py       /join (shell)
    admission/node/routes.py        /auth/invite, /invites, lab invites and joins (L4)
    network/groups/node/routes.py        /labs/... (L3)
    network/matching/node/enclave_relay.py /enclave/... (relay to the matching enclave; member session)
    network/matching/node/credentials.py   /net/credential (member credentials; member session)
    network/matching/node/control.py       /net/control (the node's control chain; public)
    network/sharing/node/routes.py       /blobs, /grants, /public, /guardians, /recovery/requests (L3)
    network/sharing/node/reads.py           read receipts and the vault delete routes (L3)
    admission/node/reader.py     reader invites (L4)
    proofs/node/verify_page.py     /verify, /proofs (public verify page)
    identity/node/store_routes.py       /store/* (personal store, L1)
    shell/node/admin.py           /admin and its forms (organizers only)
    shell/node/admin_routes.py       /admin/api/* (labs, invites)
    shell/node/brand.py           /brand/*
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from anagram.admission.api import admission_router, reader_invites_router
from anagram.core.errors import NodeError
from anagram.core.http import bearer, field
from anagram.core.version import VERSION
from anagram.identity.api import identity_router, member_check, store_router
from anagram.network.api import (
    NodeEnclave,
    control_router,
    credential_router,
    enclave_router,
    lab_router,
    member_session,
    reads_router,
    vault_router,
)
from anagram.proofs.node.routes import log_router
from anagram.proofs.node.service import NodeService
from anagram.proofs.node.verify_page import verify_router
from anagram.shell import pages
from anagram.shell.node import join_page
from anagram.shell.node.admin import admin_router
from anagram.shell.node.admin_routes import admin_api_router
from anagram.shell.node.brand import mount_brand
from anagram.shell.node.orcid_pages import orcid_pages_router


def create_app(
    service: NodeService,
    public_keys: dict | None = None,
    identity=None,
    vault=None,
    anchoring=None,
    admin=None,
    store=None,
    labs=None,
    reads=None,
    reader_invites=None,
    verify=None,
    admission=None,
    enclave=None,
    enclave_parts: NodeEnclave | None = None,
) -> FastAPI:
    """Without `identity`, the node refuses all submissions (read-only log).
    `vault` (anagram.network.sharing.node.vault.NodeVault) needs `identity`. `admission` (L4,
    `anagram.admission.node.service.AdmissionService`, `NodeHome.admission`) is
    necessary with `identity`; the app does not make one. `enclave`
    (`anagram.network.matching.node.enclave_relay.EnclaveRelay`) adds the `/enclave/*` relay routes to
    the matching enclave behind member sign-in; the caller that makes the
    relay also runs its timer (`anagram.network.api.Ticker` on `relay.tick`).
    `enclave_parts` (`NodeEnclave`, node.json "enclave") gives the relay,
    the member credential routes and the control chain together."""
    app = FastAPI(title="Anagram node", version=VERSION)

    @app.exception_handler(NodeError)
    def identity_error(_: Request, exc: NodeError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    def subject_of(authorization: str | None) -> str:
        if identity is None:
            raise HTTPException(401, "this node has no member sessions")
        return identity.authenticate(bearer(authorization))

    submit = identity.submit if identity is not None else None
    app.include_router(log_router(service, subject_of, submit, public_keys, anchoring))
    if identity is None:
        return app
    if admission is None:
        raise TypeError("create_app: a node with `identity` needs `admission`")

    def labs_of(subject: str) -> list[str]:
        return labs.directory.labs_of(subject) if labs is not None else []

    join_page.register(app, identity)  # GET /join
    app.include_router(admission_router(admission, subject_of))
    app.include_router(identity_router(identity, subject_of, labs_of, admission.invited_by))
    app.include_router(orcid_pages_router(identity, admin))
    app.include_router(lab_router(labs, subject_of))
    _mount_enclave(app, identity, subject_of, enclave, enclave_parts)
    if vault is not None:
        app.include_router(vault_router(vault, subject_of))
    if reads is not None:  # read receipts, fetch events, grant and blob delete
        app.include_router(reads_router(reads, subject_of, field))
    if reader_invites is not None:  # invite a person who is not a member to read
        app.include_router(reader_invites_router(reader_invites, subject_of))
    if verify is not None:  # public verify page and published proofs
        app.include_router(verify_router(verify, subject_of, pages.HEADERS))
    if store is not None:
        app.include_router(store_router(store, subject_of))
    if admin is not None:
        app.include_router(admin_router(admin))
        app.include_router(admin_api_router(admin, labs))
    mount_brand(app)
    return app


def _mount_enclave(app: FastAPI, identity, subject_of, relay, parts: NodeEnclave | None) -> None:
    """The relay behind member sign-in; with `parts`, also the member
    credential routes and the public control chain."""
    if parts is not None:
        relay = parts.relay
        app.include_router(credential_router(parts.issuer, member_session(identity)))
        app.include_router(control_router(parts.chain))
    if relay is not None:
        member = Depends(member_check(identity, subject_of))
        app.include_router(enclave_router(relay), dependencies=[member])
