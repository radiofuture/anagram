"""Node routes of the vault (layer L3; spec/vault.md section 8). Member
session unless marked public.

    PUT  /blobs/{blob_id}                 raw ciphertext body (octet-stream)
    GET  /blobs/{blob_id}                 owner, grant recipient, or public (no session)
    POST /grants {grant}                  GET /grants (mine)     GET /grants/{grant_id}
    POST /public {release}                GET /public[?finding_id=] (public)
    GET  /public/{release_id}             public
    PUT  /guardians {set}                 GET /guardians (mine)  GET /guardians/shares
    POST /recovery/requests {request}     GET /recovery/requests (as guardian)
    GET  /recovery/requests/{id}          POST /recovery/requests/{id}/approvals {approval}

The read receipts and the delete routes are in `anagram.network.sharing.node.reads`.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from fastapi import APIRouter, Body, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse

from anagram.core.errors import NotFound
from anagram.core.http import field


def vault_router(vault, subject_of: Callable[[str | None], str]) -> APIRouter:
    """`vault` is the `NodeVault`."""
    router = APIRouter()

    @router.put("/blobs/{blob_id}")
    async def put_blob(
        blob_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict:
        subject = subject_of(authorization)
        vault.check_upload(subject, blob_id)
        temp = vault.temp_path(blob_id)
        size = 0
        try:
            with open(temp, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > vault.max_blob:
                        raise HTTPException(413, "blob is too large")
                    f.write(chunk)
            return vault.store_blob(subject, blob_id, temp)
        finally:
            if temp.exists():
                os.unlink(temp)

    @router.get("/blobs/{blob_id}")
    def get_blob(blob_id: str, authorization: str | None = Header(default=None)) -> Response:
        subject = subject_of(authorization) if authorization else None
        path = vault.blob_path(subject, blob_id)
        return FileResponse(path, media_type="application/octet-stream")

    @router.post("/grants")
    def post_grant(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return vault.put_grant(subject_of(authorization), field(body, "grant"))

    @router.get("/grants")
    def list_grants(authorization: str | None = Header(default=None)) -> dict:
        return {"grants": vault.grants_for(subject_of(authorization))}

    @router.get("/grants/{grant_id}")
    def get_grant(grant_id: str, authorization: str | None = Header(default=None)) -> dict:
        return vault.get_grant(subject_of(authorization), grant_id)

    @router.post("/public")
    def post_release(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return vault.put_release(subject_of(authorization), field(body, "release"))

    @router.get("/public")
    def list_releases(finding_id: str | None = None) -> dict:
        return {"releases": vault.list_releases(finding_id)}

    @router.get("/public/{release_id}")
    def get_release(release_id: str) -> dict:
        return vault.get_release(release_id)

    @router.put("/guardians")
    def put_guardians(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return vault.put_guardian_set(subject_of(authorization), field(body, "set"))

    @router.get("/guardians")
    def get_guardians(authorization: str | None = Header(default=None)) -> dict:
        return vault.my_guardian_set(subject_of(authorization))

    @router.get("/guardians/shares")
    def guardian_shares(authorization: str | None = Header(default=None)) -> dict:
        return {"shares": vault.shares_for(subject_of(authorization))}

    @router.post("/recovery/requests")
    def post_request(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return vault.create_request(subject_of(authorization), field(body, "request"))

    @router.get("/recovery/requests")
    def guardian_requests(authorization: str | None = Header(default=None)) -> dict:
        return {"requests": vault.requests_for_guardian(subject_of(authorization))}

    @router.get("/recovery/requests/{request_id}")
    def get_request(request_id: str, authorization: str | None = Header(default=None)) -> dict:
        subject = subject_of(authorization)
        try:
            return vault.get_request(subject, request_id)
        except NotFound:
            return vault.get_request_for_guardian(subject, request_id)

    @router.post("/recovery/requests/{request_id}/approvals")
    def post_approval(
        request_id: str,
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return vault.add_approval(subject_of(authorization), request_id, field(body, "approval"))

    return router
