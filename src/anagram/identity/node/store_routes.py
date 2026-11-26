"""Node routes of the personal store (layer L1; spec/vault.md section 11).
Member session; ciphertext only.

    GET  /store/records                   my record IDs, versions, sizes, quota
    PUT  /store/records/{record_id}       {record} (a newer version replaces)
    GET  /store/records/{record_id}       DELETE /store/records/{record_id}
    PUT  /store/person-keys/{device}      {package} (HPKE to my other device)
    GET  /store/person-keys/{device}
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Body, Header

from anagram.core.http import field


def store_router(store, subject_of: Callable[[str | None], str]) -> APIRouter:
    """`store` is the `NodePersonalStore`."""
    router = APIRouter()

    @router.get("/store/records")
    def store_list(authorization: str | None = Header(default=None)) -> dict:
        return store.list(subject_of(authorization))

    @router.put("/store/records/{record_id}")
    def store_put(
        record_id: str,
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return store.put(subject_of(authorization), record_id, field(body, "record"))

    @router.get("/store/records/{record_id}")
    def store_get(record_id: str, authorization: str | None = Header(default=None)) -> dict:
        return store.get(subject_of(authorization), record_id)

    @router.delete("/store/records/{record_id}")
    def store_delete(record_id: str, authorization: str | None = Header(default=None)) -> dict:
        return store.delete(subject_of(authorization), record_id)

    @router.put("/store/person-keys/{device}")
    def put_person_keys(
        device: str,
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return store.put_person_keys(subject_of(authorization), device, field(body, "package"))

    @router.get("/store/person-keys/{device}")
    def get_person_keys(device: str, authorization: str | None = Header(default=None)) -> dict:
        return store.get_person_keys(subject_of(authorization), device)

    return router
