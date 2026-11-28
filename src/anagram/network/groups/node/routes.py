"""Node routes of the lab unit. Member
session on each route (`Authorization: Bearer`).

    POST /labs                         {"entry": <create entry>}
    GET  /labs/{id}                    lab member: roster view; other: ID and name
    GET  /labs/{id}/roster?after=      {"entries", "invites", "head", "seq"}
    POST /labs/{id}/roster             {"entry"} -> {"seq", "head"}; 409 if stale
    GET  /labs/changes?after=&wait=    changes of my labs; `wait` 0..25 s (long poll)
    PUT  /labs/{id}/keys/{epoch}       {"packages"} -> {"epoch"} (PI, admin); 409 if the
                                       epoch is not current + 1, or a recipient has one
    GET  /labs/{id}/keys               {"epoch", "packages": mine, "current"?: PI, admin}
    PUT  /labs/{id}/space/records/{rid} {"record", "blobs"?, "drop"?,
                                       "topic"?: "space"|"settings"};
                                       409 old version; 413 quota; 403 suspended
    GET  /labs/{id}/space/records?after=&limit=  {"records", "next", "more"}
    GET  /labs/{id}/space/records/{rid} {"record", "author", "change"}

The invite and join routes (`/labs/{id}/invites`, `/labs/invites/{id}`,
`/labs/{id}/join`) are admission (L4): `anagram.admission.node.routes`.

`POST /labs/{id}/members` is removed: a member is added with a signed `add`
entry (`POST /labs/{id}/roster`).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Body, Header, HTTPException

from anagram.core.http import field


def lab_router(labs, subject_of: Callable[[str | None], str]) -> APIRouter:
    """`labs` is a `LabService`, or None (a node with no lab unit: each
    route gives 404)."""
    router = APIRouter()

    if labs is not None:  # before GET /labs/{lab_id}, which would take this path

        @router.get("/labs/changes")
        def changes(
            after: int = 0,
            wait: float = 0,
            authorization: str | None = Header(default=None),
        ) -> dict:
            return labs.changes(subject_of(authorization), after, wait)

    @router.post("/labs")
    def create_lab(
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        subject = subject_of(authorization)
        if labs is None:
            raise HTTPException(404, "this node has no lab unit")
        return labs.create(subject, field(body, "entry"))

    @router.get("/labs/{lab_id}")
    def get_lab(lab_id: str, authorization: str | None = Header(default=None)) -> dict:
        subject = subject_of(authorization)
        if labs is None:
            raise HTTPException(404, "this node has no lab unit")
        return labs.get_lab(subject, lab_id)

    if labs is None:
        return router

    @router.get("/labs/{lab_id}/roster")
    def roster(
        lab_id: str,
        after: int = -1,
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.roster(subject_of(authorization), lab_id, after)

    @router.post("/labs/{lab_id}/roster")
    def submit(
        lab_id: str,
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.submit_entry(subject_of(authorization), lab_id, field(body, "entry"))

    @router.put("/labs/{lab_id}/keys/{epoch}")
    def put_keys(
        lab_id: str,
        epoch: int,
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.put_keys(subject_of(authorization), lab_id, epoch, field(body, "packages"))

    @router.put("/labs/{lab_id}/space/records/{record_id}")
    def put_record(
        lab_id: str,
        record_id: str,
        body: dict = Body(...),
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.put_record(
            subject_of(authorization),
            lab_id,
            record_id,
            field(body, "record"),
            body.get("blobs"),
            body.get("topic") or "space",
            body.get("drop"),
        )

    @router.get("/labs/{lab_id}/space/records")
    def records(
        lab_id: str,
        after: int = 0,
        limit: int = 200,
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.records(subject_of(authorization), lab_id, after, limit)

    @router.get("/labs/{lab_id}/space/records/{record_id}")
    def get_record(
        lab_id: str,
        record_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict:
        return labs.get_record(subject_of(authorization), lab_id, record_id)

    @router.get("/labs/{lab_id}/keys")
    def get_keys(lab_id: str, authorization: str | None = Header(default=None)) -> dict:
        return labs.get_keys(subject_of(authorization), lab_id)

    return router
