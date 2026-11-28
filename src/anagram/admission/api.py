"""Admission and growth (layer L4): the public names of `anagram.admission`.

Code outside the layer imports from this module only (the layer
contract). Code inside the layer imports its own
modules directly. A name that another part needs is added here."""

from __future__ import annotations

from anagram.admission.app.join import GroupInvites, invite_preview, join, node_of
from anagram.admission.check import GroupAdmission
from anagram.admission.formats import (
    DEFAULT_INVITE_DAYS,
    lab_invite_id,
    parse_invite_url,
    parse_lab_invite_link,
)
from anagram.admission.model import NodePolicy
from anagram.admission.node.reader import ReaderInvites, reader_invites_router
from anagram.admission.node.routes import admission_router
from anagram.admission.node.service import AdmissionService, group_creation
from anagram.admission.node.store import AdmissionStore

__all__ = [
    # Policy model
    "NodePolicy",
    # Formats
    "DEFAULT_INVITE_DAYS",
    "lab_invite_id",
    "parse_invite_url",
    "parse_lab_invite_link",
    # Roster checks
    "GroupAdmission",
    # App
    "GroupInvites",
    "node_of",
    "invite_preview",
    "join",
    # Node
    "AdmissionService",
    "AdmissionStore",
    "ReaderInvites",
    "group_creation",
    "reader_invites_router",
    # Routes
    "admission_router",
]
