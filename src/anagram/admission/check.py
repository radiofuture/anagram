"""The admission checks of a group roster (port `AdmissionCheck`,
`anagram.network.ports`). The roster of L3 (`formats.lab`) applies an `invite`
or `join` entry only with these checks. The composition root makes one and
gives it to each roster user (`LabService`, the `Client`, `LabState`).
"""

from __future__ import annotations

from datetime import datetime

from anagram.admission import formats
from anagram.admission.model import Claim, NodePolicy, endorser_may, group_endorsement


class GroupAdmission:
    """`AdmissionCheck` for lab rosters under one node policy."""

    def __init__(self, policy: NodePolicy | None = None) -> None:
        self.policy = policy or NodePolicy()

    def invite_id(self, auth: dict) -> str:
        return formats.lab_invite_id(auth)

    def check_invite(self, auth: dict) -> dict:
        return formats.verify_lab_invite(auth)

    def check_request_form(self, request: dict) -> dict:
        return formats.validate_join_request(request)

    def check_request(self, request: dict, auth: dict) -> dict:
        return formats.verify_join_request(request, auth)

    def request_hash(self, request: dict) -> str:
        return formats.request_hash(request)

    def refusal(self, invite: dict, endorser_ok: bool, at: datetime) -> str | None:
        return self.policy.decide(
            group_endorsement(invite), Claim(at=at), narrow=(endorser_may(endorser_ok),)
        )
