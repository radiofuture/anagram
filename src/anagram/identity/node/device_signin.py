"""Sign-in with an active device key on the node (layer L1), for example
after a restore from the recovery kit. The holder of an active device key can
already sign key bindings, so this gives no new power."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from anagram.core.errors import FormatError, NodeError, Unauthorized
from anagram.identity.formats.documents import validate_subject, verify_device_signin
from anagram.identity.node.challenges import Challenges
from anagram.identity.node.checks import check_device_nonce

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService

DEVICE_SIGNIN_TTL = 120


class DeviceSignIn:
    """The device sign-in challenge."""

    def __init__(self, identity: IdentityService, challenges: Challenges) -> None:
        self.identity = identity
        self.challenges = challenges

    def start(self, subject: str, device_key: str) -> dict:
        try:
            validate_subject(subject)
            check_device_nonce(device_key, "0" * 32)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        challenge = secrets.token_hex(32)
        data = {"challenge": challenge, "device_key": device_key}
        cid = self.challenges.new("device_signin", subject, data, DEVICE_SIGNIN_TTL)
        return {
            "challenge": challenge,
            "challenge_id": cid,
            "node_key": self.identity.cfg.node_key,
        }

    def verify(self, challenge_id: str, signature: str) -> dict:
        idt = self.identity
        with idt.lock:
            subject, data = self.challenges.use(challenge_id, "device_signin", None)
            self.challenges.mark_used(challenge_id)
            device = data["device_key"]
            if not idt.is_member(subject) or device not in idt.key_state(subject).devices:
                raise Unauthorized("this device key is not active for this person")
            if not verify_device_signin(
                subject, device, data["challenge"], idt.cfg.node_key, str(signature)
            ):
                raise Unauthorized("bad device signature")
            return {"session": idt.new_session(subject, "device", device)}
