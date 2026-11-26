"""Passkeys (WebAuthn) on the node (layer L1): a member registers a passkey
in a session, and later signs in with it. A passkey session has no device
key, so it can not bind keys."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from anagram.core.errors import Unauthorized
from anagram.identity.formats.documents import validate_subject
from anagram.identity.node.challenges import Challenges
from anagram.identity.node.schema import one

if TYPE_CHECKING:
    from anagram.identity.node.service import IdentityService

PASSKEY_TTL = 300


class PasskeySignIn:
    """The passkey challenges and the table `passkeys`."""

    def __init__(self, identity: IdentityService, challenges: Challenges) -> None:
        self.identity = identity
        self.challenges = challenges

    def _credentials(self, subject: str) -> list[str]:
        return [
            r[0]
            for r in self.identity.db.execute(
                "SELECT credential_id FROM passkeys WHERE subject = ?", (subject,)
            )
        ]

    def _expected(self) -> dict:
        cfg = self.identity.cfg
        return {"expected_rp_id": cfg.rp_id, "expected_origin": cfg.public_url.rstrip("/")}

    def register_options(self, subject: str) -> dict:
        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        options = generate_registration_options(
            rp_id=self.identity.cfg.rp_id,
            rp_name=f"Anagram: {self.identity.cfg.community}",
            user_id=subject.encode(),
            user_name=subject,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c))
                for c in self._credentials(subject)
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
        )
        challenge = {"challenge": bytes_to_base64url(options.challenge)}
        cid = self.challenges.new("passkey_register", subject, challenge, PASSKEY_TTL)
        return {"challenge_id": cid, "options": json.loads(options_to_json(options))}

    def register_verify(self, subject: str, challenge_id: str, credential: dict) -> dict:
        from webauthn import verify_registration_response
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

        with self.identity.lock:
            dest, data = self.challenges.use(challenge_id, "passkey_register", None)
            if dest != subject:
                raise Unauthorized("challenge is for another account")
            try:
                result = verify_registration_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(data["challenge"]),
                    require_user_verification=True,
                    **self._expected(),
                )
            except Exception as exc:  # the library raises several types
                raise Unauthorized(f"passkey not accepted: {exc}") from exc
            self.challenges.mark_used(challenge_id)
            cred_id = bytes_to_base64url(result.credential_id)
            self.identity.db.execute(
                "INSERT INTO passkeys (credential_id, subject, public_key, sign_count)"
                " VALUES (?, ?, ?, ?)",
                (
                    cred_id,
                    subject,
                    bytes_to_base64url(result.credential_public_key),
                    result.sign_count,
                ),
            )
            return {"credential_id": cred_id}

    def login_options(self, subject: str) -> dict:
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        validate_subject(subject)
        options = generate_authentication_options(
            rp_id=self.identity.cfg.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c))
                for c in self._credentials(subject)
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        challenge = {"challenge": bytes_to_base64url(options.challenge)}
        cid = self.challenges.new("passkey_login", subject, challenge, PASSKEY_TTL)
        return {"challenge_id": cid, "options": json.loads(options_to_json(options))}

    def login_verify(self, challenge_id: str, credential: dict) -> dict:
        from webauthn import verify_authentication_response
        from webauthn.helpers import base64url_to_bytes

        idt = self.identity
        with idt.lock:
            subject, data = self.challenges.use(challenge_id, "passkey_login", None)
            row = one(
                idt.db,
                "SELECT public_key, sign_count FROM passkeys WHERE credential_id = ?"
                " AND subject = ?",
                str(credential.get("id")),
                subject,
            )
            if row is None:
                raise Unauthorized("unknown passkey")
            try:
                result = verify_authentication_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(data["challenge"]),
                    credential_public_key=base64url_to_bytes(row[0]),
                    credential_current_sign_count=row[1],
                    require_user_verification=True,
                    **self._expected(),
                )
            except Exception as exc:  # the passkey library raises many types
                raise Unauthorized(f"passkey not accepted: {exc}") from exc
            self.challenges.mark_used(challenge_id)
            idt.db.execute(
                "UPDATE passkeys SET sign_count = ? WHERE credential_id = ?",
                (result.new_sign_count, credential.get("id")),
            )
            return {"session": idt.new_session(subject, "passkey", None)}
