"""Identity (layer L1): the public names of `anagram.identity`.

Code outside the layer imports from this module only (the layer
contract). Code inside the layer imports its own
modules directly. A name that another part needs is added here."""

from __future__ import annotations

from anagram.identity.app.account import Account
from anagram.identity.app.browsers import (
    Browser,
    HeadlessBrowser,
    LoopbackBrowser,
    PasteBrowser,
    urllib_fetch,
)
from anagram.identity.app.device import (
    CONFIG_SCHEMA,
    DEVICE_ED25519,
    DEVICE_X25519,
    LOCAL_STORE_KEY,
    VAULT_KEY,
    Device,
    trust_from_config,
    write_config,
)
from anagram.identity.app.directory import Directory
from anagram.identity.app.guardians import (
    Guardians,
    finish_guardian_recovery,
    pending_recovery,
    start_guardian_recovery,
)
from anagram.identity.app.identity import (
    Home,
    JoinResult,
    SignInWith,
    bind_this_device,
    config_from_trust,
    device_sign_in,
    fetch_trust,
    finish_join,
    login,
    new_person,
    remember_person,
    sign_in,
)
from anagram.identity.app.keychain import describe, open_keystore, policy
from anagram.identity.app.keychain.migrate import migrate_to_os as migrate_keychain_to_os
from anagram.identity.app.keychain.migrate import needs_migration as keychain_needs_migration
from anagram.identity.app.keychain.slots import SlotLocked, SlotUnavailable, os_slot
from anagram.identity.app.keystore import (
    FileKeystore,
    Keystore,
    KeystoreError,
    erase_file,
)
from anagram.identity.app.kit import (
    KIT_FILE,
    RecoveryKit,
    kit_file_path,
    parse_kit,
    recover,
    write_kit_file,
)
from anagram.identity.app.logcheck import LogCheck
from anagram.identity.app.personal import PersonalStore
from anagram.identity.app.session import (
    clear_session,
    read_session,
    session_token,
    write_session,
)
from anagram.identity.formats.documents import (
    ORCID_MODES,
    PUBLIC_LOG_KINDS,
    SubjectKeys,
    is_subject,
    make_node_trust,
    new_lab_id,
    new_pid,
    node_key_fingerprint,
    possession_message,
    text_field,
    validate_lab_id,
    validate_orcid,
    validate_ror,
    validate_subject,
    verify_assertion,
)
from anagram.identity.formats.personal_store import (
    StoreKeys,
    open_record,
    record_size,
    seal_record,
    validate_record,
)
from anagram.identity.formats.recovery import (
    RECOVERY_REQUEST_MAX_AGE,
    recovery_request_id,
    validate_approval,
    validate_guardian_set,
    validate_recovery_request,
)
from anagram.identity.node.checks import check_device_nonce, validate_email
from anagram.identity.node.email_signin import mask_email
from anagram.identity.node.mailer import FakeMailer, mailer_from_env
from anagram.identity.node.orcid import REGISTER_URL, FakeOrcid, OrcidOAuth
from anagram.identity.node.orcid_signin import OOB, FlowStart
from anagram.identity.node.routes import identity_router, member_check
from anagram.identity.node.service import IdentityConfig, IdentityDirectory, IdentityService
from anagram.identity.node.store import NodePersonalStore, QuotaExceeded
from anagram.identity.node.store_routes import store_router
from anagram.identity.node.vouch import stated_email
from anagram.identity.ports import Admission

__all__ = [
    # Ports
    "Admission",
    # Formats
    "ORCID_MODES",
    "PUBLIC_LOG_KINDS",
    "RECOVERY_REQUEST_MAX_AGE",
    "StoreKeys",
    "SubjectKeys",
    "is_subject",
    "make_node_trust",
    "new_lab_id",
    "new_pid",
    "node_key_fingerprint",
    "open_record",
    "possession_message",
    "record_size",
    "recovery_request_id",
    "seal_record",
    "text_field",
    "validate_approval",
    "validate_guardian_set",
    "validate_lab_id",
    "validate_orcid",
    "validate_record",
    "validate_recovery_request",
    "validate_ror",
    "validate_subject",
    "verify_assertion",
    # App
    "Account",
    "Browser",
    "CONFIG_SCHEMA",
    "DEVICE_ED25519",
    "DEVICE_X25519",
    "Device",
    "Directory",
    "FileKeystore",
    "Guardians",
    "HeadlessBrowser",
    "Home",
    "JoinResult",
    "KIT_FILE",
    "Keystore",
    "KeystoreError",
    "LOCAL_STORE_KEY",
    "LogCheck",
    "LoopbackBrowser",
    "PasteBrowser",
    "PersonalStore",
    "RecoveryKit",
    "SignInWith",
    "SlotLocked",
    "SlotUnavailable",
    "VAULT_KEY",
    "bind_this_device",
    "clear_session",
    "config_from_trust",
    "describe",
    "device_sign_in",
    "erase_file",
    "fetch_trust",
    "finish_guardian_recovery",
    "finish_join",
    "keychain_needs_migration",
    "kit_file_path",
    "login",
    "migrate_keychain_to_os",
    "new_person",
    "open_keystore",
    "os_slot",
    "parse_kit",
    "pending_recovery",
    "policy",
    "read_session",
    "recover",
    "remember_person",
    "session_token",
    "sign_in",
    "start_guardian_recovery",
    "trust_from_config",
    "urllib_fetch",
    "write_config",
    "write_kit_file",
    "write_session",
    # Node
    "FakeMailer",
    "FakeOrcid",
    "FlowStart",
    "IdentityConfig",
    "IdentityDirectory",
    "IdentityService",
    "OOB",
    "OrcidOAuth",
    "NodePersonalStore",
    "QuotaExceeded",
    "REGISTER_URL",
    "check_device_nonce",
    "identity_router",
    "mailer_from_env",
    "mask_email",
    "member_check",
    "stated_email",
    "store_router",
    "validate_email",
]
