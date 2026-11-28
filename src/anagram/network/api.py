"""Network and discovery (layer L3): the public names of `anagram.network`.

Code outside the layer imports from this module only (the layer
contract). Code inside the layer imports its own
modules directly. A name that another part needs is added here."""

from __future__ import annotations

from anagram.network.formats.lab import (
    ADMIN,
    MEMBER,
    PI,
    LabState,
    check_name,
    make_join_entry,
    make_roster_entry,
)
from anagram.network.formats.labitem import MAX_TITLE as MAX_ITEM_TITLE
from anagram.network.formats.labkey import invite_recipient
from anagram.network.formats.labsettings import OAUTH_PROVIDERS
from anagram.network.formats.vault import PUBLIC
from anagram.network.groups.app.labcontext import AppLabs
from anagram.network.groups.app.labkeys import LabKeys, invite_device
from anagram.network.groups.app.labrecords import LabItemDraft, LabSpace
from anagram.network.groups.app.labroster import CLOCK_SKEW, RETRIES, LabError, LabRoster
from anagram.network.groups.app.labs import Labs
from anagram.network.groups.app.labspace import LabSpaceConnector, publish_index_item
from anagram.network.groups.app.labspace import space_hook as lab_space_hook
from anagram.network.groups.app.labspace import sync_index as sync_lab_index
from anagram.network.groups.node.labdirectory import LabDirectory
from anagram.network.groups.node.labs import LabService, lab_policy_from_env
from anagram.network.groups.node.routes import lab_router
from anagram.network.matching.app.enclave_matching import EnclaveMatching, typed_draft
from anagram.network.matching.enclave.real_engines import (
    LlmJointJudge,
    OnnxEmbedder,
    engines_from_env,
    real_engines,
)
from anagram.network.matching.hosting.clients import HttpFeed, HttpLog
from anagram.network.matching.hosting.enclave import EnclaveHost, enclave_app
from anagram.network.matching.hosting.log import HttpCosigner, LogService, log_app
from anagram.network.matching.hosting.roster import RosterService, RosterStore, roster_app
from anagram.network.matching.hosting.runtime import Ticker
from anagram.network.matching.hosting.runtime import serve as serve_service
from anagram.network.matching.hosting.runtime import setup_logging as setup_service_logging
from anagram.network.matching.hosting.tools.devnet import DevNet, init_devnet, witness_name
from anagram.network.matching.hosting.tools.operator import Operator, ReleaseFile
from anagram.network.matching.hosting.witness import witness_app
from anagram.network.matching.node.control import control_router
from anagram.network.matching.node.credentials import credential_router
from anagram.network.matching.node.enclave_node import (
    NodeEnclave,
    enclave_config,
    member_session,
    node_record,
)
from anagram.network.matching.node.enclave_relay import (
    EnclaveRelay,
    enclave_router,
)
from anagram.network.matching.trust.release import NOTICE
from anagram.network.matching.trust.translog import EntryWitness, LogStore, TransparencyLog
from anagram.network.sharing.app.grants import COMMUNITY, Grants, ThirdPartyWarning
from anagram.network.sharing.app.invites import ReaderInvites
from anagram.network.sharing.app.reads import ReadReceipts, ShareHooks
from anagram.network.sharing.app.received import Received
from anagram.network.sharing.app.records import ReadRecords
from anagram.network.sharing.app.shares import Shares
from anagram.network.sharing.app.sync import ShareSync
from anagram.network.sharing.app.tables import SCHEMA, ShareStore
from anagram.network.sharing.node.reads import ReadLedger, reads_router
from anagram.network.sharing.node.routes import vault_router
from anagram.network.sharing.node.vault import NodeVault

__all__ = [
    # Enclave services (simulated profile): the processes of `anagram enclave|log|witness|roster`
    "DevNet",
    "EnclaveHost",
    "EntryWitness",
    "HttpCosigner",
    "HttpFeed",
    "HttpLog",
    "LogService",
    "LogStore",
    "NOTICE",
    "Operator",
    "ReleaseFile",
    "RosterService",
    "RosterStore",
    "Ticker",
    "TransparencyLog",
    "enclave_app",
    "init_devnet",
    "log_app",
    "roster_app",
    "serve_service",
    "setup_service_logging",
    "witness_app",
    "witness_name",
    # Formats
    "ADMIN",
    "LabState",
    "MAX_ITEM_TITLE",
    "MEMBER",
    "OAUTH_PROVIDERS",
    "PI",
    "PUBLIC",
    "check_name",
    "invite_recipient",
    "make_join_entry",
    "make_roster_entry",
    # Groups (labs)
    "CLOCK_SKEW",
    "AppLabs",
    "LabDirectory",
    "LabError",
    "LabItemDraft",
    "LabKeys",
    "LabRoster",
    "LabService",
    "LabSpace",
    "LabSpaceConnector",
    "Labs",
    "RETRIES",
    "invite_device",
    "lab_policy_from_env",
    "lab_router",
    "lab_space_hook",
    "publish_index_item",
    "sync_lab_index",
    # Sharing and reads
    "COMMUNITY",
    "Grants",
    "NodeVault",
    "ReadLedger",
    "ReadReceipts",
    "ReadRecords",
    "ReaderInvites",
    "Received",
    "SCHEMA",
    "ShareStore",
    "ShareHooks",
    "ShareSync",
    "Shares",
    "ThirdPartyWarning",
    "reads_router",
    "vault_router",
    # Matching
    "EnclaveRelay",
    "LlmJointJudge",
    "NodeEnclave",
    "EnclaveMatching",
    "OnnxEmbedder",
    "control_router",
    "credential_router",
    "enclave_config",
    "engines_from_env",
    "member_session",
    "node_record",
    "enclave_router",
    "real_engines",
    "typed_draft",
]
