"""Local node (layer L2): the public names of `anagram.local`.

Code outside the layer imports from this module only (the layer
contract). Code inside the layer imports its own
modules directly. A name that another part needs is added here."""

from __future__ import annotations

from anagram.local.findings import Findings
from anagram.local.index.convert import Router, Skipped
from anagram.local.index.convert.base import Blob
from anagram.local.index.convert.builtin import PDF, MarkItDownConverter
from anagram.local.index.convert.document import blocks_from_markdown, wire_blocks_v1
from anagram.local.index.indexer import POLL_S, STATUS_KEY, Indexer, helper_running
from anagram.local.index.local import ItemView, LocalIndex
from anagram.local.index.media import DOCX, media_type_for
from anagram.local.index.retention import remove_source
from anagram.local.index.retrieve import Hit
from anagram.local.index.retrieve import search as search_index
from anagram.local.index.spaces import (
    PRIVATE,
    PRIVATE_SCOPE,
    ScopeError,
    check_scope,
    lab_space,
    readable_spaces,
    space_of,
)
from anagram.local.index.store import IndexStore, loads, placeholders
from anagram.local.localdb import LocalDBError, connect
from anagram.local.ports import LabContext, LocalClient
from anagram.local.sources import (
    SOURCES,
    connector_from_config,
    describe_suggestions,
    discover,
    kind_label,
    source_state,
)
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    Suggestion,
)
from anagram.local.sources.credentials import TokenSet
from anagram.local.sources.folder import FolderConnector
from anagram.local.sources.git import GitConnector
from anagram.local.sources.http import SourceFault
from anagram.local.sources.oauth import (
    FLOW_TIMEOUT_S,
    KIND_SCOPES,
    PROVIDERS,
    OAuthError,
    OAuthFlow,
    client_resolver,
)
from anagram.local.sources.obsidian import VAULT_DIR
from anagram.local.sources.orcid import OrcidWorksConnector
from anagram.local.sources.source_labels import is_raw, shown, source_label
from anagram.local.sources.zotero import ZoteroFileConnector
from anagram.local.sources.zotero import check_key as check_zotero_key
from anagram.local.sources.zotero import urllib_transport as zotero_transport
from anagram.local.trust.policy import DISCOVERABLE as TRUST_DISCOVERABLE
from anagram.local.trust.policy import TrustPolicy
from anagram.local.trust.policy import at_least as tier_at_least
from anagram.local.trust.store import TrustStore
from anagram.local.understanding import digest, proposals
from anagram.local.understanding.ask import answer as answer_question
from anagram.local.understanding.ask import check_question
from anagram.local.understanding.ask import clear_history as clear_ask_history
from anagram.local.understanding.ask import history as ask_history
from anagram.local.understanding.ask import prepare as prepare_question
from anagram.local.understanding.ask import record as record_answer
from anagram.local.understanding.chips import NEED, OFFER, split_units, unit_polarity
from anagram.local.understanding.drafter import Drafter, ProviderDrafter
from anagram.local.understanding.drafts import FindingDraft, approve_finding, draft_findings
from anagram.local.understanding.kinds import (
    FACT_KINDS_FROM_LAB,
    KIND_IDS,
    KINDS,
    SEED_KINDS,
    kind_of,
    kinds_of,
)
from anagram.local.understanding.kinds import label as kind_name
from anagram.local.understanding.kinds import set_override as set_kind_override
from anagram.local.understanding.links import BUILDS_ON, RELATED, SUPPORTS
from anagram.local.understanding.profile.items import from_index as lens_items
from anagram.local.understanding.profile.lens import ProfileLens
from anagram.local.understanding.titles import humanize as humanize_title
from anagram.local.understanding.understand_schema import ensure as ensure_understanding_schema
from anagram.local.understanding.vocabulary import VOCAB_VERSION, default_vocabulary
from anagram.local.vault import Vault

__all__ = [
    # Ports (the composition root gives them)
    "LabContext",
    "LocalClient",
    # Sources
    "Connector",
    "ConnectorError",
    "EvidenceItem",
    "FLOW_TIMEOUT_S",
    "FolderConnector",
    "GitConnector",
    "KIND_SCOPES",
    "KnownItem",
    "OAuthError",
    "OAuthFlow",
    "OrcidWorksConnector",
    "PROVIDERS",
    "SOURCES",
    "SourceContext",
    "SourceFault",
    "Suggestion",
    "TokenSet",
    "VAULT_DIR",
    "ZoteroFileConnector",
    "check_zotero_key",
    "client_resolver",
    "connector_from_config",
    "describe_suggestions",
    "discover",
    "is_raw",
    "kind_label",
    "shown",
    "source_label",
    "source_state",
    "zotero_transport",
    # Index
    "placeholders",
    "Blob",
    "DOCX",
    "Hit",
    "IndexStore",
    "Indexer",
    "ItemView",
    "LocalIndex",
    "MarkItDownConverter",
    "PDF",
    "POLL_S",
    "PRIVATE",
    "PRIVATE_SCOPE",
    "Router",
    "STATUS_KEY",
    "ScopeError",
    "Skipped",
    "blocks_from_markdown",
    "check_scope",
    "helper_running",
    "lab_space",
    "loads",
    "media_type_for",
    "readable_spaces",
    "remove_source",
    "search_index",
    "space_of",
    "wire_blocks_v1",
    # Understanding
    "BUILDS_ON",
    "Drafter",
    "FACT_KINDS_FROM_LAB",
    "FindingDraft",
    "KINDS",
    "KIND_IDS",
    "NEED",
    "OFFER",
    "ProviderDrafter",
    "RELATED",
    "SEED_KINDS",
    "SUPPORTS",
    "VOCAB_VERSION",
    "ProfileLens",
    "answer_question",
    "lens_items",
    "approve_finding",
    "ask_history",
    "check_question",
    "clear_ask_history",
    "default_vocabulary",
    "digest",
    "draft_findings",
    "ensure_understanding_schema",
    "humanize_title",
    "kind_name",
    "kind_of",
    "kinds_of",
    "prepare_question",
    "proposals",
    "record_answer",
    "set_kind_override",
    "split_units",
    "unit_polarity",
    # Trust policy
    "TRUST_DISCOVERABLE",
    "TrustPolicy",
    "TrustStore",
    "tier_at_least",
    # Vault and findings
    "Findings",
    "LocalDBError",
    "Vault",
    "connect",
]
