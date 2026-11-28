"""The lab settings (spec/lab.md): one signed value in a lab space record.
It has five sections (models, disclosure, OAuth clients, sources, matching).
A PI or an admin writes it."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from anagram.core.canonical import JsonObject
from anagram.core.crypto.hashing import TAG_SIGN_LAB_SETTINGS
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX32, HEX64, hex_field, int_at_least
from anagram.identity.api import validate_lab_id, validate_subject
from anagram.network.formats.lab import check_roster_ref, check_text

KIND_SETTINGS = "lab_settings"
SETTINGS_REF = "settings"
SETTINGS_SCHEMA = "anagram.lab_settings.v1"
SECTIONS = ("models", "disclosure", "oauth_clients", "sources", "matching")
OAUTH_PROVIDERS = ("google", "notion")
LAB_DEFAULTS = ("private", "lab")
_SETTINGS_META = {
    "schema",
    "lab_id",
    "rev",
    "updated_by",
    "updated_device",
    "updated_at",
    "roster",
    "signature",
}


def section_defaults() -> dict[str, JsonObject]:
    """The default value of each section when the record does not have it.
    The optional key `disclosure.allow_cloud_assistant`
    (agent grant v2) has no default here, so the vectors stay; a reader
    takes an absent key as false (`LabPolicy.allows_cloud_assistant`)."""
    return {
        "models": {"profiles": [], "use": {}, "kind_hints": [], "person_facts": True},
        "disclosure": {"allow_external": [], "allow_assistant": False},
        "oauth_clients": {},
        "sources": {"allowed_kinds": None, "lab_default": "private"},
        "matching": {"enabled": True},
    }


def _only(value: Any, names: set[str], what: str) -> JsonObject:
    if not isinstance(value, dict):
        raise FormatError(f"{what}: expected an object")
    extra = set(value) - names
    if extra:
        raise FormatError(f"{what}: unknown key {sorted(extra)[0]!r}")
    return value


def _bool(value: Any, what: str) -> None:
    if not isinstance(value, bool):
        raise FormatError(f"{what}: true or false")


def _names(value: Any, what: str, limit: int = 200) -> None:
    if not isinstance(value, list) or len(value) > limit:
        raise FormatError(f"{what}: expected a list")
    for v in value:
        check_text(v, what, 200, optional=False)


def _models(value: Any) -> None:
    _only(value, {"profiles", "use", "kind_hints", "person_facts"}, "models")
    profiles = value.get("profiles", [])
    if not isinstance(profiles, list) or len(profiles) > 32:
        raise FormatError("models: profiles is a list")
    if any(not isinstance(p, dict) for p in profiles):
        raise FormatError("models: each profile is an object")
    use = value.get("use", {})
    if not isinstance(use, dict):
        raise FormatError("models: use is an object")
    for task, profile in use.items():
        check_text(task, "models use task", 64, optional=False)
        check_text(profile, "models use profile", 200)
    hints = value.get("kind_hints", [])
    if not isinstance(hints, list) or len(hints) > 200:
        raise FormatError("models: kind_hints is a list")
    for h in hints:
        if not isinstance(h, dict) or set(h) != {"kind", "text"}:
            raise FormatError("models: a kind hint has text and kind only")
        check_text(h["text"], "kind hint text", 500, optional=False)
        check_text(h["kind"], "kind hint kind", 64, optional=False)
    if "person_facts" in value:
        _bool(value["person_facts"], "models person_facts")


def validate_section(name: str, value: Any) -> JsonObject:
    """Check one section. Unknown keys are
    refused. A key that is absent takes its default (`section_defaults`)."""
    if name == "models":
        _models(value)
    elif name == "disclosure":
        _only(value, {"allow_external", "allow_assistant", "allow_cloud_assistant"}, "disclosure")
        if "allow_external" in value:
            _names(value["allow_external"], "disclosure allow_external")
        for key in ("allow_assistant", "allow_cloud_assistant"):
            if key in value:
                _bool(value[key], f"disclosure {key}")
    elif name == "oauth_clients":
        _only(value, set(OAUTH_PROVIDERS), "oauth_clients")
        for provider, client in value.items():
            _only(client, {"client_id", "client_secret"}, f"oauth_clients {provider}")
            if "client_id" not in client:
                raise FormatError(f"oauth_clients {provider}: needs client_id")
            check_text(client["client_id"], "oauth client_id", 500, optional=False)
            check_text(client.get("client_secret"), "oauth client_secret", 500)
    elif name == "sources":
        _only(value, {"allowed_kinds", "lab_default"}, "sources")
        if value.get("allowed_kinds") is not None:
            _names(value["allowed_kinds"], "sources allowed_kinds", 64)
        if "lab_default" in value and value["lab_default"] not in LAB_DEFAULTS:
            raise FormatError("sources: lab_default is private or lab")
    elif name == "matching":
        _only(value, {"enabled"}, "matching")
        if "enabled" in value:
            _bool(value["enabled"], "matching enabled")
    else:
        raise FormatError(f"unknown settings section {name!r}")
    section: JsonObject = value  # each branch above checked that it is an object
    return section


def sections_of(doc: JsonObject | None) -> dict[str, JsonObject]:
    """The five sections of a settings record (or of no record), with the
    defaults applied for each absent section and key."""
    out = section_defaults()
    for name in SECTIONS:
        if doc is not None and name in doc:
            if name == "oauth_clients":
                out[name] = dict(doc[name])
            else:
                out[name] = {**out[name], **doc[name]}
    return out


def validate_settings(doc: Any) -> JsonObject:
    if not isinstance(doc, dict) or not _SETTINGS_META <= set(doc):
        raise FormatError("lab settings: fields do not match the schema")
    extra = set(doc) - _SETTINGS_META - set(SECTIONS)
    if extra:
        raise FormatError(f"lab settings: unknown section {sorted(extra)[0]!r}")
    if doc["schema"] != SETTINGS_SCHEMA:
        raise FormatError("lab settings: unknown schema")
    validate_lab_id(doc["lab_id"])
    int_at_least(doc["rev"], "lab settings rev", 1)
    validate_subject(doc["updated_by"])
    hex_field(doc["updated_device"], HEX32, "lab settings updated_device")
    parse_time(doc["updated_at"])
    check_roster_ref(doc["roster"], "lab settings")
    for name in SECTIONS:
        if name in doc:
            validate_section(name, doc[name])
    hex_field(doc["signature"], HEX64, "lab settings signature")
    return doc


def make_settings(
    *,
    lab_id: str,
    rev: int,
    sections: Mapping[str, JsonObject],
    updated_by: str,
    key: SigningKey,
    roster: JsonObject,
    updated_at: datetime,
) -> JsonObject:
    doc: dict[str, Any] = {
        "lab_id": lab_id,
        "rev": rev,
        "roster": roster,
        "schema": SETTINGS_SCHEMA,
        "updated_at": format_time(updated_at),
        "updated_by": updated_by,
        "updated_device": key.public_bytes().hex(),
    }
    for name, value in sections.items():
        doc[name] = validate_section(name, value)
    doc["signature"] = sign_doc(doc, TAG_SIGN_LAB_SETTINGS, key)
    return validate_settings(doc)


def verify_settings(doc: Any) -> JsonObject:
    """Form and the signature of the device. The caller checks that the
    device is a key of `updated_by`, and that this person is PI or admin."""
    checked = validate_settings(doc)
    if not doc_signature_ok(doc, TAG_SIGN_LAB_SETTINGS, bytes.fromhex(doc["updated_device"])):
        raise FormatError("lab settings: bad signature")
    return checked
