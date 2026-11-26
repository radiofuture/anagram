"""The registry of model recipients: who reads text when a profile is in use.

One source for the consent text (Settings), for the rows of "What leaves this
computer" (`shell/ui/flows.py`), and for the opt-in key of each source. The values
come from the provider adapter of the profile, so the text agrees with the
real calls (docs/design/disclosure-recipient.md, rule 3).
"""

from __future__ import annotations

from typing import Any

from anagram.models.profile import ModelConfig, Profile, build

MCP = "mcp"  # the recipient id of the person's AI assistant (MCP server)
MCP_NAME = "Your AI assistant and its provider"
LOCAL_SENTENCE = "A local model keeps all text on this computer."


def recipient_id(profile: Profile) -> str:
    """The opt-in key in `source.prefs.allow_external`."""
    return f"model:{profile.id}"


def describe(profile: Profile, lab: Any = None) -> dict:
    """What the consent screen shows for one profile. `lab_allows` is None
    with no lab; else it says if this model may read text of the lab space (a
    local model always may)."""
    model = build(profile)
    allows = None
    if lab is not None:
        allows = not model.external or bool(lab.allows_recipient(model.recipient_id))
    if not model.external:
        sentence = LOCAL_SENTENCE
    else:
        sentence = (
            f"{model.recipient} reads the text of the sources that you permit,"
            " your questions, and the passages of an answer."
        )
    return {
        "external": model.external,
        "id": model.recipient_id,
        "lab_allows": allows,
        "name": model.recipient,
        "paid": model.paid,
        "profile": profile.id,
        "reads": model.reads,
        "sentence": sentence,
    }


def recipients(cfg: ModelConfig, lab: Any = None) -> list[dict]:
    """One row for each profile, in id order."""
    return [describe(p, lab) for _, p in sorted(cfg.profiles.items())]


def flow_rows(cfg: ModelConfig) -> list[dict]:
    """Rows for "What leaves this computer": one for each external profile
    that a task uses. With none, one row says that no provider is in use."""
    used = sorted({pid for pid in cfg.use.values() if pid in cfg.profiles})
    rows = []
    for pid in used:
        d = describe(cfg.profiles[pid])
        if not d["external"]:
            continue
        rows.append(
            {
                "can_see": f"{d['name']} reads this text. It never gets text that"
                " other people wrote, and it never gets your keys.",
                "id": f"model-provider-{pid}",
                "to": f"The model provider that you selected: {d['name']}",
                "what": "Excerpts of your items, your questions, and the passages of an answer.",
                "when": "Only for the sources where you permit this model.",
            }
        )
    if rows:
        return rows
    return [
        {
            "can_see": "Nothing. No model provider outside this computer is in use.",
            "id": "model-provider",
            "to": "A model provider (off by default)",
            "what": "Excerpts of your items, your questions, and the passages of an answer.",
            "when": "Only if you select a model that is not on this computer, and only"
            " for the sources where you permit it.",
        }
    ]
