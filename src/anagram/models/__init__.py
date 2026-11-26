"""Model provider layer: one interface for each text model that Anagram calls.

- `base`: `TextModel`, `TextRequest`, `TextReply`, `Capabilities`,
  `check_model`, `parse_strict`.
- `providers`: `ollama`, `openai_compat` (also OpenAI and OpenRouter),
  `anthropic`, and `fake` (tests). Import a provider module by name; this
  package does not import them, so the node does not load the index.
- `budget`: `Gate`, the only spend wrapper. A paid model runs only inside it.
- `ledger`: `BudgetLedger` (spend reservations), `check_paid_runs`, prices.
- `embed`: the embedders (`FastEmbedder` on this computer, `FakeEmbedder`).
- `ollama`: `OllamaClient`, the loopback client of a local Ollama server.
- `profile`: `Profile`, `ModelConfig`, `load`, `save`, `resolve`, `state`.
- `recipients`: the consent text and the rows of "What leaves this computer".
- `from_config`: a model from Profile JSON, for a node with no index and no
  keystore. The key comes from the environment.
"""

import os
from collections.abc import Mapping

from anagram.models.base import (
    BudgetRefused,
    Capabilities,
    ModelError,
    ModelRefused,
    TextModel,
    TextReply,
    TextRequest,
    check_model,
    check_schema,
    parse_prices,
    parse_strict,
)
from anagram.models.profile import (
    KEY_ENV,
    ModelConfig,
    Profile,
    build,
    load,
    make_profile,
    resolve,
    save,
    state,
)


def from_config(
    cfg: dict,
    *,
    key_env: Mapping[str, str] | None = None,
    transport: object | None = None,
    clients: Mapping[str, object] | None = None,
) -> TextModel:
    """A model from Profile JSON (`{"provider", "model", "label", "base_url"?,
    "route"?, "prices"?}`), for the node: no index, no keystore, and no spend
    gate (the caller puts a paid model inside `Gate`).

    The key is the value of the variable `KEY_ENV[provider]` in `key_env`
    (default: the environment of the process). Raise `ModelError` for a
    config that is not correct."""
    profile = make_profile(cfg, origin="node")
    env = os.environ if key_env is None else key_env
    name = KEY_ENV.get(profile.provider)
    key = (env.get(name) or "").strip() if name else ""
    return build(profile, key=key or None, transport=transport, clients=clients)


__all__ = [
    "KEY_ENV",
    "BudgetRefused",
    "Capabilities",
    "ModelConfig",
    "ModelError",
    "ModelRefused",
    "Profile",
    "TextModel",
    "TextReply",
    "TextRequest",
    "build",
    "check_model",
    "check_schema",
    "from_config",
    "load",
    "make_profile",
    "parse_prices",
    "parse_strict",
    "resolve",
    "save",
    "state",
]
