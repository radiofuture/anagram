# Disclosure recipient

A design pattern of Anagram. Use it for each adapter that can send user data
to a party outside the person's computer or the trusted host: a model
provider, a remote document converter, an AI client through MCP.

## Problem

Each external service is a party that can read the data. If the code adds
these services one at a time, the person cannot see who reads what, and a
default can send data without consent.

## Contract

Each adapter declares:

- `external`: true if data leaves the computer or the trusted host.
- `recipient`: the name of the party that reads the data, as people see it.
- `paid`: true if a call costs money.
- What it reads (for example "files you select").

Rules:

1. The caller refuses an external adapter unless the person opted in for
   this scope (for each source or feature). The default is off.
2. A paid adapter also needs an approved budget in the configuration.
3. One registry of recipients drives the consent text and the "who sees
   what" settings page, so the page always agrees with the real calls.
4. Each external call writes a local log row: what, when, and to whom.
5. Each adapter has a deterministic local fake for tests. Tests never use
   the network.
6. The output of an external adapter is a draft or a decision record. It is
   never a commit or a release by itself.

## In the code

`anagram.models.base` (the model adapters), `anagram.models.recipients`
(the registry), `anagram.local.index.convert.base` (converters) and the MCP
gateway (`anagram.gateway`).
