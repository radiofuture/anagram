"""The trust policy of the person (layer L2, primitive `trust-policy`): tiers
of sources, folders and items, allow and deny lists, one signed and versioned
document in the encrypted index store.

- `policy`: the format `anagram.trust_policy.v1` (spec/trust.md) and the
  evaluation (`TrustPolicy`, `Peer`).
- `store`: the current document and its history in the index store meta.

Enforcement at each use lives in the callers. Import each module
by name; this package file re-exports nothing.
"""
