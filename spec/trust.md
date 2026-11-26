# Trust policy

Status: draft, 2026-11-18. Schema `anagram.trust_policy.v1`. Code:
`src/anagram/local/trust/` (the local layer).
Vectors: [vectors/trust-policy.json](vectors/trust-policy.json).

The trust policy is one signed, versioned document for each person. It says
which items the agent of the person may use, and which people, labs,
organisations and communities the person may reach. It stays on the device,
in the encrypted index store. This document defines the format and the
evaluation. The checks at each use (beacon, negotiation, reveal, grants,
shares) are not in this document.

## 1. Tiers

| Tier | Who may use the item |
| --- | --- |
| `private` | The person, and agents with a grant on this device |
| `discoverable` | Also the agent of the person, to find fits and to answer typed questions. The agent never quotes it to a peer |
| `shared` | As `discoverable`. The person may also give it to named people or groups by the share flow. The recipients stay in the share records |

The order from narrow to wide is `private`, `discoverable`, `shared`.

The tier of an item is the **narrowest** of:

1. the mark of its source, or `defaults.own` if the source has no mark;
2. the mark of each folder of its source whose prefix starts the item key;
3. the mark of the item.

An item that another person wrote (the `third_party` mark,
[threat-model.md](threat-model.md) section 16) is always `private`.

A reading (derived data) is never wider than the narrowest tier of its basis
items. A reading with no basis item is `private`.

Default (2026-11-18): `defaults.own` is
`discoverable`. So the own items of the person in all sources are
`discoverable`, and items that other people wrote are `private`.

## 2. Allow and deny

Subjects, in four kinds:

| Kind | Value |
| --- | --- |
| `people` | A pid (`pid:<32 hex>`) |
| `labs` | A lab ID (`lab-<16 hex>`) |
| `orgs` | `ror:<ROR ID>`, or `domain:<host name>` (a verified email domain) |
| `communities` | The host name of a community |

A peer is a set of **verified** attributes: its pid, its labs (verified
roster), its organisations (verified email domain, ROR from a verified
source), its communities. A self-stated affiliation is not an attribute.

Evaluation of `reach(peer, in_scope)`, in this order:

1. If a `deny` entry matches an attribute of the peer: `denied`.
2. Else, if an `allow` entry matches: `allowed`.
3. Else: `in_scope` if the peer is inside the boundary of this use (for
   example the same community), else `out_of_scope`.

**Deny wins over allow.** Allow only widens who may be a candidate across a
boundary. The allow list of one person never cancels a deny of another
person: a pair is out when either side denies the other.

The `room_blocks` vector keeps the deny entries for pids, labs and ROR IDs
in a list form `{"orcids", "labs", "rors"}` (`orcids` also holds pids),
each sorted, at most 256 entries. Domain and community entries have no such
form; `unmapped` counts them. The enclave reads the deny list of the pack
([pack.md](pack.md) section 3.7), not this form.

## 3. Document

```json
{
  "allow": {"communities": [], "labs": [], "orgs": [], "people": []},
  "defaults": {"own": "discoverable"},
  "deny": {"communities": [], "labs": [], "orgs": [], "people": []},
  "folders": {"<source id>": {"<key prefix>": "<tier>"}},
  "items": {"<source id>": {"<item key>": "<tier>"}},
  "owner": "pid:<32 hex>",
  "rev": 1,
  "schema": "anagram.trust_policy.v1",
  "signature": "<hex64>",
  "sources": {"<source id>": "<tier>"},
  "updated_at": "<RFC 3339, UTC, seconds>",
  "updated_device": "<hex32 Ed25519 public key>"
}
```

- All fields are required. A verifier refuses other fields.
- Each subject list is sorted, with no repeats, at most 256 entries.
- `sources`, `folders` and `items` hold at most 10,000 marks together. A
  source ID has 1 to 200 characters; a key or prefix 1 to 1024. A source
  entry in `folders` or `items` has one mark or more.
- `rev` is an integer of 1 or more. A store accepts a new document only with
  a higher `rev` than the current one (no rollback). It keeps earlier
  documents for undo.

## 4. Signature

```
signature = Ed25519(device key, u8(len(tag)) || tag || canonical_json(document without "signature"))
tag       = "anagram/v1/trust/sign/policy"
```

The tag is not in the locked registry of [formats.md](formats.md). A verifier checks that `updated_device` is a device key of
`owner`. So no person can set the policy of another person.
