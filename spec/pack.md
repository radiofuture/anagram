# Pack (`anagram.pack.v1`) and known object (`anagram.known.v1`)

Status: draft, revised after the spec review of 2026-11-25 (section 15).
Licence: CC BY 4.0.
Schema: [schemas/pack.schema.json](schemas/pack.schema.json). Vectors:
[vectors/pack.json](vectors/pack.json). Implementation:
`src/anagram/network/formats/pack.py`; the vector generator
`src/anagram/vectors/net/` calls it.

Related documents: [enclave-messages.md](enclave-messages.md) (how a pack
travels, receipts, errors), [network.md](network.md) (member credential,
person key, roster), [enclave-trust.md](enclave-trust.md) (attestation,
transparency log, key custody, replay, tombstones, deletion),
[matching.md](matching.md) (the match protocol, the decision table and the
release check of the enclave).

## 1. Purpose

The **pack** is the only data about a person that the matching enclave
receives. The app builds it from the local index. The person approves it.
The app signs it with the person key, seals it to an attested enclave
instance, and uploads it once a day. Nodes see only ciphertext of one fixed
size.

The **known object** is a separate, sealed list of keyed hashes of people
that the person already knows. The enclave uses it only for the known check
([enclave-messages.md](enclave-messages.md)). It is uploaded once a week.

The pack holds enough for matching and nothing more. It never holds the
reveal card (name, lab, institution, email, ORCID iD). The reveal card
travels only inside a "yes" answer ([enclave-messages.md](enclave-messages.md)
section 5).

## 2. Words and encoding

- **Must**, **must not**, **should**, **may**: as in RFC 2119.
- **Canonical JSON**, **hex**, **times**, `u32`, `u64`, `tagged_hash`, and the
  signed message `u8(len(tag)) || tag || payload`: as in
  [formats.md](formats.md) sections 2 and 3.1.
- **Size** of a field: the number of bytes of the canonical JSON of the
  field value (not the key).
- **Text**: a JSON string that (1) is in Unicode NFC, (2) has no character of
  the general categories Cc (control) or Cs (surrogate), (3) has no
  whitespace at its start or end, and (4) has 1 to N code points (N is given
  for each field). Rule (2) also excludes line breaks and tabs.
- **Concept**: an integer from 0 to 2^32 - 1. It is an index into the product
  vocabulary that the pack names in `vocab`. The `vocabulary` descriptor of
  the release ([enclave-trust.md](enclave-trust.md) section 3.6) gives its
  ID, the SHA-256 of the file and its size. This document does not define
  the vocabulary.
- **Subject**: the Ed25519 public key that signs the pack: the person key
  ([network.md](network.md) section 4) of a person pack, or the group key of
  a group pack. In JSON it is 64 lowercase hex characters.
- **Day**: a UTC day number, `floor(unix seconds / 86400)`.

## 3. Pack document

### 3.1 Fields

```json
{
  "block": {"hide": [{"from": "<subject ref>", "line": "<line id>"}], "people": ["<subject ref>"]},
  "charter": {"disclosure": "d0", "protocols": ["<match type>"], "rules": {"<match type>": "any|inside|outside"}, "weekly_cap": 3},
  "consent": {"approved_at": "<time>", "descriptor_set": "<hex32>", "statement": "<hex32>"},
  "created": "<time>",
  "credential": {"format": "biscuit-v3", "log": {"entry_signature": "<hex64>", "hashes": ["<hex32>"], "index": 0, "join": {"index": 0, "salt": "<hex16>"}, "tree_size": 1}, "token": "<base64url>"},
  "deny": {"domains": ["<host>"], "nodes": ["<node id>"], "rors": ["<ROR ID>"]},
  "expires": "<time>",
  "facts": [{"arg": <concept|enum|null>, "kind": "<fact kind>", "value": <enum|integer>}],
  "kind": "person|group",
  "lines": {"offers": [<line>], "wants": [<line>]},
  "readings": [{"concepts": [<concept>], "confidence": "low|med|high", "kind": "<reading kind>", "text": "<text>"}],
  "reply_key": "<hex32 X25519>",
  "schema": "anagram.pack.v1",
  "signature": "<hex64>",
  "subject": "<hex32 Ed25519>",
  "teasers": ["<text>"],
  "topics": [<concept>],
  "version": <integer>,
  "vocab": "<id>"
}
```

All 19 fields are required. A receiver must refuse a pack with any other
field (`bad_message`).

| Field | Rule |
| --- | --- |
| `schema` | `anagram.pack.v1` (section 10 for other versions) |
| `kind` | `person` or `group` |
| `subject` | The subject key (section 2) |
| `version` | Integer from 1 to 2^53 - 1. It rises with each pack of this subject (section 8) |
| `created` | Time of signing |
| `expires` | Later than `created`, and at most `created` + 30 days |
| `vocab` | Matches `^[a-z0-9][a-z0-9._:-]{0,31}$` |
| `consent` | Section 3.2 |
| `credential` | Section 5 |
| `charter` | Section 3.3 |
| `lines` | Section 3.4 |
| `teasers` | 0 to 3 texts of 1 to 100 code points. Must be empty unless the `matching` descriptor has `card_option` `b` (default `a`: empty) |
| `readings` | Section 3.5 |
| `facts` | Section 3.6 |
| `topics` | 0 to 64 concepts, ascending, no repeats |
| `deny` | Section 3.7 |
| `block` | Section 3.8 |
| `reply_key` | The X25519 public key to which the enclave seals this person's slots (sections 6 and 7 of [enclave-messages.md](enclave-messages.md)). It must be a valid non-low-order X25519 point (low-order keys that yield an all-zero shared secret are refused with `bad_message`, for packs, covers and withdrawals alike). The app must make a new random key for each subject. It must not reuse a device key, the person key or a key of another use. The app keeps one reply key for a subject and changes it only after a withdrawal or a suspected compromise. The slot of day D uses the reply key of the pack, cover or withdrawal that was current at the cut of day D ([enclave-messages.md](enclave-messages.md) section 6.5). The app keeps each old reply private key for 14 days |
| `signature` | Section 4 |

### 3.2 Consent

```json
{"approved_at": "<time>", "descriptor_set": "<hex32>", "statement": "<hex32>"}
```

- `descriptor_set`: the descriptor set hash ([enclave-trust.md](enclave-trust.md)
  sections 3.2 and 3.6) of the release that the person approved. It must
  equal the descriptor set hash of the instance that opens the pack.
- `statement`: the SHA-256 of the UTF-8 bytes of the consent statement that
  the app showed. The `consent_statement` of the `matching` descriptor
  fixes the statement. The v1 statement is:

  > Anagram matches you inside a sealed service that runs our published code; other people see your name only after you both say yes.

- `approved_at`: the time when the person approved the pack content (the
  whole pack once, as a standing consent). It must be at or before
  `created`.

The consent does not name a measurement. An upgrade with the same descriptor
set needs no new consent. The HPKE `info` of the
upload binds each upload to one attestation document, so to one measurement
([enclave-messages.md](enclave-messages.md) section 3).

The app signs a new pack each day with no click from the person. A change
that **narrows** the pack (fewer lines, a narrower scope, a new deny or
block entry) applies at once. A change that **widens** it needs the
person's approval in the app before the app signs it; `approved_at` then
changes. The enclave cannot tell a narrowing from a widening; this rule is
for the app.

### 3.3 Charter

```json
{"disclosure": "d0", "protocols": ["method_help", "research_fit"], "rules": {"method_help": "any", "research_fit": "outside"}, "weekly_cap": 3}
```

- `protocols`: 1 to 6 match types, ascending, no repeats. Match types:
  `co_supervision`, `data_material_share`, `instrument_access`,
  `method_help`, `replication`, `research_fit`. A group pack may name only
  `co_supervision`, `data_material_share` and `instrument_access`.
- `rules`: exactly one entry for each protocol: `any`, `inside` (only peers
  of my node) or `outside` (only peers of other nodes).
- `weekly_cap`: 1 to 10. The most proposals that the person gets in 7
  days. The person chooses it; the app's default is 3. The enclave uses
  the smaller of this value and `weekly_cap_max` of the `matching`
  descriptor (the network maximum, [enclave-trust.md](enclave-trust.md)
  section 3.6; [enclave-messages.md](enclave-messages.md) section 6.5).
  A larger value than the maximum is not an error: the
  person may keep one value across networks.
- `disclosure`: always `d0`. No other value exists in v1.

### 3.4 Lines

```json
{"class": "method", "concepts": [101, 2044], "id": "o01", "scope": "both", "text": "Single-particle cryo-EM data collection", "types": ["research_fit"]}
```

- `lines.offers` and `lines.wants`: each 0 to 10 lines for a person pack, 0
  to 20 for a group pack. A pack has at least one line in total.
- `id`: `o01` to `o20` in `offers`, `w01` to `w20` in `wants`. Each list is
  in ascending `id` order with no repeats. IDs need not be dense.
- `class`: `data`, `instrument`, `material`, `method`, `problem`,
  `replication`, `skill` or `supervision`.
- `concepts`: 0 to 8 concepts, ascending, no repeats.
- `text`: text of 1 to 140 code points, written or approved by the person.
- `scope`: `inside`, `outside` or `both`.
- `types`: 1 to 6 match types, ascending, no repeats (group pack: section
  3.3 list only).

A line has **no vector**. The enclave embeds the text itself with the
embedding model of the measurement.

### 3.5 Readings

0 to 40 readings for a person pack, 0 to 20 for a group pack, in the order
that the app ranks them.

- `kind`: `asks`, `negative_result`, `offers`, `stage`, `stuck_on`,
  `tacit_skill` or `trajectory`.
- `text`: text of 1 to 200 code points.
- `confidence`: `low`, `med` or `high`.
- `concepts`: 0 to 8 concepts, ascending, no repeats.

### 3.6 Facts

Typed answers for the protocol questions. 0 to
150 facts. Each fact is `{"arg", "kind", "value"}`:

| `kind` | `arg` | `value` |
| --- | --- | --- |
| `has_method` | concept | `yes`, `no` |
| `has_used` | concept | `yes`, `no` |
| `solved` | concept (a problem class) | `yes`, `no` |
| `has_instrument` | concept | `yes`, `no` |
| `has_material` | concept | `yes`, `no` |
| `has_data` | concept | `small`, `medium`, `large` |
| `uses_method` | concept | `yes`, `no` |
| `supervises_in` | concept | `yes`, `no` |
| `access_mode` | `visit`, `send_samples`, `remote` | `yes`, `no` |
| `open_to` | `collab`, `advice`, `access`, `share`, `replication`, `co_supervise` | `yes`, `no`, `not_now` |
| `stage` | null | `idea`, `early`, `ongoing`, `mature` |
| `terms` | null | `open`, `agreement`, `none` |
| `timeline_months` | null | integer 0 to 60 |
| `lead_time_weeks` | null | integer 0 to 104 |
| `capacity_months` | null | integer 0 to 60 |
| `capacity_students` | null | integer 0 to 20 |

Order: ascending by `kind` (Unicode code point order), then by `arg` (null
first; integers by value; strings by code point). No two facts have the
same (`kind`, `arg`).

Facts that the protocols need from the credential (the node kind, and
whether a peer is "independent of my node") are not facts of the pack. The enclave
reads them from the credential and the roster.

### 3.7 Deny

```json
{"domains": ["rival.example"], "nodes": ["node-<32 hex>"], "rors": ["05abc1234"]}
```

- `rors`: ROR IDs in the bare form `^0[a-z0-9]{6}[0-9]{2}$`.
- `domains`: verified email domains, lowercase, 1 to 64 characters, in the
  form `label.label` (each label 1 to 63 characters of `a-z`, `0-9` and `-`,
  not at the start or end of a label; the last label 2 to 63 letters).
  Internationalised names use their A-label form.
- `nodes`: node IDs ([network.md](network.md) section 2.2).
- Each list is ascending with no repeats. **At most 32 entries in total**
  (a long deny list could act as an allow list for one institution; the
  anonymity set of the enclave is the other half of that rule).

The enclave drops a pair when either deny list names the peer's ROR ID,
verified domain or node. Deny is never output.

### 3.8 Block

- `people`: subject references, ascending, no repeats. A subject reference
  is `person:<64 hex>` (a subject key) or `pid:<32 hex>` (a person ID of
  [identity.md](identity.md), which the enclave reads from the peer's
  credential).
- `hide`: "do not show line L to X" rules, `{"from": <subject ref>, "line":
  <line id>}`. `line` must be the ID of a line of this pack. The list is
  ascending by (`from`, `line`) with no repeats.
- `people` and `hide` together hold at most 128 entries.

The enclave drops a pair when either side blocks the other.
A `hide` rule removes the line from the pair's input. Block is never
output.

## 4. Signature

```
signature = Ed25519(subject private key, u8(len(tag)) || tag || canonical_json(pack without "signature"))
tag       = "anagram/v1/pack/sign"
```

The signature covers every other field, the credential too. A receiver must
check it with `subject` (`bad_signature`). The subject of a person pack is
the person key; the app keeps it in the device keychain
([network.md](network.md) section 4).

## 5. Member credential in the pack

```json
{"format": "biscuit-v3", "log": {"entry_signature": "<hex64>", "hashes": ["<hex32>", ...], "index": 41, "join": {"index": 7, "salt": "<hex16>"}, "tree_size": 9001}, "token": "<base64url, no padding>"}
```

- `log`: an RFC 9162 inclusion proof of the `member_credential` log entry of
  this credential ([network.md](network.md) section 6.5;
  [enclave-trust.md](enclave-trust.md) section 2.3) in the enclave
  transparency log. `entry_signature` is the `signature` of that entry. The
  receiver rebuilds the entry from the credential (hash, `expires`, node),
  the node's current roster key (`signer`) and `join`, checks the entry signature,
  and proves inclusion of `canonical_json(entry)` as the leaf data.
  `tree_size` from 1 to 2^53 - 1, `index` below `tree_size`, `hashes` at
  most 32 entries of 32 bytes in hex.
- `join`: `{"index", "salt"}` of the member's join entry
  ([network.md](network.md) sections 6.5 and 6.7). `index` is from 0 to
  `index`, and `salt` is 16 bytes in hex. When `join.index` equals
  `index`, the entry is the join entry and `member` is
  `tagged_hash("anagram/v1/net/member-join", subject ‖ salt)`; else the
  entry is a renewal and `member` is null. The enclave also checks the
  join entry itself and the node's limit of new members (network.md 6.2
  step 8a). A pack with no `log`, or with a bad
  entry signature or proof, gives `bad_credential`. The receiver must trust the root of the tree at
  `tree_size` by the rules of [enclave-trust.md](enclave-trust.md) (a
  cosigned checkpoint, or a root computed from the log tiles under a
  cosigned checkpoint). The enclave accepts any `tree_size` up to the tree
  size of the latest cosigned checkpoint that it has (enclave-trust.md
  7.1).

The credential must name the same subject and kind as the pack, the network
of the release, and a node of the current roster. It must not be expired at
intake. It lives at most 24 hours, so the daily upload carries a fresh one.
A pack whose credential later expires stays stored but is **dormant**: the
enclave does not use it for a new proposal or a reveal until a pack with a
valid credential arrives (section 8).

## 6. What must not be in a pack

The app must not put any of these in any field of a pack:

- the reveal card: name, lab, institution, email address, ORCID iD;
- raw documents, item text, quotes, source excerpts, file names, item IDs,
  item URLs, email bodies, or any text that another person wrote;
- readings or lines whose basis is only `private` items;
- evidence spans, embeddings or other vectors;
- keys or seeds other than `reply_key` and `subject`;
- free text other than line text, teaser text and reading text.

A field outside the schema is refused. The other items of this list are
rules for the pack build on the app; its tests scan
built packs for them.

## 7. Size budget

A pack has two limits. A receiver must check both, and a sender must not
send a pack that breaks one.

1. The canonical JSON of the whole pack is at most **49,152 bytes** (48 KiB)
   (`too_large`). It travels in the 65,536-byte upload envelope
   ([enclave-messages.md](enclave-messages.md) section 3).
2. The size (section 2) of each field below is at most its budget
   (`too_large`):

| Field | Person | Group |
| --- | --- | --- |
| `credential` | 3,584 | 3,584 |
| `charter` | 1,024 | 1,024 |
| `lines` | 8,192 | 16,384 |
| `teasers` | 512 | 512 |
| `readings` | 11,264 | 5,632 |
| `facts` | 9,216 | 9,216 |
| `topics` | 1,024 | 1,024 |
| `deny` | 1,536 | 1,536 |
| `block` | 6,144 | 6,144 |
| **Sum** | **42,496** | **45,056** |

The other fields (header, consent, keys, signature) have fixed forms and use
less than 1,024 bytes. So a pack that obeys the budgets is below the cap.

The count limits and the byte budgets both apply. With long or non-ASCII
text, a budget can bind before the count: for example, about 80 entries of
`block` fit, not 128. The app must then drop the entries that it ranks
lowest. The vector `person_at_budget` has every count at its limit with
the longest text that fits each budget; its size is in the vector file.

The `credential` budget is 3,584 bytes (an early design said 3 KB). A Biscuit
token of about 700 bytes, the entry signature, the `join` and a proof of
32 hashes need about 3,320 bytes.
32 hashes cover a log of 2^32 entries.

### 7.1 Order of checks

A receiver checks a pack in this order and refuses with the first code
that applies:

1. byte length at most 49,152 (`too_large`);
2. canonical JSON, one object (`bad_message`);
3. `schema` accepted (`unsupported_schema`);
4. exactly the fields of section 3.1 (`bad_message`);
5. header, consent and times (sections 3.1, 3.2; section 8 for age) (`bad_message`; `expired` if `created` is more than 48 hours old);
6. each field of sections 3.3 to 3.8 (`bad_message`);
7. budgets (`too_large`);
8. signature (`bad_signature`);
9. credential (section 5; `bad_credential`, `expired`, `revoked`, `stale_roster`; [network.md](network.md) section 6.4);
10. state: version, rate and tombstone (section 8; `old_version`, `rate_limited`, `tombstoned`).

The vectors give one refused pack for most codes of this list.

## 8. Upload, refresh and retention

- **Daily upload.** The app uploads one pack each UTC day at a random
  minute, chosen again each day, also when nothing changed.
  With matching off it uploads a cover instead
  ([enclave-messages.md](enclave-messages.md) section 7.2). Each
  upload has a new `version`, a new `created` and a fresh credential. The
  enclave recomputes matches only after a material change of a line; the
  node cannot see which uploads changed.
- **Why every day.** The credential lasts at most 24 hours (section
  5), so yesterday's pack is dormant today: it gives no new proposal and
  no reveal. The daily upload with a fresh credential keeps the pack live.
  It also gives the day's slot: the enclave makes a slot for each subject
  with an upload in the 48 hours before the cut
  ([enclave-messages.md](enclave-messages.md) section 6.5), so one upload
  a day keeps a live person in every batch, with one missed day of margin.
- **Version.** `version` must be larger than the last version that the
  enclave accepted for the subject, from any pack or withdrawal
  (`old_version`). The app should use `max(last + 1, unix milliseconds of
  created)`, so that a new device or a restore from backup still gives a
  larger number.
- **Rate.** The enclave accepts at most one pack or cover for each subject
  in each UTC day (`rate_limited`). The exact same upload bytes again get the same
  receipt ([enclave-messages.md](enclave-messages.md) section 8).
- **Age.** `created` must be at most 5 minutes after the enclave time
  (`bad_message`) and at most 48 hours before it (`expired`).
- **Tombstones.** After a withdrawal, a removal or a deletion, the enclave
  keeps a tombstone ([enclave-trust.md](enclave-trust.md)). A pack with
  `version` at or below the tombstone version, or with `created` at or
  before the tombstone time, gives `tombstoned`. After a withdrawal, a new
  pack must also have `consent.approved_at` after the tombstone time (a new
  consent). [enclave-trust.md](enclave-trust.md)
  section 6.3 uses these age and tombstone rules as written here.
- **Retention.** The enclave keeps the newest accepted pack of each subject
  and deletes the older one at once. It deletes the pack at `expires`, so 30
  days after the last upload at most, and keeps a
  tombstone.
- **Offline.** An app that was offline uploads at the next chance. It does
  not upload the missed days.

## 9. Known object (`anagram.known.v1`)

### 9.1 Byte layout

The known object is binary. All integers are big-endian.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 16 | `schema`: the ASCII bytes `anagram.known.v1` |
| 16 | 32 | `subject`: the subject key (the same key as the pack) |
| 48 | 8 | `version`: `u64`, 1 to 2^53 - 1 |
| 56 | 8 | `created`: `u64`, Unix seconds |
| 64 | 32 | `vocab`: the vocabulary ID in ASCII, then zero bytes to 32 bytes |
| 96 | 4 | `count`: `u32`, 0 to 5,000 |
| 100 | 64 × `count` | entries, ascending by `tag`, no two with the same `tag` |
| 100 + 64 × `count` | 64 | `signature` |

Entry (64 bytes):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 32 | `tag`: section 9.2 |
| 32 | 32 | 8 concept slots, each `u32`. Used slots come first, in ascending order, no repeats. An unused slot is `0xFFFFFFFF`. So a concept is never 4294967295 in a known entry |

The concepts of an entry are the topics of the joint work with that person,
for the "same reason" test of the known check.

```
signature = Ed25519(subject private key, u8(len(tag)) || tag || all bytes before the signature)
tag       = "anagram/v1/known/sign"
```

The largest known object is 100 + 320,000 + 64 = 320,164 bytes. It travels
in the 393,216-byte known envelope ([enclave-messages.md](enclave-messages.md)
section 3).

A receiver refuses: a wrong `schema` bytes value, a length that does not
equal 164 + 64 × `count` (`bad_message`), `count` above 5,000
(`too_large`), entries out of order or with bad slots, a `vocab` that is
not an ID (`bad_message`), and a bad signature (`bad_signature`).

The enclave keeps the newest accepted known object of a subject only while
the subject has a live pack (accepted, not dormant). For a
subject with no live pack, a well-formed known upload gets `accepted` and
the enclave keeps nothing, so the weekly known upload of an app with
matching off acts as a cover. The enclave deletes the known object with
the pack. It uses the concept slots only while `vocab` equals the `vocab`
of the subject's current pack; the tags it uses always.

### 9.2 Tags

```
tag = HMAC-SHA256(key = the 16 ASCII bytes "anagram/v1/known", message = UTF-8 of the identifier)
```

Identifiers:

| Kind | Identifier |
| --- | --- |
| Person key | `person:` + 64 lowercase hex characters of the subject key |
| Person ID | `pid:` + 32 lowercase hex characters |
| Email address | `email:` + the address after this normalisation: remove spaces, tabs, CR and LF at the start and end; convert only the ASCII letters A to Z to lowercase; leave all other characters as they are. The app converts an internationalised domain to its A-label form first |

The HMAC key is public (a review asked for the salt of the email hash; the
answer is that there is no secret salt). The tag only keeps the plain
identifiers out of a memory dump. **Residual:** a person who breaks the TEE
can test guessed email addresses against the tags. Nobody else opens the
known object.

The enclave compares the tags of my known object with the tags of the
peer's person key, the peer's person ID and the peer's verified email tags
from the peer's credential ([network.md](network.md) section 6.2). People
met through Anagram go into the known object by their person key, which the
reveal gives ([enclave-messages.md](enclave-messages.md) section 6.4).

### 9.3 Upload and replay

- The app uploads one known object each week on a fixed weekday:
  `weekday index = tagged_hash("anagram/v1/known/day", subject)[0] mod 7`,
  where the weekday index of day number D is `D mod 7`. It uploads also
  when nothing changed, and uploads an object with `count = 0` if the person
  knows nobody yet.
- `version` must be larger than the last accepted known version of the
  subject (`old_version`; a separate counter from the pack). At most one
  known object is accepted in any 6 days (`rate_limited`).
- `created` obeys the age rule of section 8. A known object with `created`
  at or before a tombstone time gives `tombstoned`.

## 10. Versions and schema migration

- A receiver must refuse a `schema` that the release does not accept
  (`unsupported_schema`).
- A new pack version (`anagram.pack.v2`) comes with a release. During the
  **overlap** of that release with the one before it (7 days), the enclave accepts both versions. `accepted_schemas` of the
  `matching` descriptor lists the accepted schemas.
- The app changes to the new version at its next daily upload after it
  accepts the new release. It keeps the same `version` counter.
- After the overlap, a stored pack of the old version is dormant until the
  app replaces it. The enclave does not convert packs.
- A new version may add, remove or change fields. It must have its own
  budgets and its own vectors. It must keep sections 4, 6 and 8.
- The known object follows the same rules with the `schema` bytes.

## 11. Group pack

A group pack (`kind = group`) describes what a node (a lab or a university)
offers and wants.

- The designated contact's app builds it from node-space items only, and
  signs it with the **group key**: an Ed25519 key that this app makes and
  keeps. The node issues a member credential of kind `group` over the group
  key ([network.md](network.md) section 6.3).
- At most one group subject for each node is live. When the node issues a
  group credential to a new key, the enclave treats the old group subject as
  removed ([network.md](network.md) section 8.3).
- Handover to a new designated contact: the new contact's app makes a new
  group key; the node issues a new group credential and sends a
  `member_removed` control event (reason `group_handover`) for the old group
  subject. Open proposals of the old group subject end ("this proposal
  ended"). The new subject starts with no history.
- Limits differ from a person pack (sections 3.3, 3.4, 3.5 and 7).

## 12. Field labels

As in [matching.md](matching.md) section 6: for every field, `readers` is
none and `via` is the match protocols of the enclave. `teasers` has readers
`@proposal` only with `card_option` `b`. The reveal card is not a
pack field ([enclave-messages.md](enclave-messages.md) section 5.2).

## 13. Tags

| Tag | Use |
| --- | --- |
| `anagram/v1/pack/sign` | Signature of a pack |
| `anagram/v1/known/sign` | Signature of a known object |
| `anagram/v1/known` | HMAC key of a known tag (ASCII bytes) |
| `anagram/v1/known/day` | Weekday of the known upload |

These tags are not in the locked registry of [formats.md](formats.md)
section 3.2, as the room tags.

## 14. Test vectors

[vectors/pack.json](vectors/pack.json) holds: the descriptor documents and
the descriptor set hash that the packs name; a small person pack; a person
pack and a group pack at their budgets, with the size of each field; the
context of the checks (time, roster keys, trusted log roots); the
`member_credential` log entry; known tags; a small known object in hex; the
rule, size and SHA-256 of a known object with 5,000 entries; and refused
packs with their codes (over the cap, over a budget, an extra field, a bad
signature, an unknown schema, 33 deny entries, unsorted topics, a control
character, a teaser under card option `a`, a pack older than 48 hours, no log proof,
an expired credential, the credential of another subject, a float, and JSON
that is not canonical).

Keys come from `SHA-256("anagram net vector seed: <label>")`;
`seed_labels` gives the label of each key. `times.T0` is the time of
the check context: the enclave's signed time at intake for every case,
unless a case gives its own `now`. A Biscuit
token comes from a random source (the key of the next block), so a verifier
checks the tokens of the file; it recomputes every other value.
`uv run python -m anagram.vectors.net.build spec/vectors` makes the file
again and keeps each token that still verifies.

## 15. Changes after the spec review (2026-11-25)

- The vocabulary, the consent statement, the card option and the accepted
  schemas come from the descriptors of enclave-trust.md section 3.6
  (sections 2, 3.1, 3.2, 10); the vector consent values are the real
  descriptor set hash and statement hash.
- A cover shares the daily rate of a pack (section 8).
- enclave-trust.md 6.3 now uses the age and tombstone rules of section 8
  as written.
- The reply key rule (section 3.1).
- A known object is kept only for a subject with a live pack (9.1).
- The section 3.1 example has `entry_signature`.
- The public HMAC key of the known tag is kept as is; the optional network
  ID in the key is not taken.
- On the re-check: the reply key of a slot can also come from a
  withdrawal, which now carries one (section 3.1; enclave-messages.md 6.5,
  7.1).

## 16. Changes after the first enclave slice (2026-11-25)

- The app uploads a fresh pack (or a cover) every day because a credential
  lasts 24 hours; this ties to the 48-hour slot rule of
  enclave-messages.md section 6.5 (section 8).

## 17. Changes after the conformance review (2026-11-25)

- `seed_labels` in pack.json (14).
- `times.T0` in pack.json is the time of the check context (14).
- The tree sizes that the enclave trusts for the log proof of a
  credential are those of enclave-trust.md 7.1 (5).

## 18. Changes for the weekly cap and the answer window (2026-11-26)

- `weekly_cap` is 1 to 10, chosen by the person, default 3; the enclave
  applies min(`weekly_cap`, `weekly_cap_max`) (3.3). The vectors do not
  change: their packs keep the value 3.
- The answer window of 21 days, the per-node proposal rule and the decline
  rule by match type do not change the pack format (enclave-messages.md
  5.3, 6.5; enclave-trust.md 7.1).

## 19. Changes after the review of the new-member limit (2026-11-26)

- The credential's `log` has `join`, the index and salt of the member's
  join entry, so the limit of new members counts people, not daily
  renewals (5; network.md 6.7). Vectors: every credential of `pack.json`
  has `join` and is a join entry, so the canonical hashes and sizes of the
  packs changed.
