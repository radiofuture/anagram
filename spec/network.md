# Network: roster, credentials, person key, control events

Status: draft, revised after the spec review of 2026-11-25 (section 13).
Licence: CC BY 4.0. Schema: [schemas/network.schema.json](schemas/network.schema.json).
Vectors: [vectors/network.json](vectors/network.json). Implementation:
`src/anagram/network/formats/roster.py` and `credential.py`; the vector
generator `src/anagram/vectors/net/` calls them.

Related documents: [pack.md](pack.md), [enclave-messages.md](enclave-messages.md),
[enclave-trust.md](enclave-trust.md) (the transparency log, witnesses,
signed time, tombstones, deletion), [identity.md](identity.md) (person IDs,
device keys, sign-in), [admission.md](admission.md) (person admission to a
node by invite).

## 1. Purpose and parties

The network is a set of admitted **nodes** (a lab, a university or one
person runs a node; it is a trust boundary). Each person is a member of one
node (v1) and has the **app**. Nodes do no matching: they admit members, issue member credentials, relay
fixed-size ciphertext to the matching enclave, and publish control events.

| Party | Key | Signs |
| --- | --- | --- |
| Roster operator (Radiofuture in v1) | roster key (Ed25519) | the roster chain, roster checkpoints, node credentials |
| Node | node key (Ed25519) | member credentials, the node's control chain, node requests |
| Person | person key (Ed25519, section 4) | packs, known objects, answers, withdrawals, credential requests |
| Designated contact of a node | group key (Ed25519) | the group pack |
| Enclave | output key ([enclave-trust.md](enclave-trust.md)) | receipts, slots |

This document defines what a verifier (the enclave, and later other nodes)
needs to decide whether a credential is valid now.

## 2. Identifiers and node record

### 2.1 Network ID

A network has an ID that matches `^[a-z0-9][a-z0-9.-]{0,62}$`, for example
`net.anagram.example`. The roster chain (section 3) fixes it in its first
event.

### 2.2 Node ID

```
node id = "node-" + hex(tagged_hash("anagram/v1/net/node-id", initial node key)[0:16])
```

The ID comes from the first key of the node, so it stays the same after a
key rotation (section 3.4).

### 2.3 Node record

```json
{"admin": "anagram-admin@lab-a.example.org", "affiliation": "Chen Lab, Example University",
 "domain": "lab-a.example.org", "id": "node-<32 hex>", "key": "<hex32>", "kind": "lab",
 "ror": "012345678", "url": "https://anagram.lab-a.example.org"}
```

| Field | Rule |
| --- | --- |
| `id` | Section 2.2 |
| `key` | The current node key |
| `affiliation` | The display affiliation: text of 1 to 200 code points ([pack.md](pack.md) section 2) |
| `domain` | The verified domain, as a deny domain ([pack.md](pack.md) section 3.7) |
| `ror` | A bare ROR ID, or null (an individual node can have none) |
| `kind` | `individual`, `lab` or `university` |
| `url` | The node's base URL, `https://` only |
| `admin` | A contact address of the node admin, 3 to 254 characters. It should be a role address: the roster is public |

## 3. Network roster

### 3.1 The roster chain

The roster is a control chain (section 8) with the chain name `roster`.
Its events, applied in order, give the roster state: the network ID, the
current roster key, the nodes (records), the removed nodes, the bans and
the network policy. The roster operator signs every event with the current
roster key.

The first event (`seq` 0) is `roster_created` with body `{"network",
"roster_key"}`. The app and the enclave release pin the network ID and the
first roster key (`network` and `roster_key` of the `matching` descriptor,
[enclave-trust.md](enclave-trust.md) section 3.6).
A verifier refuses a chain whose first event does not match the pin.

### 3.2 Roster events

| Kind | Body | Effect |
| --- | --- | --- |
| `roster_created` | `{"network", "roster_key"}` | Section 3.1. Only at `seq` 0 |
| `node_admitted` | `{"endorsement", "endorser", "node"}` | Adds the node (section 3.3) |
| `node_updated` | `{"endorsement", "endorser", "node"}` | Replaces the record of an admitted node. `id` and `key` must not change (a key change is `node_key_rotated`). `endorser` and `endorsement` as in 3.3; the roster operator should use `"roster"` and null |
| `node_key_rotated` | `{"chain_seq", "new_key", "node", "proof"}` | Section 3.4 |
| `node_removed` | `{"node", "reason"}` | The node is removed. `reason`: `abuse`, `compromised`, `left`, `other` |
| `roster_key_rotated` | `{"new_key"}` | The old roster key signs this event; the next event must have the new key |
| `ban` | `{"reason", "subject"}` | Bans a subject in the whole network. `subject` is a subject hash (section 8.2). `reason`: `abuse`, `other` |
| `unban` | `{"subject"}` | Ends a ban |
| `policy_updated` | `{"effective", "policy"}` | The network policy (section 9) from the time `effective` |

### 3.3 Node admission

Two ways in. Both end in one `node_admitted`
event that the roster key signs.

- `endorser = "roster"`: Radiofuture admits the node. `endorsement` is null.
- `endorser = <node id>`: an admitted node, not removed, invites the node.
  `endorsement = Ed25519(inviter's node key, tagged_message("anagram/v1/net/sign/endorsement",
  canonical_json(node record)))`. The roster operator adds the event only if
  the inviter is under the quota of the policy (`node_invites_per_quarter`
  in a calendar quarter, default 2) and Radiofuture did not
  veto it.

Before it signs, the roster operator checks: (1) **domain control**: a DNS
TXT record at `_anagram.<domain>` with the value `anagram-node=<node key
hex>`; (2) the ROR ID, if any, belongs to the domain; (3) one human check.
A verifier checks: the record is valid (section 2.3),
`id` equals the node ID of `key`, the ID is new, and the endorsement
signature. The roster operator also writes each `node_admitted` event to
the enclave transparency log as a `node_admission` entry
([enclave-trust.md](enclave-trust.md) section 2.3), signed by the
roster key. Its `record_digest` is the event hash (section 8.2) of the
`node_admitted` event: the **admission record** that enclave-trust.md names
is that event, with the endorsement in its body. The invite tree is the set of `endorser` fields.

### 3.4 Node key rotation

The node makes a new key and signs the proof with its **old** key:

```
proof = Ed25519(old node key, tagged_message("anagram/v1/net/sign/key-proof",
                canonical_json({"new_key": <hex32>, "node": <node id>})))
```

The roster operator adds `node_key_rotated` with `chain_seq` = the `seq` of
the last event of the node's own control chain at the rotation (−1 if the
chain is empty). Events of the node chain with `seq` ≤ `chain_seq` are
signed by the old key; events with `seq` > `chain_seq` by the new key.

After the rotation, a verifier checks member credentials only with the new
key. The node must issue new credentials at once; the old ones stop
verifying. (A compromised old key can then sign nothing that a verifier
takes.)

### 3.5 Roster checkpoint

```json
{"head": "<hex32 event hash>", "kind": "roster_checkpoint", "network": "net.anagram.example",
 "schema": "anagram.net.roster_checkpoint.v1", "seq": 7, "signature": "<hex64>",
 "signer": "<hex32 roster key>", "time": "<time>"}
```

- `seq` and `head`: the `seq` and the event hash of the last event of the
  roster chain.
- `signer`: the current roster key. Tag: `anagram/v1/net/sign/roster-checkpoint`.
- The roster operator signs a new checkpoint at each change of the roster
  head and at least every 15 minutes, also with no change, and serves the
  newest one (section 8.7).
- **Logged.** Each roster checkpoint is also a
  `roster_checkpoint` entry of the enclave transparency log
  ([enclave-trust.md](enclave-trust.md) section 2.3): the document above is
  the entry, so it has `kind`. The roster operator writes it to the log
  when it signs it. The enclave uses a roster checkpoint only when that
  entry is in a log checkpoint with a quorum. So the roster operator cannot
  show one roster head to the enclave and another to the public; a fork of
  the roster chain also shows as two events with one `seq` (section 8.6).

**Freshness.** A verifier must hold a checkpoint whose `time` is at most
`roster_max_age` (policy; default and maximum 3,600 seconds) before its
signed time and at most 300 seconds after it, and must have applied the
roster chain exactly up to `seq` with the same `head`. If not, it refuses
every credential with `stale_roster` until it has one (fail closed: a
roster checkpoint at most 1 hour old).

## 4. Person signing key

- The **person key** is an Ed25519 key of the person, not of a device and
  not of a node. It is the subject of the person's pack, known object,
  answers and withdrawals, and of the member credential.
- The app makes it at the first credential request. It keeps it in the
  device keychain with the other person keys, moves it to a new device with
  them, and backs it up with them (guardians recovery). The person keys
  package and the key backup ([vault.md](vault.md) section 11.4,
  [identity.md](identity.md) section 12) must carry it as the key
  `person-ed25519`; that change to those formats is not part of this
  document.
- The person key is not a device key and not the `reply_key` of a pack.
- **Binding at the node.** At the first credential request (section 6.6)
  the node records the binding (person ID → person key). Later requests
  must use the same key. A change of the person key (only after a
  compromise) needs the node admin: the node sends `member_left` with reason
  `key_changed` for the old subject (section 8.4) and records the new key.
  The new key is a new subject in the enclave, with no history.
- **Moving to another node**: the person joins the new
  node by invite ([admission.md](admission.md)) and requests a credential
  there with the **same** person key. The old node sends `member_left`
  with reason `moved`. The subject, its pack history, its open proposals and
  its known object stay; the slots go to the new node from the next pack
  (section 8.4). The box and the index stay on the app.

## 5. Credentials

Credentials are **Biscuit** tokens (the default; section 10 gives the
fallback), format
`biscuit-v3`: the Biscuit specification version 3 (biscuit-auth.org,
`SPECIFICATIONS.md`), Ed25519 signatures, protobuf serialisation, base64url
without padding in JSON. Each Anagram credential is **one authority block**
with the facts of section 6.1 or 7.1 and exactly one check. Attenuation
blocks and third-party blocks are not used in v1; a verifier refuses a token
with more than one block (`bad_credential`).

A Biscuit token is not deterministic (each block has a fresh key for the
next block), so two tokens with the same facts differ. The verifier checks
the facts, not the bytes.

The fallback format `anagram-json-v1` (section 6.3) has the same facts as
a member credential in signed canonical JSON. It exists so that a change
away from Biscuit needs no new design. The network policy names the
accepted formats; v1 accepts `biscuit-v3` only. A node credential has no
JSON fallback in v1 (Biscuit only).

## 6. Member credential

### 6.1 Biscuit facts

The authority block of a member credential has exactly these facts and
this one check, in this order, and nothing else: no other fact, no rule,
no other check. A verifier compares the whole block with
the block rebuilt from the facts that it read (section 6.2 step 4):

```
anagram("member_credential", 1);
network("<network id>");
node("<node id>");
subject(hex:<32 bytes: person key or group key>);
kind("person");
pid("pid:<32 hex>");
email_tag(hex:<32 bytes>);
control_head(<integer>);
issued(<RFC 3339 date>);
expires(<RFC 3339 date>);
check if time($t), $t < <expires date>;
```

| Fact | Term type | Count | Rule |
| --- | --- | --- | --- |
| `anagram` | string, integer | 1 | Exactly `("member_credential", 1)` |
| `network` | string | 1 | The network ID |
| `node` | string | 1 | The issuing node's ID |
| `subject` | bytes (32) | 1 | The person key, or the group key |
| `kind` | string | 1 | `person` or `group` |
| `pid` | string | 1 if `person`, 0 if `group` | The member's person ID ([identity.md](identity.md)), `pid:<32 hex>` |
| `email_tag` | bytes (32) | 0 to 3 if `person`, 0 if `group` | The known tag ([pack.md](pack.md) section 9.2) of an email address that the node verified for this member. The `email_tag` facts are in ascending byte order: the rebuild of section 6.2 sorts them, so a block with another order fails the compare |
| `control_head` | integer | 1 | The number of events in the node's control chain when it issued the credential |
| `issued` | date | 1 | The time of issue |
| `expires` | date | 1 | Later than `issued`, by at most `credential_max_life` (policy; default and maximum 86,400 seconds) |

The check is `check if time($t), $t < E;` where `E` equals the `expires`
date. The root key is the node key of `node` in the roster.

Example (the vector `member_credential.datalog`):

```
anagram("member_credential", 1);
network("net.anagram.example");
node("node-<32 hex>");
subject(hex:742f874ae3cdb17ce0eb4c76db88e677ee71c760fa0844988da27f1262a55030);
kind("person");
pid("pid:<32 hex>");
email_tag(hex:<64 hex>);
control_head(2);
issued(2026-11-25T11:00:00Z);
expires(2026-11-26T11:00:00Z);
check if time($t), $t < 2026-11-26T11:00:00Z;
```

### 6.2 Verification

A verifier (the enclave at intake and again at reveal) does, in order:

1. Decode base64url. Read the `node` fact without verification to choose
   the root key; the node must be in the roster (`bad_credential`).
2. Verify the token with the node's **current** roster key as the root
   (`bad_credential`). The token has exactly one block (`bad_credential`).
3. Query each fact of 6.1 and check its count and type; `expires −
   issued` is more than 0 and at most `credential_max_life`
   (`bad_credential`).
4. Rebuild the block source of 6.1 from these facts and compare it with
   the source of the token's block, both printed by the Biscuit library.
   Any other fact, any rule, a missing check or another check gives
   `bad_credential`. (So a fact derived by a rule, or a check that fails on
   purpose, cannot change the result or the code.)
5. `issued` is at most 300 seconds after the signed time
   (`bad_credential`).
6. Authorise with the fact `time(<signed time>)` and the policy `allow if
   true`; then check `signed time < expires` from the fact, and `issued ≥
   signed time − credential_max_life`. A failure means the credential is
   expired (`expired`).

**Run limits.** Every Datalog run of steps 3 and 6 (the authorisation and
each query) has the limits: at most 1,000 facts, at most 100 iterations,
and at most 60 seconds of time. A run that hits a limit gives
`bad_credential`. The limits must not depend on the speed of the computer
for a valid token: a valid member credential needs fewer than 30 facts and
2 iterations. (The Biscuit libraries stop a run after 1 ms of wall-clock
time by default. On a busy computer that made a valid credential give
`expired`, or made the check fail with no receipt. This was the cause of
the flaky day-19 receipt in the conformance review.)
7. `network` is the network of the release; `subject` and `kind` equal the
   pack's (or the cover's) (`bad_credential`).
8. The log proof ([pack.md](pack.md) section 5) of the entry of 6.5
   (`bad_credential`).
8a. Join and new-member limit (section 6.7): the proof's
   `join` names a join entry of this node and subject, made after the
   member's last removal or exit at this node (`bad_credential`), whose
   join rank is at most `new_members_per_month` of the policy in force at
   the signed time (`issuance_limit`).
9. Network state (section 8.6): the roster is fresh and has no gap or fork;
   the node is not removed; the node chain is applied up to `control_head`
   with no gap or fork; the credential is not revoked; the subject is not
   banned; the node did not remove the member, or the member did not leave,
   after `issued` (`stale_roster` or `revoked`).

### 6.3 Fallback format `anagram-json-v1`

```json
{"control_head": 2, "email_tags": ["<hex32>"], "expires": "<time>", "issued": "<time>",
 "kind": "person", "network": "<network id>", "node": "<node id>", "pid": "pid:<32 hex>",
 "schema": "anagram.member_credential.v1", "signature": "<hex64>", "subject": "<hex32>"}
```

- The same facts and rules as 6.1. `pid` is null for a group credential.
  `email_tags` is ascending with no repeats.
- `signature = Ed25519(node key, tagged_message("anagram/v1/net/sign/member-credential",
  canonical_json(document without "signature")))`.
- The credential bytes are the canonical JSON of the document; in the pack
  they are base64url without padding. Expiry: the verifier time must be
  before `expires` (`expired`).

### 6.4 Group credential

A credential with `kind("group")`, no `pid` and no `email_tag`, over the
group key of the node's designated contact ([pack.md](pack.md) section 11).
A node has at most one live group subject: when the enclave accepts a group
pack with a credential of a new group subject of the same node, it treats
the older group subject as removed.

### 6.5 Credential hash and log entry

```
credential hash = tagged_hash("anagram/v1/net/member-credential", credential bytes)
```

The credential bytes hold a signature by the node key, so the hash is not
the hash of a low-entropy value and needs no separate salt (the concern of
[enclave-trust.md](enclave-trust.md) section 2.8).

At issue, the node writes a `member_credential` entry to the enclave
transparency log (so a node cannot mint members without a visible
record). [enclave-trust.md](enclave-trust.md) section 2 owns the entry form,
the log, its checkpoints and witnesses. For this kind the entry is:

```json
{"credential_hash": "<hex32 credential hash>", "expires": "<time: the credential's expires>",
 "kind": "member_credential", "member": "<hex32 join commitment> | null", "node_id": "<node id>",
 "schema": "anagram.enclave.member_credential.v1",
 "signature": "<hex64>", "signer": "<hex32 node key>"}
```

**Join entry.** The first credential of a person key at the node, and the
first after a `member_removed` or `member_left` (not `moved`) of that
person at the node (section 8.4), is a join entry. The node makes a random
16-byte `salt` and writes

```
member = tagged_hash("anagram/v1/net/member-join", person key ‖ salt)
```

Every later credential of the member is a renewal, with `member` null. The
log proof of each credential names the member's join entry (6.6, `join`),
so the verifier rebuilds `member` of a join entry from the subject and the
salt.

`signature = Ed25519(node key, tagged_message("anagram/v1/enclave/sign/member-credential",
canonical_json(entry without "signature")))`. The leaf data is
`canonical_json(entry)`. Ed25519 signatures are deterministic, so the pack
carries only `signature` (as `entry_signature`) and the verifier rebuilds the
other fields ([pack.md](pack.md) section 5). The entry has no person key,
person ID or email: the log shows counts for each node, not names.

### 6.6 Issue (app → node)

```
POST /net/credential              (member session)
body: anagram.net.credential_request.v1
```

```json
{"device": "<hex32 device key of the session>", "node": "<node id>", "nonce": "<32 hex>",
 "person_key": "<hex32>", "schema": "anagram.net.credential_request.v1",
 "signature": "<hex64>", "time": "<time>"}
```

- Signed by the person key, tag `anagram/v1/net/sign/credential-request`. So
  the app proves that it holds the person key; the session proves the device.
- The node checks: the session's device is `device`; `node` is its own ID;
  `time` is within 300 seconds of its clock; it did not see `nonce` in the
  last 10 minutes; the member is active; the person key matches the
  recorded binding (section 4), or there is none yet (then it records it).
- It issues a credential that expires at most 24 hours later, writes the log
  entry (6.5), and answers `200` with `{"credential": {"format", "token"},
  "hash": "<hex32>"}`. A node should issue at most 4 credentials for each
  member in a day (`429` after).
- `GET /net/credential/{hash}/proof` (member session; `hash` is 64
  lowercase hex, else `400`) answers `200` with
  `{"log": {"entry_signature", "hashes", "index", "join", "tree_size"}}` when the entry is in a
  checkpoint that the witnesses cosigned, else `404`. `join` is
  `{"index", "salt"}` of the member's join entry (6.5): `index` is at most
  the entry's index, and equal to it for a join entry. `tree_size` is the
  tree size of the latest cosigned checkpoint of the log, and `hashes` is
  the RFC 9162 inclusion proof at that size (the enclave trusts any
  size up to the latest cosigned checkpoint that it has; enclave-trust.md
  7.1). The app puts the credential and this proof in its next pack. If
  the enclave gives `bad_credential` because it has not seen that
  checkpoint yet, the app asks for the proof again after 10 minutes.
- The node gives a proof only to the member that the credential was issued
  to. For a hash that the node issued to another member, it answers `404`,
  the same as for a hash that it does not know. The proof holds the salt and
  the index of the join entry, so another member could link each renewal to
  its join entry (6.5).
- Both routes answer `401` with no member session and `403` for a person
  who is not a member, before they read the body. A request that fails a
  check gives `400`; another device than the session's, or a person key
  other than the recorded binding, gives `403`. The node uses the
  enclave log write API and the log read API of enclave-trust.md 2.1; the
  app reads the log only through that read API.
- **Each day.** A credential lasts at most 24 hours, and a pack or a
  cover must carry one that is not expired. So the app asks for a fresh
  credential and uploads a fresh pack (or a cover with matching off) every
  UTC day ([pack.md](pack.md) section 8). The slot rule of
  [enclave-messages.md](enclave-messages.md) section 6.5 (an upload in the
  48 hours before the cut) depends on this daily upload.

### 6.7 New members per node and month

The log shows how many new members each node took in each month, and the
enclave refuses a credential whose join entry is over the monthly limit of
the network policy (section 9). So a node that mints fake members to flood
other people with proposals (in a simulation, 50 fake members took 8.5 of a
target's 11.5 proposals) is visible in the public log and is capped.

- **New member**: a join entry (6.5). Renewals are daily (6.6) and never
  count, so the limit does not depend on how many members a node keeps.
  A member who comes back after a removal or an exit is new again.
- **Month** of a join entry: the UTC calendar month (`YYYY-MM`) of its
  `expires`. The log takes the entry only while `expires` is in the next
  24 hours and 300 seconds ([enclave-trust.md](enclave-trust.md) 2.3), so
  a node cannot move a join into another month, and every reader computes
  the same month.
- **Join rank** of a join entry: its place (1, 2, ...) among the join
  entries of the same `node_id` and month, in log order (the order of the
  leaf indexes). Renewals and other entry kinds do not count.
- The enclave reads the join entries under the latest cosigned checkpoint
  that it has (the same entries as the log proof of step 8). A `join` that
  names no join entry, a join entry of another node, or a commitment that
  the subject and salt do not give, gives `bad_credential`. So does a join
  entry that may be older than the member's last removal or exit (not
  `moved`) at this node: the entry's `expires` minus 86,700 seconds (24
  hours and 300 seconds, the log's window) is not after the time of the
  event. So a node cannot reuse an old join for a re-join. A join rank
  above `new_members_per_month` gives `issuance_limit`, for a pack and a
  cover alike, on every credential of that member.
- A node that marks a new member as a renewal gains nothing: a renewal
  must name a join entry of the same subject at the same node.
- Read route of the log ([enclave-trust.md](enclave-trust.md) section
  2.1):

  ```
  GET /log/issuance?month=YYYY-MM   → {"month": "YYYY-MM", "nodes": {"<node id>": <new members>, ...}}
  ```

  The counts are of join entries (new members, not renewals) over the
  cosigned entries, in canonical JSON. Anyone can compute the same counts
  from the entries.

**Operator note: a flooding node.** A node whose count of new members grows much faster
than its people, or whose members get many `no` answers that other people
report, is a sign of flooding. The roster operator traces it through the
invite tree: each `node_admitted` event names its `endorser` (section 3.3),
so the operator can walk from the node to the node that invited it, and
see the other nodes that the same endorser invited. The operator removes
the node with `node_removed` (reason `abuse`, section 3.2); the enclave
then erases its members at once ([enclave-trust.md](enclave-trust.md)
section 7.1). The endorser's quota (`node_invites_per_quarter`) limits how
fast it can invite a replacement. Steps for the reference deployment are in
`docs/enclave.md`.

## 7. Node credential

### 7.1 Biscuit facts

Root key: the current roster key.

```
anagram("node_credential", 1);
network("<network id>");
node("<node id>");
node_key(hex:<32 bytes>);
node_kind("lab");
domain("<domain>");
ror("<ROR ID>");
issued(<date>);
expires(<date>);
check if time($t), $t < <expires date>;
```

`ror` is present 0 or 1 times; every other fact exactly once; no rule and
no other check (checked as in 6.2 step 4); `expires − issued` at most
86,400 seconds. The values equal the node record in the roster when the
roster operator issued it.

### 7.2 Use

A node credential lets a party that does not follow the roster check a node
offline. The enclave does not need
it: it follows the roster and checks node requests against the current
roster ([enclave-messages.md](enclave-messages.md) section 9.3). In v1 a
node gets one from the roster operator with a signed request (the node
request signature of [enclave-messages.md](enclave-messages.md) section 9.3,
with its random `nonce` and the same replay rule, and with `audience` set
to the roster service origin, to `GET
/net/node-credential` on the roster service). A node credential has no JSON
fallback in v1.

## 8. Control events

### 8.1 Format (`anagram.control_event.v1`)

```json
{"body": {...}, "chain": "roster | <node id>", "kind": "<kind>", "prev": "<hex32>",
 "schema": "anagram.control_event.v1", "seq": 0, "signature": "<hex64>",
 "signer": "<hex32>", "time": "<time>"}
```

- `chain`: `roster` (section 3) or the node ID of the node that signs it.
- `seq`: 0, 1, 2, … in each chain, with no gap.
- `prev`: the event hash (8.2) of the event before in the same chain; 32
  zero bytes (64 `0` characters) at `seq` 0.
- `time`: not earlier than the `time` of the event before in the chain.
- `signer`: the key that must sign it (8.3). Tag:
  `anagram/v1/net/sign/control-event`.

### 8.2 Hashes

```
event hash   = tagged_hash("anagram/v1/net/control-event", canonical_json(event))   (the whole event)
subject hash = tagged_hash("anagram/v1/net/subject", subject key (32 bytes))
```

Node events name a member by the subject hash, so a reader that does not
know the person key learns nothing about who it is.

### 8.3 Who signs

- Roster chain: the current roster key (after `roster_key_rotated`, the
  new key, from the next event).
- Node chain: the node key in the roster; for a node that rotated its key,
  the old key for `seq` ≤ `chain_seq` and the new key after (section 3.4).
  A verifier applies node events only after the roster event that admits
  the node.

### 8.4 Node events

| Kind | Body | Effect in the enclave |
| --- | --- | --- |
| `member_removed` | `{"reason", "subject"}`; `reason`: `removed`, `group_handover`, `other` | If the subject's current credential is from this node and was issued before the event `time`: delete the subject's pack, known object, open proposals and yes answers; tombstone with reason "removed" ([enclave-trust.md](enclave-trust.md)) |
| `member_left` | `{"reason", "subject"}`; `reason`: `left`, `moved`, `key_changed` | As `member_removed` for `left` and `key_changed`. For `moved`: no deletion; the subject is dormant (no new proposal, no reveal) until a pack arrives with a credential from another node; if none comes in 30 days, delete and tombstone |
| `credential_revoked` | `{"credential", "reason"}`; `credential`: a credential hash (6.5); `reason`: `compromised`, `superseded`, `other` | The credential is not usable. If it is the credential of the subject's stored pack: as `member_removed` (delete and tombstone). A later pack with another credential is accepted (a revoked credential can be a stolen one, so the enclave keeps nothing that it carried) |

The rule "issued before the event time" means that a credential from
**another** node (after a move), or a later credential from the same node
(the member came back), is not affected.

The enclave deletes at once: when its writer applies the event, before it
opens the next request ([enclave-trust.md](enclave-trust.md) section 7.1).

### 8.5 Roster event effects in the enclave

- `node_removed`: every credential of the node is `revoked`; the enclave
  treats each subject whose current credential is from that node as
  `member_removed`.
- `ban`: the enclave deletes and tombstones the subject and refuses its
  packs (`revoked`) until an `unban`.
- `policy_updated`: applies from `effective`.
- `node_key_rotated`: section 3.4. `roster_key_rotated`: section 3.2.

### 8.6 Order, gaps, forks and freshness

A verifier keeps, for each chain, the number of applied events and the hash
of the last one.

1. **Order.** It applies event `seq = n` only after `n − 1`. It may receive
   events in any order; it holds an event above the next `seq` until the gap
   is filled. An event below the applied count with the same hash is a
   repeat and is ignored.
2. **Gap.** While a chain holds events above a gap, the chain is
   **stopped**: the verifier refuses the credentials of that node
   (`stale_roster`); for the roster chain, all credentials. It fetches the
   missing events (8.7). When the gap is filled, it applies the held events
   and the chain runs again.
3. **Fork.** Two different events with the same chain and `seq` are a
   fork. The chain stops for good (`stale_roster`). A fork of a node chain
   ends only with `node_removed` (a node that wants back is admitted again
   with a new key, so a new ID). A fork of the roster chain stops the
   network until a new release pins a new roster.
4. **Bad event.** An event with a wrong `prev`, `signer`, signature, time
   order or body is not applied; the chain then has a gap at that `seq`.
5. **Freshness of the roster**: section 3.5 (at most 1 hour).
6. **Freshness of a node chain**: a member credential carries
   `control_head`. The verifier must have applied at least that many events
   of the node chain before it accepts the credential (`stale_roster`). So
   a credential issued after an event commits to that event.

**Withheld revocations.** A party between a node and the enclave can delay
events but not change them. A delayed roster event is in a checkpoint at
most 15 minutes later, and the enclave refuses all credentials after 1 hour
with no fresh checkpoint: the bound is 1 hour. A delayed node event is
covered by `control_head` of every credential issued after it; credentials
issued before it expire in at most 24 hours: the bound is 24 hours. A node
that withholds events about its own members can also keep issuing
credentials to them; the node is the trust boundary for its members, so this is not a protection against the node
itself.

### 8.7 Fetch

| Route | Who serves | Response |
| --- | --- | --- |
| `GET /net/control?after={n}` | each node, at its `url` | `{"count": <events in the chain>, "events": [events with seq ≥ n, ascending, at most 1,000]}` |
| `GET /net/roster/events?after={n}` | the roster service | the same form for the roster chain |
| `GET /net/roster/checkpoint` | the roster service | the newest roster checkpoint |
| `GET /net/node` | each node, at its `url` | `{"id": <node ID>, "key": <hex of the node key>}`, so an app can fill `node` of a credential request (6.6) |

These routes are public: events are signed, and node events hold only
hashes. The enclave polls the roster and every admitted node at least every
5 minutes, and at once when a credential's `control_head` is above the
applied count.

## 9. Network policy (`anagram.net.policy.v1`)

```json
{"credential_formats": ["biscuit-v3"], "credential_max_life": 86400,
 "new_members_per_month": 200, "node_invites_per_quarter": 2,
 "roster_max_age": 3600, "schema": "anagram.net.policy.v1"}
```

| Field | Rule | Default |
| --- | --- | --- |
| `credential_formats` | Ascending, no repeats, from `anagram-json-v1`, `biscuit-v3` | `["biscuit-v3"]` |
| `credential_max_life` | 3,600 to 86,400 seconds | 86,400 |
| `roster_max_age` | 300 to 3,600 seconds | 3,600 |
| `node_invites_per_quarter` | 0 to 100 | 2 |
| `new_members_per_month` | 1 to 100,000: new members (join entries) that one node may take in one UTC month (section 6.7) | 200 |

The roster operator changes it with `policy_updated`. Before the first
`policy_updated`, a verifier uses the defaults. A verifier uses the
newest policy whose `effective` time has passed. The release of the enclave
can be stricter (for example, accept fewer formats); it cannot be looser.
Matching values (the anonymity set, caps) are not network policy; they are
in the `matching` descriptor ([enclave-trust.md](enclave-trust.md) section
3.6). The issuance limit is network policy, not a matching value: like the
invite quota, it is a rule for nodes, and the roster operator must be able
to change it without a new release.

## 10. Bespoke fallback

If the network changes from Biscuit to bespoke signed JSON, the change is:
the policy lists `anagram-json-v1`; nodes issue section 6.3 documents;
verifiers replace steps 2 to 6 of 6.2 with a signature check, the field
checks and an expiry check. A node credential fallback would need a new
format (v1 has none). Packs, log entries, control events and the enclave stay the same,
because they use the credential bytes and the facts only. Biscuit gives
attenuation, which v1 does not use (nodes do no agent negotiation), and
needs a dependency (`biscuit-python` for the reference; `biscuit-auth` in
Rust). The JSON form needs no dependency and is deterministic.

## 11. Tags

| Tag | Use |
| --- | --- |
| `anagram/v1/net/node-id` | Node ID |
| `anagram/v1/net/subject` | Subject hash in control events |
| `anagram/v1/net/control-event` | Event hash |
| `anagram/v1/net/sign/control-event` | Event signature |
| `anagram/v1/net/sign/roster-checkpoint` | Roster checkpoint signature |
| `anagram/v1/net/sign/key-proof` | Node key rotation proof |
| `anagram/v1/net/sign/endorsement` | Node invite by another node |
| `anagram/v1/net/sign/credential-request` | Credential request |
| `anagram/v1/net/member-credential` | Credential hash |
| `anagram/v1/enclave/sign/member-credential` | Log entry of a member credential (defined in [enclave-trust.md](enclave-trust.md)) |
| `anagram/v1/net/sign/member-credential` | Fallback member credential |
| `anagram/v1/net/sign/node-request` | Node request signature ([enclave-messages.md](enclave-messages.md) section 9.3) |

## 12. Test vectors

[vectors/network.json](vectors/network.json) holds: keys; node IDs; a roster
chain (created, two admissions, one by an inviting node, a policy, a node
key rotation, a ban, a roster key rotation, an update by the new roster key)
with event hashes; two node chains (one signed across a key rotation); a
roster checkpoint; the roster state after all events; ordering steps (an
event above a gap, the gap filled, a fork); a member credential, a group
credential and a node credential (Biscuit tokens with their Datalog source);
the fallback member credential; the credential hash and the signed log entry; a
credential request; credential cases (usable, banned, member left before
issue, `control_head` ahead of the chain, revoked); and Biscuit refusal
cases (`biscuit_refusals`: an extra fact, an extra rule, an extra check that
fails, a check later than `expires`, no check, an attenuation block,
`issued` in the future, the node marker, an expired token, another root
key); and `issuance`: a short log with join entries and renewals of two
nodes across a month boundary, a limit of 2, credentials that name a join
entry (subject, salt, join index) with the expected result (`ok`,
`bad_credential` or `issuance_limit`), and the counts of new members for
each month (6.7). `member_credential` also has `join_log_entry` and
`join_salt`: the entry of the same credential as a join entry.

Biscuit tokens are random; a verifier checks them and compares their facts.
It recomputes every other value.

## 13. Changes after the spec review (2026-11-25)

- The block must be exactly the facts and the check of 6.1; the verifier
  compares the rebuilt source; explicit `now < expires` and a lower bound
  on `issued`; refusal vectors (6.1, 6.2, 7.1, 12).
- Roster checkpoints are `roster_checkpoint` log entries; the enclave uses
  only logged ones (3.5).
- The network pin and matching values are in the `matching` descriptor
  (3.1, 9).
- No JSON fallback for a node credential (5, 7.2, 11).
- The node request signature names its `audience` (7.2).
- On the re-check: the `email_tag` facts are in ascending order (6.1).

## 14. Changes after the first enclave slice (2026-11-25)

Rulings on the problems that the first enclave slice found
(enclave-messages.md section 15):

- The node request signature has a 16-byte random `nonce`; the replay key
  is (node, `nonce`) (7.2; enclave-messages.md 9.3).
- A credential lasts 24 hours, so the app gets one and uploads a fresh pack
  or cover every day; the 48-hour slot rule depends on it (6.6).

## 15. Changes after the conformance review (2026-11-25)

- `credential_revoked` of the credential of a stored pack deletes and
  tombstones, as `member_removed`; the deletion is at once (8.4). Before,
  the pack was only dormant, which disagreed with enclave-trust.md 7.1.
- The exact answers of the credential routes, and the tree size of the
  proof (6.6). Code: `anagram.network.matching.node.credentials`.
- The Datalog run limits (6.2). Before, the library default of 1 ms of
  wall-clock time made the result depend on the load of the computer.

## 16. Changes for the new-member limit (2026-11-26)

- Issuance per node and month: the month and the rank of a
  `member_credential` entry, the read route `GET /log/issuance`, and the
  operator note on a flooding node (6.7).
- The enclave refuses a credential over the limit with `issuance_limit`
  (6.2 step 8a; enclave-messages.md 10).
- The policy field `member_credentials_per_month` (9). Vectors: the policy
  in the roster chain has the field (so the later event hashes changed);
  `issuance` is new (12).
- The per-node proposal rule is a matching rule (enclave-messages.md 6.5).

## 17. Changes after the review of the new-member limit (2026-11-26)

- The limit counts new members, not credentials (6.7). Credentials renew
  each day, so the old limit of 10,000 credentials a month capped a node
  at about 300 members. A join entry carries `member`, a commitment to the
  person key under a random salt (6.5); the proof carries `join` (6.6);
  step 8a checks the join (6.2).
- The policy field is `new_members_per_month`, 1 to 100,000, default 200
  (9). `GET /log/issuance` counts join entries (6.7).
- Vectors: the policy, the log entries and the `issuance` cases changed
  (12); the later event hashes of the roster chain changed.
