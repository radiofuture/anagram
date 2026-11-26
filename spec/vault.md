# Anagram vault: encrypted blobs, grants, rings, receipts, guardians

Status: version 1, locked on 2026-10-15. Licence: CC BY 4.0.
Vectors: [vectors/vault.json](vectors/vault.json). Code: `anagram.core.crypto.blob`,
`anagram.core.crypto.shamir`, `anagram.core.wraps`, `anagram.network.formats.vault`,
`anagram.identity.formats.recovery`, `anagram.network.sharing.app.grants`, `anagram.identity.app.guardians`,
`anagram.network.sharing.node.vault`.

This document tells how an owner keeps evidence encrypted on the node, shares a
finding with rings of people, proves the date of each disclosure, publishes a
finding, and recovers keys with guardians. The encoding rules are in
[formats.md](formats.md) section 2.

## 1. Principles

- Each finding version has its own random 32-byte **content key**. Only clients
  see it. The node stores ciphertext only.
- Upload is optional for each finding. Large data can stay on the device. Then
  a recipient can check the commitment but cannot get the bytes.
- A client takes recipient and guardian device keys only from the key directory
  with log inclusion proofs (`lookup`, [identity.md](identity.md) section 10).
  It never uses a key that the node gives without a proof.
- Access that a person got cannot be taken back. A revocation makes a new
  version with a new content key.

## 2. Encrypted blob (`chacha20-poly1305-chunked-v1`)

One blob holds one evidence file of one finding version.

```
blob_key = HKDF-SHA256(ikm = content key, salt = none,
                       info = tagged_message("anagram/v1/blob/key", finding_root || u32(slot)),
                       L = 32)
nonce(i) = 4 zero bytes || u64(i)
aad(i)   = tagged_message("anagram/v1/blob/chunk",
             finding_root || evidence_root || u32(slot) || u64(i) || u8(final))
ct(i)    = ChaCha20-Poly1305(blob_key, nonce(i), chunk(i), aad(i))      (pyca)
blob     = ct(0) || ct(1) || ... || ct(n-1)
```

- `tagged_message(tag, x) = u8(len(tag)) || tag || x` ([formats.md](formats.md) section 3.1).
- `finding_root` is the root of the finding version. `slot` is the evidence
  index N of field `evidence.N`. `evidence_root` is the value of that field.
- **Framing**: each plaintext chunk has `chunk_size` bytes (default 1 MiB, at
  most 64 MiB), except the last chunk, which can be shorter. Each ciphertext
  chunk is 16 bytes longer. An empty file is one final chunk with no plaintext.
  A file with a size that is a multiple of `chunk_size` has no empty chunk at
  the end. `final` is 1 for the last chunk and 0 for all other chunks.
- The key is different for each (content key, finding root, slot), so each
  nonce is used once for each key. We use 96-bit ChaCha20-Poly1305 with derived
  nonces because pyca does not have XChaCha20-Poly1305.
- A reader decrypts chunk by chunk. A changed, reordered, removed, appended, or
  moved chunk (also from another finding or slot) fails. A cut at a chunk
  boundary fails, because the new last chunk has `final` = 0 in its
  encryption. After it decrypts the file, the reader checks the content digest
  of the file against the committed `content` field of the evidence record.

The node stores a blob under a random 16-byte `blob_id` (hex). It does not get
the finding root, the slot, or the chunk size.

## 3. Rings

A ring is a named list of recipients on the owner's device. Rings are ordered
from inner to outer (the order of creation). A member is one of:

| Member | Expands to |
| --- | --- |
| `pid:<32 hex>` | that person (v2 person ID, [identity.md](identity.md) section 2) |
| an ORCID iD | the person with this ORCID iD, only if they are findable by ORCID ([identity.md](identity.md) section 13); the ring keeps the pid |
| `lab:<lab ID>` | all members of the lab, from the verified roster ([lab.md](lab.md); the share sheet does not offer it, a share to the own lab goes into the lab space) |
| `community` | all members of the community |
| `public` | a public release (section 7) |

A grant to ring R goes to the members of R and of all rings inside R. The
rings are not on the node. The node sees each grant (sender, recipient, time).

## 4. Grant receipt (`anagram.grant_receipt.v1`) and its log entry

```json
{
  "finding_root": "<hex32>",
  "grant_id": "<hex16, random>",
  "granted_at": "<RFC 3339>",
  "recipient": "pid:... | public",
  "salt": "<hex32, random>",
  "schema": "anagram.grant_receipt.v1",
  "sender_key": "<hex32, owner device Ed25519 key>",
  "signature": "<hex64>"
}
```

- `signature = Ed25519(sender_key, tagged_message("anagram/v1/sign/grant-receipt", canonical_json(receipt without signature)))`.
- `commitment = tagged_hash("anagram/v1/grant-receipt", canonical_json(receipt))`.
- Log entry: `{"commitment": "<hex>", "kind": "grant_receipt", "schema": "anagram.log_entry.v1"}`.
  The owner submits it with a member session. It is a log-only kind
  ([formats.md](formats.md) section 9).

The salt hides the receipt. The log shows only a hash: no recipient, no root,
no owner. The recipient gets the receipt and its log proof (`receipt_log`:
entry, leaf index, tree size, inclusion path, checkpoint) in the grant payload.
With them, the owner or the recipient can show later that the owner gave this
finding version to this recipient no later than the checkpoint time.

## 5. Grant (`anagram.grant.v1`) and payload (`anagram.grant_payload.v1`)

The payload (plaintext, canonical JSON):

```json
{
  "blob_alg": "chacha20-poly1305-chunked-v1",
  "blobs": [{"blob_id": "<hex16>", "chunk_size": 1048576, "size": 1234, "slot": 0}],
  "bundle": <proof bundle of the finding, no openings, no sealed opening>,
  "content_key": "<hex32>",
  "finding_id": "<hex16>",
  "opening": <anagram.opening.v1 document: all fields and salts>,
  "owner": "pid:...",
  "receipt": <grant receipt>,
  "receipt_log": {"checkpoint", "entry", "inclusion", "leaf_index", "tree_size"},
  "recipient": "pid:...",
  "schema": "anagram.grant_payload.v1",
  "version": 1
}
```

`blobs` lists only the uploaded slots, sorted by slot.

The envelope that the node stores and routes:

```json
{
  "blobs": ["<blob_id>", ...],
  "grant_id": "<hex16, the receipt grant_id>",
  "recipient": "pid:...",
  "schema": "anagram.grant.v1",
  "wraps": [{"ciphertext": "<base64>", "device": "<hex32 Ed25519>"}]
}
```

- `ciphertext = HPKE.Seal(device X25519 key, canonical_json(payload), info)`,
  suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode
  (RFC 9180, pyca), output `enc || ct`.
- `info = tagged_message("anagram/v1/hpke/grant", grant_id(16) || device Ed25519 key(32))`.
- One wrap for each active device of the recipient, sorted by device key. At
  most 32.

The node keeps `blobs` in plaintext for the download check (section 8).

### 5.1 Recipient checks

The recipient device:

1. opens its wrap; the payload `recipient` must be its subject and the receipt
   `grant_id` must be the grant ID;
2. checks that the opening gives the root of the bundle subject, and that each
   evidence opening gives the value of its `evidence.N` field;
3. looks up the owner (log proofs). The bundle owner key and the receipt
   `sender_key` must be device keys that the owner added at some time;
4. checks the receipt signature, its log entry, and its inclusion in a
   checkpoint. The checkpoint can be older than the last one the client saw;
   then the client checks consistency from it to the last one;
5. downloads each blob, decrypts it (section 2), and compares the content
   digest with the committed digest;
6. verifies the proof bundle with all fields opened and with the files
   (`verify_bundle`). It writes `proof.json` and `receipt.json`.

### 5.2 New devices of a recipient

A grant has wraps only for the devices that were active at grant time. The
owner client keeps each sent payload sealed with its vault key. On the next
owner sync (`anagram sync`), the client looks up each recipient again and, if
the device set changed, makes new wraps and replaces the envelope (same grant
ID, same sender, same blobs). The owner's device must be on for this. A
removed device keeps what it already decrypted.

## 6. Recovery guardians

Optional, after the recovery kit ([identity.md](identity.md) section 9).

### 6.1 Set up

1. The owner client makes a new 32-byte guardian secret G and a key backup
   sealed with G (the `anagram.key_backup.v1` format, `backup_id` from G).
2. It splits G with Shamir, k of n (default 2 of 3, at most 16).
   `anagram.core.crypto.shamir` uses pycryptodome `Crypto.Protocol.SecretSharing.Shamir`
   (16-byte secrets in GF(2^128)). G is cut into two 16-byte halves. Each half
   is shared on its own with the same k and n. Share i is
   `share_i(half 0) || share_i(half 1)` (32 bytes). We do not write field
   arithmetic.
3. Share document (`anagram.guardian_share.v1`):
   `{"backup_id", "index", "owner", "schema", "set_id", "share", "threshold"}`.
4. Each share document is HPKE-sealed to each device of its guardian with
   `info = tagged_message("anagram/v1/hpke/guardian-share", set_id(16) || u8(index) || device Ed25519 key(32))`.
5. Guardian set (`anagram.guardian_set.v1`), stored on the node:
   `{"backup_id", "created_at", "guardians": [{"index", "subject", "wraps"}], "schema", "set_id", "subject", "threshold"}`.
   A new set replaces the old set, and the client deletes the old backup, so
   old shares open nothing.

### 6.2 Recover

1. The new device makes a temporary Ed25519 and X25519 key. It signs in (ORCID
   or email) for the temporary key and sends a recovery request
   (`anagram.recovery_request.v1`): `{"assertion", "created_at", "device", "pop", "schema", "subject"}`.
   The node checks the session, the assertion (signature, audience, expiry),
   and the proof of possession. Request ID:
   `hex(tagged_hash("anagram/v1/recovery-request-id", canonical_json(request))[:16])`.
2. Each guardian runs an explicit approve command. The guardian client checks
   the request ID, the assertion (signature by the pinned assertion key,
   audience), and the proof of possession. It opens its share, and seals it to
   the temporary X25519 key with
   `info = tagged_message("anagram/v1/hpke/recovery-share", request_id(16) || u8(index))`.
   Approval (`anagram.guardian_approval.v1`): `{"ciphertext", "guardian", "index", "request_id", "schema"}`.
3. With k approvals, the new device opens the shares, combines k of them, and
   accepts the result only if its `backup_id` equals the set's `backup_id`. A
   fake approval cannot give a wrong secret. Then it opens the backup, restores
   the keys, and checks that the restored device key is still active.

Guardians must confirm a request with the person by another channel. The node
holds the assertion key, so it can make an assertion for anyone.

A request is valid for 7 days (`RECOVERY_REQUEST_MAX_AGE`). The node deletes an
older request and its approvals, and then answers `404`. The guardian client
also refuses a request when the `issued_at` of its assertion (signed by the
node, not set by the client) is more than 7 days old. So an old, forgotten
request cannot collect approvals later.

## 7. Public release (`anagram.public_release.v1`)

The same fields as a grant payload, with `recipient` = `public` and a receipt
for `public`. The node serves it to anyone (`GET /public/<release ID>`, where
the release ID is the receipt `grant_id`), and serves its blobs with no
session. Anyone can do the checks of section 5.1. A release cannot be taken
back.

## 8. Node API (not locked)

| Method and path | Access | Result |
| --- | --- | --- |
| `PUT /blobs/<blob_id>` | member; the first uploader owns the ID | raw ciphertext body |
| `GET /blobs/<blob_id>` | owner, anyone for a public blob, or a recipient of a grant that lists it with a read receipt (section 12; else 428) | ciphertext; else 404 |
| `DELETE /blobs/<blob_id>` | owner; refused (409) if a public release lists it | `{blob_id, deleted}` |
| `POST /grants {grant}` | member; the recipient must be a member; only own blobs | `{grant_id}` |
| `GET /grants` | recipient | envelopes; each wrap has an empty `ciphertext` |
| `GET /grants/<id>` | sender; or recipient with a read receipt (else 428 `read receipt required`) | envelope |
| `DELETE /grants/<id>` | sender | `{grant_id, deleted}`; the blobs stay |
| `POST /grants/<id>/receipts {receipt}` | recipient; `reader` is the session subject; `reader_key` is an active device key | `{receipt_id, log, event}`; the node logs the commitment and signs fetch event `seq` with `blob_id` null |
| `GET /grants/sent/reads?since=<cursor>` | sender | `{receipts: [{receipt, log}], events: [fetch_event], cursor, more}` for own grants |
| `POST /public {release}` | member, own findings and blobs | `{release_id}` |
| `GET /public[?finding_id=]`, `GET /public/<id>` | public | releases |
| `PUT /guardians {set}`, `GET /guardians` | owner | guardian set |
| `GET /guardians/shares` | guardian | share wraps for this guardian |
| `POST /recovery/requests {request}` | the person of the request | `{request_id}` |
| `GET /recovery/requests` | guardian | requests of people with this guardian |
| `GET /recovery/requests/<id>` | owner (approvals) or guardian | request |
| `POST /recovery/requests/<id>/approvals {approval}` | guardian, own slot | |
| `DELETE /recovery/backup/<backup_id>` | owner | |
| `GET /members` | member | member subjects (for the `community` ring) |
| `GET /resolve/email/<email>` | member; the same rate limit as `/resolve/orcid` (30 each hour for both); audit row with a hash of the address | `{subject}` of a member who turned on "findable" (`PUT /me/findable` sets it for the ORCID iD and the email addresses of the person); else 404 |
| `POST /reader-invites {contact: {kind, value}, expires_days}` | member; `kind` is `email` or `orcid`; 1 to 30 days (default 30); 20 open and 50 new each day for each owner | `{invite_id, invite_url, expires_at, mailed}`, the same keys for each contact; `invite_url` is null when the owner has an open invite for this contact (section 15) |
| `GET /reader-invites[?state=]` | member, own invites | `{invites: [{invite_id, state, subject, expires_at}]}`; `subject` only when `claimed` |
| `DELETE /reader-invites/<id>` | owner, before the claim | `{state: "revoked"}` |
| `GET /reader-invites/mine` | member | `{invites: [{invite_id, owner}]}`: the reader invites that this person claimed |

Receipt gate: a receipt opens the grant and its blobs for
24 hours after the node received it (node config
`sharing.read_window_hours`). Each gated blob answer adds one signed fetch
event. The node keeps receipts and events in its own file `reads.sqlite`, also
after a grant is deleted.

In version 1, a blob goes through HTTP in one piece (the client holds one blob in
memory). Encryption and decryption are streaming. Streaming HTTP is later.

## 9. Tags (added to the locked registry)

| Tag | Use |
| --- | --- |
| `anagram/v1/blob/key` | HKDF info of a blob key |
| `anagram/v1/blob/chunk` | AAD of a blob chunk |
| `anagram/v1/grant-receipt` | Commitment of a grant receipt |
| `anagram/v1/sign/grant-receipt` | Owner signature on a grant receipt |
| `anagram/v1/hpke/grant` | HPKE info of a grant wrap |
| `anagram/v1/hpke/guardian-share` | HPKE info of a guardian share wrap |
| `anagram/v1/hpke/recovery-share` | HPKE info of an approval |
| `anagram/v1/recovery-request-id` | Recovery request ID |
| `anagram/v1/vault/item` | AAD of sealed items in the local vault (content keys, sent payloads, matching profile) |
| `anagram/v1/read-receipt` | Commitment of a read receipt (section 12) |
| `anagram/v1/sign/read-receipt` | Reader signature on a read receipt |
| `anagram/v1/sign/fetch-event` | Node signature on a fetch event (section 13) |
| `anagram/v1/reading/key` | HKDF info of the reading copy key (section 14) |
| `anagram/v1/reading/blob-id` | Blob ID of the reading copy |
| `anagram/v1/reading/evidence-root` | Fixed evidence root in the AAD of the reading blob |

## 10. Local vault (not locked)

The client vault (SQLite) adds: `evidence_meta` (local path, an optional
`third_party` flag for each evidence item, blob ID, chunk size, size),
`sealed_items` (ChaCha20-Poly1305 with the vault key), `rings`, `grants_sent`,
and `kv`. The index sets `third_party` when an item holds other people's words
(for example quoted email text): `Vault.flag_third_party(root, slot)`, or
`commit_finding(..., third_party=[...])`. A grant or a release of a finding
with a flagged item needs `warnings_ack` (CLI `--ack-third-party`). Without it,
the client stops with `ThirdPartyWarning` and names the files.

## 11. Personal store (`anagram.personal_store.v1`, v2 foundations)

Status: added 2026-10-27. Not locked.

**Problem.** The local vault (`vault.sqlite`) and the local index
(`index.sqlite`) hold the salts that make proofs verifiable. Without them a
proof is worthless. Before v2, a recovery kit restored only the keys. A lost
laptop lost all proofs.

**Rule.** The data goes with the person, not with one device.

### 11.1 Person keys

The **vault key** and the **index key** are person keys. Every device of the
person has the same two keys:

- The first device makes them at the first join.
- The recovery kit and the guardian backup (key backup v2,
  [identity.md](identity.md) section 9) hold both.
- `add_device` sends both to the new device (section 11.4).

### 11.2 Keys of the store

All values come from the vault key with HKDF-SHA256 (RFC 5869, no salt):

```
store_key = HKDF(vault_key, info = tagged_message("anagram/v1/store/key", "enc"), L = 32)
id_key    = HKDF(vault_key, info = tagged_message("anagram/v1/store/key", "id"),  L = 32)
key_id    = hex(tagged_hash("anagram/v1/store/key", "key-id" || store_key)[:8])
record_id = hex(HMAC-SHA256(id_key,
              tagged_message("anagram/v1/store/record-id", lp(utf8(kind)) || utf8(ref)))[:16])
```

The node cannot compute a record ID. Two people never share a record ID.

### 11.3 Record

```json
{
  "alg": "chacha20-poly1305",
  "ciphertext": "<base64>",
  "key_id": "<16 hex>",
  "nonce": "<24 hex>",
  "record_id": "<32 hex>",
  "schema": "anagram.personal_store.v1",
  "version": 1
}
```

- `body = canonical_json({"kind": kind, "ref": ref, "value": value})`.
- Plaintext: `u32(len(body)) || body || zero bytes to a multiple of 512`.
  The padding hides small differences in size.
- AAD: `tagged_message("anagram/v1/store/record", canonical_json(record
  without ciphertext and nonce))`. So the version and the record ID are bound
  to the ciphertext.
- The reader decrypts, removes the padding, and checks that the record ID of
  `(kind, ref)` equals `record_id`.

Kinds:

| Kind | Ref | Value |
| --- | --- | --- |
| `person` | `me` | subject, ORCID iD, ORCID salt, ORCID commitment |
| `finding` | finding root | finding ID, version, time, sealed opening, proof bundle, evidence flags and blob IDs. **No local file path** |
| `sealed_item` | `<kind>\|<ref>` | a sealed item of the local vault (content keys, sent payload parts, matching profile). It stays sealed with the vault key inside the record |
| `ring` | ring name | position and members |
| `grant_sent` | grant ID | recipient, devices, time |
| `snapshot` | `<name>/<device ed25519>` | manifest: generation, chunk count, size, SHA-256 |
| `snapshot_chunk` | `<name>/<device>\|<generation>\|<i>` | `{"data": <base64 of up to 1 MiB>}` |

**Snapshot.** A snapshot is opaque bytes of one local database file (today:
`index` = `index.sqlite`). The client makes it with the SQLite backup API (a
consistent copy). If the file is not plain SQLite (for example an encrypted
database), the client copies the file bytes. The index format can change; the
store does not depend on it. Each device has its own snapshot name. A new
snapshot has a new generation; after the manifest is sent, the client deletes
the chunks of the old generation.

### 11.4 Person keys for a new device (`anagram.person_keys.v1`)

```json
{
  "ciphertext": "<base64 of HPKE enc || ct>",
  "created_at": "...",
  "recipient": "<hex Ed25519 key of the new device>",
  "schema": "anagram.person_keys.v1",
  "sender": "<hex Ed25519 key of the device that approved it>",
  "signature": "<hex, by sender, tag anagram/v1/sign/person-keys>",
  "subject": "pid:..."
}
```

- HPKE (section 5 suite) to the X25519 key of the new device, with
  `info = tagged_message("anagram/v1/hpke/person-keys", lp(utf8(subject)) ||
  recipient ed25519)`.
- Plaintext: `canonical_json({"keys": {"index-key": hex, "vault-key": hex},
  "schema": "anagram.person_keys_payload.v1", "subject": ...})`.
- The new device checks that the sender is an **active device of the same
  subject** in the key directory (log proofs), checks the signature, and
  decrypts. Thus a node cannot give the device a vault key that the node
  knows.
- The device takes the keys only if its own vault is empty. Then it reads the
  personal store.

### 11.5 Sync and restore

- `sync_store()`: (1) read the list of records; (2) import each record that is
  newer on the node than on this device (records from the other devices of
  the person); (3) send each local record whose value changed, with
  `version` = (the larger of the local and the node version) + 1; (4) send a
  snapshot if it changed. The client sends vault records after each commit
  (best effort; a failure never stops a commit) and an index snapshot at most
  once an hour, and after a refresh of sources in the UI. `anagram sync` sends
  all now.
- Restore (`anagram recover` with a kit or with guardians): restore the keys,
  check that the device key is still active, get a session with the device
  key (device sign-in, [identity.md](identity.md) section 11), read all
  records into the vault, and write the snapshot of this device's index if
  the home has no index. If an index is there, the client writes
  `index.sqlite.restored` and does not overwrite it.
- A record that does not decrypt (for example sealed with an old vault key
  before a reset) is skipped.

### 11.6 Node API (not locked)

| Method and path | Access | Result |
| --- | --- | --- |
| `GET /store/records` | member | own record IDs, versions, sizes; `used`, `quota` |
| `PUT /store/records/<record_id> {record}` | member | the version must be larger than the stored one (409); the same record again is accepted; quota (413) |
| `GET /store/records/<record_id>`, `DELETE ...` | member, own records only | record; else 404 |
| `PUT /store/person-keys/<device> {package}` | member; sender and recipient must be active devices of the member | |
| `GET /store/person-keys/<device>` | member, own subject | package; else 404 |

The node checks the form of each record (it has no key) and keeps it for the
subject of the session. The default quota is 512 MiB of ciphertext for each
person. The node sees only: opaque record IDs, versions, ciphertext sizes (in
512-byte steps), and times of change. See
[threat-model.md](threat-model.md) section 12.

### 11.7 Tags (added to the locked registry)

| Tag | Use |
| --- | --- |
| `anagram/v1/store/key` | HKDF info of the store keys, and the store key ID |
| `anagram/v1/store/record-id` | HMAC input of a store record ID |
| `anagram/v1/store/record` | AAD of a store record |
| `anagram/v1/hpke/person-keys` | HPKE info of a person-keys package |
| `anagram/v1/sign/person-keys` | Sender device signature on a person-keys package |

## 12. Read receipt (`anagram.read_receipt.v1`) and its log entry

A reader must post a read receipt before the node serves
the grant ciphertext or one of its blobs (the receipt gate).

```json
{
  "grant_id": "<hex16>",
  "read_at": "<RFC 3339>",
  "reader": "pid:...",
  "reader_key": "<hex32, a device Ed25519 key of the reader>",
  "salt": "<hex32, random>",
  "schema": "anagram.read_receipt.v1",
  "signature": "<hex64>"
}
```

- `signature = Ed25519(reader_key, tagged_message("anagram/v1/sign/read-receipt", canonical_json(receipt without signature)))`.
- `commitment = tagged_hash("anagram/v1/read-receipt", canonical_json(receipt))`.
- `receipt_id` = the first 16 bytes of the commitment, hex.
- Log entry: `{"commitment": "<hex>", "kind": "read_receipt", "schema": "anagram.log_entry.v1"}`.
  The node submits it when it accepts the receipt. It is a log-only kind
  ([formats.md](formats.md) section 9).

The receipt names the grant, not the finding. The finding root is inside the
encrypted payload; the owner maps `grant_id` to the root in its own vault. The
salt hides the receipt: the log shows one hash for each read, with no reader
and no grant.

## 13. Fetch event (`anagram.fetch_event.v1`)

The node signs one event each time it serves a gated grant or blob to a reader.

```json
{
  "at": "<RFC 3339>",
  "blob_id": "<hex16> | null",
  "grant_id": "<hex16>",
  "node_key": "<hex32, fingerprint of the node log key>",
  "reader": "pid:...",
  "receipt_id": "<hex16>",
  "schema": "anagram.fetch_event.v1",
  "seq": 1,
  "signature": "<hex64>"
}
```

- `signature = Ed25519(node assertion key, tagged_message("anagram/v1/sign/fetch-event", canonical_json(event without signature)))`.
  The client checks it with the pinned assertion key of the trust document.
- `blob_id` is `null` for the event of the receipt itself (the grant envelope).
- `seq` counts the events of one grant from 1. A missing number shows an
  event that the node removed or did not give.

What the evidence shows: a read receipt in the log shows that a device key of
the reader asked to open the grant no later than the log time. A fetch event
shows that the node sent the ciphertext to a session of the reader. Neither
shows that a person read the finding. The node cannot make a read receipt (it
has no reader key).

## 14. Reading copy (`anagram.reading_copy.v1`)

The owner's client makes a reading copy at share time: a JSON document of the
blocks that the local converters make from each evidence file. It is derived
data and is never in a commitment. It is one more encrypted blob.

```
reading_key = HKDF-SHA256(ikm = content_key, salt = none,
                          info = tagged_message("anagram/v1/reading/key", finding_root), L = 32)
blob_id     = hex(tagged_hash("anagram/v1/reading/blob-id", content_key || finding_root)[:16])
blob        = chacha20-poly1305-chunked-v1 (section 2) with content key = reading_key,
              finding_root, evidence_root = tagged_hash("anagram/v1/reading/evidence-root", ""),
              slot = 0
```

Only a holder of the content key can compute `blob_id`. The owner lists it in
the grant envelope `blobs`, so the access check of the node passes. It is not
in the payload `blobs` (those are evidence slots).

```json
{
  "items": [{
    "blocks": [{"anchor", "kind", "level", "parent", "text"}] | null,
    "figures": [{"data": "<base64>", "id": "<1 to 64 of A-Z a-z 0-9 _ ->", "media_type": "image/..."}],
    "media_type": "<type>/<subtype>",
    "name": "<file name>",
    "size": 0,
    "slot": 0,
    "table": {"columns": ["..."], "rows": [["..."]], "total_rows": 0} | null,
    "truncated": false,
    "view": "pdf | image | table | text | document | slides | file"
  }],
  "made_by": "<converter id>",
  "schema": "anagram.reading_copy.v1",
  "title": "<text> | null"
}
```

Limits: the canonical JSON is at most 8 MiB; a table has at most 500 rows
(`total_rows` gives the size); figures go in until 6 MiB, then `truncated` is
true. Item slots are sorted and unique. A validator refuses unknown keys.
In a notebook, the figure ID `code-<k>-<j>` is output `j` of the code cell
whose block has the anchor `code-<k>`; the reading view shows it under that
block. The reading view shows the other figures after the blocks.

Client behaviour (`network/sharing/app/readcopy.py`, `network/sharing/app/shares.py`,
`network/sharing/app/received.py`):

- The owner makes and uploads the reading copy one time for each version, at
  the first `share` of the version. Only local converters run. A file that
  does not convert gives view `file`; a copy over 8 MiB is not made. Neither
  stops the share. A plain `grant` (CLI) makes no reading copy.
- The first envelope of a grant fixes its blob list. The client keeps the
  extra blob IDs of each grant (`kv` `grant-extra/<grant_id>`), so that a
  later re-wrap posts the same list.
- The reader keeps the files as the owner's ciphertext in
  `received/<grant_id>/<slot>.blob` and the reading copy in
  `received/<grant_id>/reading.blob`. The payload (with the content key) is
  sealed in the vault (kind `received-payload`). No plaintext goes to disk,
  except when the person saves a copy. If the envelope has no reading copy
  (an old grant), the reader makes one locally.
- `migrate_received` moves old plaintext folders of `received/` into the
  store and erases the plaintext. A folder whose grant does not open now
  stays as it is. The app start must call it.

## 15. Reader invite

The reader invite itself (the `invites` and `reader_invites` rows, the
claim rule, and the member that it makes) is in [admission.md](admission.md)
section 5. This section has the share part.

- For an email contact the node sends one fixed message with the owner's
  display name (one line, at most 80 characters), the community name, and the
  link. It has no other text of the owner and no finding title. For an ORCID
  contact the owner sends the link.
- The owner's client keeps the share as target `invite:<invite_id>` with no
  grant, and the contact and link sealed in `sealed_items` (kind
  `share-label`). At each sync it reads `GET /reader-invites`. For a claimed
  invite it looks up the person's keys (with log proofs), grants each root,
  and the share target becomes the pid. An invite that ended unclaimed stops
  its shares (event `invite_expired`).
- Owner confirmation (from a security review). Only the node checks the
  claim, so a node that breaks the rules can name a person that it controls.
  The owner's client does not grant until the owner confirms the claimer:
  the first sync after a claim records the claimer and gives one change of
  kind `confirm` (live event `share.confirm`). `GET /reader-invites` gives
  `claimer_email` (the address of the claimer on the node, only to the
  owner). The UI shows one question for each claim: the name from the
  signed identity record, the email address, and the contact of the invite
  (`GET /api/reader-claims`, `POST /api/reader-claims/{invite_id}` with
  `{"give": bool}`). Yes grants each root for that pid only; a later claimer
  that the node names is asked again. No stops the shares of the invite
  (event `stopped`); the person stays a member and gets no key. Limit: the
  owner checks what the node shows. A node that also fakes the name and the
  address of a known person can still mislead an owner who does not check
  with the person.

## 16. Share record (`anagram.share_record.v1`)

"Export record" on a row of the share history gives one JSON file for one
finding and one person. The owner's client makes it from its local tables;
the node does not take part. Not locked: the release adds no `anagram verify`
mode for it.

```
{"schema": "anagram.share_record.v1", "finding_id": str, "person": pid,
 "grants": [{"grant_id": hex16, "root": hex32, "receipt": <grant receipt, section 4>,
             "log": {"checkpoint", "entry", "inclusion", "leaf_index", "tree_size"}}],
 "reads": [{"receipt": <read receipt, section 12>, "log": <log proof of the receipt>}],
 "fetch_events": [<fetch event, section 13>]}
```

- `grants` has each grant of each version of the finding to the person,
  also a grant that the owner withdrew later (the sealed grant payload stays
  in the vault).
- A person checks each receipt signature and each inclusion proof against a
  checkpoint of the log, and each fetch event against the node assertion key.
  A gap in `seq` of the fetch events of one grant shows a removed event.
- A share with the lab space (`lab:<lab_id>`) has no record: reads of the lab
  space are not recorded (integration 1.10).
