# Anagram formats, version 1

Status: locked (2026-10-15). Licence: CC BY 4.0. Vectors: [vectors/](vectors/).

## 1. Principles

- Commit **bytes**, not meaning. Evidence is any file, unchanged. Anagram does
  not convert or parse it before it commits it.
- Each committed field has its **own random salt**. Without a salt, a person
  can guess a short value from its hash.
- The owner can **open one field** and keep the other fields hidden.
- The public log holds only a hash. It does not show the root, the owner, or
  any field.

## 2. Encoding

### 2.1 Canonical JSON

All hashed and signed JSON uses canonical JSON. It is a strict subset of
RFC 8785 (JCS):

- Values: `null`, `true`, `false`, integers from -(2^53-1) to 2^53-1, strings,
  arrays, objects.
- **Floats are not allowed.** A parser must refuse a number with a fraction or
  an exponent.
- Object keys are strings. Sort keys by their UTF-16 code units (RFC 8785
  section 3.2.3). Duplicate keys are not allowed.
- No whitespace. Output is UTF-8.
- String escapes: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`. Other characters
  below U+0020 use `\u00xx` (lowercase hex). All other characters are literal.
  Lone surrogates are not allowed.

Because there are no floats, each output is also a valid RFC 8785 output.

### 2.2 Binary values

In JSON, hashes, salts, keys, and signatures are **lowercase hex**. The
sealed-opening ciphertext and anchor tokens are standard base64 (with padding).
Times are RFC 3339 UTC with whole seconds, for example `2026-10-15T12:00:00Z`.

### 2.3 Integers in hashes

`u32(n)` and `u64(n)` are big-endian unsigned integers of 4 and 8 bytes.
`lp(b)` is `u32(len(b)) || b`.

## 3. Hashes

All hashes are SHA-256.

### 3.1 Tagged hash

Each use of a hash has its own domain tag:

```
tagged_hash(tag, parts...) = SHA-256(u8(len(tag)) || tag || part1 || part2 || ...)
```

`tag` is ASCII, 1 to 255 bytes. Each part is fixed-length, or uses `lp()`,
or is the last part.

The signed message for an Ed25519 signature is `u8(len(tag)) || tag || payload`.

### 3.2 Tag registry (locked)

| Tag | Use |
| --- | --- |
| `anagram/v1/field` | Leaf of a committed field |
| `anagram/v1/evidence-root` | Root of an evidence record |
| `anagram/v1/finding-root` | Root of a finding envelope |
| `anagram/v1/stream-checkpoint-root` | Root of a stream checkpoint |
| `anagram/v1/stream-items` | Root over the items of one stream checkpoint |
| `anagram/v1/content` | Chunked content digest of a file |
| `anagram/v1/log-entry` | Hidden commitment in a log entry |
| `anagram/v1/sign/finding` | Owner signature on a finding root |
| `anagram/v1/sign/stream-checkpoint` | Owner signature on a stream checkpoint root |
| `anagram/v1/fake-anchor` | Signature of the local test anchor |
| `anagram/v1/vault-key-id` | Key ID of a vault key |
| `anagram/v1/node-key-fingerprint` ... `anagram/v1/invite-id` | Identity formats. See [identity.md](identity.md) section 1 |
| `anagram/v1/blob/key` ... `anagram/v1/vault/item` | Vault formats. See [vault.md](vault.md) section 9 |
| `anagram/v1/orcid-commit`, `anagram/v1/sign/device-signin` | Person IDs (v2). See [identity.md](identity.md) section 1 |
| `anagram/v1/store/key` ... `anagram/v1/sign/person-keys` | Personal store (v2). See [vault.md](vault.md) section 11.7 |

### 3.3 Merkle trees

Merkle trees use RFC 6962 (also RFC 9162 section 2.1):

- leaf hash: `SHA-256(0x00 || data)`
- node hash: `SHA-256(0x01 || left || right)`
- empty tree: `SHA-256("")`
- a tree of n > 1 leaves splits at the largest power of two that is smaller
  than n.

Inclusion and consistency proofs and their checks are as in RFC 9162 sections
2.1.3 and 2.1.4. Every leaf hash, root hash, and proof path element MUST be 32
bytes. When `old_size == 0`, a consistency proof is valid only if `old_root`
equals the empty tree hash `SHA-256("")` and the path is empty.

### 3.4 Chunked content digest

A file of any size has one content digest:

```
chunks  = the file bytes, cut into chunks of chunk_size bytes (the last chunk can be shorter)
mth     = RFC 6962 Merkle tree hash with each chunk as one leaf (empty file: SHA-256(""))
digest  = tagged_hash("anagram/v1/content", u64(size) || u32(chunk_size) || mth)
```

The JSON form (`content`):

```json
{"alg": "anagram-chunked-sha256-v1", "chunk_size": 1048576, "digest": "<hex>", "size": 1234}
```

The default chunk size is 1 MiB (1048576). The chunk size is part of the
digest, so a verifier always uses the recorded value. The maximum is 64 MiB.
A reader must refuse a `content` object with `chunk_size` not in
1 to 67108864, `size` not in 0 to 2^64-1, or a `digest` that is not 64
lowercase hex characters.
A reader needs only one chunk in memory.

## 4. Committed objects

A committed object is a flat map from field name to a JSON value.

- Field names match `^[a-z][a-z0-9_]*(\.(0|[1-9][0-9]*))?$`. A suffix `.N`
  marks item N of a list (no leading zeros).
- Each field has a random 32-byte salt from a CSPRNG. Never reuse a salt.
- Field leaf: `tagged_hash("anagram/v1/field", salt || lp(ascii(name)) || canonical_json(value))`.
- Sort the field names by byte order. The leaves in this order are the leaves
  of an RFC 6962 tree. (The tree leaf hash is `SHA-256(0x00 || field leaf)`.)
- The **layout** is the JSON array of the sorted field names. Each name is in
  it once, so the order is strict. It has 1 to 65536 names.
- Object root:

  ```
  root = tagged_hash(<object tag>, lp(canonical_json(layout)) || MTH)
  ```

The layout binds each field name to one fixed leaf position. Without it, an
owner can put two leaves with the same name (for example two `claim` leaves)
in one tree, and later open the leaf that agrees with a result (a hedged
commitment). With the layout, the leaf at position `i` is the only leaf that
can open as `layout[i]`.

A **field proof** opens one field:

```json
{"index": 3, "layout": ["claim", "created_at", ...], "name": "claim", "path": ["<hex>", ...], "salt": "<hex>", "size": 11, "value": "..."}
```

To check it:

1. The layout obeys the rules above. It has the names that the schema of the
   object needs, and no other names (sections 5, 6, 8; `.N` names are exactly
   `0` to `n-1`).
2. `size` equals the length of the layout, `0 <= index < size`, and `name`
   equals `layout[index]`.
3. Compute the field leaf, and compute MTH from the inclusion path
   (RFC 9162 2.1.3.2).
4. Compute the object root from the layout and MTH, and compare it with the
   root.

The layout shows the names and the number of the fields, but no value and no
salt. The names and counts were already visible (from `size`, and from the
count fields of a finding), so the layout does not show more.

An **opening** holds all fields and all salts:

```json
{"fields": {"<name>": <value>, ...}, "salts": {"<name>": "<hex>", ...}}
```

## 5. Evidence record (`anagram.evidence.v1`)

Object tag: `anagram/v1/evidence-root`. Fields (all required):

| Field | Value |
| --- | --- |
| `schema` | `"anagram.evidence.v1"` |
| `content` | content digest object (section 3.4) |
| `media_type` | media type, for example `image/png`. A guess is fine; it is not checked against the bytes |
| `name` | original file name, or `null` |
| `source` | where the bytes came from, for example `"file"` |

Any bytes are valid evidence: text, image, video, slide deck, email, instrument
data. A changed byte gives a different digest, so a re-saved file is a new item.

To prove that a public copy equals a committed file, the owner opens the
`content` field of that item, and the `evidence.N` field of the finding.

## 6. Finding envelope (`anagram.finding.v1`)

Object tag: `anagram/v1/finding-root`. Fields:

| Field | Value |
| --- | --- |
| `schema` | `"anagram.finding.v1"` |
| `finding_id` | 16 random bytes, hex. All versions of a finding share it |
| `version` | integer, starts at 1 |
| `owner` | `{"alg": "ed25519", "key": "<hex public key>"}` |
| `created_at` | time from the owner's clock (a claim, not a proof of time) |
| `claim` | optional one-line claim (string) or `null` |
| `evidence_count` | integer n |
| `evidence.0` ... `evidence.{n-1}` | evidence roots (hex) |
| `link_count` | integer m |
| `links.0` ... `links.{m-1}` | link objects (section 7) |

Rules:

- A finding with no evidence and only a claim is valid.
- Version 1 has no `supersedes` link. Version 2 and later have exactly one.
- Each evidence item and each link is its own field. So the owner can open one
  item and keep the others hidden. The counts show how many items there are.

## 7. Links

```json
{"target": "<hex root of the target finding version>", "type": "supersedes"}
```

| Type | Meaning |
| --- | --- |
| `supersedes` | This finding is a new version of the target |
| `builds_on` | This finding uses the target finding |
| `includes` | This finding contains the target finding (for example, a paper includes its figures) |

A link target is a finding root. A link does not show the target's content.

## 8. Stream checkpoint (`anagram.stream_checkpoint.v1`)

A connected source (folder, Git, instrument) commits a checkpoint at a set
interval. Object tag: `anagram/v1/stream-checkpoint-root`. Fields:

| Field | Value |
| --- | --- |
| `schema` | `"anagram.stream_checkpoint.v1"` |
| `stream_id` | 16 random bytes, hex |
| `seq` | 0, 1, 2, ... |
| `prev` | root of checkpoint `seq - 1`, or `null` for `seq` 0 |
| `start` | stream index of the first item in this checkpoint |
| `item_count` | number of items |
| `items_root` | `tagged_hash("anagram/v1/stream-items", u64(item_count) \|\| MTH(item roots))` |
| `owner` | as in the finding |
| `created_at` | owner's clock |

Each item is an evidence root. The `prev` chain stops a rewrite of history.

## 9. Signed subject and log entry

The owner signs the root:

```
signature = Ed25519(device key, u8(len(tag)) || tag || root)
tag = "anagram/v1/sign/finding" or "anagram/v1/sign/stream-checkpoint"
```

Subject JSON:

```json
{"kind": "finding", "owner": {"alg": "ed25519", "key": "<hex>"}, "root": "<hex>", "signature": "<hex>"}
```

The log entry hides the root, the owner, and the signature:

```
commitment = tagged_hash("anagram/v1/log-entry", lp(kind) || root || owner_key || signature)
entry      = {"commitment": "<hex>", "kind": "finding", "schema": "anagram.log_entry.v1"}
leaf data  = canonical_json(entry)
```

The node accepts a hidden entry only with exactly these three keys. The only other
entry kind is the public key-binding entry (`anagram.key_binding.v1`, see
[identity.md](identity.md) section 7).

Log-only kinds (added 2026-10-15): `match_round` and `operator_attestation`. The
node itself makes these entries. They have no signed subject. The commitment
is a 32-byte hash of the removed node-run room. The entry has the same
three keys. No code writes these kinds now; a log reader still accepts
them ([matching.md](matching.md) section 8).

Log-only kind (added 2026-10-15): `grant_receipt`. A member submits it. The
commitment is the hash of a salted, owner-signed grant receipt
([vault.md](vault.md) section 4). The entry has the same three keys.

Log-only kind (added for the first release, 2026-11-16): `read_receipt`. The node
submits it for the reader when it accepts a read receipt. The commitment is
the hash of a salted, reader-signed read receipt ([vault.md](vault.md)
section 12). The entry has the same three keys.

## 10. Opening data and sealed opening

The owner must keep the opening data. Without the salts, no proof is possible.

Opening document (`anagram.opening.v1`):

```json
{"evidence": [<opening>, ...], "finding": <opening>, "schema": "anagram.opening.v1"}
```

At rest, the client stores it only as a sealed opening
(`anagram.sealed_opening.v1`):

```json
{
  "alg": "chacha20-poly1305",
  "ciphertext": "<base64>",
  "key_id": "<hex, first 8 bytes of tagged_hash('anagram/v1/vault-key-id', vault key)>",
  "nonce": "<hex, 12 random bytes>",
  "schema": "anagram.sealed_opening.v1",
  "subject_root": "<hex finding root>"
}
```

- Plaintext: canonical JSON of the opening document.
- AAD: canonical JSON of the object without `ciphertext` and `nonce`.
- Key: the 32-byte vault key from the owner's keystore.
- After decryption, the finding root of the opening must equal `subject_root`.

## 11. Changes

Version 1 is not released yet. These changes keep the schema names (`v1`).

- 2026-10-15, after review: the object root binds the field layout
  (section 4). Before, the root was `tagged_hash(<object tag>, MTH)`, and a
  field proof had no `layout`. The vectors are new. Field names with a leading
  zero after the dot (`evidence.01`) are not valid.
- 2026-10-15, after review: a `content` object with `size` or `chunk_size` out of
  range (section 3.4) is not valid.
- 2026-10-15, after review: proven time and anchor counts follow the witness
  threshold and distinct anchor sources ([proof-bundle.md](proof-bundle.md)
  section 3).
