# Anagram log, version 1

Status: locked (2026-10-15). Licence: CC BY 4.0.

The node keeps an append-only Merkle log of log entries
([formats.md](formats.md) section 9). It follows the C2SP specifications.

## 1. Tree

- Leaf data: `canonical_json(entry)`. Leaf hash and node hash: RFC 6962.
- Inclusion and consistency proofs: RFC 9162 section 2.1. Every leaf hash,
  root hash, and proof path element MUST be 32 bytes (64 lowercase hex
  characters in JSON). A consistency proof with `old_size == 0` is valid only
  when `old_root` equals the empty tree root `SHA-256("")` and the path is
  empty.
- Proof hashes in JSON: lowercase hex, leaf side first.

## 2. Checkpoint (C2SP tlog-checkpoint)

```
<origin>\n
<tree size, decimal>\n
<root hash, base64>\n
```

The origin is a schema-less URL, for example `anagram.example.org/log`. The
root hash line MUST be canonical standard base64 of 32 bytes (44 characters,
no non-zero trailing bits). The
anchor digest of a checkpoint is `SHA-256(checkpoint text)` (not tagged, so
that standard tools can check the anchor).

## 3. Signed note (C2SP signed-note)

```
<checkpoint text>
\n
— <key name> <base64(key hash || signature)>\n
```

- The line starts with U+2014 (em dash) and a space.
- Key hash: `SHA-256(key name || "\n" || 0x01 || Ed25519 public key)[:4]`.
- Signature: Ed25519 over the checkpoint text.
- The log key name must equal the origin.
- Verifier key string: `<name>+<key hash hex>+<base64(0x01 || public key)>`.

The implementation reproduces the Go `golang.org/x/mod/sumdb/note` test vector.

## 4. Witness cosignature (C2SP tlog-cosignature)

A witness adds a signature line to the same note:

- Key hash: `SHA-256(name || "\n" || 0x04 || public key)[:4]`.
- Signed message: `"cosignature/v1\ntime <unix seconds>\n" || checkpoint text`.
- Line value: `base64(key hash || u64(time) || signature)`.

A witness keeps the last checkpoint that it cosigned for each origin. It
cosigns a new checkpoint only if:

1. a pinned log key signed it;
2. its size is not smaller than the stored size;
3. at the same size, the root is the same;
4. at a larger size, a consistency proof from the stored checkpoint is valid.

Otherwise it refuses. A refusal at step 3 or 4 is a **fork**.

In a local test node, the witness runs with the node. This tests the protocol. It does not stop
a dishonest operator, because the operator holds both keys. Production needs a
witness that another party runs.

## 5. Tiles (C2SP tlog-tiles)

The node serves hash tiles and entry bundles with the tlog-tiles paths and bytes:

- `tile/<L>/<N>[.p/<W>]`: W hashes (default 256) at tree level 8L, from index
  256N. N is in groups of three digits, `x` before each group except the last
  (for example `x001/x234/067`).
- `tile/entries/<N>[.p/<W>]`: each entry as `u16(length) || data`.

Deviation: the node does not store tile files. It derives tiles from its
SQLite node table on request. The bytes are the same.

## 6. Node HTTP API

| Method and path | Result |
| --- | --- |
| `POST /log/entries` with `{"entry": {...}}` (member session and rate limit) | `leaf_index`, `tree_size`, `inclusion`, `checkpoint` (with cosignatures), `anchors` |
| `GET /log/checkpoint` | latest checkpoint and its anchors |
| `GET /log/proof/inclusion?index=&size=` | `{"inclusion": [...]}` |
| `GET /log/proof/consistency?old=&new=` | `{"consistency": [...]}` |
| `GET /log/keys` | public keys (a hint; clients must pin keys out of band) |
| `GET /tile/...` | tiles (section 5) |

| `GET /log/entries?start=&end=` | leaf data as UTF-8 text, at most 1000 entries |
| `GET /directory/<subject>` | key-binding entries with inclusion proofs |

Vault routes (blobs, grants, public releases, guardians) are in
[vault.md](vault.md) section 8. The node's enclave relay routes are in
[enclave-messages.md](enclave-messages.md).

The node publishes one checkpoint for each entry. Batching is later.

A submission needs a session of a community member
(`Authorization: Bearer <token>`), and each member has a rate limit (default 60
entries a minute, `submit_per_minute` in `node.json`). The node still cannot
check the owner of a hidden entry; the session only stops anonymous spam.
The node also submits entries itself: `match_round`, `operator_attestation`,
and `read_receipt` (the receipt of a reader, [vault.md](vault.md) section 12).
All read endpoints stay public.

## 7. Client checks

After each submit, the client:

1. checks the checkpoint signature against the pinned log key;
2. checks the witness cosignatures against the pinned witness keys;
3. checks the inclusion proof of its entry;
4. asks for a consistency proof from the last checkpoint that it saw, and
   checks it. A smaller size or a failed proof stops the client
   (`LogMisbehaved`).
