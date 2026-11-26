# Lab unit formats

Status: draft (2026-11-16). Code: `src/anagram/network/formats/lab.py` (the roster),
`labkey.py` (the key package), `labitem.py` (the lab item), and
`labsettings.py` (the settings).
Vectors: [vectors/lab.json](vectors/lab.json).

A lab is a unit on a node with one PI, admins, and members. A person can be
in more than one lab. This document gives the formats that make a lab: the
signed roster, the invite, the join request, the lab key package, the lab
space records, the lab item, and the lab settings record. The design is the
group roster pattern ([docs/design/group-roster.md](../docs/design/group-roster.md)).

All objects are canonical JSON ([formats.md](formats.md)). Times are RFC 3339
UTC with whole seconds. A signature is
`Ed25519(key, u8(len(tag)) || tag || canonical_json(object without its signature fields))`,
as in [identity.md](identity.md).

## 1. Tags

| Tag | Use |
|---|---|
| `anagram/v1/lab/roster` | Hash of a roster entry |
| `anagram/v1/sign/lab-roster` | Signature of a roster entry |
| `anagram/v1/lab/invite` | Invite ID, invite key derivation, join request hash |
| `anagram/v1/sign/lab-invite` | Signature of an invite authorisation |
| `anagram/v1/sign/lab-join` | The two signatures of a join request |
| `anagram/v1/hpke/lab-key` | HPKE `info` of a lab key wrap |
| `anagram/v1/sign/lab-key` | Signature of a lab key package |
| `anagram/v1/lab/item` | Binds an attachment blob to its lab item (`attachment_root`) |
| `anagram/v1/sign/lab-item` | Signature of a lab item |
| `anagram/v1/sign/lab-settings` | Signature of a lab settings record |

## 2. Roster entry (`anagram.lab_roster.v1`)

```
{"schema", "lab_id": "lab-<16 hex>", "seq": <int >= 0>,
 "prev": <64 hex; 64 zeros at seq 0>, "op", "at",
 "actor": <pid>, "actor_device": <ed25519 hex>,
 "subject": <pid or null>, "role": <"pi"|"admin"|"member"|null>,
 "name": <1..200 characters or null>, "invite": <32 hex or null>,
 "request": <join request or null>, "signature": <128 hex or null>}

entry_hash = sha256(u8(len(tag)) || tag || canonical_json(entry)), tag anagram/v1/lab/roster
```

`signature` is by `actor_device` with tag `anagram/v1/sign/lab-roster`. A
`join` entry has no signature: its `request` holds the proof.

Each op uses some fields. The other fields are null.

| op | Fields | Who | Rule |
|---|---|---|---|
| `create` | subject (= actor), role `pi`, name | the PI | `seq` 0 only |
| `add` | subject, role | PI, admin | role `admin` or `member`; an admin adds `member` only; the subject is not in the lab; it ends the bar of a removed person |
| `join` | subject, role, invite, request | the joiner (request) | section 3 |
| `remove` | subject | PI, admin | not the actor; not the PI; an admin removes a `member` only; it bars the person (below) |
| `leave` | subject (= actor) | the member | not the PI |
| `role` | subject, role | PI | role `admin` or `member`; not the PI |
| `transfer` | subject | PI | the subject becomes PI; the actor becomes admin |
| `rename` | name | PI, admin | |
| `invite` | invite | PI, admin | an `admin` invite needs the PI; section 3 |
| `revoke_invite` | invite | PI, admin | an `admin` invite needs the PI |
| `close` | none | PI | no entry after it |

Rules for each entry: `lab_id` is the lab; `seq` is the last `seq` plus 1;
`prev` is the hash of the last entry; the lab is not closed; the actor is in
the lab (except `create` and `join`); the signature is correct; and
`actor_device` is a key of the actor at `at` (the node uses the active
devices of now; a client uses the key directory with log proofs). One function
applies an entry for the node and for the client. A client keeps the head
that it verified and refuses a chain that does not extend it.

Chain rules v2 (removal is final; from a security review). The entry format and
`anagram.lab_roster.v1` do not change; only the rules of `LabState.apply`
change, so a chain that obeys v2 verifies under v1 too, and the vectors stay
the same. A `remove` entry, in the same entry:

- records the person as removed, with the device keys that the person used
  in the chain (`actor_device` of the entries of the person, and the device
  of the join request);
- revokes each invite that the person made or joined with, so that no
  rotation wraps a new key to it.

A `join` of a removed person, or from a barred device key, is refused. Only an
explicit `add` by a PI or admin ends the bar. A `leave` does not bar.

## 3. Invite (`anagram.lab_invite.v1`) and join request (`anagram.lab_join.v1`)

Moved to [admission.md](admission.md) section 4. The formats did not change.

## 4. Lab key package (`anagram.lab_key.v1`)

The lab key of epoch `n` is 32 random bytes. Epoch 1 starts at `create`.

```
{"schema", "lab_id", "epoch", "recipient": <pid or "invite:<invite id>">,
 "roster_seq", "roster_head", "sender": <pid>, "sender_device", "created_at",
 "wraps": [{"device", "ciphertext"}], "signature"}
payload = canonical_json({"schema": "anagram.lab_key_payload.v1", "lab_id", "epoch",
                          "keys": {"1": <hex>, ..., "<epoch>": <hex>}})
info    = tagged_message(hpke/lab-key, lp(lab_id) || u32(epoch) || device_ed25519)
```

Each wrap is HPKE ([vault.md](vault.md) suite) of the payload to the X25519
key of one device. For an invite the one device is (`invite_pub`,
`invite_x25519`). The sender device signs the package
(`anagram/v1/sign/lab-key`). A reader accepts a package only if the roster
head that it names (`roster_seq`, `roster_head`) is in the verified chain,
the sender had the role PI or admin at a roster seq from `roster_seq` to
now, and the sender device was a key of the sender at `created_at` (log
proofs). Each other package is a node fault.

`roster_seq` is the roster seq at the start of the epoch: a rotation sets
it to the seq that the rotating device saw; a package for a new member or an
invite at the same epoch copies it. Thus each package of an epoch names the
same start.

Epochs and rotation (node routes `PUT /labs/{id}/keys/{epoch}`,
`GET /labs/{id}/keys`):

- The node stores packages and checks their form only. A PI or admin sends
  them. Epoch `current + 1` starts a new epoch, and the first request wins.
  At the current epoch, a request adds recipients; it is refused (`409`) if
  a recipient has a package at that epoch already. Each other epoch is `409`.
  The package of an invite must be of the current epoch.
- A new epoch is due when a member was removed or left after the start of the
  current epoch, or when a device in the wraps of the current epoch is not
  an active device of its member now. The device that writes a `remove`
  entry rotates in the same action. For a `leave` or a device change, the
  first PI or admin device that syncs rotates.
- A rotation wraps the new key and all earlier keys to each active device of
  each member (from `lookup`) and to each open invite. An invite that a
  removed person made or used is not open (section 2, chain rules v2).
- `GET /labs/invites/{id}` gives the key package of an invite only to a
  member who joined with that invite. A removed person gets no package. The
  node also refuses the join of a removed person (`410`), and a key package
  for a revoked invite. The clients do not trust the node for this: each
  client applies the chain rules.
- A device keeps each epoch key as a sealed vault item (kind `lab-key`, ref
  `<lab_id>:<epoch>`). The personal store carries it to the other devices of
  the person. Old records are not encrypted again.

## 5. Lab space records

Lab space records use the personal store record format
(`anagram.personal_store.v1`, [vault.md](vault.md) section 11). The keys are
`StoreKeys(lab_key[epoch])`, with one change: the record ID key comes from the
key of epoch 1. Thus the record ID of an item stays the same over epochs, and
a new version in a new epoch replaces the old version on the node. `key_id`
names the epoch of the encryption key.

| kind | ref | value |
|---|---|---|
| `lab_item` | `<item_id>` (32 hex) | lab item (section 6) |
| `lab_item_text` | `<item_id>:<n>` | `{"text": <at most 1 MiB of UTF-8>}` |
| `lab_settings` | `settings` | settings record (section 7) |

Node routes: `PUT /labs/{id}/space/records/{record_id}` with
`{"record", "blobs"?, "drop"?, "topic"?}`, `GET /labs/{id}/space/records?after=&limit=`,
`GET /labs/{id}/space/records/{record_id}`. The node checks the form, the size,
and the quota (`413`), and that the writer is a member and the lab is not
suspended. Only the first writer of a record, the PI, or an admin replaces or
drops it. A new version must be higher than the stored one (`409`). `drop`
deletes other records in the same action (the text parts of a removed or
shorter item). `topic` is `space` (default) or `settings`; it names the row
in the change feed.

A writer writes the text parts first, then the item record, all with the
key of the newest epoch. A reader takes an item record only if: it opens
with a key that the reader holds; the signature verifies; the roster head
that it names is in the reader's chain (else a fork: stop); the author was in
the lab at that roster seq; the author device was a key of the author; the
revision is newer; a new revision has the author of the first one; a removal
is by that author, the PI, or an admin; and the text parts match
`text_digest`. Other records are dropped.

## 6. Lab item (`anagram.lab_item.v1`)

```
{"schema", "lab_id", "item_id", "rev": <int >= 1>,
 "kind": "finding"|"note"|"source_item", "type": <item kind or null>,
 "title", "author": <pid>, "author_device", "published_at", "updated_at",
 "origin": {"source_kind", "name", "media_type", "time"},
 "text_parts": <int>, "text_digest": <sha256 hex of the full text>,
 "facts": [{"kind", "value", "score": <integer 0..1000 (per mille) or null>}],
 "finding": {"root", "finding_id", "version", "claim", "bundle"} | null,
 "attachments": [{"blob_id", "name", "media_type", "size", "chunk_size", "slot",
                  "evidence_root", "content_key"}],
 "roster": {"seq", "head"}, "deleted": <bool>, "signature"}
```

- The origin has no path and no source ID.
- `signature` is by `author_device` (`anagram/v1/sign/lab-item`).
- `roster` is the roster head that the writer saw. A head at a `seq` that the
  reader has, and that is not the hash of its entry at that `seq`, is a fork.
- A removed item has `deleted: true`, no text parts, no facts, no finding, and
  no attachments. Its `author` is the person who removed it: the author, the
  PI, or an admin.
- Attachments. Each file is a blob (`PUT /blobs/{blob_id}`) that
  `core/crypto/blob.py` encrypts with its own random `content_key`, with
  `finding_root = sha256(tagged_message("anagram/v1/lab/item", "<lab_id>/<item_id>"))`,
  `evidence_root` = the attachment's value or 32 zero bytes when it is null,
  and `slot` = the place of the file in the list. The key is only in the item,
  so only a lab member opens the file. A revision with no new files keeps the
  list. The item record lists its blob IDs (`blobs` of the record route); the
  node accepts only blobs that the writer uploaded, or blobs that the record
  listed already. `GET /blobs/{id}` gives a lab blob to each member of a lab
  whose space lists it (a `readers` hook of `NodeVault.blob_path`, after the
  owner and public checks and before the grant check; no read receipt). When
  no lab record lists a blob now (a removed item, a revision with other
  files), the node deletes it.

## 7. Lab settings (`anagram.lab_settings.v1`)

```
{"schema", "lab_id", "rev",
 "models":        {"profiles": [<profile>], "use": {<task>: <profile id> | null},
                   "kind_hints": [{"text", "kind"}], "person_facts": <bool>},
 "disclosure":    {"allow_external": [<recipient id>], "allow_assistant": <bool>,
                   "allow_cloud_assistant": <bool>},
 "oauth_clients": {"google": {"client_id", "client_secret"}, "notion": {...}},
 "sources":       {"allowed_kinds": [<source kind>] | null, "lab_default": "private"|"lab"},
 "matching":      {"enabled": <bool>},
 "updated_by", "updated_device", "updated_at", "roster": {"seq", "head"}, "signature"}
```

Each of the five sections is optional. A section refuses an unknown key. An
absent section, or an absent key in a section, takes its default:

| Section | Default |
|---|---|
| `models` | `{"profiles": [], "use": {}, "kind_hints": [], "person_facts": true}` |
| `disclosure` | `{"allow_external": [], "allow_assistant": false}`; the optional key `allow_cloud_assistant` is absent (false) |
| `oauth_clients` | `{}` |
| `sources` | `{"allowed_kinds": null, "lab_default": "private"}` |
| `matching` | `{"enabled": true}` |

`updated_device` signs the record (`anagram/v1/sign/lab-settings`). A reader
accepts the record only if `updated_by` is PI or admin in the verified roster.
The higher `rev` wins. No API key of a model is in the record. The writer
also checks the roster head that the record names, as for an item.

The client gives the sections to other code as a `LabPolicy` (cache only):
`allows_recipient(id, external=True)` (a local recipient always; `mcp`
follows `allow_assistant`; else `id` in `allow_external`),
`allows_assistant()`, `allows_cloud_assistant()` (an agent of class `cloud`, grant v2:
needs `allow_assistant` and `allow_cloud_assistant`), `allows_source(kind)` (`allowed_kinds` null permits
each kind; asked only for a source in this lab space), `lab_default()`, and
`matching_enabled()`. Enforcement is in honest clients.

## 8. Lab space in the local index (`labspace` source)

Each lab that this device can read (`Client.lab_keys.readable_labs`) has one source of
kind `labspace` in the local index, with config
`{"kind": "labspace", "lab_id"}` and `source_state.space = "lab:<lab_id>"`.
Its items come from the local lab cache, never from the node directly:

| Index field | Value |
|---|---|
| `key` | `item_id` |
| `kind` | `lab_item` |
| `name` | `title` |
| `media_type` | `text/markdown` (the bytes are the item text) |
| `time` | `published_at` |
| `ref` | `lab:<lab_id>/<item_id>` |
| `extra` | `{"author", "lab_id", "item_kind", "type", "facts"}`; a fact score is 0 to 1 here |

- The class flag `own` is false. A lab item goes into no checkpoint, no
  finding draft, and no brief, and it never goes back into a lab space.
- With `type` set, the index takes the kind and the facts of the author
  (`by = "lab"`) and sends the text to no model again.
- The source has no item that this device published from a source whose
  space is that lab (the original is in the index).
- The source goes when the person leaves the lab or is not in its verified
  roster. A lab whose current key is not on the device yet keeps its source.

Publish from the index. A source with the space `lab:<lab_id>` publishes each
current version of each item as a lab item of kind `source_item`: the title,
the converted text, the item kind and the facts of the index (`title`,
`claim`, `entity`, `person`, `summary`), and an origin with no path and no
source ID. A new version gives a new revision of the same lab item. A mail
source never goes into a lab space. When the source leaves the lab space, or
is removed, the items that it published are removed from the lab space; an
item that the person put into the lab space by hand stays. The publish map is
in the lab cache, so each step is safe to run again. The space hook does this
at once when the caller gives it (`labspace.space_hook(client, index)`); else the next
`labspace.sync_index` does it.
