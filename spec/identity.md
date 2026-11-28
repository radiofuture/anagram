# Anagram identity formats, version 3

Status: locked (2026-10-15). Version 2 (2026-10-27): private person IDs
and ORCID commitments, key backup v2, device sign-in, person keys on each
device. Version 3 (2026-11-16): a person needs no ORCID iD; the invite is the
proof of a person; an ORCID iD is optional and a person can link one (section
14). Licence: CC BY 4.0. Vectors:
[vectors/identity.json](vectors/identity.json).

These formats let a person join a community node, bind device keys to a
private person ID in the public log, and recover keys and data. Entry is by
invite only. The invite is the check that a person is a real researcher: the
inviter vouches for the person ([admission.md](admission.md)). A person does not need an ORCID
iD. A linked ORCID iD of a member is **not public** (section 13). They use the encoding rules of
[formats.md](formats.md) section 2 (canonical JSON, lowercase hex, RFC 3339
times).

## 1. Signed documents

The documents in this file are **public signed documents**. They are not salted
committed objects (formats.md section 4), because each one is public.

```
body      = the document without its signature field(s)
signature = Ed25519(key, u8(len(tag)) || tag || canonical_json(body))
```

New tags (added to the locked registry in formats.md section 3.2):

| Tag | Use |
| --- | --- |
| `anagram/v1/node-key-fingerprint` | Fingerprint of the node log key |
| `anagram/v1/sign/node-trust` | Log key signature on the node trust document |
| `anagram/v1/sign/invite` | Assertion key signature on an invite |
| `anagram/v1/sign/invite-receipt` | Assertion key signature on an invite receipt |
| `anagram/v1/sign/node-assertion` | Assertion key signature on a sign-in assertion |
| `anagram/v1/sign/key-binding` | Device signature on a key-binding entry |
| `anagram/v1/sign/key-possession` | Proof of possession of a new device key |
| `anagram/v1/sign/identity-record` | Device signature on an identity record |
| `anagram/v1/key-binding-entry` | Hash of a key-binding entry (the `prev` chain) |
| `anagram/v1/invite-id` | Public ID of an invite (hash of its token) |
| `anagram/v1/orcid-commit` | ORCID commitment (v2, section 2) |
| `anagram/v1/sign/device-signin` | Device key signature on a device sign-in challenge (v2, section 11) |

## 2. Identifiers

| Name | Form |
| --- | --- |
| ORCID iD | `0000-0002-1825-0097` with a valid ISO 7064 11-2 check digit. Tests use `fake-` and 1 to 63 chars of `[0-9a-z-]` |
| ROR ID | Bare ID, for example `05dxps055` (`0` + 6 base32 chars + 2 digits). Tests use `fake-...` |
| Subject (person ID, pid) | `pid:<32 hex>`: 16 random bytes. The person's first device makes it at the first join (the node makes one if the client gives none). It is never derived from an ORCID iD or an email address. It never changes. It does not identify the person. The same form for each sign-in method |
| ORCID commitment | `hex(tagged_hash("anagram/v1/orcid-commit", utf8(ORCID iD) \|\| salt))`, with a 32-byte random salt. The salt is the last part and has a fixed length, so the parts are unambiguous. `null` for a person who joined with an invite (v3) or with email |
| Lab ID | `lab-<16 hex>` |

The person's first device also makes the ORCID salt. The node keeps a copy
with its private map (section 13), because it must check the commitment. The
person's devices keep the ORCID iD and the salt in the client config and in
the personal store ([vault.md](vault.md) section 11). With them the person can
open the commitment to anyone later.

## 3. Node trust document (`anagram.node_trust.v1`)

```json
{
  "assertion_key": "<hex Ed25519 public key>",
  "community": "Example community",
  "fake_anchor_keys": ["<hex>"],
  "log_keys": ["<C2SP vkey of the log>"],
  "node_url": "https://node.example.org",
  "orcid_mode": "production | sandbox | fake",
  "schema": "anagram.node_trust.v1",
  "signature": "<hex, by the log key, tag anagram/v1/sign/node-trust>",
  "witness_keys": ["<C2SP vkey>"]
}
```

The **node key fingerprint** is
`hex(tagged_hash("anagram/v1/node-key-fingerprint", utf8(log vkey)))`.

A client must check that the fingerprint of `log_keys[0]` equals the pinned
fingerprint, and that the log key signed the document. All other node keys come
from this document. The node serves it at `GET /node/trust`.

## 4. Invite (`anagram.invite.v1`)

Moved to [admission.md](admission.md) section 2. The format did not change.

## 5. Invite receipt (`anagram.invite_receipt.v1`)

Moved to [admission.md](admission.md) section 3. The format did not change.

## 6. Node assertion (`anagram.node_assertion.v2`)

The node signs this after a sign-in. It binds the subject to one device key and
one client nonce.

```json
{
  "audience": "<hex Ed25519 device public key>",
  "community": "...",
  "expires_at": "<issued_at + 10 minutes>",
  "issued_at": "...",
  "method": "invite | orcid | orcid-sandbox | orcid-fake | email",
  "node_key": "<fp>",
  "nonce": "<hex, 16 bytes from the client>",
  "orcid_commitment": "<hex> | null",
  "schema": "anagram.node_assertion.v2",
  "signature": "<hex, assertion key, tag anagram/v1/sign/node-assertion>",
  "subject": "pid:<32 hex>"
}
```

The assertion goes into the public log (seq 0 and `reset` entries), so it has
no ORCID iD and no name (v1 had `name`). `orcid_commitment` is `null` if and
only if `method` is `invite` or `email`. Method `invite` (v3): the node checked
an open invite (section 11). A v2 verifier does not know `invite` and refuses
the assertion; it fails closed. The device that asked for the assertion must check the
signature, `node_key`, `audience`, `nonce`, and `expires_at`. A client in a
production community must refuse `orcid-fake`.

## 7. Key-binding log entry (`anagram.key_binding.v1`)

The key directory uses the **same log** as findings. A key-binding entry is a
public log entry. Its leaf data is `canonical_json(entry)`.

```json
{
  "authority": {"assertion": <node assertion>} | {"device": "<hex Ed25519 key>"},
  "created_at": "...",
  "device": {"ed25519": "<hex>", "x25519": "<hex>"},
  "kind": "key_binding",
  "op": "add | remove | reset",
  "orcid_commitment": "<hex> | null",
  "pop": "<hex> | null",
  "prev": "<hex> | null",
  "schema": "anagram.key_binding.v2",
  "seq": 0,
  "signature": "<hex> | null",
  "subject": "pid:..."
}
```

Signatures:

- `pop` (proof of possession): Ed25519 by `device.ed25519` over
  `canonical_json({"device": device, "subject": subject})`, tag
  `anagram/v1/sign/key-possession`. Required for `add` and `reset`; `null` for
  `remove`. It does not depend on the log position, so a new device can make it
  before an existing device approves it.
- `signature`: for a `device` authority, Ed25519 by that device key over the
  entry without `signature`, tag `anagram/v1/sign/key-binding`. For an
  `assertion` authority, `null`.

Chain rules for each subject, in log order:

1. `seq` starts at 0 and goes up by 1. Seq 0 has `prev` = `null`. Later entries
   have `prev` = `hex(tagged_hash("anagram/v1/key-binding-entry",
   canonical_json(previous entry)))`.
2. Seq 0 must be `add` with an `assertion` authority. The assertion subject
   must equal the entry subject, and its `audience` must equal
   `device.ed25519`. This is the node-attested sign-in (invite, ORCID, or
   email).
3. After seq 0, `add` and `remove` need a `device` authority that is active.
   A device can remove itself.
4. `reset` needs an `assertion` authority (as in rule 2). It removes all
   devices and adds `device`. It is for a person who lost all devices and the
   recovery kit.
5. `add` of an active device fails. `remove` of a device that is not active fails.
6. (v2) Each entry has the `orcid_commitment` of seq 0. An entry with an
   `assertion` authority has the commitment of its assertion. The commitment
   of a subject never changes.

The node checks the chain rules before it appends an entry, and refuses an
assertion that has expired. A verifier checks the chain from the log.

**Trust.** The node holds the assertion key, so a dishonest node can make a seq
0 entry for a person who has not joined, or a `reset` for any person. It cannot
do this in secret: the entry is in the log. Each client monitors its own
subject (section 10) and reports a key that it did not expect.

## 8. Identity record (`anagram.identity_record.v2`)

```json
{
  "devices": [{"ed25519": "<hex>", "x25519": "<hex>"}],
  "display_name": "Josiah Carberry",
  "institution": "<ROR ID> | null",
  "lab_id": "lab-<16 hex> | null",
  "orcid_commitment": "<hex> | null",
  "schema": "anagram.identity_record.v2",
  "signature": "<hex>",
  "signed_by": "<hex Ed25519 device key>",
  "subject": "pid:..."
}
```

`devices` is sorted by `ed25519`. `orcid_commitment` must equal the commitment
of the subject in the key directory (v1 had the ORCID iD here). The record
is for members only (`GET /identity/<subject>`). `signed_by` and all `devices` must be
active in the key directory. The record is not in the log; the node stores the
latest one. The node refuses a `lab_id` of a lab that the subject is not a
member of. A person can be in more than one lab; the record names one. The
roster of a lab, the lab key, and the lab invite link are in [lab.md](lab.md).
A lab invite link also makes a new person a node member: `POST
/labs/{id}/join` with a valid join request adds the member row (at most
`max_uses` people for each link) and answers `{"status": "bind_device"}`
until the device of the person is bound; the client then binds the device
and sends the join again.

## 9. Recovery kit and key backup (`anagram.key_backup.v2`)

The recovery secret is 20 random bytes. The kit shows it as base32 (RFC 4648)
in groups of 4 characters, for example `ABCD-EFGH-...` (8 groups).

```
backup_key = HKDF-SHA256(ikm=secret, salt=none, info="anagram/v1/recovery/key", L=32)
backup_id  = HKDF-SHA256(ikm=secret, salt=none, info="anagram/v1/recovery/id",  L=32)
```

The secret has 160 bits of entropy, so a slow KDF is not necessary.

```json
{
  "alg": "chacha20-poly1305",
  "backup_id": "<hex>",
  "ciphertext": "<base64>",
  "kdf": "hkdf-sha256",
  "nonce": "<hex, 12 bytes>",
  "schema": "anagram.key_backup.v2",
  "subject": "pid:..."
}
```

- Plaintext: `canonical_json({"keys": {"device-ed25519": hex, "device-x25519":
  hex, "index-key": hex, "vault-key": hex}, "schema":
  "anagram.key_backup_payload.v2", "subject": ...})`.
- Version 1 (`anagram.key_backup.v1`, payload v1) has no `index-key`. A
  client still reads it.
- AAD: canonical JSON of the document without `ciphertext` and `nonce`.

The node stores the backup under `backup_id` (`PUT /recovery/backup`, member
session) and serves it to anyone who knows the ID (`GET
/recovery/backup/<backup_id>`). The node never sees the secret or `backup_key`.

The kit file is Markdown. It holds these lines (the client reads them):

```
Node: https://node.example.org
Node key: <fingerprint>
Subject: pid:...
Recovery code: ABCD-EFGH-...
```

To restore, the client checks the node against `Node key`, gets the backup,
decrypts it, and checks that the restored device key is still active in the key
directory. Then it signs in with the restored device key (section 11, device
sign-in) and reads the personal store ([vault.md](vault.md) section 11.5): the
sealed openings, bundles, rings, the ORCID opening, and the index snapshot.
Old proofs then verify on the new computer.

## 10. Client checks

- **Lookup** (`GET /directory/<subject>`): each entry comes with an inclusion
  proof at one checkpoint. The client checks the checkpoint (signature, witness
  cosignatures, consistency with the last checkpoint it saw), each inclusion
  proof, and the chain rules. An entry that is not in the log, or a log that is
  not consistent, raises `LogMisbehaved`. The answer must also be complete:
  the client reads the log up to the same checkpoint (as in monitoring) and
  keeps its own copy of all valid key bindings. The node answer must list the
  same entries of the subject (leaf index and bytes). If the node omits an
  entry (for example a `reset` or `remove`), the lookup raises `LogMisbehaved`.
  Limit: the checkpoint can be old, but not older than the last checkpoint that
  the client saw.
- **Monitor**: the client reads all entries after the last monitored size
  (`GET /log/entries`), adds them to a compact range (the roots of the perfect
  subtrees), and checks that the range root equals the verified checkpoint root.
  So the node cannot hide or change an entry. For its own subject, an `add` or
  `reset` of a key that the client does not expect, or the removal of this
  device, makes an alert. Lookup also reads the log. A separate cursor makes
  sure that monitoring checks each of the client's own bindings one time.

## 11. Sign-in flows (node API, not locked)

Invite (v3, the main path; no third party): `POST /auth/invite` (rate-limited
per client address) with `invite`
(the `token` of a node invite, or `lab:<invite ID>` of a lab invite),
`device_key`, `nonce`, `pid` (the person ID that the first device made),
optional `invite_signature` (required for lab invites: Ed25519 by `invite_pub`
over `canonical_json({"device_key", "invite", "nonce"})`, tag
`anagram/v1/sign/lab-invite-signin`), optional `device_signature` (required
for a pre-binding retry: Ed25519 by `device_key` over
`canonical_json({"device_key", "invite", "nonce", "pid"})`, tag
`anagram/v1/sign/invite-rejoin`), and
an optional `email` (the address that the person states). An already-bound
device MUST NOT use `POST /auth/invite` to sign in again; it MUST use device
sign-in (`/auth/device/start` and `/auth/device/verify`). A pre-binding retry
is allowed only while the account has no key-binding history, the invite is
still valid/open, `device_key` matches the initial device, and
`device_signature` verifies. The node:

1. Node invite: checks that the invite exists, is open, and is not expired
   (`404`, `409`, `410`). It makes the account, claims the invite in the same
   lock (single use), and answers the assertion (method `invite`, no ORCID
   commitment), a session, and the `receipt`. The client calls
   `POST /invites/claim` as for each join; the claim is idempotent.
2. Lab invite: checks that the lab invite is open and verifies
   `invite_signature` against `invite_pub` (`403` on missing or bad proof).
   The person becomes a node member only with the lab join request
   ([lab.md](lab.md)). Any stated email is kept pending and claims uniqueness
   only upon admission as a member.
3. Reader invite (an invite to a named contact): the contact proof stays.
   For an email contact the node sends a code to that address and answers
   `{"needs": "email_code", "challenge_id", "email_hint"}`; the client then
   uses `POST /auth/email/verify`. For an ORCID contact the answer is
   `{"needs": "orcid"}`, and the client uses the ORCID flow.

A **stated** email address is private to the node. It is never a sign-in
address: an email code for it makes no session for the account. The first
admitted person who states an address keeps it.

ORCID (optional; `/authenticate` scope, authorization code):

1. Client: `POST /auth/orcid/start` with `device_key`, `nonce`,
   `code_challenge` (base64url SHA-256 of a random verifier, as in PKCE),
   `return_to`, `purpose` (`join`, `login`, or `link`; `join` if absent), and for a
   first join `pid` and `orcid_salt` (section 2). The node uses `pid` and
   `orcid_salt` only when it makes a new account.
   `return_to` must be an `http://` loopback URL (`127.0.0.1`, `localhost`,
   `::1`) or `urn:anagram:oob`.
2. The browser opens the ORCID authorize URL. ORCID redirects only to the
   node's registered URI `<public_url>/auth/orcid/callback`. A loopback URL is
   never an ORCID redirect target.
3. The node exchanges the ORCID code, then redirects the browser to `return_to`
   with a one-time code (or shows the code for `oob`).
4. Client: `POST /auth/orcid/exchange` with `flow_id`, the one-time code, and
   the verifier. The node returns the assertion, a session token, and a
   private `profile` (`name`, `orcid`, `orcid_salt`). The client checks that
   the profile opens the `orcid_commitment` of the assertion, and keeps the
   ORCID iD and the salt in its config. A flow is single use, expires after 10
   minutes, and locks after 5 attempts. A `login` for an ORCID iD that has no
   account gets `403` and makes no account.

Link an ORCID iD (v3, purpose `link`): the request has the member session.
The exchange answers `{"linked": true, "profile": {"orcid", "orcid_salt",
"orcid_commitment"}}` and no assertion. The node adds the iD to its private
map (section 13) with the new salt and marks it `linked`. The key directory
does not change (section 7, rule 6). An iD that another member has gets `409`.
A linked iD cannot sign in (`403`); the device key or the recovery kit does.

Email fallback: `POST /auth/email/start` (with the same `purpose` field) sends
an 8-digit code (10 minutes, 5 attempts, 5 codes per address per hour). The code
hash binds the challenge purpose and the challenge ID; the node keeps the
sign-in purpose with the challenge. `POST /auth/email/verify` returns the
assertion and a session.

Purposes:

- `join`: the node signs in any person. The client then claims an invite
  (section 4). Without a claim, the session cannot do member actions.
- `login` (**sign in again without an invite**): the node gives the assertion
  and the session only if the subject is a member, and the device key of the
  flow is active, or was never bound (a new device). A device that was bound
  and is not active now (removed, or replaced by a reset) gets `403`. A
  subject that is not a member gets `403`. An email login does not make an
  email account for an unknown address. The node marks the flow or the
  challenge as used before it checks, so a refused login cannot be tried
  again with the same code.

Sign in again (client `login`, `Client.sign_in`, `anagram login`, the UI
"Sign in again"). The client reads the node URL and the pinned node key
fingerprint from its config (written at the join or at a recovery), gets the
trust document, and checks it against the pinned fingerprint (section 3) and
the stored assertion key. v3: when the device key of this computer is active,
the client uses device sign-in (below) and stops. Else it runs the ORCID or
email flow with purpose `login` and checks the assertion as in section 6.
Then:

1. The device is active: the client stores the session. No new key binding,
   identity record, or recovery kit.
2. The device is not bound and the subject has active devices: the client
   shows its device request (second-device flow). An active device approves
   it; then a login again gives a session.
3. The device is not bound and the person asks for a reset (or the subject
   has no active devices): the client binds the device (`reset` or `add` with
   the login assertion, section 7), signs a new identity record, and writes a
   new recovery kit.

A home that belongs to another subject refuses the answer and ends the new
session. An invite is necessary only for the first join of a person.

Device sign-in (v2): `POST /auth/device/start {subject, device_key}` returns a
random `challenge` (2 minutes, single use) and the `node_key`. The client
signs `canonical_json({"challenge", "device", "node_key", "subject"})` with the
device key (tag `anagram/v1/sign/device-signin`) and sends `POST
/auth/device/verify {challenge_id, signature}`. The node gives a session only
to a member whose device key is active. A restore uses this: the recovery kit
holds the device key, so no ORCID step is necessary. The holder of an active
device key can already sign key bindings, so this gives no new power.

Passkeys (WebAuthn) are for node sessions only. They never derive keys.

Sessions. Each session from an invite, ORCID, or email sign-in is bound to the device key
of its assertion. The node refuses a session when its device was bound and is
not active now. When the node accepts a `reset` or a `remove`, it deletes each
session of the subject that is not bound to an active device (passkey sessions
too). `POST /auth/logout` ends the current session (`anagram logout`).

## 12. Person keys on each device (v2)

The vault key and the index key belong to the person, not to one device
([vault.md](vault.md) section 11.1). Second device flow:

1. The new device joins (or logs in) and shows its device request.
2. An active device approves it (`add_device`): it logs the `add` binding,
   then seals the person keys to the X25519 key of the new device with HPKE
   (`anagram.person_keys.v1`, [vault.md](vault.md) section 11.4) and leaves
   the package on the node.
3. The new device runs the join or login again. It is active now. It gets the
   package, checks that the sender is an active device of the same subject
   (log proofs), decrypts, takes the keys (only if its own vault is empty),
   reads the personal store, and writes a new recovery kit.

## 13. ORCID privacy (v2)

- The public log, the public directory (`GET /directory/<pid>`), invite
  receipts, and key backups show the pid, never the ORCID iD.
- The node keeps a **private map** ORCID iD -> (pid, salt, commitment,
  linked). It checks the ORCID iD at each sign-in. It does not publish the map.
  A `linked` row (v3) has a commitment that is not in the key directory; the
  client keeps its opening (the iD and the salt) in the config and the
  personal store.
- `GET /resolve/orcid/<ORCID iD>`: for signed-in members only. It answers
  `{"orcid", "subject"}` only if that person turned on **findable by ORCID**
  (`PUT /me/findable {on}`; default off; `GET /me` shows
  `findable_by_orcid`). v3: the same switch covers the email addresses of the
  person (`GET /resolve/email/<address>`: a proved address first, then a
  stated one). A stated address is findable by default, because the join
  screen says so; `GET /me` shows `findable`. Every refusal is the same `404`. Each viewer can make
  30 queries in one hour (`429` after). The node writes each query to an
  audit table (viewer, ORCID iD, time, answered).
- `GET /identity/<subject>` stays for members only. `GET /members` stays for
  members only and lists pids.
- Matching does not use these routes. A person takes part in matching with
  a member credential and a sealed pack, and the enclave releases a card
  only after two `yes` answers ([matching.md](matching.md)).
- Organizers are listed by ORCID iD in `node.json` (private to the node
  operator), or come in with an organizer invite (no ORCID iD necessary).

## 14. Invite chain (v3)

Moved to [admission.md](admission.md) section 6.

## 15. Changes

- 2026-10-27, v2: subject `pid:`; ORCID commitment in assertions (v2), key
  bindings (v2), and identity records (v2); `name` removed from the
  assertion; key backup v2 with `index-key`; device sign-in; person keys on
  each device; findable by ORCID. This is a format break. New nodes use a
  new log origin (`<domain>/log-v2`; `local.anagram/log-v2` for a local
  node). A v2 client does not read a v1 log. There is no migration (no field
  users).
- 2026-11-16, v3 (identity without ORCID; entry by invite only): assertion
  method `invite` with no ORCID commitment.
  No schema name changes and no rule for a v2 document changes, so each v2
  document and vector still verifies. New vector block `invite_join`. No data
  migration: a person who joined with ORCID keeps the commitment in the key
  directory and can still sign in with ORCID.
- Proof bundles (`anagram.proof_bundle.v1`) do not change. They hold no
  person subject (the owner is a device key), so a bundle made before v2
  still verifies offline with its pinned keys.

## 16. Keystore on the member's computer

Code: `anagram.identity.app.keychain` (`open_keystore`), `anagram.identity.app.keychain.sealed`,
`anagram.identity.app.keychain.slots`, `anagram.identity.app.keychain.migrate`, `anagram.identity.app.keystore`.

- One master key (32 random bytes) is in the keychain of the operating
  system: service `org.radiofuture.anagram`, account
  `keystore-master:<keystore ID>`. macOS Keychain, Windows Credential
  Manager, or Secret Service on Linux, through one explicit `keyring`
  backend (never a backend that is found automatically).
- Each other key is a file `<home>/keys/<name>.skey`, mode 0600:
  `{"ct", "nonce", "schema": "anagram.sealed_key.v1"}`, sealed with the
  master key (ChaCha20-Poly1305). The associated data binds the schema, the
  keystore ID, and the name: a file moved to another name or to another
  keystore does not open. A file that does not open is an error and is never
  replaced by a new key.
- Key names match `^[a-z0-9][a-z0-9-]{0,62}$`. The keys of this spec
  (`device-ed25519`, `device-x25519`, and the person keys `vault-key` and
  `index-key`, section 12) are in the keystore, and also `local-store-key` (device-local, for `vault.sqlite` and the
  sealed UI state), `lab-cache-key` (device-local), and `acct-<account>`
  (tokens of connected sources). The recovery kit (section 9) holds the keys
  of the key backup only, not the device-local keys.
- The marker `<home>/keys/keystore.json` (`anagram.keystore.v2`) records the
  backend of a home. The policy `ANAGRAM_KEYSTORE` (`file`, `auto`, `os`)
  applies only to a home with no marker and no keys. The app and each client
  command of the CLI (also `anagram` and `anagram ui`) set `auto`. Plain hex
  files (`<name>.key`, mode 0600) need `--plain-key-files` or
  `ANAGRAM_KEYSTORE=file` (the tests set it). The `node` and `demo` commands
  keep the default `file`. A home never changes its backend silently.
- A locked keychain (`SlotLocked`) stops the open. There is no fallback to
  files and no new key.
- Migration of a home with hex files: record the new keystore ID, put the
  master key into the keychain, write and check each sealed file, write the
  marker (the commit point), then write zeros on each hex file and remove it.
  A stop before the marker keeps the hex files; a stop after it erases the
  hex files at the next open. The erase is best effort on an SSD. The app
  migrates with its app lock held.
