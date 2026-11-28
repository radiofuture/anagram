# Enclave messages: app, node and enclave

Status: draft (2026-11-25), revised after a spec review (section 14).
Licence: CC BY 4.0. Schema:
[schemas/enclave-messages.schema.json](schemas/enclave-messages.schema.json).
Vectors: [vectors/enclave-messages.json](vectors/enclave-messages.json).
Implementation: `src/anagram/network/formats/enclave.py` (formats) and
`src/anagram/network/matching/enclave/` (the service); the vector
generator `src/anagram/vectors/net/` calls them.

Related documents: [pack.md](pack.md) (the pack and the known object),
[network.md](network.md) (credentials, roster, control events, node request
signature keys), [enclave-trust.md](enclave-trust.md) (attestation document
v3 and its digest, intake and output keys, the transparency log, signed
time, tombstones, deletion).

## 1. Parties and paths

| Party | Role in this document |
| --- | --- |
| App | The person's software. It seals requests, opens receipts and slots |
| Node | The person's node. It relays fixed-size ciphertext between its members and the enclave. It sees sizes, times and which member sent or fetched each object. It never sees plaintext |
| Enclave | An attested instance of the matching enclave. It opens requests, keeps state, writes receipts and slots |

Every object that a node relays has one fixed size for its class:

| Object | Path | Size (bytes) | Rate for each app |
| --- | --- | --- | --- |
| Upload (pack, cover or withdrawal) | app → node → enclave | 65,536 | 1 a day (a withdrawal replaces it; section 7.1) |
| Known upload | app → node → enclave | 393,216 | 1 a week |
| Answer | app → node → enclave | 2,048 | 3 for each proposal, one on each checkpoint day (section 5.3) |
| Receipt | enclave → node → app | 1,024 | 1 for each request, fetched after the next cosigned epoch (section 4.4) |
| Slot | enclave → node → app | 4,096 | 1 a day |

No plaintext receipt, reason, status or count crosses a node (a design
constraint).

## 2. Words and encoding

- **Must**, **must not**, **should**, **may**: as in RFC 2119.
- Canonical JSON, hex, times, `u32`, `tagged_hash`, `tagged_message(tag,
  payload) = u8(len(tag)) || tag || payload`: [formats.md](formats.md)
  sections 2 and 3.1. All integers in byte layouts are big-endian.
- **HPKE**: RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20-Poly1305.
  The output of `Seal` is `enc (32 bytes) || ciphertext`. The ciphertext is
  the plaintext length plus 16 bytes. The single-shot `Seal` and `Open` of
  RFC 9180 section 6.1 have `aad` = the empty byte string for every use in
  this document; `info` alone binds the context.
- **Padding**: `pad(body, P) = u32(len(body)) || body || zero bytes`, exactly
  `P` bytes. A receiver must check that every padding byte is zero and that
  `4 + len(body) <= P` (`bad_envelope`).
- **Day**: `floor(unix seconds / 86400)`, as a `u32` in byte layouts.
- **Cut** of day D: 23:00:00 UTC of day D − 1. The state at the cut makes
  the slots of day D (section 6.5).
- **Attestation digest**: the digest of the attestation document
  (`anagram.operator_attestation.v3`) of the instance, as
  [enclave-trust.md](enclave-trust.md) defines it.
- **Intake key**: the X25519 public key of an instance for one key epoch.
  **Output key**: the Ed25519 key with which an instance signs receipts and
  slots. Both are in the attestation document and in the transparency log
  ([enclave-trust.md](enclave-trust.md)). The app seals only to an intake key
  that it verified by those rules.
- **Signed document**: `signature = Ed25519(key, tagged_message(tag,
  canonical_json(document without "signature")))`, in hex.

## 3. Sealed requests

### 3.1 Byte layout

Every app → enclave object (upload, known upload, answer) has this layout:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `magic`: ASCII `AGE1` (`0x41 0x47 0x45 0x31`) |
| 4 | 1 | `class`: `0x01` upload, `0x02` known, `0x03` answer |
| 5 | 32 | `attestation`: the attestation digest of the instance |
| 37 | 32 | `intake`: the intake key |
| 69 | 32 | `response`: a fresh X25519 public key of the app for this request |
| 101 | 32 | `enc`: the HPKE encapsulated key |
| 133 | P + 16 | the HPKE ciphertext of `pad(body, P)` |

The first 101 bytes are the **header**.

| Class | Total size | P (padded plaintext) | Largest body |
| --- | --- | --- | --- |
| `0x01` upload | 65,536 | 65,387 | 65,383 (a pack is at most 49,152) |
| `0x02` known | 393,216 | 393,067 | 393,063 (a known object is at most 320,164) |
| `0x03` answer | 2,048 | 1,899 | 1,895 |

`P = total − 149`.

```
info       = tagged_message("anagram/v1/enclave/hpke/request", header)
sealed     = HPKE.Seal(intake, pad(body, P), info)
request    = header || sealed
digest     = tagged_hash("anagram/v1/enclave/request", request)
```

The header is in `info`, so a node that changes the attestation digest, the
intake key or the response key makes the request fail to open. The
instance ID and key epoch are not in the header: the
intake key names both, and the attestation digest commits them
([enclave-trust.md](enclave-trust.md)).

The response key must be new for each request (made from a CSPRNG). The app
keeps its private part until it has the receipt. It is not the `reply_key`
of the pack.

### 3.2 Bodies

| Class | Body |
| --- | --- |
| upload | the canonical JSON of one of: `anagram.pack.v1` ([pack.md](pack.md)), `anagram.enclave.withdrawal.v1` (section 7.1), `anagram.enclave.cover.v1` (section 7.2) |
| known | the binary known object `anagram.known.v1` ([pack.md](pack.md) section 9) |
| answer | the canonical JSON of `anagram.enclave.answer.v1` (section 5) or of `anagram.enclave.answer_filler.v1` (section 5.4) |

A body of another type for its class gives `bad_message`; a JSON body with a
`schema` that the release does not accept gives `unsupported_schema`.

### 3.3 How the enclave opens a request

In this order; the first failure gives the code:

1. the length equals the size of `class`, `magic` is `AGE1`, `class` is
   known, and `response` is a valid non-low-order X25519 public key
   (`bad_envelope`; low-order points that produce an all-zero X25519 shared
   secret are refused before any state change);
2. `intake` is a live intake key of this instance (`unknown_instance_key`);
3. `attestation` is the digest of the current attestation document for
   that intake key (`stale_attestation`);
4. the signed time is safe ([enclave-trust.md](enclave-trust.md))
   (`clock_unsafe`);
5. HPKE opens with `info` from the header, and the padding is correct
   (`bad_envelope`);
6. the body checks of its type ([pack.md](pack.md) section 7.1, sections 5
   and 7 here);
7. the subject of the body is in the shard of this instance's line
   ([enclave-trust.md](enclave-trust.md) section 5.6) (`wrong_shard`);
8. the state checks (section 8).

The front end sends every request to the writer of the line; an
instance that is not the writer takes no request
([enclave-trust.md](enclave-trust.md) section 3.7). So step 2 refuses a request sealed to a standby's key or to an
old writer's key.

The enclave answers every request with one receipt (section 4), also when
step 1, 2, 3 or 5 fails: the response key is in the header (bytes 69 to
100), so the enclave can seal the receipt without the body. For step
1 this holds when the length is right: a request whose length equals the
size of the class of its route gets a `bad_envelope` receipt for a wrong
`magic` or a `class` that is not the class of the route. A request of
another length has no header that the enclave can trust; the node already
refuses it with `400` (section 9.1), and the enclave refuses it with `400`
and no receipt. The enclave releases every receipt only by the rule of
section 4.4.

## 4. Receipts

### 4.1 Document

```json
{"reason": null, "request": "<hex32 digest>", "schema": "anagram.enclave.receipt.v1",
 "signature": "<hex64>", "signer": "<hex32 output key>", "status": "accepted", "time": "<time>"}
```

- `status`: `accepted` or `rejected`.
- `reason`: null when accepted; else one code of section 10.
- `request`: the digest of the request (section 3.1).
- `time`: the signed time of the enclave.
- `signer`: the output key of the instance. Tag:
  `anagram/v1/enclave/sign/receipt`.

### 4.2 Sealing (1,024 bytes)

```
info    = tagged_message("anagram/v1/enclave/hpke/receipt", digest)
receipt = HPKE.Seal(response key of the request, pad(canonical_json(document), 976), info)
```

The receipt is `enc (32) || ciphertext (976 + 16)` = 1,024 bytes.

### 4.3 What the app checks

1. The receipt has 1,024 bytes and opens with the private response key and
   the digest of its own request.
2. The document has exactly the fields of 4.1, `request` is its own digest,
   `signer` is a logged output key of a live instance of an accepted
   release, and the signature is correct.

A receipt that fails a check is **no receipt** (a filler of section 4.4 is
one). The app then fetches the attestation again and tries the same
request bytes again later (section 8.5). A node cannot make a valid receipt: it cannot sign with the output
key. A node can drop a request or a receipt; that shows to the app as no
receipt.

### 4.4 Release and fetch

The enclave releases **every** receipt, accepted or rejected, only after a
cosigned checkpoint holds a state epoch that it wrote after the request
arrived ([enclave-trust.md](enclave-trust.md) section 6.3: epochs at fixed
10-minute times). So the time of a receipt does not show whether the
request changed state, and no confirmed change can be undone by a restore.
An HTTP request does not wait for this:

- `POST` of a request answers `202` with no body (section 9).
- `GET /enclave/receipts/{digest}` (app → node, member session; `digest`
  is 64 lowercase hex) answers `200` with **exactly 1,024 bytes** for every
  well-formed digest: the receipt if the node has it, else the filler
  `HKDF-Expand(PRK = HMAC-SHA256(node_slot_secret, digest), info =
  "anagram/v1/enclave/receipt-filler", L = 1024)`. Bytes that do not open
  mean "no receipt yet".
- The node gets receipts with `GET /v1/relay/receipts/{digest}` (`200` and
  1,024 bytes, or `404` before release) and keeps each for 48 hours after
  it gets it.
- **Node timer**. The node runs a timer
  at least every 10 minutes (the reference runs it every 60 seconds). Each
  run fetches the slot batches of the current day and the next day that
  it does not have yet (6.7), fetches the receipts of the requests it
  relayed that it does not have yet, and deletes each receipt 48 hours
  after its fetch and each slot 28 days after its batch arrived. After the
  deletion the node serves the filler for that digest or address, the
  same as for one it never had.
- The app asks for its receipt at most every 10 minutes, from 10 minutes
  after the upload, for at most 48 hours.

## 5. Answer (`anagram.enclave.answer.v1`)

### 5.1 Document

```json
{"card": null, "choice": "no", "created": "<time>", "proposal": "<32 hex>",
 "schema": "anagram.enclave.answer.v1", "signature": "<hex64>", "subject": "<hex32>"}
```

- `proposal`: the proposal ID (section 6.4).
- `choice`: `yes`, `no` or `not_now`.
- `card`: the reveal card (5.2) when `choice` is `yes`; else null. The
  sealed answer has the same size for each choice (2,048 bytes), so the
  node cannot see the choice.
- `created`: at most 5 minutes after the enclave time (`bad_message`).
- `subject`: the subject key of the person (or group). Tag:
  `anagram/v1/enclave/sign/answer`.

This format is new.

### 5.2 Reveal card

```json
{"email": "alice.chen@lab-a.example.org", "institution": "Example University",
 "lab": "Chen Lab", "name": "Alice Chen", "orcid": null}
```

- `name`, `institution`: text ([pack.md](pack.md) section 2) of 1 to 200
  code points. `lab`: the same, or null.
- `email`: printable ASCII, `^[!-?A-~]{1,64}@[a-z0-9.-]{1,189}$` (a local
  part with no `@` or space; a lowercase domain in A-label form).
  Internationalised local parts are not in v1.
- `orcid`: an ORCID iD (`^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`) when the person
  linked one, else null.
- The canonical JSON of the card is at most 1,200 bytes (`too_large`).
- If the subject's current credential has `email_tag` facts
  ([network.md](network.md) section 6.2), the known tag of `email`
  ([pack.md](pack.md) section 9.2) must be one of them (`bad_message`). So a
  card cannot carry an email address that the node did not verify.

The enclave keeps a card only while the "yes" is open. It releases it only
inside a reveal (section 6.4) through the single release check
([matching.md](matching.md) section 5).

### 5.3 Rules

- **One answer for each proposal.** The app must send exactly one answer
  for each proposal that it received. A second answer gives
  `already_answered`. An answer to an ID that was not delivered to this
  subject, or after the proposal expired, gives `unknown_proposal`.
- **Answer window and checkpoints** (the day of an answer must not show
  engagement). A proposal has a window of 21 days and
  three checkpoints. Let `m` = (UTC day of `made`) + 1, where `made` is the
  enclave time of the sweep that made the proposal. The sweep runs at the
  cut of day D (23:00 UTC of day D − 1), so `m` = D, the first slot day
  that can carry the proposal (section 6.5). Let
  `a` = `answer_day` of the `matching` descriptor
  ([enclave-trust.md](enclave-trust.md) section 3.6; 1 to 7, production
  value 7). The checkpoints are the UTC days `m + a`, `m + 2a` and `m + 3a`
  (days 7, 14 and 21 when `a` is 7). The proposal expires at 00:00:00 UTC of
  day `m + 3a + 1`, the end of the last checkpoint day. The two copies of a
  pair have the same checkpoints and the same expiry, and the proposal item
  carries both (section 6.4).
- **One sealed object at each checkpoint.** On each checkpoint day the app
  sends exactly one 2,048-byte answer request for each proposal it holds,
  whatever the person did:
  - at the first checkpoint on or after the day of the person's choice:
    the answer (section 5.1);
  - at the last checkpoint, if the person did not choose: an answer with
    `not_now`;
  - at each other checkpoint: an answer filler (section 5.4).

  So the node sees three answer requests for each proposal, on fixed days,
  and cannot see when the person chose or whether the person chose. The app
  sends in the first 12 hours of the checkpoint day, at a random minute, so
  that a retry (section 8.5) still arrives before the expiry. After a
  withdrawal the app sends fillers at the remaining checkpoints. If the app
  sends no answer before `expires`, the enclave treats the proposal as
  `not_now`.
- **Reveal at a checkpoint.** When both people said `yes`, the enclave
  decides the reveal (section 6.6) at the first check on or after 00:00:00
  UTC of the first checkpoint day where both answers are in. An answer that
  arrives before the first checkpoint (for example from a client that does
  not wait) does not make an earlier reveal.
- **Shared expiry** (replaces an earlier rule). Because both copies expire
  together, a copy that waited in the queue can still be answered at all
  three checkpoints, and the "both or neither" rule (section 6.6) holds for
  every `answer_day` from 1 to 7. The limit 7 stays so that the window is at
  most 22 days.
- **Meaning**: `no`: for 365 days the enclave does not
  propose this pair again **for this match type**, also after the other
  person withdrew and came back (a decline record that the decliner owns,
  [enclave-trust.md](enclave-trust.md) section 7.1). The
  pair may be proposed for another match type. `not_now`: the pair may come
  back for this type after 90 days, only after a material change of a pack.
  `yes`: the enclave keeps the card; if the peer also says yes before both
  copies expire, it releases both reveals (section 6.4).
- **No trace of the choice.** The peer sees the same thing for `no`,
  `not_now` and no answer: an `ended` item at the expiry (section 6.4).
  The answer filler is the same size as an answer, so the node cannot tell
  an answer from a filler.
- **Accepted while live.** An answer to a delivered, unexpired proposal is
  `accepted` even if the peer withdrew or was removed. The receipt never
  tells a person what the peer did.

### 5.4 Answer filler (`anagram.enclave.answer_filler.v1`)

```json
{"schema": "anagram.enclave.answer_filler.v1"}
```

The document has exactly this one field. The app seals it in the `answer`
class like an answer (2,048 bytes, a new response key). The enclave opens
it, changes no matching state (it adds 1 to an audit count only), and gives an `accepted` receipt with the
usual release rule (section 4.4), so the receipt also looks the same. A
filler names no proposal and no subject, so the enclave cannot link it to
a person.

## 6. Slots

### 6.1 Address

```
address = tagged_hash("anagram/v1/enclave/slot", u32(day) || reply_key)
```

`reply_key` is the 32-byte X25519 public key of the subject's pack or cover
that was current at the cut of `day` (section 6.5; [pack.md](pack.md)
section 3.1 for the rotation rule). Only the app and the enclave know it, so other members cannot compute an
address. An address made from a public key would let any member test
whether a person has a slot. The address changes each day, so two days do not
link.

### 6.2 Document and sealing (4,096 bytes)

```json
{"day": 20783, "item": {"kind": "empty"}, "schema": "anagram.enclave.slot.v1",
 "signature": "<hex64>", "signer": "<hex32 output key>"}
```

Tag: `anagram/v1/enclave/sign/slot`.

```
info = tagged_message("anagram/v1/enclave/hpke/slot", u32(day) || address)
slot = HPKE.Seal(reply_key, pad(canonical_json(document), 4048), info)
```

The slot is `enc (32) || ciphertext (4,048 + 16)` = 4,096 bytes. The app
checks: the slot opens with its reply private key and the `info` of the day
it asked for; `day` equals that day; `signer` is a logged output key of a
live instance of an accepted release; the signature is correct; the item
obeys 6.4. Bytes that do not open are a filler (6.3) and mean "nothing for
me": the app must treat them as an empty slot.

### 6.3 Fetch API and the empty or unknown address

```
GET /enclave/slots/{address}      (node, member session)
```

- `address` is 64 lowercase hex characters. Another form gives `400`.
- The node answers **`200` with exactly 4,096 bytes for every well-formed
  address**, known or not. There is no `404`. So a fetch never shows
  whether an address belongs to a member.
- For an address with no stored slot (unknown, older than 28 days, or not
  yet made), the node returns the **filler**:

  ```
  filler(address) = HKDF-Expand(PRK = HMAC-SHA256(node_slot_secret, address),
                                info = "anagram/v1/enclave/slot-filler", L = 4096)
  ```

  `node_slot_secret` is a random 32-byte secret of the node that never
  leaves it. The filler is the same for the same address, so a second fetch
  cannot tell a filler from a real slot by a change of bytes.
- The node should compute the filler for every request and then select the
  stored slot if there is one, so that both cases take the same time.
- The node keeps each slot for 28 days, so an app that was offline can
  fetch the days it missed. 28 days is the answer window (22 days at most,
  section 5.3) plus a margin of 6 days: an app that was offline for most
  of a window can still fetch a proposal or a reveal.
- The app fetches its address for each day once, at a random minute of the
  day. After a withdrawal it should go on with one fetch a day, so the node
  does not see the stop.

### 6.4 Items

`item` is one of four forms. Each has exactly the fields listed.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `empty` | `kind` | Nothing today |
| `proposal` | `checkpoints`, `expires`, `id`, `kind`, `pack_version`, `protocol`, `reasons`, `type` | A proposal to me |
| `reveal` | `card`, `kind`, `known`, `node`, `peer`, `proposal`, `type` | Both said yes: the peer's card |
| `ended` | `kind`, `proposal` | This proposal ended |

**Proposal** (`anagram.enclave.proposal.v1`; card option (a), the default):

- `id`: the proposal ID: 16 bytes from the CSPRNG of the enclave, in hex. The
  enclave makes a new one if the value was used before. The two people of a
  pair get different IDs; nothing links the two.
- `type`: a match type ([pack.md](pack.md) section 3.3). `protocol`:
  `anagram.fit.<type>.v1`.
- `reasons`: 1 to 4 line IDs **of my own pack** (the wants and offers of mine
  that the decision used), ascending, no repeats. The app shows the text of
  those lines from the pack of version `pack_version`, which it keeps. No
  text of the peer, no score, rank, count, affiliation or known mark is in a
  proposal.
- `checkpoints`: the three answer checkpoints of section 5.3, each as the
  time 00:00:00 UTC of its day, ascending, with equal steps of 1 to 7 days.
- `expires`: 00:00:00 UTC of the day after the last checkpoint. Both copies
  of a pair carry the same `checkpoints` and `expires`, also when one copy
  waited in the queue. The first checkpoint is after the day of the slot
  that carries the proposal (section 6.5).

Under card option (b), the proposal would also carry one teaser line
of the peer. That needs a new schema version.

**Reveal**: `card` is the peer's reveal card (5.2); `peer` is the peer's
subject key (so the app can add the peer to its known object and its block
list); `type` and `proposal` name the proposal; `known` is `true` if the
peer was in my known object (the mark "you know this person; new reason",
shown only after the reveal); `node` is
`{"affiliation", "id", "ror"}` of the node of the peer's current
credential, copied by the enclave from the roster record
([network.md](network.md) section 2.3) at reveal time.
The card is what the peer wrote; `node` is what the roster verified. The
app shows both and marks `node` as verified.

**Ended**: the enclave queues it **at the expiry** of my copy of the
proposal, never before, whatever the cause: a `no`, a `not_now`, no answer,
the peer's withdrawal or removal, a peer copy that was never delivered, or
a failed check at reveal time. So the time of an `ended` item tells nothing
about the peer. The app must treat a
proposal as ended at `expires` also when no `ended` item comes.

### 6.5 One slot a day

- At the cut of day D the enclave makes one slot of day D for each subject
  whose latest accepted pack, cover or withdrawal was accepted in the 48
  hours before the cut (`cut − 48 h < time ≤ cut`, receipt `time`), or whose
  queue is not empty. The item is `empty` when the queue is empty.
- This one rule is the same for packs, covers and withdrawals, so "matching
  off" looks like "matching on" in the batch: the day after a withdrawal
  the subject still gets a slot, and an upload after the 23:00 cut gives a
  slot in the next batch, for a pack and a cover alike. The slot rule does
  not look at pack dormancy (that follows credential expiry, [pack.md](pack.md)
  section 5) and not at the calendar day of the upload.
- **Daily upload**. A member credential lasts at most 24 hours
  ([network.md](network.md) section 6), so the app gets a fresh credential
  and uploads a fresh pack, or a cover with matching off, every UTC day
  ([pack.md](pack.md) section 8). With one upload a day, each upload is
  less than 48 hours before the next cut, so a person whose app is live
  always gets a slot by this rule; the 48 hours leave one missed day of
  margin. A pack whose credential expired is dormant: it gives no proposal
  and no reveal until the next upload.
- **Reply key**. The enclave keeps the subject's reply key (and the
  node of its latest credential) while the subject has a stored pack
  (also a dormant one, until the pack's `expires`) or an open copy of a
  proposal, also after 48 hours with no upload: a reveal or an `ended`
  item that comes later still has a key to seal to. The key gives a slot
  only by the rule above. After 48 hours with no upload, with an empty
  queue, no stored pack and no open copy, the enclave deletes the
  subject's slot state (node, upload time and reply key).
- The slot is sealed to the reply key of the subject's latest pack, cover
  or withdrawal that was accepted at or before the cut. It
  is current from the receipt `time` of its acceptance. So the app knows which reply key
  each day uses. The app keeps each reply private key for 28 days after
  the last day that uses it (the node keeps slots as long, section 6.3),
  and, by the rule above, while a pack or an open copy that names the key
  may still give a slot.
- Each subject has one queue. Order: `reveal` items first, then `ended`,
  then `proposal`; first in, first out inside each kind. One item goes in
  each slot.
- **Delivery before the first checkpoint.** A sweep at the cut of day D
  proposes a pair only if the queue of each person can deliver the copy
  before the first checkpoint `D + a`: one item a day in the slots of days
  D to D + a − 1, behind every item in the queue at the sweep and the
  copies that the same sweep gave earlier. So a person whose queue holds
  `q` items, with `t` copies already taken in the sweep, can get one more
  only if `q + t < a`. A pair that this rule stops **waits**, as for a cap
  (see Ranking). So a person with a weekly cap of 10 and `answer_day` 7
  gets 7 copies from one sweep, and the other 3 go out in later sweeps.
- **Safety net.** A copy is still not delivered in a slot of the first
  checkpoint day or later (with `answer_day` 7 the wait is at most 6 days,
  as before), so each person who gets a proposal has all three
  checkpoints. Only an item that goes before it after the sweep (a reveal
  or an `ended` item, which come first in the queue) or a batch that the
  enclave did not make can push a copy that late. The pair's proposal then
  ends for both people: the other person gets `ended` at the shared expiry
  if the copy was delivered; a copy that was never delivered ends with no
  item. The audit counts each such copy (`late_copies`).
- **Weekly cap**. A person gets at most `cap` proposals in 7
  days, where `cap` = min(charter `weekly_cap`, descriptor `weekly_cap_max`).
  The person chooses `weekly_cap` (1 to 10, default 3, [pack.md](pack.md)
  section 3.3); the network sets `weekly_cap_max` (1 to 10,
  [enclave-trust.md](enclave-trust.md) section 3.6).
- **Node rule: proposals from one node in 4 weeks, by node size**
  (in a simulation with a limit of 1 per node for every size, 50 fake
  members of one node took 8.5 of a target's 11.5 proposals). A person gets at most
  `limit(N) = max(1, ceil(m(N) / 50))` proposals in 28 days with a peer
  whose current credential names a given other node `N`. Peers of the
  person's own node do not count: the person's node can already see its
  own members, and the rule is about floods from other nodes.
  - `m(N)` is the number of live packs in the current sweep whose member
    credential the enclave verified for node `N`: the pack is not expired,
    its credential is valid at the sweep time and usable in the network
    (the same check that makes a pack live, [pack.md](pack.md) section 5),
    and the credential names `N`. So `m(N)` counts the members of `N` with
    matching on. A pack that the enclave did not accept, or whose
    credential fails the check, does not add to `m(N)`. No new format
    carries `m(N)`; the enclave computes it again at each sweep.
  - The 28 days are a sliding window: the count is the proposals made to
    the person with a peer of `N` at times `t` with `now - t < 28 days`,
    plus the proposals of the same sweep.
  - Examples: a node with 500 live members gives at most 10; a node with
    5, 1 or 0 gives at most 1. A new fake node can add at most 200 members
    a month (`new_members_per_month`, [network.md](network.md) 6.7), so at
    most 4 proposals to one person in 4 weeks, and each join is in the
    public log.
- **Ranking.** At each sweep the enclave collects the mutual pairs that the
  other rules allow, sorts them by best stage-1 score (then by subject keys
  and type), and accepts them in that order while both people are under
  their weekly cap and the node rule and while both queues can deliver
  the copy in time (see above), counting the proposals of the same
  sweep. A pair that only a cap, the node rule or a full queue stops
  **waits**: the
  enclave keeps it, and each later sweep ranks it again with the new pairs
  (by its stored score), until it is accepted. No material change is
  necessary. A waiting pair ends when either pack changes (the pair is
  then found again or not by the new packs), or when a rule that is not a
  cap stops it (deny, block, decline, known, withdrawal, erasure). The type mix rule applies when the enclave makes proposals, not when it queues
  them.

### 6.6 Reveal: both or neither

When both people of a pair said `yes`, the first checkpoint day has come (section 5.3), and neither copy expired, the enclave
checks deny, block and both current credentials again. If a credential is expired but not revoked, the enclave waits until both
are valid again or a copy expires. If a check fails, there is no reveal and
both people get `ended` at their expiry. If all checks pass, the enclave
writes both reveal items into both queues in one state change. Each goes
out in the receiver's next slot.

The reveal is decided when that state change is in a cosigned epoch
([enclave-trust.md](enclave-trust.md) section 6.3). After that, a
withdrawal, a removal or dormancy of either person does not stop it: the
queued reveals stay, and each person gets slots until the queue is empty. A crash before the cosigned epoch loses both
reveal items, so neither goes out, but it does not end the pair. The yes that completed the pair got no receipt (section 4.4), so the
app sends it again; the enclave then decides the reveal again, with the
checks above. Only if no yes arrives again before a copy expires does the
pair end at expiry.

### 6.7 Slot batch (enclave → node)

```
GET /v1/relay/slots/{day}      (enclave, node request signature, section 9.3)
```

The response body is binary:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `day` (`u32`) |
| 4 | 4 | `count` (`u32`) |
| 8 | 4,128 × `count` | entries, ascending by address: `address (32) || slot (4,096)` |

The batch holds the slots of day D of the subjects whose latest credential
names the node. The node stores each entry under its address for 28 days.
The count equals the number of the node's members whose app had a pack,
cover or withdrawal accepted in the 48 hours before the cut, plus members
with a queue that is not empty (section 6.5); the node can count the
uploads anyway.

The enclave serves the batch of day D only after a cosigned checkpoint
holds a state epoch whose snapshot holds that batch; before that it
answers `503` with `Retry-After`. After that the batch never changes: each
fetch gets the same bytes, also after a restart. The node
fetches the batch after the cut and before 00:00 UTC of day D.

### 6.8 Crash and commit cases

The vector `slot_script` runs a reference model
(`anagram.vectors.net.slots`, on the real ledger and journal) with these cases: a receipt is a filler
until a cosigned epoch written after its request; a batch is `not_ready`
before its cosigned epoch; a crash before the epoch makes the batch again
from the committed state, with both reveals; a second fetch and a fetch
after a crash give the same batch; a withdrawal after the reveal is
queued still sends both reveals; a crash after a reveal but before its
cosigned epoch loses it, the app resends the yes, and the reveal is made
again, so both go out; the day after a withdrawal the subject keeps a
slot; an upload after 23:00 gives a slot in the next batch; a subject with
no upload in 48 hours and an empty queue gets no slot.

## 7. Withdrawal and cover

### 7.1 Withdrawal (`anagram.enclave.withdrawal.v1`): "Matching off"

```json
{"created": "<time>", "reply_key": "<hex32 X25519>",
 "schema": "anagram.enclave.withdrawal.v1",
 "signature": "<hex64>", "subject": "<hex32>", "version": 9}
```

Tag: `anagram/v1/enclave/sign/withdrawal`. It travels in an upload (class
`0x01`); it needs no credential, so a person can always withdraw.

**It replaces the day's upload**. When the person turns
matching off, the app sends the withdrawal at the day's upload time if
that time is still to come. If the day's upload already went, the app
sends the withdrawal at once, as an extra upload: the person's choice to
stop at once wins over the metadata, and the node then sees one extra
upload on that day. From the next
day the app sends covers (7.2).

- `reply_key` is the subject's current reply key. The
  withdrawal is the day's upload, so it gives slots by the rule of section
  6.5, like a pack or a cover. The enclave keeps (node of the latest
  credential, `reply_key`) for that rule only.

- `version` must be larger than the last version that the enclave knows
  for the subject, from a pack, a withdrawal or a tombstone (`old_version`).
- On acceptance the enclave deletes the pack, the known object, the open
  proposals of the subject and the subject's open yes answers, and writes a
  tombstone (subject, `version`, enclave time, reason `withdrawn`)
  ([enclave-trust.md](enclave-trust.md) owns the tombstone store and
  deletion). The peers of the deleted proposals
  get `ended` at the expiry of their copies. Reveals already in a queue
  stay (section 6.6). It also deletes the decline records that the subject
  owns; it keeps the records that other people own about the subject
  ([enclave-trust.md](enclave-trust.md) section 7.1).
- A later pack needs a higher version, `created` after the tombstone time,
  and a new consent ([pack.md](pack.md) section 8).

### 7.2 Cover (`anagram.enclave.cover.v1`)

```json
{"created": "<time>", "credential": {"format": "biscuit-v3", "log": {...}, "token": "<base64url>"},
 "kind": "person", "reply_key": "<hex32 X25519>", "schema": "anagram.enclave.cover.v1",
 "signature": "<hex64>", "subject": "<hex32>"}
```

Tag: `anagram/v1/enclave/sign/cover`. An app with matching off sends one
cover a day, at the day's upload time, and its weekly known upload as
before ([pack.md](pack.md) section 9.1). The node then sees the same
uploads, fetches and batch entries as for matching on.

- `credential` is a member credential with its log proof, as in a pack
  ([pack.md](pack.md) section 5; `bad_credential`, `expired`, `revoked`,
  `stale_roster`). It must come through the node that it names.
- `created` obeys the age rule of a pack (`bad_message`, `expired`).
- A cover needs no consent and no version, and a tombstone does not stop
  it: it changes no matching state. It shares the daily rate of a pack
  (`rate_limited`).
- The enclave keeps only (node, `reply_key`, acceptance time) for the slot
  rule of section 6.5 (48 hours before the cut, as for a pack), then
  deletes it. Each slot is `empty`, or carries a queued item (6.6).

## 8. Ordering and replay

### 8.1 Packs and withdrawals

One version counter for each subject covers packs and withdrawals. The
enclave accepts a pack only if (in order): the subject is not tombstoned for
it ([pack.md](pack.md) section 8: `tombstoned`), its `version` is larger
than the last accepted one (`old_version`), and no other pack or cover of
the subject was accepted in the same UTC day (`rate_limited`). A cover has
only the daily rate.

### 8.2 Known objects

A separate version counter. For a subject with no live pack, a well-formed
known upload gets `accepted` and the enclave keeps nothing. Else it is accepted only if `created` is after any tombstone time
(`tombstoned`), `version` is larger than the last accepted known version
(`old_version`), and at least 6 days passed since the last accepted known
object (`rate_limited`).

### 8.3 Answers

No counter: the "one answer for each proposal" rule (section 5.3) stops a
replay. An answer filler (section 5.4) changes no state, so a replayed
filler changes nothing.

### 8.4 Control events

The enclave applies control events in the order of their chains
([network.md](network.md) section 8) before it uses a credential. A missing
event stops the use of the credentials of that chain (`stale_roster`).

### 8.5 Retry and idempotence

The enclave keeps the receipt of each request for 48 hours, by its digest.
The same request bytes again get the same receipt and change nothing. So
the app may retry a request with the same bytes when it got no receipt. A
new request with the same body but a new response key is a new request (for
a pack in the same day: `rate_limited`). After a writer failover
([enclave-trust.md](enclave-trust.md) section 5.7), the same bytes sealed
to the old writer get `unknown_instance_key`; the app fetches the bundle
again and seals the body again to the new writer. The same holds for a
request sealed to a standby's key: the writer answers
`unknown_instance_key` (enclave-trust.md 3.7).

### 8.6 The order of time

All times that the enclave compares are its signed time
([enclave-trust.md](enclave-trust.md)). If the signed time is not safe, it
refuses requests with `clock_unsafe` and makes no proposal, reveal or
deletion by expiry.

The vector `intake_script` runs these rules on one subject: two packs in a
day, an old version, two answers to one proposal, an unknown proposal, two
known objects in six days, two covers on two days, a withdrawal, a known
upload after the withdrawal (accepted, not kept), a replay of the pack
signed before the withdrawal (`created` less than 48 hours before the
replay, so the age check of [pack.md](pack.md) 7.1 passes and the
tombstone refuses it), a pack with no new
consent, and a pack with a new consent. Each step is a full intake (the
checks of section 3.3 and pack.md 7.1), so a service and the reference
give the same codes.

## 9. HTTP API

### 9.1 App → node (member session)

The app signs in to its node as in [identity.md](identity.md) (device
sign-in). Each route below needs a member session (`401` without one, `403`
for a person who is not a member).

| Route | Request body | Response |
| --- | --- | --- |
| `GET /enclave/attestation` | — | `200`, the attestation bundle ([enclave-trust.md](enclave-trust.md) section 3.7) |
| `POST /enclave/uploads` | 65,536 bytes | `202`, no body |
| `POST /enclave/known` | 393,216 bytes | `202`, no body |
| `POST /enclave/answers` | 2,048 bytes | `202`, no body |
| `GET /enclave/receipts/{digest}` | — | `200`, 1,024 bytes: the receipt or the filler (section 4.4) |
| `GET /enclave/slots/{address}` | — | `200`, 4,096 bytes (section 6.3) |
| `POST /net/credential` | a credential request | [network.md](network.md) section 6.6 |
| `GET /net/credential/{hash}/proof` | — | [network.md](network.md) section 6.6 |

Each route of this table refuses a request with no member session
(`401`) and a session of a person who is not a member (`403`) before it
reads the body.

Content type of binary bodies: `application/octet-stream`. The node checks
only the length of a request body (`400` for a wrong length), answers
`202`, and forwards the body at once to the enclave. It fetches the receipt
later (section 4.4) and serves its bytes unchanged.

Node status codes (plaintext, about the relay only; they say nothing about a
person's data):

| Status | When |
| --- | --- |
| `200` | the body is a receipt, a filler, a slot or the attestation bundle |
| `202` | the node took the request and forwards it |
| `400` | wrong body length; an address or digest that is not 64 lowercase hex |
| `401`, `403` | no session; not a member |
| `429` | the node's own limit for the member (it should allow at least 4 uploads, 2 known uploads, 30 answers and 60 slot fetches a day) |
| `502`, `503` | the enclave did not answer, or the line has no writer now (enclave-trust.md 3.7); `Retry-After` should say when to try again |

### 9.2 Node → enclave

| Route | Request body | Response |
| --- | --- | --- |
| `POST /v1/relay/uploads` | 65,536 bytes | `202`, no body |
| `POST /v1/relay/known` | 393,216 bytes | `202`, no body |
| `POST /v1/relay/answers` | 2,048 bytes | `202`, no body |
| `GET /v1/relay/receipts/{digest}` | — | `200`, 1,024 bytes; `404` before release (section 4.4) |
| `GET /v1/relay/slots/{day}` | — | `200`, the slot batch (6.7); `503` before its cosigned epoch |
| `GET /v1/attestation` | — | `200`, the attestation bundle ([enclave-trust.md](enclave-trust.md) section 3.7) |

The three `POST` routes answer `202` when the writer took the request
(also when its receipt is a refusal), `400` for a body whose length is not
the size of the route's class, and `503` while the line has no writer.

The node knows the enclave base URL from its configuration; the app trusts
only what the attestation checks give it, not the URL. The enclave gets
control events and roster checkpoints itself ([network.md](network.md)
section 8.5).

The enclave refuses (`403`, plaintext) a relay request with no valid node
request signature. It may limit the requests of each node (`429`). A pack
or a cover must come through the node that its credential names
(`bad_credential`, in the receipt); a withdrawal, a known upload and an
answer may come through any admitted node. A node may fetch only the
receipts of requests that it relayed (`404` for others).

### 9.3 Node request signature

Each node → enclave request has four headers:

```
Anagram-Node:      <node id>
Anagram-Time:      <time>
Anagram-Nonce:     <hex16>
Anagram-Signature: <hex64>
```

```
payload   = canonical_json({"audience": "<origin of the target service>",
                            "body": hex(SHA-256(request body)), "method": "<GET|POST>",
                            "node": "<node id>", "nonce": "<hex16>",
                            "path": "<path and query>", "time": "<time>"})
signature = Ed25519(node key, tagged_message("anagram/v1/net/sign/node-request", payload))
```

`nonce` is 16 bytes from a CSPRNG, new for each request. So two
equal requests in the same second (for example two fetches of the
attestation bundle) are two requests with two signatures.

`audience` names the target: the enclave log origin of
[enclave-trust.md](enclave-trust.md) section 2.1 for the enclave, or the
roster service origin ([network.md](network.md) section 7.2). A service
refuses a payload with another `audience`. For a `GET`, the body is empty
(`SHA-256("")`). The enclave checks: the node
is in the current roster and not removed ([network.md](network.md)); the
key is the node's current roster key; `time` is within 300 seconds of the
enclave time; the signature verifies; and the same (node, `nonce`) was not
used in the last 600 seconds (the replay key; a second use gives `403`).
The window is longer than twice the time skew, so a payload that passes
the time check is always in the window. The node fetches the attestation
bundle again for each app request; it does not keep it.

## 10. Error codes

A `rejected` receipt has exactly one `reason` from this list. An
implementation must not add codes to v1.

| Code | Meaning | Messages |
| --- | --- | --- |
| `bad_envelope` | Wrong length, magic or class; HPKE did not open; padding not zero | all |
| `stale_attestation` | The attestation digest is not the current document of the intake key. The app must fetch the attestation again | all |
| `unknown_instance_key` | The intake key is not a live, logged key of this release | all |
| `bad_message` | Not canonical JSON; wrong fields; a field rule broken; a body type that does not belong to the class; a time in the future; a card email that the credential does not verify | all |
| `unsupported_schema` | A `schema` that this release does not accept | all |
| `bad_signature` | A signature check failed | pack, known, withdrawal, answer |
| `bad_credential` | The credential is missing, malformed, of a format not accepted, for another subject, kind or network, from a node not in the roster or not the relaying node, or with no or a bad log proof | pack |
| `revoked` | The node is removed, the credential is revoked, the member was removed or left, or the subject is banned | pack, answer |
| `expired` | The credential is expired; the pack or known object is more than 48 hours old | pack, known |
| `old_version` | The version is not larger than the last accepted one | pack, known, withdrawal |
| `tombstoned` | The message is older than the subject's tombstone, or a pack after a withdrawal has no new consent | pack, known |
| `rate_limited` | A second pack in a UTC day; a second known object in 6 days; the node is over its limit | pack, known, any |
| `too_large` | A pack over 49,152 bytes or a field over its budget; a known object over 5,000 entries; a card over 1,200 bytes; a body longer than its class allows | pack, known, answer |
| `unknown_proposal` | The proposal ID was not delivered to this subject, or it expired | answer |
| `already_answered` | A second answer for one proposal | answer |
| `stale_roster` | The enclave has no fresh roster checkpoint, or has not applied the node's control chain up to the credential's `control_head`, or a chain has a gap or a fork | pack, answer |
| `clock_unsafe` | The signed time and the host clock differ by more than 5 minutes ([enclave-trust.md](enclave-trust.md)) | all |
| `unavailable` | Reserved. v1 gives it in no receipt: only the writer signs receipts, and while there is no writer the front end answers `503` (enclave-trust.md 3.7). A receiver treats it as a refusal that it may retry | none in v1 |
| `wrong_shard` | The subject is not in the shard of this instance's line ([enclave-trust.md](enclave-trust.md) section 5.6). The app must fetch the attestation bundle again. v1 has one shard (n = 1), so a writer of an authorised line never gives it; the code stays for a later sharding design | pack, cover, known, withdrawal, answer |
| `issuance_limit` | The member's join entry is over the issuing node's monthly limit of new members `new_members_per_month` ([network.md](network.md) sections 6.7 and 9). Renewals never count | pack, cover |

The first design's codes are all here. This document adds
`unsupported_schema` (schema migration, [pack.md](pack.md) section 10),
`already_answered` (one answer for each proposal), `stale_roster` (roster
freshness and chain gaps, [network.md](network.md) section 8),
`unavailable` (reserved since the conformance review), `wrong_shard`
(shards), and `issuance_limit` (added last).

A receipt is about the sender's own message only. No code tells a sender
anything about another person (section 5.3).

## 11. What each party learns

- **The node** learns, for each member: one 64 KB upload a day, one 384 KB
  upload a week, one 4 KB fetch a day, one 1 KB receipt fetch for each
  request, three 2 KB answer requests for each proposal (on its fixed
  checkpoint days), and the times. So it learns how many proposals a member
  got, not their content, the choices or the day of a choice. With covers, the
  uploads, fetches and batch entries are the same for matching on and off. Residual: on the day a person turns matching off after
  the day's upload, the node sees one extra upload (section 7.1); and a
  member whose app stops all uploads stops getting slots after its queue
  and pack end.
- **Other members** cannot compute a slot address and get the same 4 KB for
  any address.
- **The enclave operator** learns the same metadata for each node.

## 12. Tags

| Tag | Use |
| --- | --- |
| `anagram/v1/enclave/hpke/request` | HPKE `info` of a request |
| `anagram/v1/enclave/hpke/receipt` | HPKE `info` of a receipt |
| `anagram/v1/enclave/hpke/slot` | HPKE `info` of a slot |
| `anagram/v1/enclave/request` | Request digest |
| `anagram/v1/enclave/slot` | Slot address |
| `anagram/v1/enclave/slot-filler` | HKDF `info` of a slot filler (ASCII bytes) |
| `anagram/v1/enclave/receipt-filler` | HKDF `info` of a receipt filler (ASCII bytes) |
| `anagram/v1/enclave/sign/cover` | Cover signature |
| `anagram/v1/enclave/sign/receipt` | Receipt signature |
| `anagram/v1/enclave/sign/slot` | Slot signature |
| `anagram/v1/enclave/sign/answer` | Answer signature |
| `anagram/v1/enclave/sign/withdrawal` | Withdrawal signature |
| `anagram/v1/net/sign/node-request` | Node request signature |

## 13. Test vectors

[vectors/enclave-messages.json](vectors/enclave-messages.json) holds: the
keys (seeds); the sizes; a sealed upload of the small pack of
[pack.md](pack.md) with its header, `info` and digest; an accepted receipt
for it and a rejected receipt; sealed answers `yes`, `no` and `not_now`;
a sealed answer filler (`answer_filler`); the checkpoints and expiry of
proposals made at several times (`answer_plans`);
a withdrawal; a cover (with the credential of the small pack); the padded
size and digests of the small known object; sealed slots with each item
kind (the reveal with its roster `node`) and their addresses; a slot filler
and a receipt filler with the node secret; a slot batch; a node request
signature with its `audience` and `nonce`; the `intake_script` of section 8; the
`slot_script` of section 6.8; and the error list.

HPKE output comes from a random source (the ephemeral key). A verifier
opens each sealed value with the private key and compares the plaintext;
it recomputes every other value. `seed_labels` gives the label of each
key: `seed = SHA-256(UTF-8("anagram net vector seed: " || label))`; each
sealed request and receipt names the label of its response key
(`response_seed_label`).

## 14. Changes after the spec review (2026-11-25)

- `wrong_shard` (3.3, 10).
- The cut; slots for live packs, covers and non-empty queues; reveals
  decided at a cosigned epoch survive withdrawal; the batch served only
  after its cosigned epoch and never changed (6.5 to 6.8, 7.1).
- Every receipt after the next cosigned epoch; `POST` answers `202`;
  `GET /enclave/receipts/{digest}` always gives 1,024 bytes (4.4, 9).
- Covers carry a credential and a reply key and get slots; the withdrawal
  replaces the day's upload; section 11 no longer claims more than holds
  (7.1, 7.2, 11).
- Reply key of the pack or cover current at the cut (6.1, 6.5).
- Writer-only intake and the attestation bundle (3.3, 9;
  enclave-trust.md 3.7).
- The reveal carries the roster `node` (6.4).
- Known uploads are kept only with a live pack (8.2).
- Answers on one fixed day (5.3); the node request signature names its
  `audience` (9.3).

Fixes of the re-check of that review:

- One slot rule for packs, covers and withdrawals (accepted in the 48
  hours before the cut); the withdrawal carries `reply_key`; vectors for
  the day after a withdrawal and an upload after 23:00 (6.5, 6.7, 6.8, 7.1,
  7.2).
- `answer_day` is 1 to 7 (5.3).
- v1 has one shard (n = 1), so a writer of an authorised line never gives
  `wrong_shard`; the code stays for a later sharding design (10).
- A crash before the epoch does not end the pair; the app resends the yes
  and the reveal is decided again (6.6, 6.8).

## 15. Changes after the simulated enclave slice (2026-11-25)

The simulated enclave slice found these problems. Each has a ruling; the
code and the vectors follow.

- Replay collision: two equal node requests in the same second had the
  same signature, so the enclave refused the second as a replay, and the
  node had to keep the attestation bundle for 60 seconds. The signed
  payload now has a 16-byte random `nonce` (header `Anagram-Nonce`), the
  replay key is (node, `nonce`) for 600 seconds, and the node does not
  keep the bundle (9.3). Vector: `node_request` has the nonce.
- Reply key: the enclave keeps a subject's reply key while the subject has
  a stored pack or an open copy of a proposal; the app keeps the private
  key as long (6.5).
- Daily upload: a credential lasts 24 hours, so the app uploads a fresh
  pack or cover every day. This also keeps the 48-hour slot rule true for
  a person who is live (6.5).
- Decline records: a `no` keeps the pair apart for 365 days, also after a
  withdrawal of the other person; the decliner's own withdrawal deletes
  the record (5.3, 7.1; enclave-trust.md 7.1).
- Writer failover: a new writer by failover answers `unknown_instance_key`
  for a request sealed to the old writer; the app fetches the bundle again
  and seals again (8.5; enclave-trust.md 5.7).

## 16. Changes after the conformance review (2026-11-25)

- The front end sends every request to the writer; a request sealed to
  another key gets `unknown_instance_key` from the writer; a step-1
  failure with the right length gets a `bad_envelope` receipt; with no
  writer the node gets `503`; `unavailable` is reserved (3.3, 8.5, 9.2,
  10). Tests: `tests/test_enclave_conformance.py`; the strict xfail of
  `test_bad_magic_gets_a_bad_envelope_receipt` is gone.
- The node timer (4.4); the node runs it from its own code.
- The `intake_script` replay step uses a pack inside 48 hours, so a full
  intake gives `tombstoned` (8.6).
- The HPKE `aad` is empty (2).
- `seed_labels` and `response_seed_label` in the vector file (13).
- Untested paths: `unsupported_schema`, `revoked` and `too_large` now come
  through the service in tests; the node routes give `401` and `403`
  (9.1).
- The flaky receipt: a credential check stopped after 1 ms of wall-clock
  time (the Biscuit library default), so a busy computer gave `expired` or
  no receipt. The run limits are now fixed (network.md 6.2).

## 17. Changes after the answer-window, node-limit and decline decisions (2026-11-26)

- Answer window: 21 days with checkpoints at `m + a`, `m + 2a`, `m + 3a`
  (`a` = `answer_day`, 7 in production); one sealed object at each
  checkpoint (the answer, `not_now` at the last one, or the new answer
  filler); the reveal at the first checkpoint where both answered; both
  copies share the checkpoints and the expiry, and the proposal item
  carries `checkpoints` (5.3, 5.4, 6.4). Re-checked timing rules:
  - copy lifetime: from 14 days after delivery to the shared expiry, at
    most 22 days after the sweep (6.4);
  - queue wait: a copy is not delivered from the first checkpoint day on,
    which is 6 days at most, as before (6.5);
  - slot retention by the node and reply key retention by the app: 14 to
    28 days (6.3, 6.5);
  - the old reason for `answer_day` at most 7 is gone (the expiry is
    shared); the range stays 1 to 7 to bound the window (5.3);
  - the tombstone life of 38 days does not change
    ([enclave-trust.md](enclave-trust.md) section 6.3).
- Weekly cap: the person chooses 1 to 10 (default 3) under the descriptor
  maximum; the ranking counts the proposals of the same sweep (6.5).
- Node rule: one proposal to a person from one other node in 28 days, in
  the ranking (6.5); `issuance_limit` (10).
- A `no` blocks the pair for the declined match type only (5.3).
- Vectors: `answer_filler`, `answer_plans`; the proposal slot carries
  `checkpoints`; `issuance_limit` is in the error list.

## 18. Changes after the review of those decisions (2026-11-26)

- A pair that only a cap or the node rule stops waits and is ranked again
  at each later sweep; before, it came back only with a material change,
  so a person with more good fits than the weekly cap lost them (6.5).
- `issuance_limit` counts new members (join entries), not credentials:
  credentials renew each day, so a limit on credentials capped a node at
  about 300 members (10, and [network.md](network.md) 6.7).
- Vectors: the credentials of `enclave-messages.json` carry the `join` of
  their log proof.

## 19. Changes after the node-size decision (2026-11-26)

A simulation of the node rule (an ablation of its variants) gave the
evidence for this change:

- The node rule scales with the size of the proposing node: at most
  max(1, ceil(m / 50)) proposals to a person from one other node in 28
  days, where m is the number of live packs in the current sweep whose
  member credential the enclave verified for that node. Before, the limit
  was 1 for every node (6.5).
- A pair that the node rule stops waits, as before (6.5, section 18).
- The weekly cap does not change.
- No format changes and no vector changes: no vector file has the node
  rule. The sealed snapshot keeps, for each person and other node, the
  times of the proposals in the last 28 days (before: only the last time);
  the snapshot body is internal to the service
  ([enclave-trust.md](enclave-trust.md) 6.1).

## 20. Changes after the dropped-copy review (2026-11-26)

- Before, a sweep could give a person more proposals than the slots
  before the first checkpoint (for example a weekly cap of 10 with
  `answer_day` 7, or a queue that already held reveals). The enclave then
  dropped the late copies, and each peer kept a one-sided proposal until
  it ended. Now a sweep proposes a pair only when both queues can deliver
  the copy before the first checkpoint; the other pairs wait for a later
  sweep (6.5). The drop at the first checkpoint stays only as a safety
  net, and the audit counts it.
- A waiting pair keeps its stage-1 score in millionths (an integer),
  because the sealed snapshot is canonical JSON, which has no floats.
  Before, a waiting pair stopped the snapshot. The snapshot body is
  internal to the service ([enclave-trust.md](enclave-trust.md) 6.1).
- No format changes and no vector changes.
