# Anagram enclave trust: transparency log, verifier profiles, key custody, anti-rollback, deletion

Status: draft (written 2026-11-25), revised after a spec review and after
a simulated enclave slice (fixes in sections 12 and 13).
Not locked. Licence: CC BY 4.0.
Vectors: [vectors/enclave-trust.json](vectors/enclave-trust.json).
Reference code (MIT): `anagram.network.matching.trust` (the
`simulated` profile in `trust.profiles.simulated`, the log entries, and
pure parsers of the SEV-SNP report and the TDX quote in `trust.profiles`).

This document specifies the trust of the network matching enclave
([matching.md](matching.md) is the overview of matching). It uses the log formats of
[log.md](log.md) (RFC 6962 tree, C2SP signed note, checkpoint,
cosignature, tiles), the encoding of [formats.md](formats.md) section 2,
and the signed-document rule of [identity.md](identity.md) section 1.

Companion documents (written in parallel; they own their formats):
[pack.md](pack.md) (`anagram.pack.v1`, `anagram.known.v1`),
[enclave-messages.md](enclave-messages.md) (sealed envelopes, answers,
receipts, slots, control events, receipt error codes), and
[network.md](network.md) (roster, node admission record, member
credential). Where this document names one of their formats, their text
wins.

A sentence marked **(to confirm)** states a vendor fact or a value that we
could not confirm from a primary source. A platform spike on real hardware
must confirm it on real evidence before the profile is locked. Section 10
lists each one.

## 1. Words, parties, codes and tags

| Word | Meaning |
| --- | --- |
| Release | One enclave image, logged as an `enclave_release` entry |
| Instance | One running confidential VM of a release. It has an `instance_id` (16 random bytes) |
| Line | A chain of state that instances hand from one to the next. It has a `line_id` (16 random bytes) and one state key. A line exists only with an authorised `enclave_line` entry (section 5.6) |
| Writer | The one instance of a line that opens requests and writes its state epochs |
| Holder | An instance that holds the state key of a line. The latest state epoch lists the holders |
| Shard | The part `k` of `n` of the subjects that one line serves (section 5.6) |
| Profile | The rules that turn the evidence of one platform into claims and a measurement |
| Signed time | A time that a pinned witness or a Roughtime server signed |
| Quorum | 2 cosignatures from distinct pinned witnesses; at least 1 of them is not run by Radiofuture |
| Independent quorum | 2 cosignatures from the 2 independent witnesses. The `security_fix` path, a revoke not signed by the release key, each `enclave_line` entry and each `enclave_writer` entry need it |
| Failover | A holder becomes the writer after the writer's lease ended, by an `enclave_writer` entry (section 5.7) |

Parties: the app (on the person's computer; trusted), the enclave
instance, the operator (Radiofuture), the log operator (Radiofuture),
3 witnesses, 2 rebuilders, the nodes, the hardware and cloud vendors.

**Trust assumption of the log.** The quorum rule stops Radiofuture alone.
It does not stop Radiofuture together with one independent witness. The
assumption is: Radiofuture and an independent witness do not collude
(this makes the assumption "at least one non-Radiofuture witness is
honest" exact). For v1 this limit is accepted and the privacy page states it. The paths that change who can run or
stop the enclave (a short notice, a revoke without the release key, a new
line) need the independent quorum, so Radiofuture with its own witness
cannot use them.

Error codes. The app (and an instance that checks a successor) uses these
codes. They are local results; nothing sends them across a node. The
receipt codes that the enclave puts in a sealed receipt are in
[enclave-messages.md](enclave-messages.md).

| Group | Codes | Section |
| --- | --- | --- |
| Entry form | `bad_entry`, `bad_entry_signature` | 2.2 |
| Release | `release_not_logged`, `release_revoked`, `release_app_too_old`, `release_rebuild_differs`, `release_rebuilds_missing`, `release_fix_not_cosigned`, `release_notice_short`, `release_not_yet` | 2.5 |
| Attestation pre-checks | `bad_attestation`, `unknown_profile` | 3.4 |
| Attestation rules 1 to 9 | `measurement_mismatch`, `tcb_below_floor`, `policy_refused`, `smt_allowed`, `ciphertext_hiding_off`, `page_swap_allowed`, `secure_boot_off`, `image_not_stable`, `launch_override`, `evidence_expired`, `binding_mismatch`, `gpu_binding_mismatch`, `instance_not_logged`, `line_not_authorised`, `instance_revoked`, `line_forked`, `instance_not_writer`, `instance_limit`, `untrusted_root`, `cert_revoked`, `evidence_not_cloud_bound` | 3.5 |
| Handoff | `handoff_not_successor`, `handoff_bad_sender`, `handoff_bad_ciphertext` (plus all codes above, and `snapshot_unknown`) | 5.3 |
| Snapshot load (enclave, counted) | `snapshot_stale`, `snapshot_unknown`, `line_forked` | 6.2 |
| Pack intake (enclave, in a receipt) | `tombstoned`, `expired`, `clock_unsafe` (defined in enclave-messages.md; the rules are in 6.3 and 6.4) | 6 |

New tags. They do not collide with the locked registry
([formats.md](formats.md) section 3.2) or the room tags
([matching.md](matching.md) section 8); a test checks this.

| Tag | Use |
| --- | --- |
| `anagram/v1/enclave/measurement` | measurement of one profile (3.3) |
| `anagram/v1/enclave/descriptor-set` | hash of the set of descriptor hashes (3.2) |
| `anagram/v1/enclave/report-data` | the key binding (3.2) |
| `anagram/v1/enclave/report-data-gpu` | the key binding that also covers the GPU evidence (3.2) |
| `anagram/v1/enclave/gpu-nonce` | the nonce given to the GPU (3.2) |
| `anagram/v1/enclave/log-entry` | digest of a log entry (2.2) |
| `anagram/v1/enclave/sign/release` | signature on enclave_release |
| `anagram/v1/enclave/sign/rebuild` | signature on enclave_rebuild |
| `anagram/v1/enclave/sign/revoke` | signature on enclave_revoke |
| `anagram/v1/enclave/sign/floor` | signature on enclave_floor |
| `anagram/v1/enclave/sign/instance-key` | signature on enclave_instance_key |
| `anagram/v1/enclave/sign/state-epoch` | signature on enclave_state_epoch |
| `anagram/v1/enclave/sign/entry-cosign` | signature on enclave_entry_cosign |
| `anagram/v1/enclave/sign/node-admission` | signature on node_admission |
| `anagram/v1/enclave/sign/member-credential` | signature on member_credential |
| `anagram/v1/enclave/sign/attestation` | output-key signature on the attestation document (3.1) |
| `anagram/v1/enclave/sign/simulated-evidence` | development-root signature, simulated CPU evidence (4.2) |
| `anagram/v1/enclave/sign/simulated-gpu` | development-root signature, simulated GPU evidence (4.2) |
| `anagram/v1/enclave/hpke/handoff` | HPKE info of the state-key handoff (5.3) |
| `anagram/v1/enclave/tombstone` | tombstone ID of a person key (6.3) |
| `anagram/v1/enclave/sign/line` | signature on enclave_line (5.6) |
| `anagram/v1/enclave/sign/handoff` | output-key signature on the handoff message (5.3) |
| `anagram/v1/enclave/shard` | shard of a subject key (5.6) |
| `anagram/v1/enclave/descriptor` | hash of one release descriptor (3.6) |
| `anagram/v1/enclave/sign/writer` | signature on enclave_writer (5.7) |
| `anagram/v1/enclave/decline` | ID of a decline record (7.1) |

The attestation document digest reuses the room tag
`anagram/v1/room/attestation` ([matching.md](matching.md) section 8).

## 2. Release transparency log

### 2.1 The log

The enclave log is one append-only log, separate from the node logs. It
follows [log.md](log.md) sections 1 to 5 with no change: leaf data
`canonical_json(entry)`, RFC 6962 hashes, RFC 9162 proofs, C2SP
`tlog-checkpoint` text, C2SP `signed-note` signature by the log key (the
key name equals the origin), C2SP `tlog-cosignature` (`cosignature/v1`)
lines by witnesses, and C2SP `tlog-tiles` paths. The origin is a
schema-less URL, for example `enclave.anagram.example/log`.

The log publishes a new checkpoint at least every 10 minutes and after each
entry. The writer of each line writes a state epoch every 10 minutes
(section 6.3), so the log grows at least every 10 minutes. This matters for section 3.5 rule 4:
a witness does not cosign a checkpoint that is smaller than the last one it
cosigned (log.md section 4, check 2), so an old checkpoint cannot get a
new cosignature after the log grew.

Read API (anyone may read). The paths are
relative to the log's base URL, `https://<origin>`:

| Route | Answer |
| --- | --- |
| `GET /log/checkpoint` | `200`, `text/plain; charset=utf-8`: the latest cosigned checkpoint note with its cosignature lines |
| `GET /log/checkpoint/covering/{index}` | `200`, the same form: the first cosigned checkpoint whose tree size is larger than `index` (section 2.4); `404` if no cosigned checkpoint holds entry `index` yet |
| `GET /log/entries?start={i}&end={j}` | `200`, `application/json`: `canonical_json({"entries": [entry i, ..., entry j - 1]})`, each entry as its leaf data parses; `400` unless `0 ≤ i < j ≤` the tree size of the latest cosigned checkpoint and `j − i ≤ 256` |
| C2SP `tlog-tiles` paths | the tiles and entry bundles, for bulk reads |

A reader checks each entry that it reads against a cosigned checkpoint
(the root of the first `size` leaves); the routes give no trust. The log
keeps every cosigned checkpoint that it published. Write API: only
Radiofuture's log service writes; each writer in section 2.3 sends its
signed entry to it. The log refuses an entry that fails section 2.2.

### 2.2 Entry form

Each entry is a public signed document ([identity.md](identity.md)
section 1). It is not a hidden commitment, so it does not use
`anagram.log_entry.v1`.

```
entry      = {fields of the kind..., "kind", "schema", "signer": "<hex Ed25519>", "signature": "<hex>"}
signature  = Ed25519(signer key, tagged_message(<tag of the kind>, canonical_json(entry without "signature")))
digest     = tagged_hash("anagram/v1/enclave/log-entry", canonical_json(entry))
leaf data  = canonical_json(entry)
```

A reader refuses an entry with an unknown `kind`, a wrong `schema`, a field
set that is not exactly the set of its kind (`bad_entry`), a field value
that is not of its form (`bad_entry`), or a signature that does not verify
(`bad_entry_signature`). Lists of hashes are sorted and have no duplicates.
Times are RFC 3339 UTC with whole seconds. An image or vendor digest is
`sha256:<64 hex>`.

### 2.3 Entry kinds

| Kind (`schema`) | Fields (besides the four common ones) | Signer |
| --- | --- | --- |
| `enclave_release` (`anagram.enclave.release.v1`) | `build` {`builder` (image digest of the pinned builder), `lock_sha256` (SHA-256 of `uv.lock`), `source_date_epoch`}, `descriptor_hashes` (1 to 64), `image_digest`, `max_instances` (1 to 64), `min_app_version` (`x.y.z`), `not_before`, `profiles` {profile → {`cloud` (not for `simulated`), `measurement`, `reference`, `tcb_floor`}}, `security_fix` (bool), `source_commit` (40 hex), `successor_of` (release digest or null), `vendor_digests` [{`name`, `digest`}], `weights` [{`name`, `digest`}] | the release key (pinned) |
| `enclave_rebuild` (`anagram.enclave.rebuild.v1`) | `image_digest`, `measurements` {profile → hex}, `release` (digest), `same` (bool) | a rebuilder key (pinned) |
| `enclave_revoke` (`anagram.enclave.revoke.v1`) | `reason` (`vulnerability`, `malicious`, `key_compromise`, `broken_build`, `superseded`), `target` (exactly one of {`release`: digest}, {`instance_id`: hex}, {`line_id`: hex}) | the release key, or any signer with an independent quorum of `enclave_entry_cosign` entries on its digest |
| `enclave_floor` (`anagram.enclave.floor.v1`) | `profile`, `release` (digest), `tcb_floor` | the release key |
| `enclave_instance_key` (`anagram.enclave.instance_key.v1`) | `evidence_digest` (SHA-256 of `canonical_json(platform_evidence)` at registration), `instance_id`, `intake_key` (X25519), `key_epoch`, `lease_until`, `line_id`, `profile`, `release` (digest) | the instance output key (so `signer` is the output key). The log accepts it only with the attestation document (section 5.4) |
| `enclave_state_epoch` (`anagram.enclave.state_epoch.v1`) | `checkpoint` (anchor digest of the latest cosigned checkpoint that the writer saw), `counter`, `holders` (sorted instance IDs that hold the state key, 1 to 64, the writer and `next_writer` among them), `instance_id`, `line_id`, `next_writer` (instance ID or null), `prev` (digest of the previous state epoch of the line, or null), `rekey` (bool), `snapshot_digest`, `snapshot_size` | the writer's output key |
| `enclave_line` (`anagram.enclave.line.v1`) | `line_id`, `reason` (`first`, `shard`, `total_loss`), `release` (digest of the release that starts it), `replaces` (the line ID that a `total_loss` line replaces; else null), `shard` {`k`, `n`} (1 ≤ n ≤ 64, 0 ≤ k < n; v1 accepts only n = 1, k = 0, section 5.6) | the release key, with an independent quorum of `enclave_entry_cosign` entries on its digest (section 5.6) |
| `enclave_writer` (`anagram.enclave.writer.v1`) | `counter` (of the line's latest state epoch), `epoch` (digest of that state epoch), `line_id`, `writer` (instance ID of the new writer) | the release key, with an independent quorum of `enclave_entry_cosign` entries on its digest (section 5.7) |
| `roster_checkpoint` (`anagram.net.roster_checkpoint.v1`) | `head`, `network`, `seq`, `time` ([network.md](network.md) section 3.5: the roster checkpoint document is the entry) | the roster key (tag `anagram/v1/net/sign/roster-checkpoint`) |
| `enclave_entry_cosign` (`anagram.enclave.entry_cosign.v1`) | `entry` (digest), `time` (unix seconds) | a witness entry key (pinned) |
| `node_admission` (`anagram.enclave.node_admission.v1`) | `node_id`, `record_digest` (digest of the admission record of [network.md](network.md), an endorsement-chain record) | the roster key, or the inviting node's key, as network.md says |
| `member_credential` (`anagram.enclave.member_credential.v1`) | `credential_hash` (as network.md defines it), `expires` (the log takes the entry only when `expires` is after its own time and at most 24 hours and 300 seconds later), `member` (the join commitment of network.md 6.5, or null for a renewal), `node_id` | the issuing node's key |

`enclave_release.profiles` holds only the profiles of section 4 that the
release supports. A production release never lists `simulated`.
`cloud` pins the clouds that may run the release (rule 9). It has exactly
the pin names of its profile, each a sorted list of 1 to 16 distinct
non-empty strings (at most 128 characters): `raw-snp` {`csp_ids`} (the
`csp_id` of a VLEK, section 4.3); `gcp-cs` {`project_numbers`, `zones`}
(section 4.5); `raw-tdx` and `azure-cvm-gpu` {} (their evidence names no
cloud). `simulated` has no `cloud`.
`max_instances` is the largest number of holders of one line (rule 7 (f)).

The enclave uses a roster checkpoint only when it is a `roster_checkpoint`
entry in a log checkpoint with a quorum. The roster operator
logs one at each change of the roster head and at least every 15 minutes
([network.md](network.md) section 3.5).

Witnesses have two keys each: the `cosignature/v1` key of log.md section 4,
and a separate Ed25519 **entry key** for `enclave_entry_cosign`. The app
pins both.

### 2.4 Checkpoints, witnesses and signed times

Three witnesses: one run by Radiofuture, one run by a
university node, and one public witness network. The app pins each
witness's two keys and an `independent` flag (true for the two not run by
Radiofuture).

The app accepts a checkpoint only if:

1. the log key signed it (log.md section 3), and the key name equals the
   origin;
2. it has a **quorum**: valid `cosignature/v1` lines from 2 distinct pinned
   witnesses, at least 1 with `independent = true`;
3. it is consistent with the last checkpoint that the app accepted (log.md
   section 7, check 4). A failed proof stops the app (`LogMisbehaved`) and
   shows a notice (section 7.5).

From the cosignature times (log.md section 4: `time <unix seconds>`),
the app takes two signed values. They are over **all** valid
`cosignature/v1` lines of distinct pinned witnesses in the checkpoint, not
only over the lines that make the quorum:
more lines can only make `lower` smaller and `upper` larger, so each value
stays a true bound, and the result does not depend on which lines a
reader picks.

- `lower(cp)` = the smallest such time. Under the assumption of section 1
  an honest witness signed at or after it, so "now" is at least
  `lower(cp)` when the app sees `cp`.
- `upper(cp)` = the largest such time. Each entry of `cp` was in the log
  at or before `upper(cp)`.
- `logged_by(e)` = the smallest `upper(cp)` over the accepted checkpoints
  that include entry `e`.

**Old checkpoints for a fresh app**. An app that starts with no
history has only the bundle's checkpoint, so `logged_by` of an old entry
would be "now", and an old release would fail the notice rule. So the app
asks `GET /log/checkpoint/covering/{index}` for each entry whose
`logged_by` a rule uses: `enclave_release` and `enclave_rebuild` (2.5),
`enclave_line` (5.6) and `enclave_instance_key` (rule 7 (a), 5.6). One
covering checkpoint serves every entry below its size, so the app asks
once for each run of such entries. It checks each one like any checkpoint
(rules 1 and 2 above; its root must equal the root of the first `size`
entries that it read) and adds it to the minimum. After that, the hourly
checks of 2.7 give the times of new entries.

Why this is sound: every cosigned checkpoint that includes `e` gives a
true upper bound of the time at which `e` was in the log. If the log
serves a later checkpoint than the first, `logged_by` only gets later.
That makes the notice and rebuild rules (2.5) and the total-loss rule
(5.6) stricter, not weaker. For the lease bound of rule 7 (a) a later
`logged_by` is more lenient, so the log and the two Anagram witnesses also
refuse an `enclave_instance_key` entry whose `lease_until` is more than 24
hours after their own time (5.4). The bound then holds without the first
checkpoint.

**State counters and forks.** A line's state epochs must form one chain
(section 5.5). The two Anagram witnesses (Radiofuture and the university)
also read the new entries before they cosign and refuse a checkpoint that
adds a second state epoch with the same `line_id` and `counter`, a
state epoch whose `prev` is not the digest of the line's last one, an
`enclave_instance_key` entry whose attestation document fails section 3.4
(rules 1 to 6 and 8; section 5.4) or whose `lease_until` is more than 24
hours after the witness's time, or a second `enclave_line` entry with
the same `line_id`. A
public witness network checks only consistency (C2SP); it does not read
entries. This is enough: consistency stops a split view, so each reader
sees the same entries, and section 5.5 makes any break of the chain a
`line_forked` line for every reader. The witness refusal only makes the
fork visible sooner.

### 2.5 Release acceptance (the notice period)

Before the app seals anything to an instance of release `R`, it checks `R`
against the entries that it has from accepted checkpoints. The checks run
in this order; the first failure gives its code.

1. `R` is in the log and its signer is the pinned release key. Else
   `release_not_logged`.
2. No valid `enclave_revoke` targets `R` (signed by the release key, or by
   any signer with an independent quorum of `enclave_entry_cosign` entries
   on the revoke entry's digest). Else `release_revoked`.
3. The app's version is at least `min_app_version`. Else
   `release_app_too_old`.
4. Each pinned rebuilder logged one `enclave_rebuild` for `R` with
   `same = true`, the same `image_digest`, and `measurements` equal to the
   measurement of each profile of `R`. An entry from a pinned rebuilder with
   `same = false` or with other values gives `release_rebuild_differs`.
   A missing record, or one with `logged_by > not_before`, gives
   `release_rebuilds_missing`. `release_rebuild_differs` comes first: the
   app reads each record of a pinned rebuilder for `R` and refuses at the
   first one that differs; only if none differs does it check that each
   pinned rebuilder has a record in time. (Who checks each release during the notice:
   CI and one party that is not Radiofuture.)
5. Notice: `logged_by(R) + 14 days ≤ not_before`. If this fails and
   `security_fix = false`: `release_notice_short`. If this fails and
   `security_fix = true`, the notice is 48 hours, and only if an
   independent quorum (both independent witnesses) logged
   `enclave_entry_cosign` entries on the digest of `R` with `time ≤
   not_before − 48 h`. Without
   that quorum: `release_fix_not_cosigned`. With it, but
   `logged_by(R) + 48 h > not_before`: `release_notice_short`. A
   self-flagged `security_fix` alone never shortens the notice.
6. The app's "now" (section 3.5: `max(computer clock, lower(latest
   accepted checkpoint))`) is at or after `not_before`. Else
   `release_not_yet`. Every rule of the app that says "now" uses this
   value.

A witness cosigns a `security_fix` entry only after a person at the
witness reads the advisory that the release names; the witness's own
policy says how. The spec requires only the signature.

### 2.6 What the app pins

The app binary holds: the log origin and log key; the 3 witnesses (two keys
and the `independent` flag each); the release key; the 2 rebuilder keys;
the vendor roots of section 4 (AMD ARK per product, Intel SGX Root CA,
Google Confidential Space root, Microsoft MAA signing chain, NVIDIA device
identity root and RIM signing root) **(to confirm: exact certificates,
except AMD, Intel and Google)**.

The AMD ARKs are pinned by the SHA-256 of their DER, as AMD KDS serves
them (`https://kdsintf.amd.com/{vcek,vlek}/v1/<Product>/cert_chain`; the
VCEK and VLEK chains share the ARK):

| Product | SHA-256 of the ARK DER |
| --- | --- |
| `milan` | `69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd` |
| `genoa` | `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1` |
| `turin` | `1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a` |

The Confidential Space Root CA (`gcp-cs`) is pinned by the SHA-256 of its
DER, as Google serves it
(`https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt`;
Google's page gives its SHA-1 fingerprint `B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21`;
it rotates every 10 years):
`148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39`.

The Intel SGX Root CA is pinned by the SHA-256 of its DER, as Intel serves
it (`https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer`):
`44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`.

A production app pins no development root, so it refuses the `simulated`
profile with `untrusted_root`. A change to any pinned value needs a new app
release.

### 2.7 What the app monitors

Each hour the app gets the latest checkpoint, checks consistency, reads the
new entries, and:

- drops instance keys of revoked releases, instances and lines, and of
  forked lines (section 5.5);
- applies `enclave_floor` entries (section 7.2);
- applies `enclave_line` entries (section 5.6) and drops instance keys of
  lines that are not authorised or that a total-loss line replaced;
- applies `enclave_writer` entries (section 5.7): after a failover it
  seals only to the new writer;
- checks that each `member_credential` entry of its own node matches a
  credential that the node issued to a member it knows (a node operator's
  own check; network.md);
- shows a notice for each event of section 7.5.

### 2.8 Privacy of the log

The log holds no person data. `member_credential` entries are hashes, so
counts of credentials and of new members per node and per day show;
names, keys and affiliations do not. A join commitment hashes the person
key with a random 16-byte salt that only the app, the node and the enclave
know, so it does not link two entries or name the person. A `credential_hash` must not be a hash of a
low-entropy value. [network.md](network.md) section 6.5 defines it over
the credential bytes, which hold a node signature, so it needs no separate
salt.
Tombstones (section 6.3) are never in the log.

## 3. Attestation document and the verifier

### 3.1 Document (`anagram.operator_attestation.v3`)

Version 3 is the only version. Versions 1 and 2 were the formats of the
removed node-run room, and their schema names are retired
([matching.md](matching.md) section 8).

```json
{"checkpoint": "<signed checkpoint note, with cosignatures>",
 "descriptor_hashes": ["<hex>", ...],
 "gpu_evidence": <object of the profile> | null,
 "instance_id": "<hex16>", "intake_key": "<hex32 X25519>", "key_epoch": 0,
 "line_id": "<hex16>", "log_proof": {"index": <log index of the enclave_instance_key entry>} | null,
 "output_key": "<hex32 Ed25519>",
 "platform_evidence": <object of the profile>,
 "profile": "simulated | raw-snp | raw-tdx | gcp-cs | azure-cvm-gpu",
 "release": "<release digest>",
 "schema": "anagram.operator_attestation.v3",
 "signature": "<hex64>"}
```

- `signature = Ed25519(output key, tagged_message("anagram/v1/enclave/sign/attestation", canonical_json(document without "signature")))`.
  It proves that the instance holds the output key.
- Digest: `tagged_hash("anagram/v1/room/attestation", canonical_json(full document))`.
  The sealed envelopes of enclave-messages.md bind to this digest.
- `log_proof` is a hint only. The app proves inclusion of the instance key
  entry against its own latest accepted checkpoint.
- `descriptor_hashes` must equal the release's `descriptor_hashes`. Each is
  the hash of one descriptor document (section 3.6).
- The document has no `measurement` field. The verifier derives it
  (section 3.3).

The instance makes a new document at least every 12 hours, and at once
after a new key epoch, a lease renewal, or a handoff.

### 3.2 Key binding (report data) and GPU nonce

```
descriptor_set = tagged_hash("anagram/v1/enclave/descriptor-set",
                             u32(n) || sorted descriptor hashes (32 bytes each))
binding        = tagged_hash("anagram/v1/enclave/report-data",
                             line_id (16) || instance_id (16) || u64(key_epoch) ||
                             intake_key (32) || output_key (32) || descriptor_set (32) ||
                             release digest (32) || checkpoint anchor (32))
gpu_nonce      = tagged_hash("anagram/v1/enclave/gpu-nonce", binding)          (32 bytes)
report_data    = binding                                                       (no GPU)
               = tagged_hash("anagram/v1/enclave/report-data-gpu",
                             binding || SHA-256(GPU evidence bytes))            (with a GPU)
REPORT_DATA    = report_data || 32 zero bytes                                  (the 64-byte field)
```

The checkpoint anchor is `SHA-256(checkpoint text)` (log.md section 2) of
the note in the document's `checkpoint` field.

This extends the first binding design (`intake key || key epoch ||
instance ID || descriptor set hash`) with the line ID, the output key, the
release digest and the checkpoint. The output key binding stops a party
that has a valid report from logging its own output key for it. The
checkpoint binding gives raw reports (which have no time) a signed age
(rule 4).

**Correction of the first GPU binding design.** That design said: "the GPU report nonce is
the hash of the CPU report data, and the CPU report data covers the hash of
the GPU report". Both together are a cycle and no evidence can meet them.
This spec breaks the cycle: the GPU nonce is derived from `binding` (not
from `report_data`), and `report_data` covers the GPU evidence. So the GPU
evidence is fresh and bound to the same keys, and the CPU evidence names
the exact GPU evidence. The measured code in the CPU TEE gets the GPU
evidence over its own SPDM session with the GPU that it uses; this is why
a GPU report from another machine does not help an attacker **(to confirm:
that the CC driver gives the report of the attached GPU only)**.

### 3.3 Measurement

```
measurement(profile) = tagged_hash("anagram/v1/enclave/measurement",
                                   lp(profile, UTF-8) || canonical_json(reference))
```

`reference` is the object of reference values that section 4 defines for
the profile. The release entry holds `reference` and `measurement` for each
profile. The verifier takes the claims from the evidence, builds the same
object from them, and compares the hash with the release (rule 1). So one
logged value per profile covers the image and everything that the platform
measures, and an auditor can read the inputs.

### 3.4 Check order

The app (and an instance that checks a successor, section 5.3) checks a
document in this fixed order. The first failure gives its code.

1. Pre-checks: exact field set and schema; `release` is the digest of an
   accepted release (section 2.5); `descriptor_hashes` equal the release's;
   the output-key signature verifies; the `checkpoint` note has a quorum
   (section 2.4). Else `bad_attestation`. Then, after all of these: the
   profile is in the release's `profiles` and the app supports it. Else
   `unknown_profile`. So a document that fails a check of its integrity
   always gives `bad_attestation`, whatever its `profile` says.
2. Rule 8 (roots), rule 9 (cloud), rule 4 (age), rule 3 (policy), rule 2 (TCB floor),
   rule 1 (measurement), rule 5 (key binding), rule 6 (GPU binding),
   rule 7 (log and instance count).

Roots come first, so no claim of unverified evidence is read. The cloud
comes next: evidence from a machine that no pinned cloud runs says
nothing else worth reading. The
measurement comes after policy and floor, so a debug or old-firmware VM
gives the code that names its cause.

### 3.5 The nine rules

Each rule has one or more refusal vectors in `vectors/enclave-trust.json`
(`attestation_cases`), and the test refuses each one with its code. The
codes of the strict policy (rule 9 and the rule 3 codes after
`policy_refused`) have their vectors in `vectors/enclave-policy.json`, at
the level of verified claims (section 4.9).

| # | Rule | Code |
| --- | --- | --- |
| 1 | Evidence → claims → reference object → measurement (section 3.3) equals `profiles[profile].measurement` of the release | `measurement_mismatch` |
| 2 | Each item of the effective TCB floor (release floor, raised by `enclave_floor` entries, section 7.2) is met by the claims (section 4.8). The GPU items (`gpu_driver`, `gpu_vbios`) apply only to a document with GPU evidence; without GPU evidence rule 6 decides (a release whose reference has `"gpu": true` then gives `gpu_binding_mismatch`) | `tcb_below_floor` |
| 3 | Policy: debug off, migration off, GPU confidential mode on and GPU debug off; then the bits of the profile (section 4.9), in the order of its table | `policy_refused`; the bits of 4.9 each give their own code: `smt_allowed`, `ciphertext_hiding_off`, `page_swap_allowed`, `secure_boot_off`, `image_not_stable`, `launch_override` |
| 4 | Age: `now − lower(checkpoint of the document) ≤ 24 h`, and `lower(...) ≤ now + 300 s`. A token-based profile also needs `valid_from ≤ now + 300 s` and `now < valid_until` (the token's `nbf` and `exp`, narrowed by its certificates, section 4.5). A profile with collateral (the AMD CRL, section 4.3) also needs `now <` its next update | `evidence_expired` |
| 5 | The evidence carries `report_data` (section 3.2) in its binding place (section 4) | `binding_mismatch` |
| 6 | If the release reference has `"gpu": true`: GPU evidence is present; its nonce is `gpu_nonce`; and `report_data` is the GPU form. If `report_data` equals the plain `binding` while GPU evidence is present, the CPU evidence does not cover the GPU. A profile whose CPU evidence itself carries the GPU claims (`gcp-cs`) has no GPU evidence and uses the plain form | `gpu_binding_mismatch` |
| 7 | (a) An `enclave_instance_key` entry matches `release`, `line_id`, `instance_id`, `key_epoch`, `intake_key`, `profile`, with `signer = output_key`; its latest such entry `e` has `now < lease_until ≤ logged_by(e) + 24 h`. (b) The line is authorised (section 5.6): it has one `enclave_line` entry with an independent quorum, its reason rules hold, no authorised total-loss line replaces it, and its shard is the shard of the app's subject. (c) No valid revoke targets the instance or the line. (d) The line is not forked (section 5.5). (e) The instance is the writer of the line: the `next_writer` of the latest state epoch, or its `instance_id` if `next_writer` is null. (f) The latest state epoch lists at most `max_instances` holders | (a) `instance_not_logged`, (b) `line_not_authorised`, (c) `instance_revoked`, (d) `line_forked`, (e) `instance_not_writer`, (f) `instance_limit` |
| 9 | The evidence shows that a cloud pinned by the release's `profiles[profile].cloud` runs the instance (section 4.9). `raw-snp`: the report is signed by a VLEK whose `csp_id` is in `csp_ids`. `gcp-cs`: the token's project number and zone are in `project_numbers` and `zones`. `raw-tdx`: refused by a production app (it pins no development root); its evidence names no cloud. `azure-cvm-gpu`: refused (parked). `simulated`: no check (rule 8 refuses it in production) | `evidence_not_cloud_bound` |
| 8 | The evidence chains to a pinned vendor root (and, for `simulated`, to the pinned development root). Every certificate in the chain and every RIM signing certificate has OCSP or CRL status "good" | `untrusted_root`; a revoked or not-good status gives `cert_revoked` |

"now" in the app is `max(computer clock, lower(latest accepted
checkpoint))`. The person's computer is trusted; the checkpoint time
only stops a clock that is far behind.

### 3.6 Descriptor set (`anagram.enclave.descriptor.v1`)

A descriptor fixes a value that the app shows or checks and that a
measurement does not make readable.

```
descriptor      = {"body": {...}, "kind": "matching" | "vocabulary" | "model",
                   "schema": "anagram.enclave.descriptor.v1"}
descriptor hash = tagged_hash("anagram/v1/enclave/descriptor", canonical_json(descriptor))
```

`descriptor_hashes` of a release lists the hashes, sorted. The descriptor
set hash is `descriptor_set` of section 3.2 over these hashes; a pack names
it in `consent.descriptor_set` ([pack.md](pack.md) section 3.2). A set has
exactly one `matching`, exactly one `vocabulary` and at most 16 `model`
descriptors. Each body has exactly the fields below.

| Kind | Body fields |
| --- | --- |
| `matching` | `accepted_schemas` (sorted list of the accepted pack and known schemas, [pack.md](pack.md) section 10), `anonymity_min_nodes` (1 to 100), `anonymity_min_people` (2 to 1,000), `answer_day` (1 to 7, default 7: the step in days between the three answer checkpoints of a proposal, so the answer window is `3 × answer_day` days; [enclave-messages.md](enclave-messages.md) section 5.3), `card_option` (`a` or `b`), `consent_statement` (the text that the app shows; [pack.md](pack.md) section 3.2), `network` and `roster_key` (the network ID and the first roster key that the release pins; [network.md](network.md) section 3.1), `weekly_cap_max` (1 to 10: the network maximum of proposals to one person in 7 days; the person may choose a lower value in the charter, [pack.md](pack.md) section 3.3) |
| `vocabulary` | `concepts` (the count), `id` (the `vocab` ID of a pack), `sha256` (of the vocabulary file) |
| `model` | `digest` (`sha256:` of the weights; equal to an entry of the release's `weights`), `name`, `role` (`embed`, `screen`, `judge`) |

The app refuses a release whose descriptor documents do not hash to
`descriptor_hashes` (`bad_attestation`). Vectors: `descriptors`.

### 3.7 Attestation bundle and instance choice

`GET /enclave/attestation` (app → node) and `GET /v1/attestation` (node →
enclave) answer with one canonical JSON document:

```json
{"checkpoint": "<latest cosigned checkpoint note>",
 "descriptors": [<descriptor documents of section 3.6>],
 "documents": [<v3 attestation document of the writer of each authorised line>],
 "schema": "anagram.enclave.attestation_bundle.v1"}
```

At most 64 documents and 1 MiB in total. The node passes it on unchanged;
the app trusts nothing in it that its own checks do not confirm. The app:

1. checks the checkpoint (section 2.4) and reads the new log entries;
2. checks the descriptors (section 3.6);
3. for each document, computes `shard(subject, n)` with the `n` of the
   document's line and keeps the documents whose line serves its subject;
4. seals to the first kept document that passes section 3.4 with its
   subject. If none passes, it sends nothing and tries again in one hour.

**Instance roles.** Only the writer of a line opens requests, keeps state
and signs receipts and slots. A standby becomes the writer only by a
handoff that names it `next_writer` (5.3) or by a failover (5.7).

**Routing**. The operator's front end
sends **every** relay request to the writer of the line, whatever the
`intake` field of its header says. An instance that is not the writer (a
standby, a draining or retired writer) takes no request and signs no
receipt. A request sealed to the intake key of another instance gets
`unknown_instance_key` from the writer (step 2 of
[enclave-messages.md](enclave-messages.md) section 3.3), signed by the
writer and released after its next cosigned epoch like every receipt
(6.3); the app then fetches the bundle again and seals the body again
(enclave-messages.md 8.5). While the line has no writer (for example
between a handoff message and the epoch that names the successor), the
front end answers the node `503`. So one key signs the receipts of a line
at a time, and every receipt follows the one release rule of 6.3. A
standby cannot release an `unavailable` receipt at once: that would need a
second release rule for receipts that no cosigned epoch holds. A front end
that routes a request to another instance only drops it, which the app
sees as no receipt, the same as a node that drops it.

## 4. Verifier profiles

### 4.1 Trusted base per profile

| Profile | Use | Trusted base (besides our code, the witnesses and the rebuilders) |
| --- | --- | --- |
| `simulated` | development and CI | nothing; it protects nothing. A production app refuses it |
| `raw-snp` | later; first choice to drop cloud verifiers | AMD (silicon, PSP firmware, ARK/ASK/VCEK, KDS) |
| `raw-tdx` | later | Intel (silicon, TDX module, QE, PCS collateral) |
| `gcp-cs` | CPU path first; GPU if the platform spike confirms it | Intel (or AMD); Google firmware, the Confidential Space image and launcher, the Google Cloud Attestation verifier and its signing keys; for a GPU, NVIDIA and Google's GPU verification |
| `azure-cvm-gpu` | GPU path | AMD; Microsoft's paravisor (HCL) and vTPM, Microsoft Azure Attestation (MAA); NVIDIA (device root, RIM service, OCSP, and NRAS if used) |

This table is the trusted base of each profile. The privacy page shows it.

### 4.2 `simulated`

Evidence (both signed by the pinned development root):

```json
platform_evidence = {"report": {"debug": false, "migratable": false,
                                "reference": {"gpu": true, "image_digest": "sha256:..."},
                                "report_data": "<hex32>", "tcb": {"svn": 3}},
                     "signature": "<hex64>", "signer": "<hex32 dev root>"}
gpu_evidence      = {"report": {"cc_mode": "ON", "dbgstat": "disabled",
                                "driver_version": "550.90.07", "nonce": "<hex32>",
                                "ocsp": "good", "vbios_version": "96.00.9F.00.01"},
                     "signature": "<hex64>", "signer": "<hex32 dev root>"}
```

- CPU signature: `Ed25519(dev root, tagged_message("anagram/v1/enclave/sign/simulated-evidence", canonical_json(report)))`.
- GPU signature: the same with `anagram/v1/enclave/sign/simulated-gpu`.
- GPU evidence bytes (for `report_data`): `canonical_json(gpu_evidence)`.
- Claims: `reference` → rule 1; `tcb.svn` → `svn`; `driver_version` →
  `gpu_driver`; `vbios_version` → `gpu_vbios` (rule 2); `debug`,
  `migratable`, `dbgstat`, `cc_mode` (rule 3); `ocsp` (rule 8);
  `report_data`, `nonce` (rules 5, 6).

The simulated profile has every field that a real profile checks, so the
eight refusal tests run in CI. Reference code:
`anagram.network.matching.trust.attestation.verify_attestation`.

### 4.3 `raw-snp` (AMD SEV-SNP)

Sources: AMD, *SEV Secure Nested Paging Firmware ABI Specification*
(publication 56860): the `ATTESTATION_REPORT` structure table (Table 23 in
the revision that google/go-sev-guest cites; the table number changes
between revisions), the guest policy structure, and the `TCB_VERSION`
structure; AMD, *Versioned Chip Endorsement Key (VCEK) Certificate and KDS
Interface Specification* (publication 57230). Offsets were checked against
google/go-sev-guest `abi/abi.go` and `kds/kds.go`.

Evidence: `{"ark", "ask", "crl", "leaf", "report"}`, each the standard
base64 of: the ARK DER; the ASK DER (the ASVK for a VLEK); the ARK's CRL
DER, as AMD KDS serves it (`.../<Product>/crl`); the VCEK or VLEK DER;
the 1184-byte report. No other field. `gpu_evidence` is null (refuse:
`bad_attestation`). The instance gets the chain and the CRL from AMD KDS
(or the cloud's cache of it) when it makes the evidence; the app makes
no network call for this profile.

Report layout used (little-endian; size `0x4A0`): `VERSION` 0x00 (u32),
`GUEST_SVN` 0x04, `POLICY` 0x08 (u64), `FAMILY_ID` 0x10 (16), `IMAGE_ID`
0x20 (16), `VMPL` 0x30, `SIGNATURE_ALGO` 0x34 (1 = ECDSA P-384 with
SHA-384), `CURRENT_TCB` 0x38, `PLATFORM_INFO` 0x40, signer bits 0x48
(bit 0 `AUTHOR_KEY_EN`, bit 1 `MASK_CHIP_KEY`, bits 4:2 `SIGNING_KEY`: 0
VCEK, 1 VLEK), `REPORT_DATA` 0x50 (64), `MEASUREMENT` 0x90 (48),
`HOST_DATA` 0xC0 (32), `ID_KEY_DIGEST` 0xE0 (48), `AUTHOR_KEY_DIGEST`
0x110 (48), `REPORT_ID` 0x140, `REPORT_ID_MA` 0x160, `REPORTED_TCB` 0x180,
CPUID family/model/stepping 0x188 to 0x18A (version ≥ 3), `CHIP_ID` 0x1A0
(64), `COMMITTED_TCB` 0x1E0, current build/minor/major 0x1E8 to 0x1EA,
committed build/minor/major 0x1EC to 0x1EE, `LAUNCH_TCB` 0x1F0, launch and
current mitigation vectors 0x1F8 and 0x200 (version ≥ 5), `SIGNATURE`
0x2A0 (R: 72 bytes, S: 72 bytes, little-endian). Reserved ranges must be
zero. Parser: `anagram.network.matching.trust.profiles.snp`.

Guest policy bits: 7:0 ABI minor, 15:8 ABI major, 16 SMT, 17 reserved
(must be 1), 18 `MIGRATE_MA`, 19 `DEBUG`, 20 `SINGLE_SOCKET`, 21
`CXL_ALLOW`, 22 `MEM_AES_256_XTS`, 23 `RAPL_DIS`, 24 `CIPHERTEXT_HIDING`,
25 `PAGE_SWAP_DISABLE`; 63:26 must be 0.

`TCB_VERSION` (8 bytes): Milan and Genoa: byte 0 boot loader, 1 TEE, 6
SNP, 7 microcode. Turin: byte 0 FMC, 1 boot loader, 2 TEE, 3 SNP, 7
microcode.

A certificate, CRL or extension that does not parse (any error of the
parser, such as an unknown version) gives `bad_attestation`, at whatever
step reads it.

Product: from the CPUID fields (version ≥ 3), which must equal the
product that the leaf's product name extension (1.3.6.1.4.1.3704.1.2, an
IA5String such as `Milan-B0`) names; from the leaf alone for a version 2
report. Any other product: `untrusted_root`.

Rules:

- Rule 8, in this order (each failure gives `untrusted_root` unless it
  says otherwise):
  1. `MASK_CHIP_KEY = 0`.
  2. The SHA-256 of `ark` equals the pinned ARK of the product (2.6).
  3. `SIGNING_KEY` is 0 (VCEK; the ASK's CN is `SEV-<Product>`) or 1
     (VLEK; the ASVK's CN is `SEV-VLEK-<Product>`); the ARK's CN is
     `ARK-<Product>`.
  4. ARK (self-signed) → ASK → leaf: each issuer name matches, and each
     signature is RSASSA-PSS with SHA-384, MGF1 SHA-384 and salt 48. The
     inner and outer AlgorithmIdentifier are exactly the DER of those
     parameters, with or without an explicit `trailerField` 1 (AMD's
     certificates carry it, its CRLs do not), and the signature BIT
     STRING has no unused bits. The outer copy is not signed; these rules
     stop its bytes from changing without a refusal.
  5. The leaf key is ECDSA P-384, and its product name is the product.
  6. The leaf SPL extensions (1.3.6.1.4.1.3704.1.3.1 boot loader, .3.2
     TEE, .3.3 SNP, .3.8 microcode, each a DER INTEGER 0 to 255) equal
     `REPORTED_TCB`. For Turin the FMC extension is not confirmed
     (section 10), so a Turin leaf is refused until it is: without it, a
     leaf for a lower FMC could sign a report that claims a higher one.
  7. A VCEK has a 64-byte `hwID` extension (1.3.6.1.4.1.3704.1.4) equal
     to `CHIP_ID`. A VLEK has a `csp_id` extension
     (1.3.6.1.4.1.3704.1.5, a string) that names the cloud provider.
  8. The CRL is issued by the ARK (name and RSASSA-PSS signature as in
     4) and has a next update; neither the ASK nor the leaf serial is on
     it (else `cert_revoked`). Rule 4 checks its next update.
  9. The report signature: ECDSA P-384 with SHA-384 by the leaf key over
     bytes 0x000 to 0x29F; R and S are little-endian, and their bytes
     48 to 71 are zero.
- Rule 3: `POLICY.DEBUG = 0`; `POLICY.MIGRATE_MA = 0`. (`VMPL` is in the
  reference object, so rule 1 fixes it: 0 for a guest with no SVSM.) Then `POLICY.SMT = 0`
  (else `smt_allowed`), `POLICY.CIPHERTEXT_HIDING = 1` (else
  `ciphertext_hiding_off`) and `POLICY.PAGE_SWAP_DISABLE = 1` (else
  `page_swap_allowed`). The firmware launches a guest only on a platform
  that meets its policy, so the report shows that SMT is off, that
  ciphertext hiding is on and that the host can not swap the guest's
  pages. Only firmware with ciphertext hiding can launch such a guest
  **(to confirm: Turin and later parts, and the firmware version)**.
- Rule 9: `SIGNING_KEY = 1` (a VLEK, which AMD issues to one cloud) and
  its `csp_id` is in the release's `csp_ids`. A VCEK names one chip, and a
  machine that the operator owns can have one: physical attacks on the
  memory bus forge evidence on such machines (TEE.fail, 2025).
- Rule 2: each `REPORTED_TCB` component ≥ the floor of the product;
  `SIGNATURE_ALGO = 1`; `VERSION ≥` the floor `report_version`.
- Rule 5: `REPORT_DATA = report_data || 32 zero bytes`.
- Claims (`trust/profiles/snp.py`): `debug`, `migratable`
  (`MIGRATE_MA`), the whole decoded `policy`, `signing_key` (`vcek` or
  `vlek`), `csp_id` (VLEK) or null, the reference object, `report_data`,
  `valid_until` (the CRL's next update), and the TCB under the floor names
  of section 4.8.
- Reference object: `{"family_id", "host_data", "image_id",
  "measurement", "product", "vmpl"}` (hex values; `product` is `milan`,
  `genoa` or `turin` from the CPUID fields). `MEASUREMENT` is the launch
  digest of the firmware, kernel, initrd and command line (a UKI with a
  dm-verity root hash of the image) **(to confirm: launch digest tool and inputs)**.

### 4.4 `raw-tdx` (Intel TDX)

Sources: Intel, *Intel TDX DCAP Quoting Library API* (the "Quote Format"
appendix, quote version 4: header, TD quote body, signature data); Intel,
*Intel TDX Module ABI Specification* (TD attributes); Intel, *Intel SGX
PCK Certificate and Certificate Revocation List Profile Specification*
(the chain, the SGX extensions, the CRLs); Intel, *Intel SGX and TDX PCS
API* version 4 (`/tdx/certification/v4/tcb`, `/tdx/certification/v4/qe/
identity`, `/sgx/certification/v4/pckcrl`) and the TCB Info (TDX, version
3) and Enclave Identity (TD QE, version 2) formats. Offsets and the TCB
level rules were checked against google/go-tdx-guest `abi/abi.go` and
`verify/verify.go`.

Evidence: `{"quote", "tcb_info", "qe_identity", "tcb_signing", "root_crl",
"pck_crl"}`, each base64 of: the quote, exactly its declared length (the
guest removes the padding of its buffer); the TCB Info and the QE Identity
responses, byte for byte as Intel PCS serves them; the DER of the Intel
SGX TCB Signing certificate (the first certificate of PCS's issuer chain
header); the DER CRL of the Intel SGX Root CA; the DER CRL of the PCK CA
that issued the PCK certificate. Any other field, a GPU evidence, or a
part that does not parse is `bad_attestation`.

Quote layout used (little-endian): header 48 bytes (version 4,
attestation key type 2 = ECDSA-256 with P-256, TEE type `0x00000081`, 4
reserved bytes, QE vendor ID 16, user data 20); TD quote body 584 bytes:
`TEE_TCB_SVN` 16, `MRSEAM` 48, `MRSIGNERSEAM` 48, `SEAMATTRIBUTES` 8,
`TDATTRIBUTES` 8, `XFAM` 8, `MRTD` 48, `MRCONFIGID` 48, `MROWNER` 48,
`MROWNERCONFIG` 48, `RTMR0..3` 48 each, `REPORTDATA` 64; then a u32
signature data length, the ECDSA signature (64, r || s), the attestation
key (64, x || y) and the certification data (type u16, size u32, data).
No byte may follow. The certification data must be type 6: the QE report
(384), its signature (64), the QE authentication data (u16 size, data),
then certification data type 5: the PCK chain as PEM (leaf, CA, root),
with at most one NUL after it. Quote version 5 (TD 1.5 body) is not
parsed here **(to confirm: which version the spike platform gives)**.
Parser: `anagram.network.matching.trust.profiles.tdx`; chain and
collateral: `...profiles.intel`.

TD attribute bits: 0 `DEBUG`, 28 `SEPT_VE_DISABLE`, 29 `MIGRATABLE`, 30
`PKS`, 31 `KL`, 63 `PERFMON`.

Rule 8, in this order (signatures are ECDSA P-256 with SHA-256; the
certificates' and CRLs' outer and inner algorithm identifiers must be
exactly `ecdsa-with-SHA256` with no parameters, and their signature BIT
STRING has no unused bits):

1. The quote and its certification data parse as above, and the QE
   vendor ID is Intel's (`939a7233f79c4ca9940a0db3957f0607`): else
   `bad_attestation`.
2. The PCK chain has exactly 3 certificates, and the SHA-256 of the third
   is the pinned Intel SGX Root CA (2.6): else `untrusted_root`.
3. Names and signatures (`untrusted_root`): the root is
   `Intel SGX Root CA` and signs itself; the CA is `Intel SGX PCK Platform
   CA` or `Intel SGX PCK Processor CA`, signed by the root; the leaf is
   `Intel SGX PCK Certificate`, signed by the CA, with a P-256 key; the
   `tcb_signing` certificate is `Intel SGX TCB Signing`, signed by the
   root, with a P-256 key.
4. The leaf's SGX extensions (OID `1.2.840.113741.1.13.1`) are strict DER
   with each OID once: PPID, TCB (the 16 component SVNs, PCESVN, and a
   CPUSVN equal to the 16 SVNs), PCE-ID, FMSPC and SGX type (0 Standard,
   1 Scalable, 2 ScalableWithIntegrity); else
   `untrusted_root`.
5. The root CRL is the root's (issuer and signature), and lists neither
   the CA nor the TCB signing certificate; the PCK CRL is the CA's, and
   does not list the leaf. A listed certificate is `cert_revoked`; a CRL
   with no next update is `bad_attestation`.
6. The leaf key signs the QE report: else `untrusted_root`.
7. The QE Identity is signed by the TCB signing key over the exact bytes
   of its `enclaveIdentity` body (`untrusted_root`); its body is JSON
   with no duplicate names, `id = "TD_QE"`, `version = 2`
   (`bad_attestation`); the QE report's `MRSIGNER` and `ISVPRODID` equal
   it, and its `MISCSELECT` and `ATTRIBUTES` equal it under its masks
   (else `untrusted_root`: not Intel's quoting enclave). The QE TCB status
   is that of the first level whose `isvsvn` ≤ the report's `ISVSVN`.
8. The QE report's `REPORTDATA` is `SHA-256(attestation key || QE
   authentication data) || 32 zero bytes`: else `untrusted_root`.
9. The attestation key signs the header and the body: else
   `untrusted_root`.
10. The TCB Info is signed like the QE Identity, with `id = "TDX"`,
    `version = 3`, `tcbType = 0` (`bad_attestation`); its `fmspc` and
    `pceId` are the leaf's (else `untrusted_root`); `MRSIGNERSEAM` equals
    `tdxModule.mrsigner` and `SEAMATTRIBUTES` equals its `attributes`
    under `attributesMask` (else `untrusted_root`: not Intel's TDX module).
    The TCB status is that of the first level where each of the leaf's 16
    SVNs ≥ the level's `sgxtcbcomponents`, the leaf's PCESVN ≥ `pcesvn`,
    and each `TEE_TCB_SVN` byte ≥ the level's `tdxtcbcomponents` (bytes 0
    and 1 are not compared when `TEE_TCB_SVN[1] > 0`). When
    `TEE_TCB_SVN[1] > 0`, the TDX module identity `TDX_<TEE_TCB_SVN[1] as
    2 hex digits>` (compared without case) must match `MRSIGNERSEAM` and `SEAMATTRIBUTES` the
    same way (else `untrusted_root`), and the module TCB status is that of
    its first level whose `isvsvn` ≤ `TEE_TCB_SVN[0]`; otherwise it is
    `UpToDate`. A module identity that is missing or listed twice, or
    has no such level, gives the module status `Unsupported`. A status that is not one of Intel's names
    (`UpToDate`, `SWHardeningNeeded`, `ConfigurationNeeded`,
    `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
    `OutOfDateConfigurationNeeded`, `Revoked`) is `bad_attestation`. No
    matching level gives the status `Unsupported`.

The collateral's `valid_until` (rule 4) is the earliest of: the TCB Info
and QE Identity `nextUpdate`, the two CRLs' next update, and the expiry of
the 4 certificates.

Claims for the other rules:

- Rule 3: `debug` (`TDATTRIBUTES.DEBUG`), `migratable`
  (`TDATTRIBUTES.MIGRATABLE`); all the decoded attribute bits are in
  `td_attributes`. `SEPT_VE_DISABLE = 1` is checked by a later change
  **(to confirm: the guest boots with it)**.
- Rule 9: a production app refuses `raw-tdx` (`evidence_not_cloud_bound`):
  a TDX quote names a chip, not a cloud. The profile stays for
  development and for the differential tests.
- Rule 2: `tcb_status`, `tdx_module_tcb_status`, `qe_tcb_status`, and
  `tcb_evaluation_data_number` (the lower of the TCB Info's and the QE
  Identity's). The floor must name all 4 (4.8). The advisory IDs of the
  matched levels are claimed as `advisory_ids` for a later advisory rule.
- Rule 5: `REPORTDATA = report_data || 32 zero bytes`.
- Reference object: `{"mr_config_id", "mr_owner", "mr_owner_config",
  "mr_td", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "xfam"}`. `RTMR3` is zero
  unless the release says what the image extends into it **(to confirm: RTMR
  values of the UKI boot)**.

### 4.5 `gcp-cs` (Google Confidential Space)

Sources: Google Cloud, *Confidential Space token claims* (sections
"Top-level claims", "Submods claims", "Workload container claims", "Intel
TDX claims", "NVIDIA GPU claims"); *Access resources not managed by Google
Cloud IAM* (the PKI token and its validation); *Attestation token
validation endpoint fields* (`root_ca_uri`). Read 2026-11-27. Parser:
`anagram.network.matching.trust.profiles.gcp`.

Evidence: `{"token": <Confidential Space attestation token, PKI type>}`;
any other field, or a GPU evidence, is `bad_attestation`. The instance
asks the launcher for a custom token (`token_type = PKI`) with audience
`anagram/v1/enclave` and one nonce: the 64-character lowercase hex of
`report_data` (inside Google's nonce length limits).

Rule 8, in this order:

1. The token is at most 64 KiB of ASCII, a compact JWS of 3 base64url
   parts (no padding); header and payload are JSON objects with no
   duplicate names (else `bad_attestation`). The header has only `alg`,
   `kid`, `typ` and `x5c`; `alg = RS256`; `typ`, if present, is `JWT`
   (else `bad_attestation`).
2. `x5c` is exactly 3 base64 certificates: leaf, intermediate, root (else
   `untrusted_root`); the SHA-256 of the root's DER is the pinned root
   (2.6) (else `untrusted_root`).
3. The root is `Confidential Space Root CA` and signs itself; the root
   signs the intermediate; the intermediate signs the leaf. Each is
   sha256WithRSAEncryption with the exact algorithm identifier (with NULL
   parameters) inside and outside the signed part, no unused bits in the
   signature, an issuer name equal to its signer's subject, and RSA keys
   of at least 2048 bits (else `untrusted_root`).
4. The leaf key signs `header.payload` (RS256): else `untrusted_root`.
5. `iss = https://confidentialcomputing.googleapis.com` (else
   `untrusted_root`); `aud` is the string `anagram/v1/enclave`; `exp`,
   `iat`, `nbf` are integers with `nbf ≤ iat < exp` (else
   `bad_attestation`).

A claim that the rules read with the wrong type, or that is absent, is
`bad_attestation`.

Claims and the other rules:

- Rule 4: `valid_from` is the latest of `nbf` and the certificates'
  not-before; `valid_until` the earliest of `exp` and their expiry
  (3.5). The instance fetches a new token each hour.
- Rule 3: `debug` is `dbgstat ≠ disabled-since-boot`; `migratable` is
  false (Confidential Space VMs do not live-migrate). Then `secboot` is
  true (else `secure_boot_off`); `support_attributes` has `STABLE` (else
  `image_not_stable`: a debug image has none, and an image that Google no
  longer supports loses it); `cmd_override` and `env_override` are empty
  (else `launch_override`). With a GPU: `cc_mode = ON` and `dbgstat = disabled` (the GPU
  `dbgstat` is `enabled` when `cc_mode = DEVTOOLS`); `cc_feature` is
  claimed.
- Rule 9: `submods.gce.project_number` is in the release's
  `project_numbers` and `submods.gce.zone` is in its `zones` (claimed as
  `cloud`; a token without `submods.gce` names no place). The project
  number never changes and is never reused.
- Rule 2: `swversion` (the one value of `swversion`, decimal digits);
  from the one object of `tdx` (absent unless `hwmodel = GCP_INTEL_TDX`):
  `tcb_evaluation_data_number` and `tcb_status`
  (`gcp_attester_tcb_status`). The floor must name all 3 (4.8), so a token
  without TDX claims never passes. With a GPU: the lowest
  `driver_version` and `vbios_version` of `submods.nvidia_gpu.gpus` meet
  `gpu_driver` and `gpu_vbios`; the GPU models are claimed as `hwmodels`.
- Rule 5: `eat_nonce` (a string, or an array of exactly one string) =
  hex of `report_data`.
- Rule 6 (GPU): Google verifies the GPUs and puts their claims in the
  same token, so the token binds them; Google is then in the trusted base
  for the GPU. The GPU claims carry `bound_by_cpu_evidence`, there is no
  `gpu_evidence`, and `report_data` is the plain form (3.5) **(to confirm:
  the spike decides if this replaces `azure-cvm-gpu`)**.
- Reference object (rule 1): `{"args", "env", "gpu", "hwmodel",
  "image_digest", "restart_policy", "swname"}` from
  `submods.container.args`, `submods.container.env` (an empty object if
  absent), whether the token has GPU claims, `hwmodel`,
  `submods.container.image_digest`, `submods.container.restart_policy`
  and `swname`. So the release's measurement fixes `hwmodel =
  GCP_INTEL_TDX` (`GCP_AMD_SEV` and `GCP_AMD_SEV_ES` give no memory
  integrity), `swname = CONFIDENTIAL_SPACE` and `restart_policy = Never`.
  The image sets the launch policy labels that refuse command and
  environment overrides **(to confirm: label names)**.

### 4.6 `azure-cvm-gpu` (Azure confidential VM with an H100)

**Parked (section 20):** this profile stays a refused stub.

Sources: Microsoft, *Azure Attestation claim sets* (section "Outgoing
claims", "SEV-SNP attestation"); Microsoft, Azure confidential VM guest
attestation documentation **(to confirm: the exact page and the vTPM report
format)**; NVIDIA, *Attestation Claims Guide: GPU Claims* (claims version
3.0 and 4.0).

Evidence: `{"maa_token": <JWT>, "tpm_quote": <base64 TPMS_ATTEST>,
"tpm_signature": <base64>, "pcrs": {"<index>": "<hex SHA-256>"},
"event_log": <base64>}` and `gpu_evidence` (section 4.7).

The paravisor (HCL) runs at VMPL0 and gets the SNP report. Its
`REPORT_DATA` is the hash of the HCL runtime data, which holds the vTPM
attestation key (AK) public key **(to confirm)**. MAA verifies the SNP report and
the HCL data and signs a token.

- Rule 8: the MAA token chains to the pinned MAA signing certificate
  (the `x5c` of the token, or the instance's `/certs` keys pinned by
  thumbprint) **(to confirm)**; the TPM quote is signed by the AK named in the
  token's `x-ms-runtime` claims **(to confirm: claim path)**.
- Rule 3: `x-ms-isolation-tee.x-ms-attestation-type = sevsnpvm`
  (the outer `x-ms-attestation-type` is `azurevm`) **(to confirm: nesting)**;
  `x-ms-sevsnpvm-is-debuggable = false`;
  `x-ms-sevsnpvm-migration-allowed = false`; `x-ms-sevsnpvm-vmpl = 0`;
  `x-ms-compliance-status = azure-compliant-cvm` **(to confirm: claim present on
  the GPU size)**.
- Rule 2: `x-ms-sevsnpvm-bootloader-svn`, `-tee-svn`, `-snpfw-svn`,
  `-microcode-svn` ≥ the floor; `x-ms-sevsnpvm-launchmeasurement` (the HCL
  image, which Microsoft controls) is in the floor's `hcl_measurements`
  list; `x-ms-sevsnpvm-guestsvn` ≥ the floor; GPU floor as 4.7.
- Rule 5: the TPM quote's `extraData` (qualifying data) = `report_data`.
- Rule 1: PCR values in the quote equal the reference after replay of the
  event log. Reference object: `{"gpu": true, "pcrs_sha256": {"4", "7",
  "8", "9", "11"}}` (boot manager and UKI, Secure Boot state, command line,
  initrd, UKI sections) **(to confirm: the PCR set of the UKI boot on Azure)**.

The paravisor, the vTPM and MAA are in the trusted base.

### 4.7 NVIDIA GPU evidence (rule 6 and rule 8)

The instance gives the GPU the 32-byte `gpu_nonce` (the SPDM
`GET_MEASUREMENTS` nonce size) and gets the attestation report and
certificate chain. Two forms; the release says which one with the
reference field `gpu_verifier`:

- `nras` (v1 default): the instance sends the evidence to the NVIDIA Remote
  Attestation Service and staples the signed EAT to `gpu_evidence`
  `{"nras_token": <JWT>, "gpu_report": <base64>, "cert_chain": <base64>}`.
  The app checks the token against the pinned NRAS signing key
  **(to confirm: JWKS pinning)** and needs (claims version 3.0 or 4.0):
  `x-nvidia-overall-att-result = true`; `measres = success`;
  `x-nvidia-gpu-attestation-report-nonce-match = true`;
  `x-nvidia-gpu-attestation-report-signature-verified = true`;
  `x-nvidia-gpu-driver-rim-signature-verified = true`;
  `x-nvidia-gpu-vbios-rim-signature-verified = true`; in each of
  `x-nvidia-gpu-attestation-report-cert-chain`,
  `x-nvidia-gpu-driver-rim-cert-chain` and
  `x-nvidia-gpu-vbios-rim-cert-chain`: `x-nvidia-cert-status = valid` and
  `x-nvidia-cert-ocsp-status = good` (else `cert_revoked`); `secboot =
  true`; `dbgstat = disabled` (else `policy_refused`);
  `x-nvidia-gpu-driver-version` ≥ `gpu_driver` and
  `x-nvidia-gpu-vbios-version` ≥ `gpu_vbios` (else `tcb_below_floor`);
  `eat_nonce` = hex of `gpu_nonce` (else `gpu_binding_mismatch`). The
  GPU evidence bytes for `report_data` are the bytes of `gpu_report`.
  NVIDIA's service is then in the trusted base.
- `local` (later): the app checks the report signature, the device chain to
  the pinned NVIDIA device identity root, the driver and VBIOS RIMs (SWID
  tags) signed by the RIM chain, and stapled OCSP responses for every
  certificate, with the OCSP nonce set to `gpu_nonce` **(to confirm: OCSP nonce
  support and response lifetime)**.

Confidential-computing mode: the report must show CC mode on **(to confirm: the
field in the Hopper report; NRAS claims do not name it)**.

### 4.8 TCB floor format

`tcb_floor` is an object of named items. An integer is a minimum. A list is
the set of allowed values. A dotted string is a minimum version: decimal
parts for `gpu_driver`, hexadecimal parts for `gpu_vbios`.

| Profile | Items |
| --- | --- |
| `simulated` | `svn`, `gpu_driver`, `gpu_vbios` |
| `raw-snp` | `report_version`, and per product, named `<product>_<component>` (`milan_snp`, `genoa_microcode`, ...): `boot_loader`, `tee`, `snp`, `microcode` (and `fmc` for Turin). The floor must name `report_version` and every component of the evidence's product (else `tcb_below_floor`); the items of other products do not apply |
| `raw-tdx` | `tcb_evaluation_data_number`, `tcb_status` (list), `tdx_module_tcb_status` (list), `qe_tcb_status` (list). The floor must name all 4 (else `tcb_below_floor`) |
| `gcp-cs` | `swversion`, `tcb_evaluation_data_number`, `tcb_status` (list), `gpu_driver`, `gpu_vbios`. The floor must name the first 3 (else `tcb_below_floor`) |
| `azure-cvm-gpu` | `bootloader_svn`, `tee_svn`, `snpfw_svn`, `microcode_svn`, `guest_svn`, `hcl_measurements` (list), `gpu_driver`, `gpu_vbios` |

A status claim (an item whose name ends in `_status`) of `Revoked` or
`Unsupported` (no TCB level of the collateral matches) is
`tcb_below_floor` whatever the floor lists.

The values come from the vendors' current advisories at release time.
The platform spike records the values of the spike platforms.

### 4.9 What each profile enforces, and what it can not

Rule 9 and the bits of rule 3, per profile. A bit that the evidence can
not show is a named risk, not a check. Vectors:
`vectors/enclave-policy.json` (claims, release pins, production or not,
expected code).

| Profile | Cloud (rule 9) | SMT off | Ciphertext hiding | Page swap off | Other bits (rule 3) |
| --- | --- | --- | --- | --- | --- |
| `simulated` | none (refused in production by rule 8) | no | no | no | debug, migration |
| `raw-snp` | VLEK `csp_id` in `csp_ids` | `smt_allowed` | `ciphertext_hiding_off` | `page_swap_allowed` | debug, migration (VMPL is fixed by rule 1) |
| `raw-tdx` | refused in production | not shown: risk | not shown: risk | not applicable (TDX has no host swap of private pages) | debug, migration |
| `gcp-cs` | project and zone pinned | not shown: risk | not shown: risk | not shown: risk | debug, migration, `secure_boot_off`, `image_not_stable`, `launch_override`, GPU mode |
| `azure-cvm-gpu` | refused (parked, section 20) | not shown | not shown | not shown | (none: parked) |

What these bits do and do not give:

- **SMT off** stops a sibling thread on the same core from reading the
  guest's timing through shared core state.
- **Ciphertext hiding** stops the host from reading the ciphertext of the
  guest's memory, so it can not see which values repeat. It is a defence
  against software side channels from the host, not against physical
  attacks on the memory bus.
- **Page swap off** stops the host from moving the guest's encrypted
  pages out and back.
- **Residual risks of every profile:** physical access to the machine at
  the cloud (memory-bus interposers); a compromise of the vendor's root
  keys; page-fault and cache side channels that these bits do not close.
  On `gcp-cs`, Google's firmware, launcher and attestation service are in
  the trusted base (section 4.1), and the token does not show SMT,
  ciphertext hiding or page swap.

## 5. Key custody

### 5.1 Keys

All keys come from the CSPRNG of the guest kernel inside the TEE.

| Key | Made | Lives | Leaves the TEE |
| --- | --- | --- | --- |
| Output key (Ed25519) | at the start of each instance | the instance | never (its public key is logged) |
| Intake key (X25519, HPKE) | per instance and key epoch (30 days); the next epoch's key 7 days before the switch | epoch + 7 days overlap, then erased | never (its public key is logged) |
| State key (32 bytes, ChaCha20-Poly1305) | at the first start of a line | the line; rotated on a `rekey` | only by handoff (5.3), sealed to an attested successor |

**No KMS.** No key management service holds or releases any key.
**No hardware-derived sealing keys.** The enclave does not use
`MSG_KEY_REQ` (SEV-SNP) or TDX key derivation for state: such a key is the
same for every VM with the same measurement on the same chip, so a clone
of the image could open the snapshots. The state key exists only in the
memory of live instances of the line.

### 5.2 What a clone can and cannot do

A clone is a VM that runs the logged image, which anyone can start. It
makes its own keys. Its intake key is not logged by a live line unless it
logs an `enclave_instance_key` entry; if it does, the entry is public,
it is not a holder, so apps do not seal to it and it does not count
against `max_instances` (rule 7 (e), (f); section 5.4), and it has no
state key because no live instance hands one to it without the checks of
section 5.3. It cannot load a snapshot (no key; section 6.2). The operator +
Sybil + clone attacker tests this.

### 5.3 Handoff

A new instance (restart, upgrade, second instance) gets the state key only
from a live instance of the same line:

1. The new instance logs its `enclave_instance_key` entry (section 5.4)
   and sends an `anagram.enclave.handoff_request.v1` `{attestation: <v3
   document>, line_id, schema}` to the live writer (through the operator's
   network; the content is public).
2. The live instance checks, in order: the successor's release passes
   section 2.5 (with the live instance's own signed time); the successor's
   release is the same release or names the live release in
   `successor_of` (else `handoff_not_successor`; so there is no downgrade
   without its own release entry and notice); the document passes section
   3.4 with rules 1 to 6 and 8, and rule 7 (a) to (d) (the successor is not
   yet the writer or a holder); the holders with the successor are at most
   `max_instances`; the successor's `key_epoch` is the current epoch.
3. The live instance sends the signed message `anagram.enclave.handoff.v1`:

   ```json
   {"ciphertext": "<base64 HPKE output>", "counter": 41, "line_id": "<hex16>",
    "schema": "anagram.enclave.handoff.v1", "signature": "<hex64>",
    "signer": "<hex32 output key of the live instance>",
    "snapshot_digest": "<hex32>", "successor": "<hex32 attestation digest of the successor>"}
   ```

   `ciphertext = HPKE.Seal(successor intake key, canonical_json({"counter",
   "line_id", "snapshot_digest", "state_key": hex}), info)` with the suite
   of [enclave-messages.md](enclave-messages.md) section 2 and `info =
   tagged_message("anagram/v1/enclave/hpke/handoff", successor)`.
   `signature = Ed25519(output key, tagged_message("anagram/v1/enclave/sign/handoff",
   canonical_json(message without "signature")))`. HPKE base mode does not
   say who sealed; the signature does.
4. The successor checks, in order: `signer` is the output key (from
   `enclave_instance_key`) of a holder in the latest state epoch of the
   line, and the signature verifies (else `handoff_bad_sender`); `counter`
   and `snapshot_digest` equal that epoch (else `snapshot_unknown`);
   `successor` is the digest of its own document and the ciphertext opens
   to the same `line_id`, `counter` and `snapshot_digest` (else
   `handoff_bad_ciphertext`).
5. The writer then writes a state epoch whose `holders` adds the
   successor. If it hands the line over (upgrade), the epoch has
   `next_writer` = the successor, and the writer stops writing and opening
   requests. If it adds a standby, `next_writer` is null and the writer
   goes on; the standby can take over by failover (5.7).
6. At an upgrade, the successor loads the state epoch of step 5: the one
   that names it `next_writer`. Its counter is one more than the counter
   of the handoff message, and its snapshot is the state at the handoff,
   sealed again by the writer (section 6.2, rule 3). The successor
   does not load the epoch that the handoff message names: that epoch is
   no longer the latest one when the successor may write.

Handoff refusals are counted in the audit counts ([matching.md](matching.md)
section 7) with their code. Nothing else about them leaves the instance.

Reference checks: step 2 (successor rule) `verifier.check_successor`;
step 4 `handoff.accept`. Vectors: `handoff_cases`, `handoff_messages`.

### 5.4 Intake keys, epochs and leases

Each instance logs one `enclave_instance_key` entry per key epoch, and a
new entry with the same keys and a later `lease_until` every 12 hours.
`lease_until` is at most 24 hours after the entry's log time
(`logged_by`); rule 7 (a) refuses a longer lease, and the log and the two
Anagram witnesses refuse an entry whose `lease_until` is more than 24 hours
after their own time (2.4). Apps seal only to an instance whose latest
lease is unexpired.

**Evidence before logging**. The instance sends its
attestation document with each `enclave_instance_key` entry. The log
accepts the entry only if `evidence_digest` is the SHA-256 of
`canonical_json(platform_evidence)` of the document and the document
passes section 3.4 rules 1 to 6 and 8. The log serves the document at
`GET /log/evidence/{evidence_digest}`, and the two Anagram witnesses check
it again before they cosign (section 2.4). So only a TEE that runs the
logged image can log an instance key.

**Holders, not keys, count.** An attested clone can still log a key. It is
not a holder (no live holder hands it the state key without the checks of
5.3), so it is not in the latest state epoch, apps do not seal to it (rule
7 (e)) and it does not count against `max_instances` (rule 7 (f)). A clone
cannot fill the instance limit. `max_instances` should be at least 2, so
one instance can restart while another keeps the state key.

### 5.5 Lines and writers

A line's state epochs, in log order, must satisfy:

1. the first has `counter = 0` and `prev = null`; each next one has
   `counter` + 1 and `prev` = digest of the one before;
2. `signer` is the output key of an `enclave_instance_key` entry with the
   same `instance_id` and `line_id`;
3. the writer of the first entry is its `instance_id`; after an entry with
   `next_writer = X`, only X writes; after a failover that holds (5.7) and
   names X, only X writes; else the same instance writes;
4. `holders` lists the writer of the entry and its `next_writer` (if any).

A line that breaks a rule is **forked**: apps refuse its instances
(`line_forked`), instances refuse to hand its key, and the witnesses that
read entries refuse the checkpoint that adds the break. Reference checks:
`verifier.line_forked` and `verifier.line_writer` (the instance that may
write next).

### 5.6 Authorised lines, shards and total loss

A line exists for apps only with an `enclave_line` entry.
The release key signs it and an independent quorum cosigns it. A witness
cosigns only after it checks the reason rules below. The app checks the
same rules (rule 7 (b)):

- `first` or `shard`: `replaces` is null. The line serves the subjects with
  `shard(subject, n) = k`, where
  `shard(subject, n) = u32(tagged_hash("anagram/v1/enclave/shard", subject key)[0:4]) mod n`.
  A change of `n` needs a new release.
- **v1 has one shard**. An `enclave_line` entry with
  `n` other than 1 is not authorised in v1 (rule 7 (b),
  `line_not_authorised`), and a witness does not cosign it. The format
  keeps `n` up to 64 for a later sharding design, which must first define
  matching across shards; until then every pair is decided in one line.
- `total_loss`: `replaces` names a line that has its own `enclave_line`
  entry with an independent quorum of `enclave_entry_cosign` entries, the
  same `shard`, and a `logged_by` before the new entry's (the check
  reads the replaced line's own entry and cosigns; it does not use "is
  authorised", which the new entry changes);
  no instance of that line had an unexpired lease at `logged_by` of the new
  entry (so every instance had stopped); and no other authorised
  `total_loss` line for the same shard was logged in the 30 days before.
  The replaced line is then not authorised.
- A `line_id` logged twice is not authorised.

The writer refuses a request whose subject is not in its shard (receipt
code `wrong_shard`, [enclave-messages.md](enclave-messages.md) section
10). So each new line starts with no subjects other than its shard, and
the operator cannot open fresh lines (with no tombstones, caps or history)
to probe the same people again: a new line needs the independent quorum,
and a total-loss line is rate limited and shows a notice (section 7.5).

**Total loss.** If every instance of a line stops, the state key is gone:
the state is lost, not leaked. A total-loss line starts with a new state
key. Apps upload their packs each day ([pack.md](pack.md)), so packs return
within 24 hours. Open proposals and yes answers are gone. No `ended` item
comes; each app treats each open proposal as ended at the expiry of its own
copy, with the same text as an expiry or a "no". Vectors:
`line_cases`, and the line cases in `attestation_cases`. A line with a live
holder does not need a total loss: it uses a failover (5.7).

### 5.7 Writer failover

If the writer stops while another holder of the line is live, the line
keeps its state key and its state. The holder may become the writer
only by an `enclave_writer` entry. The entry is valid ("holds") only if all
of these are true:

1. the release key signed it;
2. both independent witnesses logged an `enclave_entry_cosign` on its
   digest after it (the independent quorum, as for a new line). The entry
   takes effect at the log position of the later of the two;
3. at that position, its `counter` and `epoch` are the counter and the
   digest of the line's latest state epoch (the latest cosigned state);
4. `writer` is in the `holders` of that epoch and is not the current
   writer;
5. every `enclave_instance_key` entry of the current writer for this line
   that is in the log before that position has `lease_until` at or before
   the `time` of each of the two cosignatures. So the writer's lease
   ended: apps already refuse to seal to it.

A witness cosigns an `enclave_writer` entry only after it checks rules 3
to 5 at its own time. An entry that does not hold changes nothing: the old
writer stays the writer, and an epoch by the named holder is then a fork
of section 5.5. So a failover never makes a second chain. If the old
writer writes the next epoch before the entry takes effect, rule 3 fails
and the entry does nothing.

After an entry that holds:

- the new writer loads the latest state epoch (the one that the entry
  names) by the rules of section 6.2, with no handoff message. It holds the
  state key from an earlier handoff (5.3, a standby);
- its first epoch has `prev` = the digest of that epoch, `next_writer` =
  null, and `holders` without the old writer;
- the old writer, if it runs again, sees the entry, erases its state key
  and opens nothing. An epoch that it writes is a fork.

What survives: everything in the latest cosigned epoch. Every receipt and
every day batch that a node got was released only after a cosigned epoch
held it (6.3), so the new writer has each of them, and serves the same
bytes. A request that only the old writer's memory held got no receipt;
the app sends it again (enclave-messages.md 8.5), and the new writer
answers `unknown_instance_key` for the old intake key, so the app fetches
the bundle again and seals to the new writer. A reveal is in both queues
or in neither (6.3). The line is without a writer from the stop until the
failover: at most the 24 hours of the last lease plus the time to cosign.
Days with no writer get no batch; queued items wait for the next one.

Reference: `verifier.line_writer`; the `simulated` log
(`DevTrust.fail_over`) and the instance (`EnclaveInstance`). Vectors:
`writer_cases`.

## 6. Anti-rollback and time

### 6.1 Sealed snapshot (`anagram.enclave.snapshot.v1`)

The writer keeps working state in memory. It writes whole snapshots, never
records:

```
header   = {"counter", "line_id", "schema": "anagram.enclave.snapshot.v1", "size"}
plain    = u32(len(body)) || body || zero padding to `size` bytes
sealed   = lp(canonical_json(header)) || nonce (12) ||
           ChaCha20-Poly1305(state key, nonce, plain, aad = canonical_json(header))
digest   = SHA-256(sealed)
```

`size` is one of a fixed list of buckets in the release (powers of two
from 64 MiB) **(to confirm: bucket list from the sharding sizes)**. `body` is the
canonical JSON of the state, defined with the service. The vector
uses a 4,096-byte bucket.

### 6.2 Load only at the cosigned counter

The writer writes `enclave_state_epoch` (with the new snapshot's digest
and size) after each snapshot, every 10 minutes (section 6.3). A snapshot
loads only if:

1. the line is not forked (else `line_forked`);
2. `header.counter` equals the `counter` of the line's latest state epoch
   in a checkpoint with a quorum and `lower(cp)` within 1 hour of signed
   now (an older counter: `snapshot_stale`);
3. `digest` equals that entry's `snapshot_digest` (else
   `snapshot_unknown`). At an upgrade (5.3 step 6) also: that latest epoch
   names the loading instance `next_writer`; its `counter` is the `counter`
   of the handoff message plus 1; and the line's epoch at the message's
   `counter` has the message's `snapshot_digest` (else
   `snapshot_unknown`). At a restart or a failover (5.7) there is no
   handoff message, and only the first part applies.

So a restore of an older snapshot, or of a snapshot of another line,
undoes nothing. A snapshot that fails is counted, not loaded.
Reference: `snapshot.check_load`; vectors: `snapshot.cases`.

### 6.3 Commit before output, and tombstones

**Fixed epochs.** The writer writes a snapshot and its state epoch at each
10-minute boundary of its signed time (00:00, 00:10, ...), whatever
changed. The time of an epoch shows nothing about a request.

**Commit before receipt**. The writer releases **every**
receipt, accepted or rejected, only after a cosigned checkpoint holds a
state epoch that it wrote after the request arrived. So no state that a
receipt confirmed is in a window that a restore can undo, and the time of
a receipt does not show what the request was or did. Receipts are fetched,
not returned on the request ([enclave-messages.md](enclave-messages.md)
section 4.4).

**Commit before slots**. The writer makes the batch of
day D at the cut ([enclave-messages.md](enclave-messages.md) section 6.5).
The batch is part of the state. The node can fetch it only after a
cosigned checkpoint holds a state epoch whose snapshot holds the batch;
after that the batch never changes. A reveal goes into both queues in one
state change, and a queued item stays until a slot carries it, also after
a withdrawal, a removal or dormancy. A crash goes back to the latest
cosigned epoch: either both reveals are in it, or neither is, and a node
never has a slot that the restored state does not have. If neither is, the
pair does not end: the second yes got no receipt, so the app sends it
again and the enclave decides the reveal again. The vector
`slot_script` of enclave-messages.json runs these cases.

**Tombstones.** On a withdrawal, a revocation by control event, or a
deletion, the enclave keeps `(tombstone_id, version, time)` with
`tombstone_id = tagged_hash("anagram/v1/enclave/tombstone", person key)`.

```
tombstone life = pack life (30 days) + intake key overlap (7 days) + clock margin (1 day) = 38 days
```

The age and tombstone rules of a pack are those of [pack.md](pack.md)
section 8; this section does not change them: a pack
more than 48 hours old is `expired`; while a tombstone lives, a pack with
`version ≤` the tombstone's version, or with `created ≤` the tombstone's
time, is `tombstoned`. A person who comes back sends a higher version,
made after the withdrawal, with a new consent.

Why 38 days: after 48 hours no pack made before the withdrawal is
accepted anyway (age rule). The tombstone lives longer so that a pack that
the person approved before the withdrawal (old consent), signed later by a
second device that did not see the withdrawal, cannot restart matching
during the life of a pack (30 days) and of its intake key (7 days of
overlap), plus 1 day of clock margin. This replaces the first design value of 400
days (the derived value keeps person keys a shorter time).

Re-check after the change to a 21-day answer window: the tombstone life
does not depend on the life of a proposal copy, so it stays 38 days. A
peer's copy of a proposal with the withdrawn person lives at most 22 days
after the sweep (enclave-messages.md 5.3), which is less than 38 days; the
rule "nothing new after the tombstone" (7.1) covers the whole life of that
copy.

### 6.4 Signed time

Sources inside the enclave:

- Witness times: `lower(cp)` and `upper(cp)` of each checkpoint with a
  quorum (section 2.4).
- Roughtime (RFC 10049, Experimental, October 2026; the RFC number,
  section numbers and context strings below were checked against the
  datatracker text on 2026-11-25): at least 2 pinned servers, queried in a
  chained measurement sequence (section 8.2), the first nonce derived from
  the latest checkpoint anchor (the RFC asks for a random first nonce; the
  anchor is not known before the checkpoint exists, so it serves). Each response
  gives `MIDP` (seconds) and `RADI` (seconds, ≥ 1) in a `SREP` signed with
  the context "Roughtime v1 response signature" (sections 5.2.1, 5.2.5)
  by a delegated key (context "Roughtime v1 delegation signature", section
  5.2.6). The enclave checks `MIDP_i − RADI_i ≤ MIDP_j + RADI_j` for each
  pair and keeps the chain as proof of malfeasance (section 8.4).

From these: `lower` = the largest lower bound (`lower(cp)`, `MIDP − RADI`)
plus the guest's elapsed monotonic time since it was taken; `upper` = the
smallest upper bound (`MIDP + RADI`) plus elapsed time. `max_seen` is the
largest signed lower bound ever seen by the line (carried in the snapshot).

**Clock rule.** The enclave is in state `clock_unsafe` if any of these is
true: no signed source is newer than 1 hour; `upper − lower > 300 s`;
`lower < max_seen − 300 s` (time goes back); the host clock differs from
`(lower + upper) / 2` by more than 300 s. In `clock_unsafe` the enclave
does no sweep, no release, no expiry, no handoff and no new evidence, and
it answers each pack with the receipt code `clock_unsafe`. Each entry into
the state is an audit count.

The guest monotonic clock: on SEV-SNP, Secure TSC when the platform has it;
on TDX, the TD's TSC **(to confirm: the host cannot scale or offset
it on the spike platforms)**.

### 6.5 Time in the app

The app's "now" is `max(computer clock, lower(latest accepted
checkpoint))` (section 3.5). The app does not need Roughtime.

## 7. Deletion, withdrawal and compromise

### 7.1 Deletion and withdrawal

Three paths remove a person: a signed withdrawal ([enclave-messages.md](enclave-messages.md)); a signed control
event from the person's node or the roster that makes the credential of
the stored pack `revoked` for good (`member_removed`; `member_left` with
reason `left` or `key_changed`; `credential_revoked` of that credential;
`node_removed` of its node; `ban`; [network.md](network.md) sections 8.4
and 8.5); expiry 30 days after the last upload. A gap or a fork of a chain
(`stale_roster`) only pauses a credential, and `member_left` with reason
`moved` makes the pack dormant (network.md 8.4); neither erases.

"At once" for a control event means: when the writer applies the event,
before it opens the next request and before the next sweep or epoch. The tombstone has the reason `removed`, the
subject's last version and the signed time. If a restart loads an epoch
that is older than the erasure, the writer erases again before it opens a
request.

On each path the enclave, at once and in memory: deletes the pack, the
known object, the pair cache rows, the open proposals and the yes answers
of the person; ends each proposal that names the person (the peer gets
"this proposal ended" at the **expiry of the peer's copy**, never before,
the same text, size and time as an expiry or a "no"); does no
reveal for an open mutual yes that is not yet committed (both or neither); adds the tombstone (6.3); on a withdrawal, deletes the
person's own decline records (below); and commits the change in the next
10-minute epoch (6.3). A reveal that is already in both queues stays and
goes out (6.3); the enclave keeps the person's queue and reply key only
until the queue is empty. Then the snapshot holds no record of the person
other than the tombstone and, after a removal or an expiry, the person's
own decline records.

**Nothing new after the tombstone**. After the tombstone,
no state change may write a value that is the person's key or is made
from it. In particular, when a peer's copy of a proposal with the person
ends later (by expiry, `no` or `not_now`), the enclave writes no history
row for the pair and no "met" row for a revealed pair. The only
exceptions: the tombstone; queued reveals and the slot record until the
queue is empty and 48 hours passed (above; enclave-messages.md 6.5, 7.2);
and a decline record that a living peer owns. A peer's copy holds its own
`decline_id` from the time of the proposal, so a `no` after the
withdrawal still records it without the person's key. Sealed receipts
and day batches hold only ciphertext, request digests and slot addresses,
and leave within 48 hours (6.3; enclave-messages.md 4.4, 6.7). Tests:
`tests/test_enclave_ledger.py` scans the whole snapshot form for the key,
the reply key and every hash made from the key.
Older snapshots do not load (6.2). The audit counts get one count. The log
gets nothing about the person.

What stays: the person's `member_credential` hashes in the public log (no
person data; section 2.8); the tombstone for 38 days; and the decline
records that other people own about the person (below).

**Credential log proofs**. The writer
trusts the root of the log at any `tree_size` from 1 to the tree size of
the latest cosigned checkpoint that it has seen: it computes that root from
the entries under that checkpoint, whose root the checkpoint signs
([pack.md](pack.md) section 5). A proof at a larger `tree_size` gives
`bad_credential`; the app asks the node for the proof again after the next
checkpoint (network.md 6.6).

**Decline records**. Without them, a deletion would erase a "no": the
person who was declined could withdraw, come back, and be proposed again
to the person who said no. So when a person answers `no`, the enclave
keeps one decline record that belongs to that person (the decliner):

```
decline_id = tagged_hash("anagram/v1/enclave/decline", decliner key || other key || ASCII(type))
record     = (owner = tombstone_id(decliner key), decline_id, expires = answer time + 365 days)
```

`type` is the match type of the declined proposal ([pack.md](pack.md)
section 3.3), in ASCII bytes with no length prefix (the keys have a fixed
length of 32 bytes each, so the input is not ambiguous).

- While the record lives, the enclave does not propose the pair for that
  match type, in either order, also after the other person withdrew and
  came back. The pair may be proposed for another match type: a person who does not want to work on one question with a peer
  may still want help with a method from the same peer.
- A deletion of the other person does not delete it: it holds no data of
  the other person, only a one-way hash with the decliner's key.
- A withdrawal of the decliner deletes all the decliner's records (the
  owner field finds them). A removal or an expiry of the decliner's pack
  does not.
- The enclave deletes the record at `expires`.
- It is never visible to the other person: no receipt, slot, size or time
  changes with it. The other person gets the same bytes as when no one
  declined and no match was found (an `empty` slot, or a filler).

A record is 32 bytes of ID, the owner hash and a time. The snapshot holds
it; the log never does. Reference: `Ledger.declines`.

### 7.2 Raising a floor

A vendor advisory (for example a new microcode or TCB level) is answered
with an `enclave_floor` entry signed by the release key. It applies at the
app's next log check (≤ 1 hour), with no notice: a floor can only narrow.
An integer item can only go up; a list can only lose values; a lower value
in an `enclave_floor` entry has no effect. A lower floor needs a new
release with the full notice.

### 7.3 Revoking a release, an instance or a line

`enclave_revoke` with a `target`:

| Target | Effect |
| --- | --- |
| `release` | apps refuse it at their next log check (≤ 1 hour, `release_revoked`); they drop its instance keys; live instances of other releases refuse a handoff to it |
| `instance_id` | apps refuse that instance (`instance_revoked`); it gets no handoff |
| `line_id` | apps refuse every instance of the line; its state key must not be handed on |

Signers: the release key, or (if the release key is lost or misused) any
signer with an independent quorum of `enclave_entry_cosign` entries on the
revoke entry.

### 7.4 Rekey

For reason `vulnerability`, `malicious` or `key_compromise`, the operator
starts a new instance of a fixed release. A live instance of the fixed
release with the state key writes a new snapshot under a **new state key**
(`rekey = true` in its state epoch), erases the old key, and starts a new
intake key epoch. If no trusted instance holds the key (the bad release was
the only one), the line is revoked and a new line starts (total loss,
5.6). Apps re-seal at their next daily upload. Old snapshots stay
unreadable: the old key is gone.

If the revoked release itself was malicious, everything it held while it
ran must be treated as exposed. Revocation stops new exposure;
it cannot undo past exposure.

### 7.5 Notice to apps

The app shows a notice, in plain words, when it sees: a revocation of a
release or instance it sealed to; a raised floor that refuses its
instance; a forked line; a log that fails consistency (`LogMisbehaved`);
a release with `security_fix = true`; or a `total_loss` line for its
shard (its open proposals end, and its pack returns with the next daily
upload). Each notice says what happened,
whether the person's pack may have been exposed (yes only for reason
`malicious` or `key_compromise` of a release it sealed to), and what the
app does: it stops sending until an instance passes all checks again, and
then re-seals. The privacy page lists these events.

### 7.6 Compromise summary

| Compromise | Detection | Response |
| --- | --- | --- |
| TEE break at the floor (side channel, fault) | vendor advisory | floor raise (7.2); revoke if exploited; rekey (7.4) |
| Malicious or broken release | rebuilders, witnesses, reviewers during the notice | `release_rebuild_differs`; revoke; rekey |
| Release key lost or misused | unexpected release in the log; apps see it during the notice | witness-quorum revoke; new app with a new release key |
| Witness key misuse | other witnesses; fork evidence | quorum still needs an independent witness; new app pins |
| Log key misuse or split view | witness refusal, consistency failure | apps stop (`LogMisbehaved`); notice |
| Clone or Sybil instance | log entries; evidence checked before logging; holders in the state epoch | rule 7 (a), (e), (f); revoke the instance |
| Extra lines (fresh state to probe) | `enclave_line` entries with an independent quorum; total-loss notice and rate limit | rule 7 (b); `wrong_shard` |
| Instance output or intake key leaked | log; anomaly | revoke instance; new key epoch |
| Node misuses credentials | `member_credential` entries; node's own check | control events; node removal (network.md) |

## 8. Test vectors

`vectors/enclave-trust.json` (made by `python -m anagram.vectors.enclave_trust
spec/vectors`; checked by `tests/test_enclave_trust.py`) holds:

- `seed_labels`: the label of each key; `seed = SHA-256(UTF-8("anagram
  enclave-trust vector seed: " || label))`;
- `roots`: the pinned keys (log, 3 witnesses with entry keys, release, 2
  rebuilders, development root);
- `base_entries`: one entry of each kind except revoke and floor (which
  appear in cases), among them the authorised first line with its two
  independent cosignatures and a roster checkpoint, with leaf bytes and
  digests; two checkpoints with quorum cosignatures;
- `descriptors`: three descriptor documents, their hashes, the set hash,
  the statement hash, refused documents and sets, and a shard example;
- `measurements`: an example reference object and its measurement for
  each profile;
- `binding`: the inputs, `binding`, `gpu_nonce`, and the GPU form of
  `report_data`;
- `release_cases`: `now` is the computer clock; the app's now is
  `max(now, lower(last of checkpoints))` (3.5), and the app reads only the
  entries under that checkpoint. One case for each release code, a
  `release_not_yet` case where only the first checkpoint is known and a
  case where the clock is behind the checkpoint (accepted), a `security_fix`
  cosigned by both independent witnesses (accepted) and by Radiofuture and
  one independent witness (refused), and quorum revokes with and without
  the independent quorum;
- `attestation_cases`: valid `simulated` documents and one or more refusal
  cases for each pre-check and each rule code (an unknown profile on a
  correctly signed document, and a bad signature with an unknown profile,
  which gives `bad_attestation`), among them a lease over 24
  hours, lines with no entry, a weak cosign or another shard, and a logged
  clone that is not the writer;
- `line_cases`: total-loss lines while the old line runs, after every
  lease ended, the replaced line, and a second total loss within 30 days;
- `handoff_cases`: same release, named successor, not a successor, no
  downgrade;
- `handoff_messages`: one sealed, signed handoff and its refusals (a
  sender that is not a holder, an older counter, another successor);
- `snapshot`: one sealed snapshot (key, nonce, digest) and the load cases:
  restart cases with no handoff, and upgrade cases on `handoff_line`, where
  the successor loads the epoch that names it (6.2);
- `writer_cases`: failovers that hold and that do not (lease not ended,
  one independent cosignature, not the release key, an old epoch, not a
  holder, the old writer after the failover, the old writer first), each
  with `forked` and the next writer (5.7);
- `tombstone`: the tombstone ID and the replay cases;
- `decline`: the `decline_id` rule, the record life in seconds, and the IDs
  for two keys in both orders and two match types (7.1);
- `clock`: the cases of the clock rule;
- `snp`, `tdx`: constructed (not real) report and quote bytes with their
  parsed claims, a debug-and-migration case, and malformed cases.

Real evidence fixtures for each profile come from the platform spike.

## 9. What this spec does not cover

The pack and known object ([pack.md](pack.md)); sealed envelopes, answers,
receipts, slots and control event formats, and receipt codes
([enclave-messages.md](enclave-messages.md)); the roster, the admission
record and the member credential ([network.md](network.md)); the service
logic; sharding (v1 has one line per shard).

## 10. To confirm in the platform spike

1. AMD: the table numbers of 56860 in the current revision; the FMC SPL OID
   of the Turin VCEK (until then, Turin is refused, 4.3); the launch digest
   tool and inputs for our UKI image.
2. Intel: the quote version that the spike platform gives (4 or 5); that
   the guest boots with `SEPT_VE_DISABLE = 1`; RTMR values of the UKI boot.
3. Google: a real PKI token (its intermediate and leaf, and the token
   lifetime; the root is pinned, 2.6); launch policy label names; whether `nvidia_gpu` claims
   (H100, TDX) make `gcp-cs` the GPU profile (the first design said GPU in
   Confidential Space is not verified).
4. Azure: the guest attestation page and report format; that the HCL
   `REPORT_DATA` covers the vTPM AK; the MAA claim path of the AK;
   MAA token signing chain pinning; `x-ms-compliance-status` on the GPU
   size; the PCR set of the UKI boot.
5. NVIDIA: NRAS JWKS pinning and endpoint version; the CC mode field in
   the Hopper report; OCSP nonce support and response lifetime; that the
   CC driver gives only the attached GPU's report.
6. Guest time: Secure TSC (SNP) and TSC protection (TDX) on the spike
   hosts.
7. Snapshot size buckets (from the sharding sizes).
8. Exact vendor root certificates for section 2.6 (AMD and Intel are
   pinned).

## 11. Changes

- 2026-11-25: first draft.
- 2026-11-25: fixes of a spec review (section 12).
- 2026-11-25: fixes after a simulated enclave slice (section 13).
- 2026-11-27: the `raw-snp` verifier (section 17).
- 2026-11-27: the `raw-tdx` verifier (section 18).
- 2026-11-27: the `gcp-cs` verifier (section 19).
- 2026-11-27: differential tests; `azure-cvm-gpu` parked (section 20).
- 2026-11-27: cloud binding (rule 9) and the policy bits per profile
  (section 21).

## 12. Changes after the spec review (2026-11-25)

A spec review asked for these changes. All are in this draft.

- `enclave_line` entries with an independent quorum, shards and the
  total-loss rules (5.6); `wrong_shard` at the writer; evidence checked by
  the log and the witnesses before an instance key is logged (5.4);
  `holders` in the state epoch, so clones do not count (rule 7 (e), (f));
  `lease_until ≤ logged_by + 24 h` (rule 7 (a)).
- Fixed 10-minute epochs; every receipt and every day batch only after a
  cosigned epoch; queued reveals survive withdrawal (6.3, 7.1).
- Descriptor format and set (3.6). Attestation bundle, instance choice,
  writer-only intake (3.7).
- Pack age and tombstone rules refer to pack.md section 8 (6.3).
- "Proposal ended" at the expiry of the peer's copy (5.6, 7.1).
- Signed handoff message and the successor's checks (5.3).
- `roster_checkpoint` log entries (2.3).
- The independent quorum for `security_fix`, quorum revokes and lines (1,
  2.5, 7.3); the residual is stated in section 1.
- Credential-hash salt wording (2.8); Roughtime citation checked (6.4).

Fixes of the re-check of that review:

- Slots by one 48-hour rule for packs, covers and withdrawals
  (enclave-messages.md 6.5); the commit rules of 6.3 do not change.
- `answer_day` is 1 to 7 (3.6).
- v1 accepts only lines with n = 1 shard (2.3, 5.6, rule 7 (b)); the
  vector `r7_line_with_two_shards_in_v1` refuses n = 2.
- A crash before the cosigned epoch loses a reveal but does not end the
  pair: the app resends the yes (6.3; enclave-messages.md 6.6).

## 13. Changes after the simulated enclave slice (2026-11-25)

The simulated enclave slice found these problems. Each has a ruling; the
code and the vectors follow.

- Handoff load: the successor loads the state epoch that names it
  `next_writer`, whose counter is one more than the handoff message's. The
  old text of 6.2 rule 3 asked for the same counter, so it could never pass
  (5.3 step 6, 6.2). Vectors: `snapshot.cases` (restart cases now have
  `handoff: null`; five upgrade cases replace the case
  `handoff_disagrees`).
- Old checkpoints for a fresh app: `GET
  /log/checkpoint/covering/{index}`; the app asks it for each timed entry;
  the log and the Anagram witnesses refuse a lease that ends more than 24
  hours after their own time, so a later covering checkpoint cannot widen
  rule 7 (a) (2.1, 2.4, 5.4).
- Writer failover: the `enclave_writer` entry, signed by the release key
  and cosigned by both independent witnesses, after the writer's lease
  ended. It never forks a line (1, 2.3, 2.7, 3.7, 5.3, 5.5, 5.7). Vectors:
  `writer_cases`. Test: `tests/test_enclave_failover.py`.
- Withdrawal erased history: decline records that the decliner owns, for
  365 days, deleted by the decliner's withdrawal, never visible to the
  other person (7.1). Test: `tests/test_enclave_ledger.py`.
- Follow-up: a peer's copy that ended after a withdrawal wrote a history
  row with the withdrawn person's key again. Now nothing that names the
  person is written after the tombstone (7.1).

The node request nonce, the reply-key rule and the daily upload are in
enclave-messages.md section 15.

## 14. Changes after the conformance review (2026-11-25)

- A control event that removes a member erases the subject at once, with a
  tombstone; the list of events and "at once" are exact; a restart erases
  again (7.1). Tests: `tests/test_enclave_conformance.py`, one for each
  event, each with the scan for values made from the key.
- One routing rule. The front end sends every request to the writer;
  another instance takes none; a request to another key gets
  `unknown_instance_key` from the writer; no writer gives `503` (3.7;
  enclave-messages.md 3.3, 10).
- `unknown_profile` comes after every `bad_attestation` check (3.4).
  Vectors: `pre_unknown_profile` now has a valid signature;
  `pre_bad_signature_before_profile` is new.
- Release rule 6 uses the app's now of 3.5 (2.5). Vectors: `not_yet` knows
  only the first checkpoint; `not_yet_clock_behind_checkpoint` is new.
- `lower` and `upper` are over all valid cosignatures (2.4).
- `release_rebuild_differs` before `release_rebuilds_missing` (2.5).
- GPU floor items apply only with GPU evidence (3.5 rule 2).
- The total-loss rule reads the replaced line's own entry (5.6).
- `seed_labels` in the vector file (8).
- Exact read routes of the log (2.1).
- The tree sizes that the writer trusts for a credential log proof (7.1).

## 15. Changes after the answer-window and decline decisions (2026-11-26)

- `answer_day` is the step between the three answer checkpoints; the range
  stays 1 to 7, but its old reason is gone because both copies of a pair
  now share one expiry (3.6; enclave-messages.md 5.3). `weekly_cap_max` is
  1 to 10 (3.6). The tombstone life of 38 days was re-checked and does not
  change (6.3).
- `decline_id` includes the match type, so a `no` blocks the pair for that
  type only (7.1). Vector: `decline` (8). The scans of "nothing new after
  the tombstone" include the IDs of each type.

## 16. Changes after the review of those decisions (2026-11-26)

- `member_credential` has `member`, the join commitment of a new member
  or null, and the log checks the time window of `expires` (2.3, 2.8).
  So anyone can count new members of each node in a month (network.md
  6.7). Vector: the `member_credential` entry of `enclave-trust.json` is a
  join entry, so the later leaf hashes and roots changed.

## 17. The `raw-snp` verifier (2026-11-27)

- The `raw-snp` evidence step is real: the AMD chain to a pinned ARK, the
  leaf TCB and hwID, the CRL and the report signature, in a fixed order
  (4.3). The evidence form is `{"ark", "ask", "crl", "leaf", "report"}`,
  and the product comes from CPUID and the leaf's product name.
- The AMD ARK pins are their SHA-256 values (2.6).
- Rule 4 also checks the next update of a profile's collateral (3.5).
- The `raw-snp` floor items are named `<product>_<component>`, and the
  floor must name every component of the evidence's product (4.8).
- A Turin leaf is refused until its FMC extension is confirmed (4.3, 10).
- After review: the steps run in the listed order (`MASK_CHIP_KEY` first,
  the CRL after the leaf checks); a part that does not parse gives
  `bad_attestation`; the algorithm identifiers must be exact (4.3).
- The policy rules (SMT, ciphertext hiding, page swap) and a VLEK-only
  rule are not in this change; a later change adds them.

## 18. The `raw-tdx` verifier (2026-11-27)

- The `raw-tdx` evidence step is real: the quote and QE report
  signatures, the PCK chain to the pinned Intel SGX Root CA, the PCK's SGX
  extensions, both CRLs, and Intel's signed TCB Info and QE Identity, in a
  fixed order (4.4). The evidence form is `{"quote", "tcb_info",
  "qe_identity", "tcb_signing", "root_crl", "pck_crl"}`, and no byte may
  follow the quote.
- The Intel root is pinned by its SHA-256 (2.6).
- The TDX module identity (`MRSIGNERSEAM`, `SEAMATTRIBUTES`) and the
  quoting enclave identity are rule 8 checks (`untrusted_root`): a
  mismatch means the evidence is not from Intel's module or enclave. The
  first draft listed the module check under rule 2.
- The floor has a fourth item, `tdx_module_tcb_status`, for TDX 1.5
  modules (`TEE_TCB_SVN[1] > 0`); `Revoked` and `Unsupported` never pass
  (4.8).
- `SEPT_VE_DISABLE` and the advisory IDs are claimed; the rules that use
  them come in a later change.

## 19. The `gcp-cs` verifier (2026-11-27)

- The `gcp-cs` evidence step is real: a PKI Confidential Space token,
  its `x5c` chain to the pinned Confidential Space Root CA, and the RS256
  signature, issuer, audience and times, in a fixed order (4.5).
- The Confidential Space root is pinned by its SHA-256 (2.6).
- Rule 4 uses `valid_from` and `valid_until` for a token (3.5).
- Rule 6 allows CPU evidence that carries the GPU claims (3.5, 4.5).
- `hwmodel`, `swname` and `restart_policy` are fixed by the reference
  object; the other Confidential Space policy claims are claimed, and a
  later change checks them.
- Google publishes no signed sample token: the tests use a fake root, and
  a real token comes from the platform spike.

## 20. Differential tests and the parked Azure profile (2026-11-27)

- The `raw-snp` and `raw-tdx` verifiers are checked against Google's
  reference verifiers, go-sev-guest and go-tdx-guest, at pinned revisions
  (`tests/differential/refverify`, a small Go program that runs them
  offline). CI gives both the real fixture evidence and thousands of
  copies with one byte changed, cut or added. Both accept the real
  evidence. For each copy the verdicts are the same, except where Anagram
  is stricter by design: a byte after the end of a field, a letter in
  another case in the unsigned part of Intel's JSON (a field name or a
  signature digit), or a changed AMD ARK (the reference does not check
  each byte of it; Anagram pins its hash). Anagram never accepts a
  copy that the reference refuses. Any other difference fails CI.
- `azure-cvm-gpu` (4.6) is parked and stays a refused stub. An Azure
  confidential VM cannot turn SMT off, signs with a VCEK (no VLEK), and
  adds Microsoft's paravisor and vTPM to what must be trusted. GPU
  enclaves use `gcp-cs`, whose token reports the H100 (4.5). If Azure is
  taken up again, the path is the raw HCL report, the AMD VCEK chain, the
  vTPM quote and the event log, with no Microsoft Azure Attestation.

## 21. Cloud binding and the strict policy bits (2026-11-27)

- New rule 9 (`evidence_not_cloud_bound`), checked right after rule 8:
  the evidence must name a cloud that the release pins in
  `profiles[profile].cloud` (2.3, 3.5). `raw-snp` needs a VLEK of a
  pinned cloud; `gcp-cs` a pinned project and zone; a production app
  refuses `raw-tdx`.
- Rule 3 checks the bits of each profile, each with its own code: SMT
  off, ciphertext hiding on and page swap off for `raw-snp`; secure boot,
  a `STABLE` image and no launch overrides for `gcp-cs` (4.3, 4.5).
- Section 4.9 lists what each profile enforces and the risks it can not
  close.
- The codes of rule 9 and the new rule 3 codes have their vectors in a
  new file, `vectors/enclave-policy.json`; `enclave-trust.json` is
  unchanged. Every release in it lists only `simulated`, which has no
  `cloud`.
