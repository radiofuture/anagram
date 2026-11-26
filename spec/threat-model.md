# Anagram threat model

Status: version 1 (proofs and log, identity, local index, vault and
sharing; after the second security review), v2 (2026-10-27: sections 12
and 13 for the personal store and private person IDs), and 2026-11-26
(sections 7, 9 and 11 describe the matching enclave; a test checks that
every test named here exists). Licence: CC BY 4.0.
Source: the trust boundaries table of the first design of Anagram.

## 1. Assets

- **Evidence bytes and claims.** Private until the owner shares them.
- **Opening data** (salts and field values). Without it, no proof is possible.
- **Keys**: device keys (Ed25519, X25519), vault key, content keys (one for
  each finding version), guardian recovery secret.
- **Disclosure dates**: when an owner gave a finding to a person
  ([vault.md](vault.md)).
- **Priority**: the fact that a finding existed no later than a time.
- **Identity facts**: who works on what. A match can leak this.
- **Membership**: which ORCID iDs are members of a community (v2: private).

## 2. Parties

| Party | Can see | Must not be able to | How we enforce it | Spec |
| --- | --- | --- | --- | --- |
| Owner's device | Everything the owner has | — | Keys in a keystore: a master key in the OS keychain and sealed key files (section 14); plain key files only on request (`--plain-key-files`, `ANAGRAM_KEYSTORE=file`) or where there is no keychain. Only the local client touches keys or plaintext | [identity.md](identity.md) |
| Community node (storage, log) | Log entries (kind and a hash), checkpoints, later ciphertext, public keys, hidden grant receipts, metadata (sizes, times, membership), the private ORCID -> pid map, personal store ciphertext (record IDs, versions, sizes, times) | Read findings; backdate a claim; swap a user's key in secret; fork the log in secret | Log entries hide root, owner, and signature; client-side encryption; anchored checkpoints; client inclusion and consistency checks; witness cosignatures | [log.md](log.md) (log), [identity.md](identity.md) (keys), [vault.md](vault.md) (storage) |
| Community node as relay (matching) | Fixed-size sealed requests, their times and sizes, receipts, slots, and fillers; who has a member credential | Read matching lines, proposals, answers or cards; tell a pack from a cover | The app seals each request to the attested enclave key (HPKE); fixed sizes; fillers for unknown digests and addresses ([enclave-messages.md](enclave-messages.md) 11) | [enclave-messages.md](enclave-messages.md) |
| Matching enclave operator (`simulated` profile) | In the simulated profile: every pack, card and answer ([enclave-trust.md](enclave-trust.md); `docs/enclave.md`) | In the TEE profile (not in this build): read any of them | Attestation, a cosigned release log, the 14-day notice, witnesses. The simulated profile gives no confidentiality from the operator | [enclave-trust.md](enclave-trust.md) |
| Opt-in model provider | Files the user selects for drafting | — | Off by default. The UI names the provider as a reader | [understanding.md](understanding.md) |
| Match peer | After two `yes` answers: your reveal card and the roster record of your node. Never your lines | See your lines, your work, or the reason a proposal ended | The release check permits only the recipient's own copy, and a card only after two `yes` answers | [matching.md](matching.md) |
| Ring member | Findings granted to them | Forget what they saw | Revocation protects only new versions | [vault.md](vault.md) |
| Recovery guardians (optional) | One share each | Recover alone | Shamir threshold; shares encrypted to each guardian device | [vault.md](vault.md) |
| Witness | Checkpoints | Make a client accept a fork | Witness checks consistency before it cosigns; clients require a pinned witness cosignature | [log.md](log.md) |
| Anchor (TSA, OpenTimestamps) | Checkpoint digests only | Backdate a checkpoint | Independent time sources; verifier pins TSA roots and Bitcoin headers | [log.md](log.md) |
| Public | Log entries, proofs that the owner publishes, person IDs and ORCID commitments in key bindings | Link a hidden entry to a person; guess a committed value; list the ORCID iDs of members | Hidden log commitments; a 32-byte random salt on each field; v2: random person IDs and salted ORCID commitments in the log | [log.md](log.md), [identity.md](identity.md) |

## 3. Threats and responses (proofs and log)

| Threat | Response | Test |
| --- | --- | --- |
| Node changes or removes an old entry | Client keeps the last checkpoint and checks consistency; witness refuses an inconsistent checkpoint | `test_client_detects_forked_log`, `test_witness_refuses_fork` |
| Node shows different logs to different clients (split view) | Each checkpoint needs a pinned witness cosignature; the witness refuses a fork | `test_witness_refuses_fork` |
| Node or owner backdates a finding | Time comes from anchors and cosignatures over the checkpoint, not from `created_at`; a changed time or a moved anchor fails | `test_backdated_checkpoint_fails` |
| Someone changes a claim or a file after commit | Field leaves are salted hashes in a Merkle tree under a signed root | `test_changed_claim_fails`, `test_prove_file_negative` |
| Someone claims another person's finding | The owner signature binds the root to the device key; the log entry hashes the owner key | `test_wrong_keys_fail` |
| A verifier uses keys from the bundle | `verify` takes keys only from pinned configuration or flags | design |
| Node disappears | Bundles verify offline with pinned keys | `test_verify_offline_after_node_deleted` |
| Public guesses a short committed value | 32-byte random salt per field | `test_salts_hide_equal_values` |
| Opening data is lost or read from disk | Sealed with the vault key (ChaCha20-Poly1305) before the node sees anything; stored in the vault | `test_sealed_opening_round_trip` |
| Large files exhaust memory | Chunked Merkle digest, one chunk in memory | `test_large_file_streams` |

## 4. Threats and responses (identity)

| Threat | Response | Test |
| --- | --- | --- |
| Attacker sends a link to a different node | Invite pins the log key fingerprint; client checks the signed trust document | `test_wrong_pinned_fingerprint_rejected` |
| Someone changes an invite (community, expiry) | Node signs the invite; client checks it | `test_tampered_invite_rejected` |
| Invite reuse or late use | Single use, expiry on node and client, idempotent claim for the same person | `test_invite_single_use_and_idempotent_claim`, `test_invite_expiry` |
| Forged sign-in assertion | Client checks node signature, audience (its device key), nonce, and expiry; node checks assertions in key bindings | `test_forged_assertion_rejected_by_client`, `test_forged_assertion_rejected_by_node` |
| Intercepted one-time code | PKCE-style verifier; code goes only to a loopback URL or the user's screen | `test_pkce_and_return_to` |
| Node swaps a person's key (entry not in the log) | Lookup needs an inclusion proof for each entry | `test_directory_entry_not_in_log_detected` |
| Node forks the log to swap a key | Consistency with the last seen checkpoint | `test_log_fork_detected` |
| Node puts a valid swap in the log (it holds the assertion key) | Owner monitors all new entries; unknown key or reset raises an alert | `test_node_key_swap_detected_by_owner_monitor` |
| Node hides or changes entries during monitoring | Compact range root must equal the verified checkpoint root | `test_monitor_detects_changed_entries` |
| Node hides a `reset` or `remove` in a lookup, so senders encrypt to a stolen key | Lookup reads the log up to the checkpoint of the answer; the answer must list the same bindings as the client's own copy | `test_directory_answer_that_hides_a_reset_is_refused` |
| Thief keeps using the session of a stolen device after a reset | Sessions are bound to the device key of the sign-in assertion; refused when that device is not active; deleted at reset and remove; `anagram logout` | `test_reset_revokes_sessions_of_old_devices`, `test_session_of_removed_device_is_refused`, `test_logout_ends_the_session` |
| Node reads private keys or the recovery secret | Node gets only ciphertext of the key backup and hashes of tokens and codes | `test_node_never_stores_private_keys` |
| Sign in again without an invite is used by a non-member, or by a removed or stolen device | Purpose `login`: the node gives a session only to a member, and only for a device that is active or never bound; the flow is used before the check; the client pins the node key from its config | `test_non_member_cannot_sign_in_without_an_invite`, `test_removed_device_cannot_sign_in_again`, `test_login_checks_the_pinned_node_key` |
| Anonymous log spam | Member session and per-member rate limit | `test_unauthenticated_and_non_member_submission`, `test_submission_rate_limit` |
| Email code guessing | 8 digits, 10 minutes, 5 attempts, 5 codes per hour per address | `test_email_sign_in` |

## 5. Known limits of proofs, log and identity

- The witness runs with the node. It shows that the protocol works. It does not
  stop a dishonest operator. Production needs an independent witness.
- The fake anchor gives no independent time. A real deployment uses RFC 3161
  and OpenTimestamps.
- RFC 3161 checks do not include revocation (CRL, OCSP).
- OpenTimestamps verification needs Bitcoin block headers from a source that the
  verifier trusts. Anagram does not fetch them.
- The app keeps the keys sealed by a master key in the OS keychain (section
  14). The CLI and headless hosts keep them in plain files (mode 0600)
  unless `ANAGRAM_KEYSTORE` is `auto` or `os`.
- The node holds the assertion key. It can bind a key to a person who has not
  joined yet, or reset a person's keys. This is visible in the log, and the
  person's own monitor reports it, but only when the person runs it. A person
  who never joins never sees it.
- A lookup cannot omit bindings up to its checkpoint, but the checkpoint can
  be old (not older than the last one that the client saw). A node can so
  delay a new binding for a client that does not ask for a newer checkpoint.
- Sessions are bearer tokens. A stolen session lets the thief submit entries
  as a member (not sign as the person) until it expires (7 days), until the
  person signs out, or until a reset or remove of its device. Passkey sessions
  are not bound to a device; a reset or remove deletes them.
- A wrong or stolen recovery kit: anyone with the kit can restore the keys.
- The first checkpoint a client sees is trusted on first use, except for the
  witness cosignature.
- Metadata leaks: the node sees entry times, entry counts, and which client
  sends them. A field count (for example, the number of evidence items) shows
  in an opened field proof.

## 6. Vault, rings, guardians

See [vault.md](vault.md).

| Threat | Response | Test |
| --- | --- | --- |
| Node reads evidence | Client-side chunked AEAD with a content key for each finding version; node stores ciphertext only | `test_node_holds_no_plaintext` |
| Node reorders, cuts, or moves chunks or blobs | AAD binds finding root, evidence root, slot, index, final flag; content digest check after decryption | `test_blob.py`, `test_tampered_payload_parts_are_refused` |
| Node swaps a recipient's key | Keys only from `lookup` with inclusion proofs; all lookups before any send | `test_node_swaps_recipient_key_grant_refused` |
| Non-member reads a grant or blob | HPKE wraps only to recipient devices; access check on download (404 for all refusals) | `test_non_member_cannot_read` |
| Node or another member fakes a grant | Recipient checks the opening against the signed root, the owner's key history, the signed receipt, and its log inclusion | `test_grant_to_ring_member`, `test_grant_receipt_opens_and_verifies` |
| Owner denies a disclosure, or a recipient claims an earlier one | Salted, owner-signed receipt commitment in the log; recipient keeps the receipt and its log proof | `test_grant_receipt_opens_and_verifies` |
| Public links a receipt to a person | 32-byte random salt; the log entry is one hash | `test_grant_receipt_opens_and_verifies` |
| A removed ring member reads new work | Revocation makes a new version with a new content key | `test_revoke_makes_new_version` |
| Owner shares other people's words by mistake | Per-evidence `third_party` flag; grant and publish need an acknowledgement | `test_third_party_warning_gates_grant_and_publish` |
| One guardian (or the node) recovers keys | Shamir k of n; shares HPKE-sealed to guardian devices; node has ciphertext only | `test_one_of_three_fails`, `test_share_ciphertexts_on_node_reveal_nothing` |
| Fake approval gives a wrong secret | The combined secret must give the set's backup ID | `test_forged_approval_is_ignored` |
| Someone asks guardians for another person's keys | Session, node assertion, and proof of possession must agree; the guardian client checks them; guardians confirm by another channel | `test_request_needs_matching_session_and_slot` |
| An old, forgotten recovery request collects approvals later | 7-day limit: the node deletes older requests and approvals; the guardian client checks the node-signed assertion time | `test_recovery_requests_expire` |

## 7. Matching and identity

The node no longer runs matching. A person takes part with a member
credential of the node and a sealed pack ([pack.md](pack.md),
[network.md](network.md)).

| Threat | Response | Test |
| --- | --- | --- |
| Anonymous requests | The enclave relay routes of the node need a member session; the enclave accepts a pack only with a member credential of the node that relayed it | `test_the_enclave_routes_need_a_member_session`, `test_a_pack_through_another_node_is_refused` |
| Two keys of one person are matched with each other | The match protocol never pairs two packs with the same pid | `test_two_keys_of_one_person_are_not_a_pair` |
| A removed or banned member stays in matching | A control event that removes the member erases the member's state at once; a pack of a banned subject is refused (`revoked`) | `test_a_removal_erases_at_once_and_nothing_names_the_member_after`, `test_a_pack_of_a_banned_subject_is_revoked` |

## 8. Known limits of the vault, sharing and recovery

- Access that a person got cannot be taken back. A revocation protects only
  new versions. A recipient can keep and pass on what it decrypted.
- The node sees metadata: who grants to whom and when, blob sizes and counts,
  which blobs a grant covers, guardian subjects, and recovery requests.
- A public release cannot be taken back. Its content key is public, so all
  blobs that it lists are public.
- New devices of a recipient get a grant only after the owner syncs
  (`anagram sync`). The owner's device must be on.
- The node holds the assertion key. It can make a recovery request for anyone.
  Guardians must confirm by another channel before they approve.
- Blobs go through HTTP in one piece (one blob in client memory).
- The name and institution on a reveal card are what the person wrote.
  When the node verified email addresses, the email on the card must be one
  of them. The node record next to the card comes from the roster.

## 9. Matching enclave: release and traces

See [enclave-messages.md](enclave-messages.md) section 11 for what each
party learns, and [matching.md](matching.md) section 5 for the release
check. In the `simulated` profile (the only profile of this build) the
operator of the enclave can read every pack, card and answer (section 19).

| Threat | Response | Test |
| --- | --- | --- |
| Code sends a field that is not the recipient's, or to a wrong recipient | One release check before each slot is sealed and when each reveal is made | `test_the_release_check_denies_what_is_not_the_recipients`, `test_no_person_bytes_reach_a_peer_before_mutual_yes` |
| A peer learns that it is blocked, or why a proposal ended | Blocked, incompatible, absent and withdrawn peers give the same slots; `no`, `not_now` and no answer give the same `ended` item at the expiry | `test_non_interference_when_a_hidden_peer_changes`, `test_no_and_not_now_give_the_peer_the_same_trace` |
| The host disk or the logs show packs | The state is a sealed snapshot; the service logs hold no pack text, key or subject | `test_sealed_snapshot`, `test_the_service_logs_hold_no_pack_text_key_or_subject` |
| The host rolls the enclave state back | A snapshot loads only at the counter of the latest cosigned epoch in the log; a batch and a receipt go out only after a cosigned epoch | `test_snapshot_case`, `test_a_batch_waits_for_its_cosigned_epoch` |
| The app encrypts to a wrong key | The app checks the attestation document against the release log and the rules of its profile; a request for an old document is refused | `test_attestation_cases_cover_every_rule`, `test_a_stale_attestation_is_refused_after_the_document_changes` |
| Replay or fast probing | Signed node requests with replay checks; one pack or cover a day; tombstones refuse old consents | `test_the_relay_refuses_unsigned_and_replayed_requests`, `test_one_pack_a_day`, `test_old_consent_after_withdrawal_is_tombstoned` |
| A member reads the slots of another member to learn who takes part | The slot address is a hash of the day and the secret reply key; a slot opens only with that key and day | `test_slots` |

## 10. Local index

| Threat | Response | Test |
| --- | --- | --- |
| A repository from another person runs commands through its `.git/config` (`core.fsmonitor`, `gpg.program`, hooks) during a scan | Each Git command gets fixed safe settings (`GIT_CONFIG_COUNT`, the priority of `git -c`), no global or system config, no network protocols; only object reads (`log`, `ls-tree`, `cat-file`) | `test_repo_config_cannot_run_commands` |

## 11. Match protocol and models

See [matching.md](matching.md) section 3. The models of a release are in
its descriptor set in the release log. This build runs only the simulated
engines (no model).

| Threat | Response | Test |
| --- | --- | --- |
| The operator changes a model or a rule in secret | The descriptors of a release (models with digests, matching values) are in the release log, with a notice period; the enclave refuses a model descriptor that its build does not run | `test_descriptor_set`, `test_release_case`, `test_engines_refuse_a_model_this_build_does_not_run` |
| A protocol bug or a forged decision releases a card | The release check permits a reveal only after two `yes` answers to an open pair, with the peer's own card and the roster's node record | `test_the_release_check_denies_what_is_not_the_recipients`, `test_no_person_bytes_reach_a_peer_before_mutual_yes` |
| The model writes free text or a peer's text into a proposal | The judge gives enums only; the reasons are line IDs of the recipient's own pack | `test_sweep_proposes_the_pair_with_own_reasons`, `test_the_planted_pair_gets_proposals_with_own_reasons_only` |
| Prompt injection in a line | Two orders of the judge must agree. At worst a forced proposal, which shows only the recipient's own lines; a card needs two `yes` answers. The weekly cap, the node rule, deny and block still apply | `test_joint_judge_is_the_same_in_both_orders`, `test_the_weekly_cap_is_the_persons_own_value`, `test_deny_by_node_domain_and_ror` |
| Probing: a person changes the lines each day to learn who is in the pool | One pack a day; the weekly cap; the anonymity rule | `test_one_pack_a_day`, `test_the_weekly_cap_is_the_persons_own_value`, `test_sweep_respects_the_anonymity_rule` |
| The audit leaks lines | The enclave keeps counts only; the decision table holds no text and stays inside | `test_the_service_logs_hold_no_pack_text_key_or_subject` |

Known limits:

- A model can be wrong. A false match shows a card to a person who cannot
  help, after two `yes` answers. A missed match shows nothing.
- The stage-1 shortlist can miss true pairs. The fake embedder sees words,
  not meaning.

## 12. Personal store (v2 foundations)

See [vault.md](vault.md) section 11. The node keeps each person's vault
records and index snapshot as ciphertext, so a lost laptop does not make the
person's proofs worthless.

**What the node sees:** opaque record IDs, record versions, ciphertext sizes
(in 512-byte steps), the times of each change, and which member owns which
records. So it can see how much a person stores and when the person works
(for example, a sync after each commit). It cannot see kinds, roots, salts,
claims, file names, paths, or the index. Snapshot chunks are near 1 MiB, so
the node can guess which records are snapshot chunks and the size of a
person's index.

| Threat | Response | Test |
| --- | --- | --- |
| A lost or broken laptop makes old proofs worthless (salts gone) | Vault records and an index snapshot go to the personal store; the recovery kit (key backup v2) and guardians restore the vault key and index key; restore reads the store | `test_lost_laptop_recovery_kit_restores_proofs`, `test_lost_laptop_guardians_restore_proofs` |
| Node reads salts, claims, or the index | Records sealed with a key from the vault key; the node has no key | `test_node_holds_only_ciphertext` |
| Node changes, swaps, or moves a record | AEAD with AAD over the record ID, version, and key ID; the reader checks the record ID of the content | `test_store_records_reject_changes` |
| Node gives a new device a vault key that the node knows | The person-keys package must have a signature of an active device of the same subject (log proofs) | `test_person_keys_from_a_foreign_device_are_refused` |
| A member reads or overwrites another member's records | Records are kept for the session subject; versions must go up | `test_store_node_rules` |
| A thief uses a restored kit to get a session without ORCID | Device sign-in works only for an active device key; the kit holder could sign key bindings anyway | `test_device_sign_in_rules` |
| A commit fails because the node is down | Sync after a commit is best effort; the error is kept and the next sync sends the records | `test_commit_works_when_the_node_has_no_store` |

Known limits:

- **Rollback.** The node can serve an older version of a record, or hide a
  record, at a restore. The new device has no earlier state to compare. A
  restore then lacks the newest data (for example a new anchor of a bundle).
  The old salts stay valid, because a finding never changes after the commit.
- **Availability.** The node can delete records. A person who wants a second
  copy must keep an export (later: a second node).
- **Snapshot age.** Automatic sync sends an index snapshot at most once an
  hour. Index data that is newer than the last snapshot is lost with a lost
  laptop (finding records are sent after each commit).
- **One index for each device.** A new device (`add_device`) gets the vault
  records but not the index of the other device.
- **Timing.** The node learns when the person commits (a sync follows each
  commit).

## 13. Private person IDs (v2 foundations)

See [identity.md](identity.md) sections 2 and 13.

| Threat | Response | Test |
| --- | --- | --- |
| Anyone lists the ORCID iDs (or names) of members from the public log or the public directory | Subject is a random `pid:`; the log has a salted ORCID commitment; assertions have no ORCID iD and no name | `test_log_and_directory_show_no_orcid_or_name`, `test_no_orcid_in_public_identity_documents` |
| Someone guesses an ORCID iD from its commitment | 32-byte random salt in the commitment | `test_orcid_commitment_hides_and_binds` |
| A member enumerates ORCID iDs with the lookup | `/resolve/orcid` only for members, only for people who turned on "findable by ORCID", 30 queries per hour, audit table, the same 404 for all refusals | `test_resolve_by_orcid_needs_member_and_opt_in`, `test_resolve_rate_limit`, `test_non_member_cannot_resolve` |
| The node gives a commitment for another ORCID iD | The client checks that the profile (ORCID iD, salt) opens the commitment of the assertion | `test_client_refuses_a_wrong_orcid_opening` |
| A person changes the ORCID commitment of a subject | Key-binding rule 6: the commitment never changes in a chain | `test_commitment_must_stay_the_same_in_the_chain` |

Known limits:

- The node knows the ORCID iD of each member (it checks ORCID at sign-in). A
  node operator, or an attacker with the node database, has the full map.
- The member list (`GET /members`) and identity records (display name, lab,
  ROR) are visible to all members. A display name can identify a person.
- Timing and the community size are visible in the log (one seq-0 binding for
  each new person).
- A person who turns on "findable by ORCID" can be found by any member who
  knows the iD (by design).

## 14. App and keys on the member's computer

The app runs as one process for each data directory: the local UI, the
index helper, and the background tasks (`anagram.shell.app`). The keys are in a
keystore with a master key in the keychain of the operating system
([identity.md](identity.md) section 16). The local databases are SQLCipher.
A design decision: a person who controls the running computer of a member
can read the data of that member; this is not a defect to solve for the
release.

What each party sees:

| Party | Sees |
| --- | --- |
| A person with a copy of the disk, without the account password | `config.json` (node, community, subject, public keys). Sizes and change times of `vault.sqlite`, `index.sqlite`, `keys/*.skey`, `ui.sealed`. `logs/app.log` (events, counts, source IDs, error classes). Plain files in `received/`. The model cache. No key, no token, no ring, no path |
| The same person with the account password, or a program in the signed-in account | Everything. The keychain gives the master key. The runtime file gives the control token, which gives a UI session |
| Another user account on the same computer | Nothing in the data directory (modes 0700 and 0600). On the loopback port, `GET /health`: that an Anagram app runs, and its version |
| A website in the browser of the member | It can ask the browser to open `anagram://join/<invite>`; the browser asks the member first. The result is a pending invite that the member must confirm. It cannot reach `/control/*` or `/api/*` |
| The node | No change |
| The update server (only a build with a manifest URL) | The IP address and the time of one request each day |

| Threat | Response | Test |
| --- | --- | --- |
| A copied disk gives the keys | Master key in the OS keychain; sealed key files bound to the name and the keystore ID; hex files of an old home are erased after the migration | `test_keychain.py::test_sealed_key_does_not_open_with_other_name`, `test_keychain_migrate.py::test_migrate_a_joined_home_and_the_client_works`, `test_stop_after_the_marker_erases_the_hex_files_at_the_next_open` |
| A copied disk gives ring names, recipients, or paths | `vault.sqlite` is SQLCipher | `test_vault_encrypted.py::test_vault_file_has_no_plaintext` |
| A copied disk gives the session or the invite | The session and the UI state are sealed | `test_home_at_rest.py::test_home_has_no_plaintext_secrets` |
| The recovery kit is next to the data | The kit is only a sealed item until the member saves it | `test_home_at_rest.py::test_join_writes_no_kit_file` |
| A keychain that is not available leads to new keys and lost data | `SlotLocked` stops the open; no fallback, no new key | `test_keychain.py::test_locked_slot_never_creates_keys` |
| A web page uses the control route | No `Origin`, `Cookie`, or `Sec-Fetch-Site` header permitted; the bearer is in a 0600 file | `test_app_control.py::test_control_refuses_browser_requests` |
| An open token is used again | One use, 60 seconds | `test_app_control.py::test_open_token_one_use` |
| A hostile invite through the URL scheme | Pending only, shown for confirmation, ignored when the home is joined | `test_open_url.py::test_open_url_join_is_pending_only`, `test_open_url_ignored_when_joined` |
| Argument injection through the URL scheme | One argument, prefix check, length limit | `test_open_url.py::test_open_url_rejects_options` |
| The log leaks names or content | Redaction filter, no access log | `test_app_runtime.py::test_log_has_no_canary` |
| A false update | Signed manifest, pinned release key, `https` links only, download and install by the member; no URL in the build means no request | `test_app_update.py::test_update_manifest_bad_signature`, `test_no_url_means_no_request` |

Known limits:

- A program in the signed-in account of the member reads all the data of
  that member (by design, see above).
- The operating system can write memory to the disk (sleep image, swap).
  Disk encryption (FileVault, BitLocker, LUKS) closes this gap.
- `config.json` and `received/` are plain files.
- Homes made before the release had plain hex key files. The migration
  erases them, but the erase is best effort on an SSD.
- An unsigned build changes its code identity at each build, so the keychain
  asks again. A signed build is necessary for the release.
- The update check has no release key and no URL until the update service
  is chosen; until then, the check is off.

## 15. Lab unit

A lab is a group of node members with a roster that the members sign, a lab
key for each epoch, and a lab space of encrypted records
([lab.md](lab.md); the [group roster](../docs/design/group-roster.md)
pattern). Code:
`network/formats/lab.py` (with `labkey.py`, `labitem.py`, `labsettings.py`),
`network/groups/app/labs.py` (with `labroster.py`, `labkeys.py`, `labrecords.py`),
`network/groups/app/labcache.py`, `network/groups/node/labs.py`, `network/groups/node/labdirectory.py`,
`network/groups/node/routes.py`; the lab invite and the join are in `admission/` ([admission.md](admission.md)).

What each party sees:

| Party | Sees | Does not see |
| --- | --- | --- |
| Node (disk and operator) | Lab ID and name; roster entries (person IDs, roles, device keys, times, who invited whom); invite authorisations and use counts; key packages as ciphertext (epoch, recipient, size); lab records as ciphertext (opaque ID, version, size, time, author); blob sizes; the change feed | Lab keys, invite seeds, item titles and text, files, settings, which model a lab uses |
| Organizer page | Counts and sizes for each lab | The same things as the node does not see |
| Lab member | All lab-space items, the settings, the roster | Private items of each other member |
| PI, admin | The same as a member, plus the invite list | Private items. No key path to them exists |
| Removed member | All that they got before the removal (it cannot be taken back) | Records of later epochs |
| Node member outside the lab | Lab ID and name | Members, roster, records |
| Public | Nothing new (no log entry) | |

| Threat | Response | Test |
| --- | --- | --- |
| The node adds itself or a person to a lab to get the key | Clients wrap the key only to subjects in a roster of member-signed entries; a node table row alone gives nothing | `test_lab_host.py::test_node_table_row_without_roster_entry_gives_no_access`, `test_lab_key.py::test_package_from_a_member_is_refused` |
| The node replays or forges a join | The join request needs the invite key; the seed never goes to the node; the chain counts the uses | `test_lab_formats.py::test_join_needs_invite_key`, `test_replayed_join_refused`, `test_invite_use_limit_in_chain`; `test_lab_host.py::test_join_needs_invite_key_on_node` |
| The node hides a removal from a member (an old epoch stays in use) | Pinned roster head; each lab record and key package names the head of its writer; a mismatch stops the client | `test_lab_space.py::test_fork_detected_from_record_head` |
| The node rolls the roster back or drops an entry | The client refuses a chain that does not extend its pinned head | `test_lab_client.py::test_shorter_chain_refused`, `test_dropped_entry_raises`, `test_forged_entry_raises` |
| The node swaps a device key of a member before a wrap | Device keys only from `lookup` with log proofs ([identity.md](identity.md) section 10); an entry must be signed by a device of its actor | `test_lab_formats.py::test_device_must_be_a_key_of_the_actor` |
| A member without the role writes settings | Readers check the role of the signer in the roster | `test_lab_settings.py::test_member_write_refused_by_readers` |
| A record of a person who is not a member | Readers drop it | `test_lab_space.py::test_record_from_a_non_member_author_is_dropped` |
| A removed member reads new items | A new epoch at once on `remove`; `leave` and a device loss rotate at the next PI or admin sync; the node refuses lab blobs to a person who is not a member | `test_lab_key.py::test_removed_member_cannot_open_the_next_epoch`, `test_lab_files.py::test_outsider_and_removed_member_get_404` |
| A removed member joins again (the same link, a new request, another open link, or a new account on the same device) and gets the new epoch key | Chain rules v2 ([lab.md](lab.md) section 2): `remove` records the person and the device keys of the person in the signed roster, and revokes each invite that the person made or used. Each client refuses a join of a removed person or a barred device, and a rotation wraps no key to a revoked invite. Only an explicit `add` by a PI or admin takes the person back. The node also refuses the join, a package for a revoked invite, and the invite package to a person who did not join with it. Limit: a removed person who has the seed of another open invite (one that the person did not use) and a node that breaks the rules can open the key package of that invite; the PI or admin revokes such a link | `test_lab_formats.py::test_removed_member_cannot_join_again_with_the_same_link`, `test_remove_revokes_the_invites_of_the_removed_person`; `test_lab_key.py::test_removed_joiner_cannot_come_back_with_the_same_link`, `test_node_refuses_the_join_of_a_removed_person` |
| A leaked invite link | The person who has it can join and read. Single use and 7 days by default. Each join shows to all members at once. Revoke, then remove (rotation) | `test_lab_formats.py::test_revoked_invite_refused` |
| A leaked lab invite makes node accounts | At most `max_uses` node members come in with one invite; revoke stops new ones; the organizer page shows the member count | `test_lab_host.py::test_lab_invite_member_limit` |
| A stolen device of an admin signs entries | The device must be active at the time of a new entry; a device removal ends its power and starts a rotation | `test_lab_key.py::test_pi_removes_a_device_and_the_lab_key_changes`, `test_device_reset_triggers_rotation` |
| A member lists the private blob of another person in a lab record | The node refuses a blob that the writer did not upload | `test_lab_files.py::test_a_record_cannot_list_the_blob_of_another_person` |
| The PI reads private items | No shared key exists. Private data uses the vault key of the person. Mail and private files do not go into the lab space | `test_lab_index.py::test_mail_and_files_do_not_go_into_the_lab_space` |
| The node or a copied disk reads the lab space | Records and keys are ciphertext on the node; the lab cache on the computer is SQLCipher | `test_lab_space.py::test_node_holds_no_plaintext`, `test_lab_key.py::test_node_holds_no_key_bytes`, `test_lab_client.py::test_cache_is_encrypted` |
| The organizer page shows lab content | Rows hold counts and sizes only | `test_admin_labs.py::test_rows_need_the_session_and_hold_no_content` |

End to end: `test_local_e2e_scenario.py::test_three_people_in_two_labs` (the
scenario of `deploy/local_e2e.py`: a new person joins with a lab link, the
lab space, a finding shared to the other lab with a read receipt, a matching
round with an introduction).

Known limits:

- The node learns the membership graph and the activity times.
- The node can withhold service or delay a rotation. The client shows
  `rotation_due`.
- A member can copy what they read. A removed member who kept old keys can
  still read the old epochs.
- A removed member who kept an old key can make an old-looking item only
  through a node that breaks the rules (the honest node refuses a non-member).
- The settings are enforced by honest clients only.
- The lab key is on the computer of each member. A person who controls the
  running computer of one member can read the lab space (by design,
  section 14).

## 16. Connected sources

Google Drive, Gmail, and Notion sources (`local/sources/oauth.py`,
`local/sources/credentials.py`; the
[installed-app OAuth](../docs/design/installed-app-oauth.md) pattern). The sign-in and
the reads go from the member's computer to the service. The node gets nothing
new: no token, no file name, no mail.

What each party sees:

| Party | Sees |
| --- | --- |
| The Anagram node | Nothing new. Checkpoint roots as before. The space of a source only through the lab space (section 15). |
| The PI | That a member has a source in the lab space. Nothing of a private source. Never a token. |
| Google, Notion, Zotero | The OAuth client, the account, the scopes, the IP address of the member, and each API request (which items the app reads, and when). Not the index. |
| The owner of the OAuth client (a lab admin with a lab client, or Radiofuture) | Request counts in the provider console. No token, no content. A Workspace admin can see in the audit log that the member gave access to the app. |
| A person who copies the disk | SQLCipher bytes and keychain entries that the copy cannot open. No plain cloud bytes: there is no spool file. |
| A person who controls the running computer of the member | Everything of that member, tokens too (by design, section 14). A stolen refresh token gives read-only access until it is revoked. |

| Threat | Response | Test |
| --- | --- | --- |
| A local web page or a second local process sends a forged OAuth callback | `state` (32 random bytes, constant-time compare), PKCE, a one-use receiver that binds to 127.0.0.1 only and stops after one request or 300 seconds | `test_oauth_receiver_*` |
| Another local app takes the authorization code | PKCE S256: the code has no value without the verifier | `test_pkce_vector`, `test_flow_with_a_stolen_code_and_no_verifier_fails` |
| A token leaks through a config, a log, an event, an error, or an answer | Tokens only in the keychain entry `acct-<account id>`; a write replaces the value with no copy | `test_token_never_leaves_keystore`, `test_connect_a_google_account`, `test_access_token_refreshes_near_expiry_and_erases_the_old_token` |
| A connector sends a token to a wrong host (redirect, bad plug-in URL) | `CredentialStore` gives a token only for the API hosts of the provider; the HTTP layer is HTTPS only and follows no redirect to another host | `test_token_host_allow_list`, `test_redirect_to_another_host_is_refused` |
| The client secret in the build or in the lab settings is public | Google documents that the secret of a desktop client is not confidential; the redirect is loopback only. For Notion the secret is a real secret: it is only in the build, or a lab uses its own integration. | — (documented limit) |
| A shared document or a received mail holds text that attacks a model, or leaks the words of another person | A Gmail message without the label `SENT` is received (fail closed); a Drive file whose owners do not include the member's address, or with no known address, is another person's (fail closed). The connector sets `extra.third_party` and gives a neutral name ("Received mail, <date>", "Attachment <n> of received mail, <date>", "Shared file, <date>"): the subject, the sender name, and the file name are text of the other person. The converter then puts all text of the item (subject, body, title, attachment text) in `context` chunks only (`local/understanding/third_party.py`). The item is not in `items(own_only=True)` (briefs, drafts, finding proposals), not in the timeline, refused by the lab space and by MCP `read_item`, and never goes to an external converter. A file in a shared drive has no owner: it is lab work and stays own text | `test_third_party_text.py`, `test_received_text_is_third_party`, `test_third_party_owner_is_marked` |
| A local `.eml` file or a sent reply holds the words of another person | The `.eml` converter: a message is own only with the source hint (`SENT`) or a sender in the owner addresses; no address or no sender gives third-party text (fail closed). In an own message, `>` lines and all text from the first quote marker (an attribution, also when it wraps; "Original"/"Forwarded message"; "Begin forwarded message:"; an Outlook underscore line; a "From:" header block with "Sent:", "To:", or "Subject:") are quoted. A subject with "Re:" or "Fwd:" is quoted | `test_third_party_text.py::test_quote_blocks_without_marks_are_quoted`, `test_the_owner_test_fails_closed`, `test_an_own_mail_keeps_its_text_and_quotes_a_reply_subject` |
| Mail of other people goes into the lab space | A Gmail source is private only | `test_gmail_space_private_only`, `test_kind_choices_follow_the_lab_policy` |
| A lab puts a kind of source into the lab space that its policy refuses | `SourcesUI` asks `LabPolicy.allows_source` before a lab space; a private source is never refused | `test_kind_choices_follow_the_lab_policy`, `test_space` |
| A raw path or an internal ID shows as the name of a source | Each source gets a label when it is made, and old labels are changed when the index opens (`local/sources/source_labels.py`) | `test_no_route_or_event_gives_a_path_as_a_label`, `test_old_labels_are_migrated` |
| Removal leaves data or a live grant | `remove_source` deletes the rows and revokes the grant when the last source of the account goes; the items that a finding keeps are shown to the person | `test_remove_source_deletes_all`, `test_the_account_is_revoked_with_its_last_source` |
| The member loses the device | The member removes the access at the provider (Google account page, Notion "My connections"). The personal store and the recovery kit hold `vault-key` and `index-key` only, not `acct-*` entries, so a recovered computer has no token and the member signs in again. | — (no test yet; the screen after recovery is checked by hand) |

Known limits:

- A Google client in testing gives refresh tokens that expire after 7 days.
  Until Google verifies a Radiofuture client for the restricted scopes
  a lab uses its own Google Workspace client
  ("Internal"; `docs/google-client.md`). Accounts outside that Workspace
  cannot sign in with it.
- The provider sees each read. Anagram polls; there is no push channel.

## 17. Understanding and model providers

Item kinds, the model layer, Ask, the timeline, and assistant access (MCP).
Details: [understanding.md](understanding.md). This part sends nothing to
the node.

What each party sees:

| Party | Sees |
| --- | --- |
| The Anagram node, the PI (as admin) | Nothing new. |
| A local model on this computer (Ollama) | Item text. Nobody else. |
| A university endpoint, Anthropic, OpenAI, OpenRouter and its pinned provider | Only excerpts of the sources with the opt-in for that model, the questions, and the passages of an answer. Lab text only if the lab allows the model. Never text that other people wrote. Never keys. |
| The person's AI assistant and the company that runs it (MCP) | The search results, passages, and item text that the assistant asks for, in the places that the person opened to that assistant, up to the daily limit. Never text that other people wrote. |
| Other lab members | Nothing from this part. Kinds, answers, and summaries are made on each computer. |
| A person who copies the disk | Nothing: the model config, the caches, the ask log, the assistant consent, and the facts are in the SQLCipher store; keys are in the keystore (section 14). The spend ledger is a plain file with model names, token counts, and costs only. |

| Threat | Response | Test |
| --- | --- | --- |
| Item text holds instructions for the model | Text goes in as escaped JSON data with the data rule; strict schema; enum kinds; output is a draft or a fact only | `test_index_understand.py::test_injected_item_does_not_change_the_enum_result`, `test_prompt_has_owner_text_only_as_data`, `test_index_ask.py::test_an_injected_passage_is_data` |
| A planted instruction that the detector does not recognise (another language, an order cut over lines, a table, a footnote, a quoted mail, a code comment) asks for a title, claims, a summary, or names | Layer 1, `local/understanding/extractive.py`: the model writes no free text into a kept fact. The title is a candidate that the code made from the item, chosen by number; a claim or the summary is an item sentence word for word that the output covers for 60 percent or more; a name must be in text that layer 1 accepts. The cache keeps only the defended answer | `test_index_extractive.py::test_an_order_the_detector_misses_puts_no_planted_word_into_a_kept_fact`, `test_with_detection_off_the_structure_alone_keeps_no_planted_word`, `test_purge_removes_cached_answers_with_free_model_text` |
| A planted instruction asks for a title, claims, or a kind, with words that are in the item (so they pass grounding) | Layer 2, `local/understanding/planted.py`: a sentence that gives orders to a model is a strong span: it does not go to the model, and a title or claim must ground in the other text. An answer that copies a strong span, or a new kind that a flagged span names, keeps no model fact (the rules stay). An output that copies a weak span is dropped | `test_index_planted.py::test_a_strong_order_does_not_reach_the_model_and_no_planted_title_is_kept`, `test_an_answer_that_copies_a_strong_span_keeps_the_rules`, `test_a_copied_weak_span_is_dropped_and_its_kind_is_not_kept` |
| A model puts words into a finding, a title, or an answer | Extractive outputs for titles, claims, names, and summaries (`local/understanding/extractive.py`); citation check for Ask and the timeline; an ungrounded summary is not kept; nothing stamps a finding | `test_index_understand.py::test_triage_extraction_and_grounding`, `test_index_ask.py::test_the_answer_streams_and_a_citation_outside_the_list_is_removed`, `test_index_digest.py::test_an_ungrounded_summary_is_not_kept` |
| A default sends text to a cloud | An external profile needs the opt-in for each source and an acknowledgement; a lab-space source also needs the lab policy; with no choice the default is a local model or no model | `test_models_base.py::test_check_model_needs_the_opt_in_for_an_external_model`, `test_index_understand.py::test_external_model_needs_the_opt_in_and_batches`, `test_lab_space_needs_the_lab_policy`, `test_ui_models_api.py::test_an_external_profile_needs_acknowledgement_key_and_source_opt_in` |
| An answer, a search, or a timeline leaks an item of a different space | The scope is applied in SQL; a lab scope never holds private items | `test_index_retrieve.py::test_a_word_in_two_spaces_is_found_only_in_the_asked_space`, `test_index_ask.py::test_no_scope_crossing`, `test_ui_ask_api.py::test_a_lab_scope_never_gives_private_passages`, `test_index_digest.py::test_a_lab_timeline_holds_lab_items_only` |
| Text that other people wrote (mail, its subject and attachments, quoted replies, Drive files of another owner) leaves this computer | Context chunks are a separate table; only a private scope finds them; no `understand` prompt, proposal, brief, external model, or assistant result gets them; an item that another person wrote has no own text, no title, and a neutral name (section 16) | `test_third_party_text.py::test_text_of_other_people_never_leaves_the_private_context`, `test_index_context.py::test_no_understand_prompt_proposal_or_lens_item_gets_the_text`, `test_index_ask.py::test_an_external_model_reads_only_the_passages_that_it_may_read`, `test_mcp.py::test_search_gives_own_text_of_open_places_only` |
| An injected assistant reads all of the index through MCP | Off by default; consent for each assistant; read-only tools; size limits; a daily limit of characters; a disclosure row for each source read; a lab space only with the lab permission | `test_mcp.py::test_off_by_default_and_after_removal`, `test_each_assistant_has_its_own_consent`, `test_the_daily_limit_stops_bulk_reads`, `test_a_lab_space_needs_the_lab_and_the_device`, `test_the_handshake_and_the_tool_list` |
| A web page changes the model or the assistant consent | All routes keep the local UI boundary | `test_ui_models_api.py::test_model_routes_obey_the_local_ui_boundary`, `test_ui_ask_api.py::test_routes_obey_the_local_ui_boundary`, `test_mcp.py::test_assistant_routes_obey_the_local_ui_boundary` |
| A provider key leaks | Keystore only; an overwrite leaves no old value; no route, event, config, error, or ledger row holds it | `test_ui_models_api.py::test_no_route_event_or_stored_config_holds_a_key`, `test_models_providers.py::test_errors_hold_no_key_and_no_body`, `test_models_profile.py::test_a_key_overwrite_leaves_no_old_value` |
| A paid endpoint has no price in its profile, so no gate counts its calls | A model with no price that is not on this computer runs inside `UsageGate` (calls and characters for each day); a cloud host with no price is refused until it has prices or a limit; the Anthropic SDK does not retry (the old research judge, outside the product, reserves again for each retry) | `test_models_profile.py::test_an_endpoint_with_no_price_never_skips_the_gate`, `test_models_paid.py::test_anthropic_sdk_does_not_retry_outside_the_reservation` |
| A provider bills more than planned | `Gate` reserves the upper cost before each call; no call without a budget, prices, and a key; the ledger halts on a breach | `test_models_paid.py::test_gate_stops_at_the_limit_before_the_call`, `test_gate_needs_budget_prices_and_a_ledger_inside_the_approval`, `test_gate_halts_when_the_provider_reports_more_than_the_reservation` |
| A remote "Ollama" address, or a key goes to a second host | Ollama is loopback only; a remote address is HTTPS only, follows no redirect, and is an external profile | `test_models_providers.py::test_ollama_refuses_a_remote_address`, `test_url_rules` |
| OpenRouter routes to an unknown provider | `route` is mandatory, with no fallback | `test_models_paid.py::test_openrouter_route_is_mandatory_and_pinned` |

Known limits:

- An assistant and its company keep what they read. Anagram cannot take it
  back. Removal of an assistant stops new reads only.
- The assistant id in the setup text names a consent. It is not a secret: a
  program of this user on this computer can start the server with it. Such a
  program can also read the index key (by design, section 14).
- The detection of planted instructions (layer 2) is a list of word
  patterns (English). An order in words that it does not know (or in another
  language) is at most a weak span. Layer 1 (extractive outputs) stops new
  words, but an order that the detector does not flag can still change the
  kind (in the closed set), and can choose which real text of the item is the
  title, a claim, or a name: for example a short planted sentence near the
  start, or a planted sentence that is the payload itself. That text is in
  the person's own item word for word. The rates were measured with local
  models in a research harness outside this repository (2026-11-16).
- A planted instruction can still change the free text of an Ask answer or of
  an assistant answer. The citation check removes numbers outside the list;
  it does not prove that a sentence follows from its passage.
- The "What leaves this computer" list shows the general model row. The rows
  for each selected external profile (`models/recipients.flow_rows`) are not
  on that screen yet; the Account screen names the recipient of each profile.

## 18. Sharing, guests, and read records

To be written.

## 19. Matching for the release

Node-run matching was removed on 2026-11-26. The matching enclave of
the network is the only matching path. The node relays sealed messages and
holds no matching key. The threats and responses of the enclave are in
[enclave-messages.md](enclave-messages.md) section 11 (what each party
learns) and [enclave-trust.md](enclave-trust.md); docs/enclave.md lists
what the `simulated` profile does not protect.

| Threat | Response | Test |
|---|---|---|
| The node reads matching lines | The app seals each request to the attested enclave key; the relay checks only the length | `test_enclave_service.py::test_the_node_checks_lengths_and_forms`, `test_net_vectors.py::test_receipt_filler` |
| A node floods people with proposals from fake members | max(1, ceil(m / 50)) proposals from one node in 4 weeks; m counts only packs with a verified credential | `test_enclave_funnel.py::test_fifty_fake_members_of_one_node_get_one_proposal_in_four_weeks`, `test_m_counts_only_packs_with_a_verified_credential` |
| A reveal goes to one side only | Both-or-neither release of the slots | `test_enclave_services.py::test_both_or_neither_reveal` |
| A person keeps a one-sided proposal because the peer's copy waited too long | A pair is proposed only when both queues can deliver the copy before the first checkpoint; the other pairs wait | `test_enclave_funnel.py::test_cap_10_with_answer_day_7_never_gives_a_one_sided_proposal` |

Known limits:

- In the `simulated` profile (the only profile of the release), the
  operator of the enclave can read every pack, card and answer. The
  consent names the operator as a reader.
- The node sees the times and sizes of sealed requests and slot reads.
- A wrong match shows a card to a person who cannot help.
- After a reveal, the cards are outside Anagram. Anagram cannot take them
  back.

## 20. Live local UI

The local UI (`anagram.shell.ui`) keeps the local UI boundary
([local UI boundary](../docs/design/local-ui-boundary.md)). The release
adds a render layer and a live event stream
([live local UI](../docs/design/live-local-ui.md)). What each party can see
does not change.

| Change | Effect | Control |
|---|---|---|
| `GET /api/events` (Server-Sent Events) | A second way out of the UI process, to the same page. | The same guard and cookie as each `/api/` route. No CORS. No WebSocket. The buffer of events is in memory only. |
| Event data | An event can go to a log or a screenshot. | Events carry IDs, counts, and states, never a file path or the content of a file. Tests check that no path of a source is in an event. |
| Source event bridge | A thread reads `source_event` while a page is open. | It reads only while the bus has a subscriber, with its own connection (`open_client`). It publishes the rows as they are. |
| Import map hash in the CSP | One inline block is allowed. | The hash is of fixed text; a test compares it. No `unsafe-inline` for scripts or styles. |
| Vendored code (Preact, htm, signals) runs on the page that holds plaintext | Supply chain. | Pinned versions and SHA-256 hashes in `vendor/manifest.json`; a test checks the files; one module imports them. The code is readable in review. |
| Text on the page | A name or a title can hold markup. | All text goes in as text. No HTML sink (`innerHTML` and the like); a test checks the code. |
| Screenshots in tests | Images can hold names and file names. | Demo data only. Screenshots are saved only when `ANAGRAM_UI_SHOTS` names a folder. |

Known limit: the page shows the folder name of a source as its label. A
folder name can be private; it stays on this computer.
