# Changelog

All notable changes to Anagram are in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version is in `src/anagram/core/version.py`.

## [0.1.0] - Unreleased

The first release for labs, and private matching through a network enclave.

### Added

- **Priority proofs.** Commit evidence (any files) and an optional one-line
  claim. A transparency log records only a hash, witnesses cosign it, and
  timestamps anchor it (RFC 3161, OpenTimestamps). A proof or a one-page
  certificate shows that you had the work no later than a date, and opens
  only the files that you choose. Anyone can verify it with the pinned public
  keys, without a node.
- **The lab app.** One local app for each person, with a web UI on
  `127.0.0.1` only. It connects to sources (folders, Git repositories,
  Zotero, ORCID works and more), indexes them in the background, and
  identifies findings and notes. All stored data is encrypted. Each person
  has a private space; the lab has a shared space. People search and ask
  questions of their own material. Drafts can become a preprint package.
- **Community nodes.** A Docker deployment with Caddy (automatic HTTPS) and
  an organizer page. Entry is by invite only; an ORCID iD is optional. The
  public log shows a random person ID, never an ORCID iD.
- **Sharing.** Share a finding with a ring of people. The app encrypts each
  file for that finding version; the node stores only ciphertext. Anagram
  records the share and the read.
- **Recovery.** A recovery kit and guardians restore keys, findings and the
  index on a new computer from the encrypted personal store.
- **Matching through the network enclave.** People approve their lines
  (what they offer, what they want) and give consent. Their app seals each request to the enclave key; nodes see only
  fixed-size sealed messages. The enclave writes each state epoch to a
  transparency log that 3 witnesses cosign. A match is revealed to both
  people or to neither, and a person can withdraw. The enclave restarts from
  sealed state and fails over to a standby writer. `anagram demo up` runs
  the whole network on one computer, with no Docker.
- **Specs and vectors.** The wire formats and protocols are in `spec/`, with
  test vectors that an independent implementation can check.
- **Project tooling.** CI checks, type checks on a strict set, coverage
  floor, dependency audit, secret scan, pre-commit hooks, Dependabot, and the
  contributor, security and conduct files.

### Removed

- **Matching on the node.** A node no longer runs a matching
  room: no operator keys, no `/room` routes, no `anagram match` or
  `anagram node round close` commands, no `ANAGRAM_MATCH_*` settings, and
  no brief or People screens. The matching enclave is the only matching
  path; a node only relays sealed messages to it. The assistant act
  `propose_brief` is now `propose_lines` (a draft of the matching lines).

### Security

- The matching enclave runs only in the **simulated profile**. It gives no
  confidentiality from the host operator. The hardware (TEE) profile is not
  in this build. See [SECURITY.md](SECURITY.md) and
  [docs/enclave.md](docs/enclave.md).
- **Enclave transparency log & handoff hardening.** Enforced signer
  authorization, line/epoch invariants, and immutable `(line_id, instance_id)`
  output-key binding in `TransparencyLog.append()` and
  `append_instance_key()`; rejected low-order X25519 `reply_key` and
  `response` keys before state mutation and isolated slot-sealing failures;
  verified control-chain signatures before recording `seen` or marking forks;
  fixed `Network.removes()` so bans, node removals, and credential revocations
  still erase previously moved subjects; tightened `accept_hand_off()` role
  and line checks, self-handoff refusal, and per-successor standby tracking;
  required fresh user approval when `statement_hash` or `descriptor_set`
  changes; and enforced certificate validity windows, CA `BasicConstraints`/
  `KeyUsage`, and SEV-SNP `launch_tcb` floors across AMD, Intel, and GCP
  attestation verifiers.
- **Lab & sharing access hardening.** Required `settings` permission on
  `topic="settings"` writes, transferred stored `author` on settings updates,
  bounded record version jumps, enforced monotonic `roster.seq` and exact
  `from_seq` keeper checks on clients, refused writes to closed labs, revoked
  member invites on `leave`, wrapped multi-table `ReadLedger`/`NodeVault`
  writes in transactions under locks, checked `grant_id` via `gated_call` in
  `Grants.fetch_payload()`, disallowed `image/svg+xml` in reading-copy
  figures, and bounded ZIP figure decompression.

### Fixed

- The vector makers took `--help` as an output folder and wrote vector
  files into `./--help/`. They now print help.
- **Enclave reliability & matching.** Prevented writer crash/restart before
  epoch cosigning from emitting conflicting epochs or deadlocking the log;
  fetched covering checkpoints during incremental `LogFollower.follow()` and
  verified checkpoints when `size <= len(view.entries)`; persisted and
  restored `max_seen` across restarts and takeovers; handled non-positive
  stage-1 cosine scores in `_reasons()` and validated judge candidate types;
  rejected non-release entry digests cleanly in `accept_release()`; and
  cleaned up user-facing error messages in `EnclaveMatching`.
