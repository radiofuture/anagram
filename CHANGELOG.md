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
- **Local OCR with Datalab Indra.** Added optional `IndraConverter` (`name = "indra"`,
  `external = False`) for 100% local CPU / Apple Silicon ONNX OCR of PDFs and
  images (`PNG`, `JPEG`, `WebP`, `TIFF`) via `indra-ocr`, rendering pages in
  memory with `pypdfium2`/Pillow (zero plaintext temp files), emitting
  `Span(page=..., bbox=...)` blocks, and falling back automatically to
  `markitdown` and `basic` when unavailable or offline without cached weights.
- **Native `.ipynb` and `.tex` extraction.** Added stdlib-only extractors for
  Jupyter notebooks (`application/x-ipynb+json` — markdown cells, fenced code
  cells, and concise plain-text outputs with binary/base64 blobs skipped) and
  LaTeX manuscripts (`text/x-tex` — title/author/abstract extraction, preamble
  and `%` comment stripping, section headings, inline macro unwrapping, and
  compact math preservation).
- **Project tooling.** CI checks, type checks on a strict set, coverage
  floor, dependency audit, secret scan, pre-commit hooks, Dependabot, and the
  contributor, security and conduct files.
- **Ambient matching profile and real enclave engines.** Enforced `TrustPolicy`
  tier filtering in `EnclaveUI` beacon drafting so `private`-tier items never
  leak into drafts; added persistent `lens_cache` SQLite caching and batched
  per-document LLM synthesis in `ProfileLens`; added one-time opt-in ambient
  consent (`mode: "ambient" | "manual"`) with non-blocking background line
  updates from indexed work, direct line removal with `excluded_lines`
  suppression, a quiet switch back to manual lines, and a local decline-archive
  helper; wired fail-closed `pack.v1` `deny`, `block` (refusing over-limit
  combined lists instead of truncating), per-type `charter.rules`, and
  `MAX_LINES = 10` in `EnclaveMatching`; preserved credential `kind` in
  `Matching._member` and unified `T1` (`research_fit`); added stage-1
  `min_score` filtering, class-contextualized line embeddings, offline
  `OnnxEmbedder` (`local_files_only=True`, `HF_HUB_OFFLINE=1`), SHA-256 weight
  file fingerprinting (`fingerprint_model_path`) verified against release
  descriptors, and deterministic in-enclave `LlmJointJudge` (in-process runtime
  or strictly loopback-only HTTP with `follow_redirects=False` and
  `trust_env=False`, opt-in via `ANAGRAM_ENCLAVE_ENGINE=real`, keeping
  `simulated_engines` as the default).

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
- **Invite sign-in hardening.** Removed the unauthenticated `rejoin_ok`
  shortcut for already-bound devices on `POST /auth/invite` (active devices now
  authenticate via device sign-in); pre-binding retries require proof of
  possession of the initial device key and an open invite. Added per-address
  rate limiting on `POST /auth/invite`, required an `invite_pub` signature
  proving the lab invite seed, and deferred stated-email uniqueness claims
  until admission.
- **RFC 3161 and OpenTimestamps anchor verification.** Enforced full RFC 5280
  CA `BasicConstraints`, `pathLenConstraint`, `KeyUsage.keyCertSign`,
  intermediate `ExtendedKeyUsage`, non-CA leaf, and cycle checks in RFC 3161
  chain verification, and keyed RFC 3161 anchor sources on the pinned root CA
  fingerprint. Normalized OpenTimestamps anchor sources to
  `opentimestamps:bitcoin` regardless of block height and allowlisted calendar
  URIs to configured `https://` calendars during upgrades.
- **Merkle proof length validation.** Required 32-byte hashes for all leaf,
  root, and path elements in Merkle inclusion and consistency proofs (and the
  empty tree root when `old_size == 0`), closing 64-byte split attacks across
  proof bundles, witnesses, and client log checks.
- **SMTP, email, ORCID, and node identity hardening.** Passed an explicit
  default TLS context to `SMTP.starttls()`, enforced strict single `addr-spec`
  email validation with explicit `to_addrs=[to]`, serialized email code rate
  limiting with challenge creation, released `identity.lock` across ORCID OAuth
  token exchanges with atomic callback completion and attempt caps, made
  `IdentityService.key_state()` read-only, wrapped invite claims in atomic
  transactions, enforced key backup size/count limits, and verified signatures
  in `NodePersonalStore.put_person_keys()`.
- **Models and spend gate.** Rejected zero-price or non-sequence price tuples,
  non-positive ledger reservations, and lab profiles undercutting built-in
  model price tables; included canonical sorted OpenRouter `route` in
  `profile_id` and `same_party`; halted the spend ledger on invalid, negative,
  or non-finite provider-reported costs and clamped negative token counts;
  disabled external proxies and HTTP redirects for `OllamaClient` and loopback
  model transports.
- **Local sources, extractors, and understanding.** Blocked Git `rev` argument
  injection (`--end-of-options`), Google Drive query injection via strict folder
  ID validation and escaping, cross-host redirects and URL path injection in v1
  source connectors, decompression bombs in PNG/PDF/Office/ZIP extraction, and
  symlink reads in local file ingestion and repo summaries; enforced scope,
  source/lab opt-in, third-party exclusion, stripped quoted text, and
  disclosure logging across drafters, external enrichers, and failed external
  ask/digest calls; fixed `TrustPolicy.item_tier` folder prefix boundaries,
  Obsidian fail-closed private frontmatter and >4 MiB privacy checks, and
  `0o600` permissions / leftover journal cleanup for `index.sqlite`.
- **MCP gateway.** Rejected expired grant bearer keys at HTTP auth, duplicate
  `Host` headers, and reads from sources being removed; made grant updates,
  daily character quota enforcement, `acts.decide`, and `propose_lines`
  rollback transactional.
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
- Stopping the local app or demo no longer waits 5 seconds for an in-flight
  `lab.watch` `/labs/changes` long-poll to time out; shutdown cancels the
  poll immediately.
- Hardened core validators (`\Z` regex anchors, strict 64-char lowercase hex in
  `ContentDigest.from_json()`, `FormatError` on invalid calendar dates in
  `parse_time()`, and Windows guard in `fsync_dir()`).
- Checked subject match before writing session tokens in `join()`, guarded
  `.old` key erasure to single-link inodes (`st_nlink == 1`), wrote configs,
  recovery kits, and restored snapshots atomically with `0600` permissions,
  stopped skipping 1–4 MiB vault records in `PersonalStore._pull()`, and
  hardened guardian recovery against duplicate share indices and missing
  temporary keys.
- Used `SharedDB` with `BEGIN IMMEDIATE` in `Witness`, enforced canonical
  base64 checkpoint roots, enforced streaming body size caps on `/verify`,
  `/proofs`, and `/log/entries`, excluded non-open reader invites from
  `open_invites()`, and fixed `verify.js` crashes on empty `other_node`,
  overwritten `no_crypto` notices, and malformed content digests.
- Production nodes (`anagram node start` and `anagram node init`) now allow
  starting without ORCID credentials (omitting both client ID and secret
  disables ORCID sign-in cleanly and hides the ORCID form on `/admin`),
  default `forwarded_allow_ips` to `127.0.0.1`, and disable raw access logs
  while preserving structured ticker fields.
- Hardened `/admin` login and passkey options against ORCID enumeration,
  missing `Origin`, brute-force floods, and logout CSRF; hardened
  `/auth/orcid/callback` redirect headers, UI `/auth/callback` state checks
  (with a join cancel route), node-supplied redirect URL validation,
  `received_file` path traversal/symlink checks, `Content-Disposition` header
  escaping, systemd/XDG `%` and newline escaping, `Client.close()` cleanup,
  Windows PID checks, Caddy environment isolation in `deploy/compose.yaml`,
  and macOS packaging (`entry.py`, `anagram.spec`, `build.sh`).
- Improved local app onboarding, model setup, live "What leaves this
  computer" flow status, deep-linking to `#/account#models-title`, optional
  institution entry, copy polish across screens, and confirmation dialogs for
  destructive actions.
- Summed token counts and costs across both billed attempts on `OpenAICompatModel`
  `text`-mode retries.
- Prevented `remove_source` foreign-key failures when items have `kind_override`
  rows, preserved existing OAuth `refresh_token` on re-grant, prevented
  concurrent `Streams.checkpoint` overwrites, and fixed `ProfileLens` cache
  keying on `published` sets and error handling.
- Fixed `Gateway` multi-client HTTP/1.1 concurrency via `ThreadingHTTPServer`
  with request timeouts, `IndexStore` nested `SAVEPOINT` transactions,
  `vec_store` search loop termination, RFC 2822 email date parsing, Git `\x1e`
  commit parsing, Gmail label add/remove history sync, Notion empty timestamp
  and stop handling, `LoopbackReceiver` IPv6/timeout cleanup, stranded
  understanding job recovery, redacted error logging, and `after_scan` ordering.
- **Enclave reliability & matching.** Prevented writer crash/restart before
  epoch cosigning from emitting conflicting epochs or deadlocking the log;
  fetched covering checkpoints during incremental `LogFollower.follow()` and
  verified checkpoints when `size <= len(view.entries)`; persisted and
  restored `max_seen` across restarts and takeovers; handled non-positive
  stage-1 cosine scores in `_reasons()` and validated judge candidate types;
  rejected non-release entry digests cleanly in `accept_release()`; and
  cleaned up user-facing error messages in `EnclaveMatching`.
