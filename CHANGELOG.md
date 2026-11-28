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

### Fixed

- The vector makers took `--help` as an output folder and wrote vector
  files into `./--help/`. They now print help.
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
