# Anagram

Anagram helps researchers find the few people whose work fits with their own,
without exposing unpublished plans.

You run a local app on your own files, join an invite-only research community,
and let a private matching service compare what people need and can offer across
communities. Nobody learns a name unless both people say yes. Anagram also
creates **priority proofs**: signed, timestamped proofs that you had a result by
a date, revealing only what you choose.

> **Early development: do not use for real unpublished plans yet.** Today,
> matching runs in a local/simulated test mode without hardware privacy, so
> whoever hosts it can read summaries and answers. See
> [Privacy: design vs. today](#privacy-design-vs-today) and
> [docs/enclave.md](docs/enclave.md).

## Try the demo (~2 minutes)

Requires [uv](https://docs.astral.sh/uv/) (0.7.20+; installs Python 3.13
automatically). No account, AI model, or Docker needed:

```sh
git clone https://github.com/radiofuture/anagram
cd anagram
uv sync
uv run anagram demo up --dir /tmp/anagram-demo --ready --day-seconds 60
```

Open Mei-Lin Chen's printed link, join, save the recovery kit, open **Network
matching**, and click **Approve and start matching**. A proposal arrives in 60
seconds, and the introduction follows after you say yes. Stop anytime with
`uv run anagram demo down --dir /tmp/anagram-demo`.

- **Full demo guide** (all 4 researchers, multiple nodes): [docs/demo.md](docs/demo.md)
- **Run your own local app:** `uv run anagram` -> [docs/install.md](docs/install.md)
- **Timestamp a file from the CLI (priority proofs):**
  `uv run anagram init && uv run anagram commit data.csv --claim "X binds Y"`
  -> [docs/priority-proofs.md](docs/priority-proofs.md)

## How it works

1. **Your app reads your work locally.** Connect folders, Git repos, Zotero
   exports, or ORCID works. The app indexes them on your computer and drafts
   short summaries of what you need and offer; you edit and approve them and
   pick match types (such as method help, data sharing, or instrument access).
2. **You join an invite-only community.** A lab, university, or organizer runs a
   small server (a *node*) that stores only encrypted backups and relays sealed
   messages it cannot read.
3. **A private matching service proposes pairs.** Your approved summaries are
   sealed to the matching service (an *enclave*), which compares people across
   communities and sends proposals showing only the match type and your own
   summaries.
4. **Mutual consent only.** Answer yes, not now, or no. Only when both people
   say yes do you see each other's name, affiliation, and contact details;
   otherwise neither side learns anything. See
   [docs/matching.md](docs/matching.md) for default matching rules.

Anagram is free and open source, using a local model via
[Ollama](https://ollama.com) by default or your own API key behind a spend cap.

## Privacy: design vs. today

Designed to guarantee:

- **Files stay local.** Only summaries you approve leave your computer, and the
  app lists every outbound flow.
- **Community servers stay blind.** Nodes store encrypted backups and relay
  fixed-size sealed messages.
- **Auditable, mutual-only reveals.** The enclave logs every state change to a
  witness-signed public log, and names reveal on both sides or neither.

Not true today:

- **No hardware privacy yet.** Matching runs only in a `simulated` test profile
  with dev keys, not a confidential VM, so the host operator can read summaries
  and answers (and holds all witness keys in dev networks).
- **Simulated demo matching.** Demo matchers illustrate the flow, not real match
  quality.

Details: [docs/enclave.md](docs/enclave.md) and [SECURITY.md](SECURITY.md).

## Documentation

| Audience | Guides |
| --- | --- |
| **Researchers** | [Install & setup](docs/install.md) · [Demo guide](docs/demo.md) · [Matching rules](docs/matching.md) · [CLI priority proofs](docs/priority-proofs.md) · [Google Drive & Gmail](docs/google-client.md) |
| **Server operators** | [System architecture](docs/architecture.md) · [Run a node](docs/deploy.md) · [Local Docker test](docs/local-test.md) · [Enclave guide](docs/enclave.md) |
| **Contributors** | [Contributing & layout](CONTRIBUTING.md) · [Indexer & plug-ins](docs/indexing.md) · [Design notes](docs/design/README.md) · [Protocol specs](spec/README.md) |

## Contributing, Security & License

- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md),
  [Code of Conduct](CODE_OF_CONDUCT.md), and [CHANGELOG.md](CHANGELOG.md).
- **Security:** Report vulnerabilities privately via GitHub's **Security** tab
  (3-working-day reply); see [SECURITY.md](SECURITY.md). Simulated-enclave
  visibility is a known limit, not a vulnerability.
- **License:** Code under MIT ([LICENSE](LICENSE), [NOTICE](NOTICE));
  specifications in `spec/` under [CC BY 4.0](spec/LICENSE.md).
