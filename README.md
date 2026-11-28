# Anagram

Anagram is a coffeehouse for frontier science. It helps researchers find the
few people whose work fits with their own, without showing their plans to
anyone else.

Each person runs a local app that reads and understands their own work. Labs,
universities or single people run small, invite-only servers called
**nodes**. A sealed **matching enclave** looks across all nodes and proposes
pairs of people who can help each other. Nobody learns a name unless both
people say yes.

Anagram also makes **priority proofs**: signed, timestamped proofs that you
had a result no later than a date, which show only the parts that you choose.

> **Status: early, not for real research plans yet.** Today the matching
> enclave runs only in a *simulated* mode for development and tests. Read
> [What we promise, and the limits](#what-we-promise-and-the-limits).

## Quick start (30-second demo)

You need [uv](https://docs.astral.sh/uv/) (0.7.20 or later); it installs
Python 3.13 for you. The local web app (`uv run anagram`) runs on macOS and
Linux; the packaged `.app` bundle is macOS-first, and community nodes run on
Linux in Docker.

```sh
git clone https://github.com/radiofuture/anagram
cd anagram
uv sync
```

| Goal | Start here | Time |
| --- | --- | --- |
| **Try the simulated demo** | `uv run anagram demo up --dir /tmp/anagram-demo --ready --day-seconds 60` | ~2 min (1 tab) |
| **Run your own local app** | `uv run anagram` | Immediate |
| **Make a CLI priority proof** | `uv run anagram init && uv run anagram commit data.csv --claim "X binds Y"` | ~1 min |

### Try the simulated demo

Starts a local node, a `simulated` matching enclave network, and 4 invented
researchers on your computer. No account, no model, no Docker, and no network
are needed. With `--ready`, three researchers are already set up and matching,
leaving only Mei-Lin Chen for you in a single browser tab:

```sh
uv run anagram demo up --dir /tmp/anagram-demo --ready --day-seconds 60
```

Open the printed link for Mei-Lin Chen, join, save the recovery kit, open
**Network matching**, and click **Approve and start matching**. A proposal
arrives on the next demo day (60 seconds), and a reveal follows after you say
yes.

- **All 4 tabs yourself:** drop `--ready` (`uv run anagram demo up --dir /tmp/anagram-demo`).
- **Several nodes:** add `--nodes 2` or `--nodes 3` to match across local nodes.
- **Stop:** `uv run anagram demo down --dir /tmp/anagram-demo`

Full walk-through: [docs/demo.md](docs/demo.md).

### Run your own local app

```sh
uv run anagram
```

Starts the local web UI on `127.0.0.1` and opens your browser with a one-time
link. Your data stays in `~/.anagram` (use `--home DIR` for another folder).

Optional extras:

- `uv sync --extra node` — required to run a community node or enclave process
  (not needed for the local app alone).
- `uv sync --extra anthropic` — required to use Anthropic as a model provider.

### Make a CLI priority proof

Run these from the `anagram` folder (or pass the full path to any file):

```sh
echo "sample,value" > data.csv                       # any file of your results
uv run anagram init                                  # keys and a local test node
uv run anagram commit data.csv --claim "X binds Y"   # prints the proof file name
uv run anagram verify anagram-*.proof.json           # VALID ...
uv run anagram list                                  # your findings: time, finding id, version, root
uv run anagram certificate <finding id>              # one HTML page that holds the proof
uv run anagram verify anagram-certificate-*.html --file data.csv
```

The local test node uses a **fake time anchor** (`verify` flags this; a real
node uses independent anchors). If `init` reports a locked or unavailable
keychain (for example over SSH), run `uv run anagram --plain-key-files init`.
Run `uv run anagram --help` to see all commands.

## How it works

1. **Your app reads your work.** You connect folders, Git repositories,
   Zotero exports or ORCID works. The app indexes them on your computer. A
   model of your choice (local by default) drafts a few short **lines**: what
   you need and what you can offer. You edit them and approve them. You also
   choose the **match types** you want, for example method help, data or
   material share, instrument access, replication, co-supervision or a
   research fit.
2. **You join a node by invite.** A lab, a university or one person runs the
   node. Entry is by invite only. The node stores only encrypted data for its
   members.
3. **The enclave proposes matches.** Your app seals your approved lines to
   the enclave key. The node passes on sealed messages of a fixed size; it
   cannot read them. The enclave compares people across all nodes and sends
   each person a few proposals. A proposal shows the match type and your own
   lines, not the other person.
4. **Both say yes, or nobody learns anything.** You answer yes, not now, or
   no. If both people say yes, each sees the other's **card** (name,
   affiliation and how to make contact). If not, neither side learns who the
   other person was, or what they answered.

```
 your computer            your node                 matching enclave
+--------------+  sealed  +-------------+  sealed   +-------------------+
| Anagram app  | -------> | lab / uni / | --------> | compares people   |
| (your files, |          | person      |           | across all nodes  |
|  your model) | <------- | invite only | <-------- | proposes pairs    |
+--------------+ proposal +-------------+           +-------------------+
        |
        v
  both say yes  -> each sees the other's name and card
  anything else -> nobody sees anything
```

### The default rules

- You get at most **3 proposals a week**. You can change this from 1 to 10.
- You have **21 days** to answer a proposal.
- A **"no"** stops the enclave from proposing the same pair again for **that
  match type** for 365 days. The same pair can still match for a different
  type.
- One node can send you only a few proposals: at most one for each 50 of its
  matching members, every 4 weeks (minimum 1). This limit stops a node that
  makes fake members.
- Your answer stays private. The other person sees the same thing for "no",
  "not now" and no answer.

## What we promise, and the limits

What Anagram is designed to give:

- Your files stay on your computer. The app sends only what you approve, and
  the "What leaves this computer" page in the app lists each flow.
- Your node sees only encrypted data and fixed-size sealed messages.
- The enclave writes each change of its state to a public log that
  independent witnesses sign, so a hidden change of code or rules shows.
- Names are shown on both sides, or on neither side.

What is **not** true today:

- **The enclave runs only in the `simulated` profile.** It is an ordinary
  process. Its attestation is signed by a development key. **The operator of
  the host can read every summary and every answer.** The hardware profile
  (a confidential VM with real attestation) is not in this build. We do not
  claim the hardware privacy promise until it passes a real
  confidential-VM test.
- In a development network, one operator holds all the witness keys.
- The demo matching uses simulated engines, not a real model, so the
  matches show the data flow, not good quality.

Until the hardware profile ships, do not use Anagram for real, unpublished
research plans. Details: [docs/enclave.md](docs/enclave.md) and
[SECURITY.md](SECURITY.md).

## Documentation

| Audience | Guides |
| --- | --- |
| **Researchers** | [Install the app](docs/install.md) · [Demo walk-through](docs/demo.md) · [Google Drive & Gmail setup](docs/google-client.md) |
| **Node & network operators** | [Run a community node](docs/deploy.md) · [Test a Docker deployment locally](docs/local-test.md) · [Matching enclave operator guide](docs/enclave.md) |
| **Developers & protocol readers** | [Contributing & checks](CONTRIBUTING.md) · [Background indexer & plug-ins](docs/indexing.md) · [Design notes](docs/design/README.md) · [Protocol specifications](spec/README.md) |

## Develop

Install all extras and hooks with `uv sync --all-extras && uv run pre-commit install`,
then run the test and lint checks listed in [CONTRIBUTING.md](CONTRIBUTING.md).
Key rules: change the spec before wire behaviour, never modify existing files
in `spec/vectors/`, and import across layers only through each layer's `api.py`
(`tests/test_layers.py`).

## Project layout

```
src/anagram/
  identity/    person IDs, device keys, sign-in, recovery
  local/       sources, the encrypted index, understanding, your vault
  network/     labs, sharing, matching (the enclave is in network/matching/enclave/)
  admission/   invites and who can join a node
  core/        crypto, canonical JSON, signed documents
  proofs/      the log, proof bundles, time anchors, certificates
  models/      model providers and the spend gate
  gateway/     the MCP server for your own AI assistant
  shell/       the CLI, the local UI, the node app
  web/         static pages (reader, verify page)
  sim/         the synthetic community for the demo and tests
spec/          wire formats and test vectors (the protocol)
docs/          guides for members and operators
deploy/        Dockerfile, Compose files, Caddy, end-to-end tests
packaging/     the macOS app build
tests/         the test suite
```

A layer imports only the layers below it, and only through their `api.py`.
`tests/test_layers.py` checks this.

## FAQ

**Can my node read my research?**
No. The node stores only ciphertext and fixed-size sealed messages. It knows
who its members are, but not what they wrote or whom they match.

**Can the enclave operator read it?**
Today, yes. The simulated enclave gives no protection from the person who
runs the host. That is the reason for the warning above. The hardware
profile is designed to stop this, and we will say when a real test passes.

**Which models and agents work?**
For understanding your work: a local model through
[Ollama](https://ollama.com) (the default, if it runs on your computer), any
OpenAI-compatible address (also OpenAI and OpenRouter), or Anthropic (requires
`uv sync --extra anthropic`). You choose. Your own AI assistant (for example
Claude Desktop, or any MCP client) can connect through `anagram mcp` on your
computer; it supports read tools plus draft proposals (such as matching lines)
that wait for your explicit approval in the app. You approve each assistant
and what it can access.

**What does it cost?**
The software is free and open source. A local model costs nothing. With a
cloud model you use your own API key and pay the provider; Anagram refuses a
paid call unless you set a budget or a limit. A node needs one small server
and a domain name.

**Do I need an ORCID iD?**
No. The invite is the proof. You can link an ORCID iD later.

**What if I lose my computer?**
Save the recovery kit when you join. You can also name recovery guardians
(for example 2 of 3 colleagues). Your node keeps an encrypted copy of your
findings, so a new computer gets them back.

## License

Code: MIT License, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Specifications in `spec/`: [CC BY 4.0](spec/LICENSE.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## Security

Do not open a public issue for a vulnerability. Report it privately on
GitHub: the **Security** tab, then **Report a vulnerability**. We reply
within 3 working days. See [SECURITY.md](SECURITY.md). A report that the
simulated enclave is not confidential is a known limit, not a vulnerability.
