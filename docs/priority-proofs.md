# Priority proofs (CLI)

Anagram can create **priority proofs**: signed, timestamped proofs that you had
a file or research claim no later than a given date, revealing only the parts
you choose. You can create and verify proofs directly from the command line
without running the local web UI.

## Quick walk-through

First install dependencies from the repository root (`uv sync`). Then run these
commands from the `anagram` folder (or pass the full path to any file):

```sh
echo "sample,value" > data.csv                       # any file of your results
uv run anagram init                                  # keys and a local test node
uv run anagram commit data.csv --claim "X binds Y"   # prints the proof file name
uv run anagram verify anagram-*.proof.json           # VALID ...
uv run anagram list                                  # your findings: time, finding id, version, root
uv run anagram certificate <finding id>              # one HTML page that holds the proof
uv run anagram verify anagram-certificate-*.html --file data.csv
```

What each step does:

- `anagram init` generates your local keys and sets up a local test node.
- `anagram commit` hashes the file, attaches your claim, commits it to the log,
  and writes a portable `.proof.json` bundle.
- `anagram verify` checks the signatures, log inclusion, and time anchor of a
  proof bundle or certificate (and checks a file hash when `--file` is passed).
- `anagram list` shows your recorded findings with their timestamps, finding
  IDs, versions, and roots.
- `anagram certificate` exports a self-contained HTML certificate page that
  holds the proof and can be verified offline.

Run `uv run anagram --help` to see all available commands and options.

## Time anchors

The local test node created by `anagram init` uses a **fake time anchor** for
convenience during local testing. `anagram verify` flags fake anchors clearly
in its output. A production community node uses independent time anchors; see
[deploy.md](deploy.md) for node setup and
[spec/proof-bundle.md](../spec/proof-bundle.md) and
[spec/log.md](../spec/log.md) for the underlying formats.

## Troubleshooting: locked or unavailable keychain

If `anagram init` reports a locked or unavailable operating-system keychain (for
example, over SSH or on a headless Linux server), tell Anagram to store keys in
plain local files instead:

```sh
uv run anagram --plain-key-files init
```

You can also set `ANAGRAM_KEYSTORE=file` in your environment. See
[install.md](install.md#8-for-developers-and-headless-computers) and
[spec/identity.md](../spec/identity.md) for keystore details.
