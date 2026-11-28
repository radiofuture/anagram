# Contributing to Anagram

Thank you for your help. This file tells you how to set up the project, which
checks must pass, and the rules that keep the protocol safe.

## Set up

You need [uv](https://docs.astral.sh/uv/) (0.7.20 or later). uv installs
Python 3.13 for you.

```sh
git clone https://github.com/radiofuture/anagram
cd anagram
uv sync --all-extras          # dependencies from uv.lock
uv run pre-commit install     # hooks for each commit (see below)
uv run anagram                # start the local UI
```

Browser tests need Chromium: `uv run playwright install chromium`. Without
it, those tests skip.

## Checks

Run these before you open a pull request. CI
(`.github/workflows/checks.yml`) runs the same checks.

```sh
set -o pipefail
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy                                        # strict set, see pyproject.toml
HF_HUB_OFFLINE=1 uv run pytest -q -p no:randomly --cov
biome ci .                                         # or: uv run pre-commit run --all-files
```

- **Coverage.** CI fails when the total is below `fail_under` in
  `pyproject.toml`. Do not lower the floor to make a change pass.
- **Types.** `uv run mypy` checks the strict set. The plan to make more
  packages strict is in the `[tool.mypy]` comments in `pyproject.toml`.
- **Differential tests (Go).** CI runs a Go differential job
  (`tests/test_enclave_differential.py` with `tests/differential/refverify`)
  that checks Anagram's AMD SEV-SNP and Intel TDX verifiers against Google's
  `go-sev-guest` and `go-tdx-guest`.
- **JS and CSS.** We use [Biome](https://biomejs.dev/) in check mode
  (`biome ci .` at the repository root). The config is `biome.json`. Vendored
  files and the brand copies are not checked.
- **Dependencies.** `pip-audit` checks the locked set in CI. Dependabot
  proposes updates each week.
- **Secrets.** gitleaks scans each commit (pre-commit) and the tree (CI).
  Never commit a key, a token or an `.env` file.
- **End-to-end.** `deploy/local-e2e.sh` runs the Docker deployment. It is
  slow, so CI runs it only on manual request.

### Pre-commit hooks

`.pre-commit-config.yaml` at the repository root runs ruff, ruff-format, end-of-file and trailing
whitespace, large files, gitleaks and Biome. Run all hooks on all files with
`uv run pre-commit run --all-files`.

## Rules

### Spec first

Behaviour on the wire is in `spec/`. Change the spec first, in the same pull
request as the code. The code follows the spec, and a test recomputes each
vector.

### Vectors never change

Files in `spec/vectors/` are signed or locked formats. **Never change an
existing vector file.** A new format or a new version gets a new vector file.
The vector makers are in `src/anagram/vectors/`
(`uv run python -m anagram.vectors.build --help`).

### Layers

The code has layers: identity, local, network, admission, core, proofs,
models, gateway and shell. Each layer has an `api.py` facade. Import another
layer only through its facade. `tests/test_layers.py` checks this.

### Code style

- ruff with the project rules (complexity limits, no access to private
  names).
- Docstrings and comments say why, not what.
- No dead code and no compatibility shims, unless a locked format needs one.

## Commits and pull requests

- One logical change per commit. Write the subject in the imperative mood,
  for example "Parse --help in the vector makers".
- Say in the body why the change is necessary.
- **AI agents only:** end the commit message with the trailer that names the
  model, for example
  `Co-Authored-By: <Model Name> <noreply@...>`. Human
  contributors do not add this trailer.
- Fill in the pull request template. Link the issue.

## Security problems

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
