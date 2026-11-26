# Synthetic community (`anagram.sim`)

`anagram.sim` writes a fake research community to a folder. Tests use it for
extraction, matching, and leakage checks. All names, institutions, proteins,
strains, compounds, and IDs are invented. The table of labs is in
`src/anagram/sim/labs.py`.

## Run

```sh
uv run python -m anagram.sim OUT_DIR --seed 0 --large-mb 20
```

From Python: `generate_community(out_dir, seed, large_bytes)`. It returns a
`SimResult` with `ground_truth` and `canaries`. `OUT_DIR` must not exist or
must be empty.

## Output

```
OUT_DIR/
  ground_truth.json            schema anagram.sim.ground_truth.v1
  canaries.json                schema anagram.sim.canaries.v1
  labs/<lab>/<person>/
    notes/      PI plan (.md), notebook (.md), manager log (.txt)
    decks/      <lab>-talk.pptx (PI)
    mail/       collaborator-thread.eml (PI), vendor-thread.eml (manager)
    library/    zotero-export.json, CSL-JSON (PI)
    figures/    <name>.png, 96x64 greyscale (scientist)
    data/       <name>.csv, 24 rows (scientist)
    code/<repo> Git repository, 3 commits (scientist)
    raw/        one large file per lab (scientist)
```

The Varga Lab has 2 people. Its scientist also holds the manager files. The
other labs have 3 people.

## Ground truth

- `institutions`: fake ROR IDs (`fake-ror-<9 hex>`).
- `people`: fake ORCIDs (`fake-0000-000N-NNNN-NNNN`), role, lab, folder.
- `labs`: lab ID (`fake-lab-<slug>`), field, has, needs, and the intended
  profile chips (`topics`, `needs`, `offers`). Each chip has a plain `label`
  and a placeholder `id` (`tbd:<kind>/<slug>`). Vocabulary IDs are not decided.
- `planted_matches`: Chen and Okafor, Varga and Helix, Chen and Helix, Okafor
  and Helix. A pair is a match when each lab needs a chip that the other lab
  offers. `labs.chip_matches()` computes the same set.
- `blocks`: Helix blocks the Okafor Lab.
- `expected_matches`: planted matches less blocked pairs (3 pairs).
  `suppressed_matches`: Okafor and Helix.
- `files`: path, lab, person, kind, media type, size, and SHA-256 of each file.
  A Git repository has `head` and `commits` in place of a hash.

## Canaries

Each canary has the form `CANARY-<LAB>-<NNN>-<12 hex>`. Each file has its own
canary. Each email has two: one in the owner's text, and one in the quoted
third-party text (`third_party: true`). An entry in `canaries.json` gives the
path, and `member` for a zip part (for example `ppt/slides/slide3.xml`).
Canaries are private. No output of Anagram may contain one unless its labels
permit it.

## Determinism

The same seed and size give the same bytes for every file outside `.git`
folders. Zip entries have a fixed date. Email headers are fixed. Git runs with
fixed `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE`, no global or system config,
and no hook templates, so commit IDs are the same. Other Git metadata (for
example the index file) can change between runs.

The large file is written in 256 KiB chunks from a seeded generator. Memory
use does not grow with the size.

Without `git` on the path, the generator writes the files of the last commit
state and records `head: null`.
