# Indexing: the background helper and plug-ins

The full rules are in [spec/index.md](../spec/index.md). This page tells you
how to run the helper and how to write a plug-in.

## Run the background helper

The helper indexes your sources when the UI is closed. It watches your
folders, checks all sources each 15 minutes, and does a full check each night.

    uv run anagram indexer            # runs until you press Ctrl+C
    uv run anagram indexer --once     # one check and all work, then stop
    uv run anagram indexer --no-embed # no local embedding model

- Join a community first (`anagram ui`). Until then, the helper waits.
- The log is `<home>/logs/indexer.log`. The UI shows the progress and the files
  that the helper did not read (Sources).
- The first run with embeddings downloads a small public model (about
  70 MB) into `<home>/models/`. No user data goes out. Use `--no-embed` to
  stop this.
- Only one helper runs for each data directory.

To start the app and its background index helper automatically at login (via
`AppRuntime`), install the login service:

```sh
uv run anagram app install     # registers launchd (macOS), systemd/XDG (Linux), or Task Scheduler (Windows)
uv run anagram app status      # check running state and login service
uv run anagram app uninstall   # remove the login service and stop the app
```

---

## Optional local OCR with Datalab Indra

By default, Anagram converts PDFs and Office files with `markitdown` and its
built-in standard-library extractors (`basic`). Scanned PDFs and images with
text need optical character recognition (OCR).

You can enable 100% local CPU and Apple Silicon OCR by installing **Datalab
Indra** (`indra-ocr`), a lightweight (~76 MB) ONNX Runtime pipeline that runs
without PyTorch or a GPU:

```sh
uv pip install indra-ocr
```

- **Local only:** `IndraConverter` (`name = "indra"`, `external = False`) decodes
  images in memory via Pillow and renders PDF pages in memory via `pypdfium2` —
  no plaintext files are written to `/tmp`, and no user document bytes leave
  your computer.
- **Automatic routing and fallback:** Once `indra-ocr` is installed, the
  converter router tries `indra` ahead of `markitdown` and `basic` for PDFs and
  images (`PNG`, `JPEG`, `WebP`, `TIFF`), recording page and bounding-box spans.
  If `indra-ocr` is not installed, fails on a file, or runs with
  `HF_HUB_OFFLINE=1` before its weights are cached locally, the router falls back
  automatically to `markitdown` and `basic`. You can override per-source order
  with `index.set_source_prefs(source_id, prefer=["markitdown"])`.
- **Weights and licence note:** The first online run downloads Indra's ~76 MB
  ONNX weights from Hugging Face (`datalab-to/indra-ocr`). Indra's code is
  Apache 2.0, while its model weights use a modified OpenRAIL-M licence — that
  is why `indra-ocr` is an optional user-installed package rather than a core
  dependency of Anagram.

> **Power-user note (Datalab Chandra VLM):** For heavily handwritten lab
> notebooks, dense multi-column scans, or complex scientific charts that benefit
> from a vision-language model, you can run **Datalab Chandra** behind a local
> vLLM or OpenAI-compatible server and connect it as a custom
> `anagram.converters` plug-in (see below).

---

## Native `.ipynb` and `.tex` indexing

Anagram's built-in `basic` converter extracts both Jupyter notebooks and LaTeX
manuscripts using only the Python standard library:

- **Jupyter notebooks (`.ipynb`):** Markdown cells are kept as Markdown headings
  and prose, code cells become language-tagged fenced code blocks, and concise
  plain-text cell outputs (`stream`, `text/plain`) are indexed while binary
  images (`image/png`) and large HTML/base64 payloads are skipped.
- **LaTeX manuscripts (`.tex`):** Extracts `\title`, `\author`, and the
  `abstract` environment, drops preambles before `\begin{document}` and unescaped
  `%` comments (preserving `\%`), converts `\section` through `\paragraph` into
  Markdown headings, unwraps inline formatting macros, and keeps compact math
  expressions readable.

---

## Write a plug-in (Python SDK)

A plug-in is a Python package with an entry point. There are three groups:

| Group | Base class | You write |
| --- | --- | --- |
| `anagram.sources` | `anagram.local.sources.Connector` | `kind`, `from_config`, `config`, `scan`, `describe`, and optional `discover` |
| `anagram.converters` | `anagram.local.index.convert.Converter` | `name`, `version`, `accepts`, `cost`, `convert(blob) -> Document` |
| `anagram.enrichers` | `anagram.local.index.enrich.Enricher` | `name`, `version`, `enrich(doc, ctx) -> list[Fact]` |

Example: a converter for LaTeX files.

```python
# my_plugin/latex.py
from anagram.local.index.convert import Blob, ConversionError, Converter, Document, blocks_from_markdown


class LatexConverter(Converter):
    name = "latex"
    version = "1"
    cost = "cheap"
    accepts = frozenset({"text/x-tex"})

    def convert(self, blob: Blob) -> Document:
        try:
            text = blob.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConversionError("not UTF-8") from exc
        md = text.replace("\\section{", "# ").replace("}", "")
        return Document(markdown=md, blocks=blocks_from_markdown(md))
```

```toml
# pyproject.toml of your package
[project.entry-points."anagram.converters"]
latex = "my_plugin.latex:LatexConverter"
```

Rules:

- Do not change the evidence. A converter reads bytes and returns a document.
- Raise `ConversionError` when the bytes do not read. Then the next converter
  tries, or the file goes into the skipped list with the reason.
- Put third-party text (for example quoted email) in `Document.quoted`, not in
  `markdown`.
- If your plug-in sends data off the computer, set `external = True`, set
  `recipient` to the name of the party that reads the data, and set `paid`.
  The index then uses it only for the sources where the user turns it on.
  See [the disclosure recipient pattern](design/disclosure-recipient.md).
- A built-in name always wins. Use a new name.
- Plug-ins come after the built-ins. If a built-in reads the same type (here
  `basic` reads `text/x-tex`), the user can put your converter first for a
  source: `index.set_source_prefs(source_id, prefer=["latex"])`.
- Tests use no network. Give your plug-in a local fake for tests.
