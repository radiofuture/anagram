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

The helper does not start at login yet. A later step adds a launchd (macOS)
and systemd (Linux) install.

## Write a plug-in

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
