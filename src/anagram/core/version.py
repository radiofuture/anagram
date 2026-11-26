"""The version of Anagram: the one source. It lives in `core` so that every
layer can read it (the package root re-reads it as `anagram.__version__`),
and the build reads it too (`[tool.hatch.version]` in pyproject.toml)."""

VERSION = "0.1.0"
