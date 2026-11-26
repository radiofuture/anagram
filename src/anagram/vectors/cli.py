"""The command line of the vector makers.

Each maker takes one optional output folder. A plain `sys.argv[1]` read
took `--help` as a folder name and wrote a full set of vectors into
`./--help/`. argparse gives `--help` its usual meaning and refuses
unknown options, so a typo can not become a folder.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

DEFAULT_DIR = "spec/vectors"


def output_dir(argv: Sequence[str] | None, *, prog: str, description: str) -> Path:
    """Parse the maker arguments and return the output folder."""
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument(
        "directory",
        nargs="?",
        default=DEFAULT_DIR,
        type=Path,
        help=f"folder for the vector files (default: {DEFAULT_DIR})",
    )
    return parser.parse_args(argv).directory
