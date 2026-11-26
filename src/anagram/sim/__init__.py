"""Synthetic community for Anagram tests.

`generate_community(out_dir, seed)` writes fake labs, their evidence files,
planted matches, a block, canary strings, and the ground truth. See
spec/sim.md.
"""

from anagram.sim.generate import (
    DEFAULT_LARGE_BYTES,
    SimResult,
    build_ground_truth,
    fake_orcid,
    fake_ror,
    generate_community,
)
from anagram.sim.labs import BLOCKS, LABS, PLANTED_MATCHES, chip_matches

__all__ = [
    "BLOCKS",
    "DEFAULT_LARGE_BYTES",
    "LABS",
    "PLANTED_MATCHES",
    "SimResult",
    "build_ground_truth",
    "chip_matches",
    "fake_orcid",
    "fake_ror",
    "generate_community",
]
