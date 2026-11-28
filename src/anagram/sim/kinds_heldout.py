"""The held-out group of planted instructions for the labelled set.

A different agent wrote this group. The designer of the defence must not read
it before the measurement. Each entry has the same format as `kinds.DESIGN`:
(text, target kind, where). `text` is a `str.format` template with
`{canary}` and, if necessary, `{target}`.

The data are in `sim/data/kinds_heldout.json`.
"""

from __future__ import annotations

from anagram.sim.fixtures import load

HELDOUT = load("kinds_heldout")
