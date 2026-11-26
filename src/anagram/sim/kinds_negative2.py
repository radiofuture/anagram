"""A second held-out group of negative results, with decoys.

A different agent wrote it and it was committed before the work on
negative-result recall (2026-11-18). The designer of that work did not read
it before the measurement.

Each entry is (path, kind, polarity, text, claims), the format of
`kinds_negative.py`. The path, the text, and each claim are `str.format`
templates with the keys of the lab `fill` in `kinds.py`, plus `T`, `first2`,
and `slug`. Only a "finding" or a "result" has a polarity. For a "finding",
each claim is in the text, word for word. All names, places, and numbers are
invented.

The data are in `sim/data/kinds_negative2.json`.
"""

from __future__ import annotations

from anagram.sim.fixtures import load

NEGATIVE_RESULTS2 = load("kinds_negative2")
