"""A held-out group of finding decoys and true findings.

A different agent wrote it; the designer of the finding check must not read it
before the measurement.

Each entry is (path, kind, text, claims). All four parts are `str.format`
templates. The keys are the keys of the lab `fill` in `kinds.py`, plus `T`
(thing with a capital first letter), `first2` (first name of person2), and
`slug` (lab slug). For a "finding", each claim is in the text, word for word.
All names, places, and numbers are invented.

The groups, in the order of the file (entry numbers from 0):

- 0 to 17: decoys: claim words, but not a finding of the lab.
- 18 to 29: true findings: a new claim of the lab, with support.

The data are in `sim/data/kinds_heldout_findings.json`.
"""

from __future__ import annotations

from anagram.sim.fixtures import load

HELDOUT_FINDINGS = load("kinds_heldout_findings")
