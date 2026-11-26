"""A held-out group of negative results, with decoys, for the polarity check.

A different agent wrote it. The designer of the model prompt did not read it
before the measurement.

Each entry is (path, kind, polarity, text, claims). The path, the text, and each
claim are `str.format` templates. The keys are the keys of the lab `fill` in
`kinds.py`, plus `T` (thing with a capital first letter), `first2` (first name of
person2), and `slug` (lab slug). The polarity is "positive", "negative",
"unclear", or None. Only a "finding" or a "result" has a polarity. For a
"finding", each claim is in the text, word for word. All names, places, and
numbers are invented.

The groups, in the order of the file (entry numbers from 0):

- 0 to 9: true negative findings: own work, with support.
- 10 to 12: negative results: values that show nothing happened, no claim yet.
- 13 to 16: positive findings with negation words.
- 17 and 18: unclear: a mixed finding and a result of values only.
- 19 to 25: decoys: negative words, but not a finding or a result.

The data are in `sim/data/kinds_negative.json`.
"""

from __future__ import annotations

from anagram.sim.fixtures import load

NEGATIVE_RESULTS = load("kinds_negative")
