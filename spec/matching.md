# Anagram matching

Status: draft. Rewritten on 2026-11-26 to describe only the matching
enclave (section 9).
Licence: CC BY 4.0.
Code: `src/anagram/network/matching/enclave/` (`funnel.py`, `decisions.py`,
`slot_release.py`, `ledger.py`, `pairs.py`).
Test vectors: none of their own. The messages that carry matching state are
in the vectors of [enclave-messages.md](enclave-messages.md) and
[enclave-trust.md](enclave-trust.md).

Matching finds pairs of people whose wants and offers complement each other.
A person's app seals a pack (lines and rules) to the matching enclave of the
network. Nodes relay sealed messages only. The enclave decides the pairs,
and tells each person of a pair about the other only when both said yes.

This document is the overview, and it specifies the parts of matching that
no other document specifies: the match protocol (section 3), the decision
table (section 4), the release check (section 5), the field labels
(section 6) and the audit counts (section 7).

## 1. Documents

| Topic | Document |
| --- | --- |
| The pack: lines, match types, charter, deny and block lists, known object, refresh | [pack.md](pack.md) |
| Sealed requests, receipts, slots, proposals, answers, reveals, the queue, the weekly cap and the node rule | [enclave-messages.md](enclave-messages.md) |
| Release log, attestation, verifier profiles, key custody, snapshots, deletion | [enclave-trust.md](enclave-trust.md) |
| Roster, control events, member credentials | [network.md](network.md) |
| Who can see what | [threat-model.md](threat-model.md) |

## 2. Code

| Part | Module |
| --- | --- |
| Match protocol (filters, stage 1, joint judge, ranking) | `enclave/funnel.py` |
| Decision table | `enclave/decisions.py` |
| Release check | `enclave/slot_release.py` |
| State rules (proposals, answers, queue, slots) | `enclave/ledger.py` |
| Live packs, sweep, reveal, day batch | `enclave/pairs.py` |
| Simulated engines (no model) | `enclave/simulated_engines.py` |

## 3. Match protocol `anagram_pack_match.v1`

The enclave runs one sweep at each cut (23:00 UTC,
[enclave-messages.md](enclave-messages.md) section 2). A sweep uses only the
live packs: the pack is not expired, and its member credential is valid
and usable in the network ([pack.md](pack.md) section 5). Each live pack is
a **party**, with the roster record of the node of its credential.

### 3.1 Filters

Before the enclave uses a pack for a pair, it applies these filters. A pair
that fails one is not a candidate:

1. The two parties are different people: different subject keys and
   different pids.
2. Neither deny list names the node, the verified domain or the ROR ID of
   the peer's node.
3. Neither block list names the peer (by subject key or pid).
4. For each match type: the charter of both people has the type, and the
   charter rule of each (`any`, `inside`, `outside`) allows the pair
   (`inside`: same node; `outside`: other nodes).
5. Line scope: a line with scope `inside` is used only for peers of the
   same node; `outside` only for other nodes; `both` for all.
6. A `hide` rule removes one line from the pair's input when it names the
   peer.

### 3.2 Stage 1

For each party whose pack changed materially since the last sweep, for
each match type of its charter, and for each of its visible wants (and
offers), the enclave finds the nearest visible offers (and wants) of the
other parties by cosine of the line vectors. It keeps the top `k` (default
50) for each line. The enclave makes each vector itself, inside the
enclave, with the embedding model of the release (`model` descriptor with
role `embed`, [enclave-trust.md](enclave-trust.md) section 3.6). No app
supplies a vector.

A **material change** is a change of the lines, the charter, the deny list
or the block list. A new version with the same values is not a material
change.

### 3.3 Joint judge

For each candidate pair, one judge call reads both people's visible lines
for the candidate types and gives `{"fit_a", "fit_b", "type"}`, where each
fit is `fit` or `pass`. The enclave asks twice, with the order of the two
people swapped. When the two answers do not agree, or when the returned
`type` is not a candidate type for the pair, there is no decision
(the audit counts it). The judge gives enums only, never free text. The
enclave makes one decision for each pair and each material change of
either pack.

### 3.4 Rules before a proposal

A pair is **mutual** when both fits are `fit`. A mutual pair may be
proposed for its type only when all of these are true:

- there is no open proposal of the pair for the type;
- neither person has a decline record for the pair and the type, and the
  pair did not meet for the type; a `not_now` comes back only after 90
  days ([enclave-messages.md](enclave-messages.md) section 5.3);
- the anonymity rule: after the person's filters, the parties that could be
  matched with the person for the type are at least `anonymity_min_people`
  people in at least `anonymity_min_nodes` nodes (for an `inside` rule:
  `anonymity_min_people` members of the person's node). The values are in
  the `matching` descriptor.

### 3.5 Ranking

The sweep ranks the mutual pairs by their best stage-1 score and takes them
in that order under the weekly cap, the node rule and the delivery rule.
A pair that only those rules stop waits for a later sweep.
[enclave-messages.md](enclave-messages.md) section 6.5 specifies the
ranking and the waiting pairs.

### 3.6 Reasons

The `reasons` of each copy are 1 to 4 line IDs of that person's own pack:
the lines of the person that stage 1 matched for the pair and type, with a
score at or above half the pair's best score (or `2 * best` when the best
score is non-positive, falling back to the person's highest-scoring matched
line so `reasons` is never empty). A copy never names a line of the peer.

## 4. Decision table

Each sweep makes one row for each judged pair, with `a < b` (subject keys):

```json
{"a": "<hex>", "b": "<hex>", "evidence": "<hex>", "mutual": true | false,
 "reason_a": "<type>" | null, "reason_b": "<type>" | null}
```

```
evidence = tagged_hash("anagram/v1/room/evidence",
             canonical_json([[subject, pack version, line digest] for a, then b]))
line digest = SHA-256(canonical_json({"block", "charter", "deny", "lines"} of the pack))
```

The table holds no pack text and no score. It stays inside the enclave;
only its number of rows leaves, as an audit count (section 7).

## 5. Release check

One function checks each item before the enclave seals it into a slot, and
each reveal when the enclave makes it. It does not trust the code that made
the item. An item that fails goes out as `empty`, and the audit counts it
(`release_denied`). The check permits only:

- the item form of [enclave-messages.md](enclave-messages.md) section 6.4;
- in a proposal: the recipient's own copy, with the pair's checkpoints and
  expiry, the type and pack version of the copy, and reasons that are line
  IDs of the recipient's own pack;
- in an `ended` item: the recipient's own copy;
- in a reveal, after two `yes` answers to an open pair: the recipient's own
  proposal ID, the peer's subject key and type, the peer's reveal card
  exactly as the peer sent it, and the peer's node record exactly as the
  roster has it.

No score, rank, count, affiliation, known mark or peer text is in a
proposal.

## 6. Field labels

For each pack field, `readers` (who can receive the raw value) is none, and
`via` (which function can use the value) is the match protocol of the
enclave. The only exceptions are the reveal card (released to the peer
after two `yes` answers, section 5) and, under card option (b), the
`teasers` ([pack.md](pack.md) section 12).

## 7. Audit counts

The enclave keeps counts only, never rows about a person, in its sealed
state ([enclave-trust.md](enclave-trust.md) section 6.1). Examples:
`sweeps`, `proposals`, `reveals`, `decision_rows`, `judge_disagreements`,
`cap_stops`, `queue_stops`, `late_copies`, `release_denied`,
`answer_fillers`, `erase_<reason>`, `handoff_<code>`, `clock_unsafe`,
`bad_control_event`.

## 8. Names kept from the removed node-run room

Node-run matching was removed before the first release. Some of its names
stay, so that a new format never reuses them:

- The hash tags `anagram/v1/room/attestation` (the digest of an attestation
  document, [enclave-trust.md](enclave-trust.md) section 3.1) and
  `anagram/v1/room/evidence` (section 4) are in use.
- These tags are reserved and not in use: `anagram/v1/room/measurement`,
  `anagram/v1/room/sign/attestation`, `anagram/v1/room/sign/consent`,
  `anagram/v1/room/sign/withdrawal`, `anagram/v1/room/input`,
  `anagram/v1/room/audit`, `anagram/v1/room/round`,
  `anagram/v1/room/store-slot`, `anagram/v1/room/hpke/submission`,
  `anagram/v1/room/hpke/delivery`, `anagram/v1/room/delivery-address`,
  `anagram/v1/room/decision`. They do not collide with the locked registry
  of [formats.md](formats.md) section 3.2.
- The log entry kinds `match_round` and `operator_attestation`
  ([formats.md](formats.md) section 9): a log reader still accepts them.
  No code writes them.
- The schema names `anagram.pool_screen.*.v1`,
  `anagram.operator_attestation.v1` and `.v2`, `anagram.match.*` are
  retired. No code reads or writes them.

## 9. Changes after the rewrite (2026-11-26)

- This document described the node-run matching room, its protocols and
  its wire formats, which were removed before the first release. It now
  describes only the matching enclave: the match protocol, the decision
  table, the release check, the field labels and the audit counts. The
  other parts are in the documents of section 1.
- The decision table rows have no Merkle root: no round record commits
  them now.
- No format changes and no vector changes.
