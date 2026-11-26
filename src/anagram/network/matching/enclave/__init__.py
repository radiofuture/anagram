"""The matching enclave of the network.

The only place where matching happens. One attested service holds the
packs of many nodes, decides pairs inside, and lets only sealed,
fixed-size objects out (spec/enclave-messages.md, spec/enclave-trust.md,
spec/pack.md). A node only relays sealed bytes to it.

- `ledger`: the working state that a sealed snapshot holds, and the state
  rules (versions, rate, tombstones, answers, queues, the day batch);
- `journal`: state epochs, commit before output, restart from the latest
  cosigned snapshot;
- `funnel`: the match protocol `anagram_pack_match.v1` (filters, stage 1
  vector search, the joint judge), with its decision table (`decisions`);
- `slot_release`: the single release check for slot items;
- `intake`: how a sealed request is opened and checked, in spec order;
- `instance`: one enclave instance; its parts are `state` (ports, roles),
  `instance_keys`, `pairs` (matching) and `handoff_steps`;
- `simulated_engines`: the test engines of the `simulated` profile;
- `http`: the relay API of the enclave (node to enclave).

Profile: `simulated` only. The real-CVM profile runs the same code with
another platform and verifier.
"""
