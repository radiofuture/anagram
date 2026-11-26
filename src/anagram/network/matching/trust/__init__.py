"""Enclave trust (spec/enclave-trust.md).

What the app, the log, the witnesses and the instances check:

- `roots`: what an app pins, and the witness quorum of a checkpoint;
- `pins`: the public pins file of a network (the roots and the profile);
- `logview`: the checked entries of the log, with their signed log times;
- `release`: the release rules (notice, rebuilds, revocation, floors);
- `lines`: leases, authorised lines, shards, state epochs and failovers;
- `attestation`: the attestation document and its checks (rules 1 to 8);
- `platform`: the ports of a confidential VM (`Platform`) and of a
  profile's evidence step (`EvidenceVerifier`), with the registry;
- `profiles/`: `simulated` (development and CI), and the SEV-SNP and TDX
  parsers with verifier stubs that refuse (no production profile);
- `binding`: the measurement, the report-data binding and the GPU nonce;
- `entries`: the transparency log entries (format, signature, digest);
- `descriptor`: the release descriptor documents and the descriptor set;
- `handoff`: the signed state-key handoff message and its checks;
- `snapshot`: the sealed snapshot and the load rule;
- `clock`: the clock rule and the signed clock;
- `translog`, `follow`, `log_routes`, `issuance`: the log, its witnesses,
  its readers and its read API;
- `devtrust`: a whole development network in one process (tests).

The enclave service is in `anagram.network.matching.enclave`.
"""
