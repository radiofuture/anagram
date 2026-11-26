"""Deployable processes of the matching enclave, `simulated` profile.

The enclave code (`enclave`, `trust`) is pure: it takes its log, its
control feed, its disk and its clock as ports. This package gives those
ports over HTTP and on disk, so each party runs as its own process:

- `tools.devnet`: the keys of a development network and the public pins
  (`devnet.json`) that nodes and apps read;
- `clients`: the HTTP clients of the log (read and write API) and of the
  control feed (roster and node chains);
- `log` (`anagram log serve`): the transparency log, with the read and
  write API of spec/enclave-trust.md 2.1;
- `witness` (`anagram witness serve`): one witness;
- `roster` (`anagram roster serve`): the network roster (spec/network.md 3);
- `enclave` (`anagram enclave serve`): one enclave instance (writer or
  standby) and the operator's front end;
- `tools.operator`: the release-key steps (release, line, failover);
- `runtime`: what each process shares: JSON logs that never carry pack
  text, keys or subjects; a ticker; health; shutdown.

The `simulated` profile protects nothing (spec/enclave-trust.md 4.1): the
development root signs the evidence, and the instance keys are on disk. It
exists so that the whole network runs in development and CI. Real privacy
needs a TEE profile.
"""
