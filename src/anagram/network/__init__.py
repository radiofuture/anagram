"""Network and discovery (layer L3): groups (labs),
sharing, reads, and matching, in the app (`app/`) and on the node
(`node/`).

- `formats/`: the locked lab, sharing, and vault formats.
- `groups/`: the lab unit (roster, keys, lab space, lab cache).
- `sharing/`: grants, shares, read receipts, reading copies, the node vault.
- `matching/`: matching through the matching enclave of the network: the
  app part, the node relay, the enclave (`matching/enclave/`), and its
  services.
- `ports.py`: `AdmissionCheck` (L4 gives it). What the node groups and
  matching read from L1 is `IdentityDirectory` in `identity.api`.
"""
