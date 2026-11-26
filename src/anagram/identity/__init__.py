"""Identity (layer L1 of the layers plan): registration of a person, the
person ID, device keys and the key directory, sign-in, recovery, and links
(ORCID).

- `formats/`: the locked identity formats (node trust, assertion, key
  binding, identity record, key backup, recovery, personal store).
- `app/`: the app side (keys, keychain, account, guardians,
  personal store, log checks).
- `node/`: the node side (identity service, sign-in methods, the personal
  store, the routes).
- `ports.py`: `RegistrationGate` and `Admission` (L4 gives them).
"""
