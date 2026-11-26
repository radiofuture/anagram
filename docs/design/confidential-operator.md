# Confidential operator

A design pattern of Anagram. Use it when a host processes private inputs
from many people, and the host must run in a trusted execution environment
(TEE) with no change to the clients. The matching enclave of Anagram uses it
(spec: [enclave-trust.md](../../spec/enclave-trust.md) and
[enclave-messages.md](../../spec/enclave-messages.md)).

## Base contract

Put all plaintext work behind one operator interface. Clients encrypt each
input to the public key of the operator (HPKE). Before they send, they
verify an attestation document that binds that key to a measurement of the
operator code.

| Profile | Attestation | Key source |
| --- | --- | --- |
| `simulated` | The host signs the code hash | A local file |
| hardware | A hardware quote (for example AMD SEV-SNP or Intel TDX) | Keys that the enclave makes inside |

The client check is the same for all profiles. Only the verifier of the
document type changes. The `simulated` profile protects nothing from the
host: it tests the protocol and the client path only.

Operator storage holds only ciphertext sealed to the storage key. Do not log
plaintext. Do not add debug endpoints. One test suite runs against each
profile.

## Network enclave rules

1. **Reproducible image.** The measurement covers the image digest, the
   launch policy, the model weights hash and the protocol descriptor hashes.
   Two independent builders get the same digest.
2. **Transparency log of releases.** Each release and each revocation is an
   entry in a log with witnessed checkpoints. Clients accept a measurement
   only from the log, after a notice period.
3. **Keys stay inside.** The enclave makes its keys; no key management
   service holds them. A new instance gets the state key only from a live
   instance that verified its evidence, its log entry and the instance
   count. Witnesses cosign a state counter, so a clone or an old snapshot
   cannot act.
4. **The model runs inside the boundary.** Open weights run in the enclave;
   there is no call to a model vendor.
5. **Deletion and replay.** Withdrawal, removal or expiry deletes the state
   of a person and keeps a tombstone (key and last version), so an old
   sealed input cannot come back. Time comes from cosigned log checkpoints,
   not from the host clock.
6. **A verifier profile for each platform.** Each platform has a written
   mapping from hardware evidence to the logged measurement, a TCB floor,
   policy bit rules and an evidence expiry.
7. **Commit before receipt.** Nothing leaves the enclave (a receipt, a slot)
   before a cosigned state epoch holds it. Bind each piece of evidence to a
   recent cosigned log checkpoint, because raw hardware reports carry no
   time.
