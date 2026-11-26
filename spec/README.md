# Anagram specifications

Status: version 1, locked on 2026-10-15.
Licence: [CC BY 4.0](LICENSE.md). The code is Apache-2.0.

These documents define the formats that make a priority proof. A proof that
you make today must verify in many years, with a different implementation. So
the formats are locked. A change makes a new version (`v2`). It never changes
`v1`.

| Document | Contents |
| --- | --- |
| [formats.md](formats.md) | Canonical JSON, hash tags, committed objects, evidence record, finding envelope, links, stream checkpoint, log entry, sealed opening data |
| [log.md](log.md) | Log hashing, checkpoints (C2SP signed note), witness cosignatures, tiles |
| [proof-bundle.md](proof-bundle.md) | Proof bundle, anchors, and the offline verification procedure |
| [matching.md](matching.md) | Matching overview: the match protocol `anagram_pack_match.v1` of the enclave, the decision table, the release check, field labels, audit counts, and the names kept from the removed node-run room |
| [identity.md](identity.md) | Node trust document, invite, receipt, node assertion, key-binding entry (key directory), identity record, recovery kit and key backup; v2: private person IDs, ORCID commitment, device sign-in, person keys |
| [vault.md](vault.md) | Encrypted blobs, rings, grants, grant receipts, public release, recovery guardians; v2: personal store (section 11) |
| [admission.md](admission.md) | Entry by invite (admission layer): node invite, invite receipt, lab invite and join request, reader invite, invite chain. Schemas `anagram.invite.v1`, `anagram.invite_receipt.v1`, `anagram.lab_invite.v1`, `anagram.lab_join.v1` (text moved from identity.md and lab.md; formats unchanged) |
| [lab.md](lab.md) | Lab unit (draft): signed roster, lab invite, join request, lab key package, lab space records, lab item, lab settings. Schemas `anagram.lab_roster.v1`, `anagram.lab_invite.v1`, `anagram.lab_join.v1`, `anagram.lab_key.v1`, `anagram.lab_item.v1`, `anagram.lab_settings.v1` |
| [index.md](index.md) | Local index: connectors, streams, extraction, vocabulary, chips, drafts (draft; no new committed format) |
| [understanding.md](understanding.md) | Item kinds (`anagram.item_kind.v1`), model providers, the `understand` stage, proposals, scoped retrieval, Ask, timeline, assistant access (MCP) (draft; no committed format) |
| [trust.md](trust.md) | Trust policy of a person (draft): tiers, allow and deny, signed document. Schema `anagram.trust_policy.v1` |
| [pack.md](pack.md) | Matching enclave input (draft): pack `anagram.pack.v1` with size budgets, known object `anagram.known.v1` (binary), refresh, migration. Schema `schemas/pack.schema.json` |
| [enclave-messages.md](enclave-messages.md) | App, node and enclave messages (draft): sealed request envelope, receipt, slot, answer, withdrawal, cover, fetch API, node request signature, error codes. Schema `schemas/enclave-messages.schema.json` |
| [network.md](network.md) | Network roster, control events, node and member credentials (Biscuit, JSON fallback), person signing key and moves (draft). Schema `schemas/network.schema.json` |
| [enclave-trust.md](enclave-trust.md) | Matching enclave trust (draft): release transparency log and entry kinds, attestation document `anagram.operator_attestation.v3`, verifier profiles, key custody, anti-rollback, tombstones, deletion |
| [threat-model.md](threat-model.md) | Parties, what each party can see and do, and how we enforce it |
| [vectors/](vectors/) | Test vectors (JSON) for each format |

## Code

The reference implementation is in `src/anagram/` (see the README,
section Project layout). Where each document is implemented:

| Document | Code |
| --- | --- |
| formats.md | `core/canonical.py`, `core/crypto/`, `proofs/records.py`, `proofs/sealed.py` |
| log.md | `proofs/log/`, `proofs/node/service.py`, `proofs/node/routes.py` |
| proof-bundle.md | `proofs/bundle.py`, `proofs/proof.py`, `proofs/anchors/` |
| identity.md | `identity/formats/`, `identity/app/`, `identity/node/` |
| admission.md | `admission/` (`formats.py`, `model.py`, `service.py`, `reader.py`, `join.py`) |
| vault.md | `network/formats/vault.py`, `network/formats/sharing.py`, `network/sharing/`, `identity/formats/recovery.py`, `identity/formats/personal_store.py` |
| lab.md | `network/formats/` (`lab.py`, `labkey.py`, `labitem.py`, `labsettings.py`), `network/groups/` |
| matching.md | `network/matching/enclave/` (`funnel.py`, `decisions.py`, `slot_release.py`, `ledger.py`, `pairs.py`) |
| index.md | `local/sources/`, `local/index/`, `local/understanding/chips.py`, `local/understanding/drafts.py` |
| understanding.md | `local/understanding/`, `models/`, `gateway/` |
| trust.md | `local/trust/` |
| pack.md, enclave-messages.md, network.md | `network/formats/` (formats), `network/matching/enclave/` (service), `network/matching/node/enclave_relay.py`, `network/matching/app/enclave_client.py`; `vectors/net/` generates the vectors with them |
| vectors/ | `vectors/` (`python -m anagram.vectors.build`) |

## Versions

Each JSON object has a `schema` field, for example `anagram.finding.v1`. A
verifier must refuse a schema that it does not know.

| Schema | Document |
| --- | --- |
| `anagram.evidence.v1` | formats.md |
| `anagram.finding.v1` | formats.md |
| `anagram.stream_checkpoint.v1` | formats.md |
| `anagram.log_entry.v1` | formats.md |
| `anagram.opening.v1` | formats.md |
| `anagram.sealed_opening.v1` | formats.md |
| `anagram.proof_bundle.v1` | proof-bundle.md |
| `anagram.operator_attestation.v1` (retired; no code) | matching.md |
| `anagram.pool_screen.*.v1` (retired; no code and no vectors) | matching.md |
| `anagram.node_trust.v1` | identity.md |
| `anagram.invite.v1` | admission.md |
| `anagram.invite_receipt.v1` | admission.md |
| `anagram.node_assertion.v2` (v1 replaced, 2026-10-27) | identity.md |
| `anagram.key_binding.v2` (v1 replaced, 2026-10-27) | identity.md |
| `anagram.identity_record.v2` (v1 replaced, 2026-10-27) | identity.md |
| `anagram.key_backup.v2` (a client still reads v1) | identity.md |
| `anagram.personal_store.v1`, `anagram.person_keys.v1` | vault.md |
| `anagram.grant_receipt.v1`, `anagram.grant.v1`, `anagram.grant_payload.v1` | vault.md |
| `anagram.public_release.v1` | vault.md |
| `anagram.read_receipt.v1`, `anagram.fetch_event.v1`, `anagram.reading_copy.v1` | vault.md |
| `anagram.guardian_set.v1`, `anagram.guardian_share.v1` | vault.md |
| `anagram.recovery_request.v1`, `anagram.guardian_approval.v1` | vault.md |
| `anagram.trust_policy.v1` (draft) | trust.md |
| `anagram.pack.v1`, `anagram.known.v1` (draft) | pack.md |
| `anagram.enclave.receipt.v1`, `anagram.enclave.slot.v1`, `anagram.enclave.answer.v1`, `anagram.enclave.withdrawal.v1`, `anagram.enclave.cover.v1` (draft) | enclave-messages.md |
| `anagram.control_event.v1`, `anagram.net.roster_checkpoint.v1`, `anagram.net.policy.v1`, `anagram.member_credential.v1`, `anagram.node_credential.v1`, `anagram.net.credential_request.v1` (draft) | network.md |

## Test vectors

`src/anagram/vectors/build.py` makes the files in `vectors/` from fixed
inputs. The test suite checks that the files are current and that they verify.
To make them again:

```sh
uv run python -m anagram.vectors.build spec/vectors
uv run python -m anagram.vectors.net.build spec/vectors   # pack.json, enclave-messages.json, network.json
```

The files of `vectors/net/` hold random values (HPKE output, Biscuit
tokens). The builder keeps the values of the last run while they verify,
and a verifier opens or checks them instead of recomputing them.

An independent implementation must give the same outputs from the same inputs.

## Words

- **Must**, **must not**: a requirement.
- **Root**: a 32-byte SHA-256 value at the top of a Merkle tree.
- **Opening**: the salts and values that let a person check a commitment.
- **Owner**: the person whose device key signs a finding.
