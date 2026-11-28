# Anagram proof bundle, version 1

Status: locked (2026-10-15). Licence: CC BY 4.0.

A proof bundle shows that a signed finding was in a log no later than a time.
It verifies **offline**, with no node, given keys that the verifier pins.

## 1. Format (`anagram.proof_bundle.v1`)

```json
{
  "schema": "anagram.proof_bundle.v1",
  "subject": {"kind": "finding", "owner": {...}, "root": "<hex>", "signature": "<hex>"},
  "log": {
    "entry": {"commitment": "<hex>", "kind": "finding", "schema": "anagram.log_entry.v1"},
    "leaf_index": 3,
    "tree_size": 4,
    "inclusion": ["<hex>", ...],
    "checkpoint": "<signed note: checkpoint, log signature, cosignatures>"
  },
  "anchors": [<anchor record>, ...],
  "openings": {
    "finding": [<field proof>, ...],
    "evidence": [{"slot": 0, "fields": [<field proof>, ...]}, ...]
  },
  "sealed_opening": <sealed opening> or null
}
```

- `openings` is optional. It holds only the fields that the owner chooses to
  show. An evidence opening for slot N needs the finding field `evidence.N`.
- `sealed_opening` is for the owner. It is encrypted
  ([formats.md](formats.md) section 10). Remove it before you publish a bundle.
  (`anagram prove-file` does this.)

## 2. Anchor records

An anchor gives an independent time for the checkpoint digest
`SHA-256(checkpoint text)`.

| `type` | Fields | Check |
| --- | --- | --- |
| `rfc3161` | `token` (base64 DER CMS SignedData), `tsa` (URL) | Message imprint is SHA-256 and equals the digest; signed attributes; signature; ESS certificate hash; critical timeStamping EKU; non-CA leaf; RFC 5280 chain to a pinned TSA root (CA BasicConstraints, pathLenConstraint, keyCertSign when KeyUsage is present, timeStamping or anyExtendedKeyUsage on intermediates when EKU is present, cycle-free), valid at genTime. Not checked: revocation, RSA-PSS |
| `opentimestamps` | `ots` (base64 of a `.ots` detached timestamp) | File digest equals the digest; a Bitcoin attestation whose value equals the merkle root of a block header that the verifier supplies. Pending attestations give no time |
| `fake` | `digest`, `time`, `key`, `signature` | Ed25519 by a pinned key. For tests only. No independent time |

## 3. Verification

Inputs: the bundle, pinned log keys, pinned witness keys and a threshold,
pinned anchor trust (fake keys, TSA roots, Bitcoin headers), the minimum number
of anchors, and (optional) files to compare.

1. The owner signature on the root is valid.
2. `log.entry` equals the entry made from the subject.
3. The checkpoint note has a valid signature from a pinned log key whose name
   equals the origin.
4. `log.tree_size` equals the checkpoint size.
5. The inclusion proof of `SHA-256(0x00 || canonical_json(entry))` at
   `leaf_index` gives the checkpoint root.
6. Valid cosignatures from pinned witnesses reach the threshold (default 1 if
   any witness key is pinned). Each pinned witness counts once. A cosignature
   whose time is out of range is not valid.
7. Anchors over `SHA-256(checkpoint text)`: valid anchors from **distinct
   sources** reach the minimum (default 1). One anchor that the verifier cannot
   check does not fail the bundle by itself. The source of an anchor is its
   trust root:

   | `type` | Source |
   | --- | --- |
   | `rfc3161` | SHA-256 fingerprint of the pinned TSA root certificate |
   | `opentimestamps` | Bitcoin blockchain (`opentimestamps:bitcoin`, independent of block height) |
   | `fake` | the anchor public key |
   | other | SHA-256 of the canonical record bytes |

   Two anchors with one source count as one anchor. Their time is the earlier
   of the two.
8. Each finding field proof gives the subject root, with the layout checks of
   [formats.md](formats.md) section 4 (the layout fits the schema, and
   `name` equals `layout[index]`). If `owner` is open, it equals the subject
   owner key. If `evidence_count` or `link_count` is open, it equals the
   number of `evidence.N` or `links.N` names in the layout.
9. Each evidence field proof gives the evidence root in the opened
   `evidence.N` field, with the same layout checks.
10. Each given file has the same size and content digest as an opened
    `content` field.

All checks must pass.

### 3.1 Proven time

One witness or one anchor source alone must not set the time when the verifier
needs more than one. So:

- **Witness time**: the k-th earliest time of the valid cosignatures, where k
  is the witness threshold. No witness time if k is 0.
- **Anchor time**: the m-th earliest time over distinct anchor sources (one
  time for each source, its earliest), where m is the minimum number of
  anchors. No anchor time if m is 0.
- **"Existed no later than"**: the earlier of the witness time and the anchor
  time.

Example: with 2-of-3 witnesses, one witness that backdates its cosignature does
not move the time. The time is the second earliest cosignature.

The report shows all three times.

`created_at` in the envelope is the owner's own claim. It is never a proof of
time.

## 4. What a bundle does not prove

- That the owner made the work. It proves only that the owner's key signed the
  commitment, and when the log had it.
- What the bytes mean. Meaning is not in the commitment.
- Anything about fields that are not open.

## 5. Proof certificate (container)

A proof certificate is one HTML file that holds one bundle. It is a
container, not a new format: the bundle inside it is the proof.

- The bundle is in exactly one element
  `<script type="application/json" id="anagram-proof">`. The JSON escapes
  `<`, `>`, and `&` as `<`, `>`, and `&`.
- A reader (`anagram.proofs.certificate.load_proof`, `anagram verify`, the verify
  page) refuses a file with no such element or with more than one.
- The words of the page are a copy of the verify report. Nothing checks
  them. Only the check of the embedded bundle counts.
- The owner chooses what the bundle opens: the finding ID and the version
  (always), the claim, the evidence names and media types, and the evidence
  content digests. The page shows only opened fields. A name and an ORCID iD
  on the page are stated by the owner; the bundle does not prove them.
- The file has a CSP that refuses each script and each remote load. The font
  and the mark are inline.
