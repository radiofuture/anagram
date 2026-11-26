# Endorsement chain

A design pattern of Anagram for admission by invite. The internal model is
in `anagram.admission.model` (`Endorsement`, `Claim`, the policy function
`invite_only`, and `NodePolicy`, whose group rules can only narrow it).

## Problem

A community grows by invite: a member vouches for a new person. Later the
community can want other rules: two vouches, a quota for each member, an
open door for some roles. If each kind of invite has its own code and its
own record, and the node writes the record, the node can claim that anyone
vouched for anyone.

## Contract

1. **An endorsement is a signed record.** Fields: the endorser (person ID
   and device key), the subject (an invite authorization key until the
   person joins, then the person ID), the scope (community, group, reader of
   one item), the purpose (`admit`, `introduce`), the limits (`max_uses`,
   `expires`), and the policy that it claims to satisfy. A device of the
   endorser signs it.
2. **A claim closes it.** The new person signs a claim with the key that the
   invite secret gives. The node never sees the secret (see
   [group roster](group-roster.md), rule 4). The pair (endorsement, claim)
   is one admission.
3. **Admissions go into an append-only log.** A group admission is an entry
   of its roster chain. The node orders entries; it cannot make one.
4. **One policy function.** `admit(chain, request) -> yes | no(reason)`.
   The node and each client run the same function on the same records.
5. **Revocation is an entry, not a delete.**
6. **The people concerned can see the chain.** A member sees who vouched for
   them; an organizer sees who invited whom (names only).

## Status in 0.1.0

Rules 1 and 3 hold only for the lab invite (signed roster entries `invite`
and `join`). The node invite and the reader invite are node rows that use
the same internal model; a signed record for them is future work.

## Limits

The node learns the vouch graph. A member can vouch for a fake person; the
chain shows who did, but does not prevent it.
