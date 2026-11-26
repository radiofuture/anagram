# Group roster with epoch keys

A design pattern of Anagram: the lab unit (`anagram.network.formats.lab`,
specified in [spec/lab.md](../../spec/lab.md)).

## Problem

A group (a lab) shares data on a node. The node must store and order the
data, but it must not decide who is in the group. If the node keeps the
member list in a table, the operator can add a row and then get the group
key from an honest client that wraps the key to each listed member.

## Contract

1. **Membership is a member-signed hash chain.** Each roster entry names the
   hash of the previous entry, an operation (`create`, `add`, `remove`,
   `leave`, `role`, `transfer`, `invite`, `join`, ...), the actor and the
   actor's device key. A device of the actor signs it. The node orders the
   entries (a stale sequence number gets a conflict) but cannot make one.
2. **One apply function.** The node and each client apply the chain with the
   same function and the same permission table. A client applies the entries
   from its pinned head and refuses a chain that does not extend that head,
   or that has an entry it cannot verify.
3. **Device keys come from a log with proofs.** The check "this device is a
   key of this person" uses a key directory with inclusion proofs, not a
   list that the node gives.
4. **An invite is a secret that the node never sees.** The link holds a
   seed. Keys from the seed sign the join request and open the key package
   of the invite. The node stores only the public authorization, so it
   cannot replay or forge a join. The chain counts the uses of each invite.
5. **The group key has epochs.** A key package names the roster head that
   its sender saw and holds the keys of all earlier epochs, so a new member
   can read the full history. A remove or a leave starts a new epoch. Old
   records are not sealed again: a removed member keeps what they got.
6. **Records carry the head of the writer.** A reader compares the head with
   its own chain. A different head at a known sequence number is a fork:
   stop and alert.

## Limits

The node learns the membership graph and the activity times. The node can
withhold service or delay a key rotation; clients show that a rotation is
due. A member can copy what they read.
