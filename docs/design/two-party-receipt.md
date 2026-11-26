# Two-party receipt

A design pattern of Anagram: the read records of shared findings
(`anagram.network.formats.sharing`, `anagram.network.sharing.node.reads`).

## Problem

The owner of a shared finding needs evidence that a reader opened it. A
record that only the server writes can be false (the server can add or
remove an event). A record that only the reader writes can be absent (the
reader can take the data and write nothing). The record must not show the
reader to the public.

## Contract

1. **The reader signs first.** Before the server gives the data, the
   reader's app signs a receipt with a device key that the log binds to the
   reader: the object (a grant ID, not the content), the reader, the time,
   and a random 32-byte salt.
2. **No receipt, no data.** The server serves the data only to a session of
   that reader with a valid receipt for the object, made in a short window
   (24 hours). Without it the server gives one fixed refusal (HTTP 428 "read
   receipt required").
3. **The commitment goes into the log.** The server submits
   `tagged_hash(<receipt tag>, canonical_json(receipt))` as a log-only
   entry. The salt hides the reader and the object.
4. **The server signs each delivery.** Each time it serves data under a
   receipt, the server signs an event with its pinned key: the object, the
   part (a blob ID), the reader, the receipt ID, the time, and a sequence
   number for each object that starts at 1.
5. **The owner checks both sides.** The owner's app gets the receipts with
   their log proofs and the events. It checks the reader's signature against
   the reader's key history (from the log, not from the server), the log
   inclusion against a checked checkpoint, and each server signature. A gap
   in the sequence numbers shows as a removed event.
6. **The product states the limit.** The record shows that the reader's
   software asked for the data and that the server sent it. It does not show
   that a person read it, and it cannot stop a copy after the delivery.

| Party | Can | Cannot |
|---|---|---|
| Server | Refuse to serve; hide later events (a gap shows) | Make a receipt; give data with no receipt and still show a record |
| Reader (honest app) | Read after one receipt | Read with no record |
| Reader (changed app) | Copy the data after the first receipt | Get the data with no receipt |
| Public | See the count and time of events | Link an event to a person or an object |
