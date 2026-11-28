# Matching rules

Anagram matches researchers across invite-only community nodes through a
matching enclave. Nobody learns another person's name or contact details unless
both sides say yes.

## How a match flows

```
 your computer            your node                 matching enclave
+--------------+  sealed  +-------------+  sealed   +-------------------+
| Anagram app  | -------> | lab / uni / | --------> | compares people   |
| (your files, |          | person      |           | across all nodes  |
|  your model) | <------- | invite only | <-------- | proposes pairs    |
+--------------+ proposal +-------------+           +-------------------+
        |
        v
  both say yes  -> each sees the other's name and contact details
  anything else -> nobody sees anything
```

1. Your local app drafts short statements of what you need and what you can
   offer from your indexed work. You review, edit, and approve them, and choose
   which match types you want: method help, data or material sharing, instrument
   access, replication, co-supervision, or research fit.
2. Your app seals your approved statements to the matching enclave's key and
   sends fixed-size messages through your community node. Your node cannot read
   them.
3. The enclave compares researchers across all participating nodes and sends
   proposals showing only the match type and your own statements—never the other
   person's identity.
4. You answer **yes**, **not now**, or **no**. If both people answer **yes**,
   each receives the other's contact card (name, affiliation, and how to reach
   them).

## Default rules

The matching enclave enforces these defaults to keep proposals focused, private,
and resistant to spam:

- **Weekly proposal cap:** You receive at most **3 proposals a week** by
  default. You can adjust your cap from **1 to 10** per week in the app.
- **21-day answer window:** You have **21 days** to respond to a proposal before
  it expires.
- **365-day cooldown per match type:** Answering **"no"** prevents the enclave
  from proposing the same pair again for **that match type** for **365 days**.
  The same pair can still be matched for a different match type.
- **Anti-sybil node quota:** Any single community node can generate at most
  **1 proposal per 50 of its matching members every 4 weeks** (minimum 1) toward
  you. This cap limits a malicious node that creates fake members to flood
  proposals.
- **Private answers:** Your answer is never disclosed unless both sides say yes.
  The other person sees the exact same outcome for **"no"**, **"not now"**, and
  **no answer**.

## Privacy status and specifications

- Today, matching runs only in a `simulated` development profile without
  hardware confidentiality. Read [enclave.md](enclave.md) before using matching
  for sensitive work.
- To see the matching flow end to end on your own computer in ~2 minutes, follow
  [demo.md](demo.md).
- For a system diagram of the app, community nodes, witnesses, and matching
  enclave, see [architecture.md](architecture.md).
- For the wire formats, scheduling, and queue rules, see
  [spec/matching.md](../spec/matching.md) and
  [spec/enclave-messages.md](../spec/enclave-messages.md).
