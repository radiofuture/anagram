# Anagram admission formats

Status: the formats are locked as in [identity.md](identity.md) (node invite
and receipt) and [lab.md](lab.md) (lab invite and join request, draft). This
file was made when the code was split into layers (2026-11-17): the text
moved here from identity.md sections 4, 5 and 14, lab.md section 3, and
vault.md section 15. No format, schema name, signature tag, or
vector changed. Licence: CC BY 4.0. Vectors:
[vectors/identity.json](vectors/identity.json) (blocks `invite`, `invite_id`,
`invite_url`, `receipt`, `invite_join`) and [vectors/lab.json](vectors/lab.json)
(block `invite`).
Code: `src/anagram/admission/` (the admission layer).

## 1. Model

Entry is by invite only. Each way into a community has the same parts
(the endorsement chain pattern,
[docs/design/endorsement-chain.md](../docs/design/endorsement-chain.md)):

- an **endorser** vouches: a node organizer or the node operator (node
  invite), a PI or lab admin (lab invite), or a member (reader invite);
- a **claimer** claims with the secret of the link (the token, or the invite
  seed of a lab invite);
- a **policy** decides. The policy is per node. Today there is one policy,
  `invite_only`: the invite is not revoked, not used up, not expired, and
  (for a reader invite) the claimer proved its contact. A lab narrows the
  node policy with one rule: the person who made the invite can still
  invite. A group cannot open what the node policy closes.

The node records who vouched for each member (section 6). The policy checks
in this order: revoked, used, expired, endorser, contact.

## 2. Node invite (`anagram.invite.v1`)

```json
{
  "community": "Example community",
  "expires_at": "2026-10-22T12:00:00Z",
  "node_key": "<node key fingerprint>",
  "node_url": "https://node.example.org",
  "schema": "anagram.invite.v1",
  "signature": "<hex, by the assertion key, tag anagram/v1/sign/invite>",
  "token": "<hex, 32 random bytes>"
}
```

Invite link: `<node_url>/join#<base64url, no padding, of canonical_json(invite)>`.
A browser does not send the fragment to a server.

The client:

1. parses the link and refuses an expired invite;
2. gets the trust document from `node_url` and checks it against `node_key`
   (section 3). A wrong fingerprint stops the join;
3. checks the invite signature with the assertion key. A changed field stops
   the join.

The node stores only the invite ID `hex(tagged_hash("anagram/v1/invite-id",
token))`, never the token. An invite is **single use**. A claim by the same
subject again returns the same receipt. A claim by another subject fails (409).
An expired invite fails (410).

## 3. Invite receipt (`anagram.invite_receipt.v1`)

```json
{"claimed_at": "...", "community": "...", "invite": "<invite ID>", "node_key": "<fp>",
 "schema": "anagram.invite_receipt.v1", "signature": "<hex, assertion key>", "subject": "pid:..."}
```

## 4. Lab invite (`anagram.lab_invite.v1`) and join request (`anagram.lab_join.v1`)

The client of a PI or admin makes a random 32-byte `seed`:

```
invite_sign = Ed25519 seed  HKDF-SHA256(seed, salt none, info = tagged_message(lab/invite, "sign"), 32)
invite_kem  = X25519 private HKDF-SHA256(seed, salt none, info = tagged_message(lab/invite, "kem"), 32)
```

The authorisation is public and the node stores it:

```
{"schema", "node_url", "node_key", "community", "lab_id", "lab_name",
 "genesis": <hash of the create entry>, "role": "member"|"admin",
 "invite_pub", "invite_x25519", "max_uses": <1..25>,
 "expires_at": <after created_at, at most 30 days>, "created_by": <pid>,
 "creator_device", "created_at", "signature"}
invite_id = hex(tagged_hash(lab/invite, "id" || canonical_json(authorisation))[:16])
```

The creator device signs it (`anagram/v1/sign/lab-invite`). The roster gets
an `invite` entry with the ID; the actor and the device of that entry must be
`created_by` and `creator_device`.

Link: `<node_url>/join#<base64url(canonical_json({"auth": authorisation, "seed": <64 hex>}))>`.
The app scheme form is `anagram://join/<the same fragment>`. A parser refuses
a link whose seed does not give `invite_pub` and `invite_x25519`.

Join request:

```
{"schema", "lab_id", "invite": <invite id>, "subject": <pid>, "device": <ed25519 hex>,
 "at", "device_signature", "invite_signature"}
```

The device key and the invite key each sign the request without its two
signature fields (tag `anagram/v1/sign/lab-join`). The node puts the request
into a `join` entry. A `join` entry is valid when: the invite is in the
roster and not revoked; the uses are below `max_uses`; `at` of the request is
not after `expires_at`; the creator still has the role to make the invite;
the request was not used before (hash with tag `lab/invite` and `"request"`);
the subject is not in the lab; both signatures are correct; and the device is
a key of the subject. The node cannot make a request, because it does not have
the seed.

## 5. Reader invite

A member shares a finding with a person who is not a member.
The member gives an email address or an ORCID iD. The node makes a node
invite (`invites` row with role `reader`, link `<node_url>/join#...`, the
normal join path) and a `reader_invites` row in `identity.sqlite`:
`(invite_id, owner, contact_kind, contact, state, subject, created_at,
expires_at, mailed_at)`; `state` is `open`, `claimed`, `revoked`, or
`expired`.

- Claim (`POST /invites/claim`): for a reader invite, the session subject
  must have proved the contact (an `email_accounts` row with that address, or
  an `orcid_accounts` row with that iD). A wrong person, a revoked or expired
  invite, and an invite that another person claimed give the same 404 as an
  unknown invite, and no member is made. The claim is idempotent for the same
  person and for a member.
- The new member has no lab: `members.invite` is `reader:<invite_id>`. The
  lab create rule `organizer_invite` refuses a `reader:` or `lab:` member.

The share part of a reader invite (the sealed label, the grants, and the
owner confirmation) is in [vault.md](vault.md) section 15.

## 6. Invite chain (v3)

Entry is by invite only. The inviter vouches for the person. The node records
who invited whom and shows it:

- A node invite: `invites.created_by` (null: the node operator) and
  `members.invite` (the invite ID; `reader:<ID>` for a reader invite).
- A lab invite: `members.invite` is `lab:<invite ID>`; the signed roster join
  entry names the invite, and the lab invite names `created_by`.
- `GET /me` has `invited_by` (`{"via": "node" | "lab" | "reader", "by": pid |
  null}`). The organizer page lists "Who invited whom" (names only, no
  address). A PI or lab admin sees "Invited by" on each member row.

## 7. Node routes (not locked)

`POST /auth/invite`, `POST /auth/invite/preview`, `POST /invites`,
`POST /invites/claim`, `POST /labs/{id}/invites`, `GET /labs/invites/{id}`,
`POST /labs/{id}/join`, and `/reader-invites*`. The sign-in flow with an
invite is in [identity.md](identity.md) section 11.
