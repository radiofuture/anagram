# Run an Anagram community node

This guide is for a community organizer. You need one Linux server with Docker,
a domain name, and about 30 minutes. For a test on a laptop, see
[local-test.md](local-test.md); for how a node fits into the wider network, see
[architecture.md](architecture.md).

The node is one container (`anagram node start`) behind Caddy. Caddy gets a
Let's Encrypt certificate automatically. All node data is in one Docker volume.
The database is SQLite. There is no other service.

## 1. Before you start

1. A server with Docker Engine and the Compose plugin (`docker compose version`).
2. A domain name, for example `anagram.example.org`. Make DNS A (and AAAA)
   records that point to the server.
3. Open ports 80 and 443 (TCP) and 443 (UDP). Caddy needs port 80 to get the
   certificate.
4. A copy of this repository on the server.

## 2. Register an ORCID client (optional)

Entry is invite only: people join with an invite and need no ORCID iD
(`spec/identity.md`). ORCID is optional for both members and node startup; you
only need an ORCID client if you want members to link ORCID iDs or organizers
to sign into `/admin` via ORCID.

1. Sign in at <https://orcid.org/developer-tools> and register a public API
   client. (For a test, use <https://sandbox.orcid.org/developer-tools> and set
   `ANAGRAM_ORCID_SANDBOX=1`.)
2. Application URL: `https://anagram.example.org`
3. Redirect URI. Type it exactly, with no slash at the end:

   ```
   https://anagram.example.org/auth/orcid/callback
   ```

   ORCID accepts only exact, registered redirect URIs. The node, the client
   app, and the organizer page all use this one URI.
4. Copy the client ID (`APP-...`) and the client secret.

The node uses only the `/authenticate` scope. It gets the ORCID iD and the
public name. It does not read or write ORCID records.

## 3. Configure

```sh
cd deploy
cp anagram.env.example anagram.env
chmod 600 anagram.env
```

Edit `anagram.env`.

**Required:**

| Variable | Value |
| --- | --- |
| `ANAGRAM_DOMAIN` | `anagram.example.org` (no `https://`) |
| `ANAGRAM_COMMUNITY` | The name that members see |

**Optional:**

| Variable | Value |
| --- | --- |
| `ANAGRAM_PUBLIC_URL` | Public URL override (default `https://<ANAGRAM_DOMAIN>`, e.g. when using a non-standard port) |
| `ANAGRAM_ORCID_CLIENT_ID`, `ANAGRAM_ORCID_CLIENT_SECRET` | From step 2; only needed if you want members to link ORCID iDs or sign into `/admin` via ORCID |
| `ANAGRAM_ORCID_SANDBOX` | `1` only for the ORCID sandbox |
| `ANAGRAM_ORGANIZER_ORCIDS` | Comma list of ORCID iDs that become organizers when they join |
| `ANAGRAM_SMTP_HOST`, `_PORT`, `_FROM`, `_USER`, `_PASSWORD` | Mail server for email sign-in. Port 587 with STARTTLS. Without SMTP, codes go to the node log only |
| `ANAGRAM_DOWNLOAD_URL` | `https://` page where a person gets the Anagram app. The join page (`/join`) shows "Get Anagram" with this link |
| `ANAGRAM_ENCLAVE_*` | Matching through the matching enclave of the network. See [enclave.md](enclave.md), "Connect a node". The node does no matching itself: it only relays sealed messages |
| `ANAGRAM_LAB_QUOTA_MB` | Ciphertext storage quota per lab in MB (default `2048`) |
| `ANAGRAM_LAB_CREATE` | Who can create labs: `organizer_invite` (default: organizers or members invited by a node invite) or `member` (any node member) |
| `ANAGRAM_TSA_URLS`, `ANAGRAM_OTS`, `ANAGRAM_OTS_CALENDARS`, `ANAGRAM_ANCHORS`, `ANAGRAM_ANCHOR_BATCH_SECONDS` | Time anchors (section 6). `ANAGRAM_ANCHORS` overrides the TSA/OTS variables. The defaults are good |

Most variables are read at the **first start only** and written to
`/data/node/node.json`. The following variables are read again at **each
start**: `ANAGRAM_PUBLIC_URL`, `ANAGRAM_ORCID_CLIENT_ID`,
`ANAGRAM_ORCID_CLIENT_SECRET`, the SMTP variables (`ANAGRAM_SMTP_*`),
`ANAGRAM_ENCLAVE_*`, `ANAGRAM_DOWNLOAD_URL`, `ANAGRAM_LAB_QUOTA_MB`, and
`ANAGRAM_LAB_CREATE`.

Never set `ANAGRAM_DEV_FAKE_ORCID` on a real node. It lets anyone sign in as
any ORCID iD. The node refuses it for a domain that is not `localhost` or
`*.localhost`.

## 4. Start

```sh
docker compose up -d --build
docker compose logs node
```

The log shows the community, the public URL, the ORCID redirect URI, the
anchors, the node key fingerprint, and:

```
FIRST ORGANIZER INVITE (single use, 30 days). Open it with Anagram:
  https://anagram.example.org/join#...
```

Open this link in a browser. The join page of the node has "Open Anagram",
which opens the installed app with the invite (the `anagram://` link). The
person confirms the join in the app and types a name. The invite is the
proof; there is no ORCID step. On a computer
where the app does not open, the page shows the full link to paste in the app
(or use `anagram join '<link>' --name "Your Name"`). The person who uses it becomes an organizer.
It is printed only once.

More invites:

```sh
docker compose exec node anagram node invite              # a member, 7 days
docker compose exec node anagram node invite --days 14
docker compose exec node anagram node invite --organizer  # another organizer
```

Or use the organizer page.

## 5. Organizer page

In the app, open **Account** and click "Organizer page". The app gets a
one-time link to `https://anagram.example.org/admin` (two minutes, one use).
Only organizers get the link. (An organizer who linked an ORCID iD can also
sign in on the page with ORCID, and the page accepts a passkey that is
registered on this node.)

The page shows: member and organizer counts, open invites, lab names with
member counts, the anchor status, and the log size. Matching runs in the
matching enclave of the network, not on the node: `anagram node enclave
status` checks the connection. It makes single-use member invite links.

It never shows findings, claims, files, profiles, member names, or match
results. The node does not have most of these in plain text.

## 6. Time anchors

Each proof gets an independent time from anchors over the log checkpoint:

- RFC 3161 timestamps from two free public TSAs: FreeTSA
  (`https://freetsa.org/tsr`) and DigiCert (`http://timestamp.digicert.com`;
  the token is signed, so http is safe).
- OpenTimestamps (Bitcoin) through the public calendars.

A commit never waits for an anchor. The node anchors the newest checkpoint in a
batch every 10 minutes (`ANAGRAM_ANCHOR_BATCH_SECONDS`). A failure goes to the
log and the node tries again later. OpenTimestamps records become complete
some hours later; the node asks the calendars again each hour. The organizer
page shows the last anchored log size and the last error.

The client adds the anchors to its proofs: `anagram anchors refresh`, and
automatically when you download a proof in the app. `anagram verify` lists
the anchors that back a proof.

The anchor services see only a SHA-256 digest of a checkpoint. They learn
nothing about findings or members.

## 7. Backups

All node data is in the `anagram-data` volume, folder `/data/node`:

| File | Contents |
| --- | --- |
| `node.json` | Configuration (no secrets) |
| `keys/` | Node keys (`log-ed25519`, `witness-ed25519`, `assertion-ed25519`, `network-ed25519`, plus `fake-anchor-ed25519` in dev) and the ORCID client secret. **Keep secret** |
| `log.sqlite` | The public log and checkpoints with anchors |
| `identity.sqlite` | Members, invites, sessions (hashes), key backups (ciphertext) |
| `store.sqlite` | Personal store records and person-key packages (ciphertext only) |
| `labs.sqlite` | Lab rosters, lab names and members, lab key packages and lab space records (ciphertext) |
| `vault.sqlite`, `blobs/` | Grants and encrypted evidence (ciphertext only) |
| `reads.sqlite` | Grant read receipts and fetch events |
| `proofs.sqlite` | Published public proof bundles for the verify page |
| `enclave/` | With matching on: the control chain, member credentials, and the relay state (sealed messages only) |
| `anchors.sqlite`, `admin.sqlite`, `witness.sqlite` | Anchor jobs, organizer sessions, witness state |

Back up the whole folder. Stop the node first, so that SQLite files are
consistent:

```sh
docker compose stop node
docker run --rm -v deploy_anagram-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/anagram-$(date +%F).tgz -C /data node
docker compose start node
```

(The volume name is `<project>_anagram-data`; `docker volume ls` shows it. The
project is the folder name, `deploy`, unless you set `-p`.)

Restore: stop the node, extract the archive into the volume, start the node.
Keep backups encrypted and offline: `keys/` holds the node's signing keys. If
you lose the keys, members must join a new node, but their proofs stay valid.

## 8. Upgrades

```sh
git pull
docker compose up -d --build
```

The node changes old databases at start when a new version needs it. Make a
backup before each upgrade.

## 9. What the operator can and cannot see

You run the server, so you are the operator. In plain words:

You **can** see:

- Who is a member (ORCID iDs), who is an organizer, labs and lab members,
  and when people join. The server keeps the ORCID iD of each member in a
  private table. The public log and the public key directory show only a
  random person ID (`pid:...`) and a salted ORCID commitment, so the public
  cannot list your members. Members can find another member by ORCID iD only
  if that person turned on "findable by ORCID" (off by default; each lookup
  goes into an audit table).
- The personal store of each member: encrypted records (the data that makes
  their proofs work, and a snapshot of their local index). You see only record
  sizes, counts, and times. A member who loses a laptop restores from it with
  the recovery kit.
- The public log: one entry for each timestamped finding, with only the kind
  and a hash. You see when and how often a member timestamps, and the size of
  encrypted files that members upload.
- Encrypted files and grants (ciphertext only), and who shares with whom.
- With matching on: which members ask for a matching credential, and when,
  and the fixed-size sealed messages that the node relays to the matching
  enclave of the network. You do not see the lines, the proposals, the
  answers, the cards, or who matched whom: matching runs only in the
  enclave, and the app seals each request to the enclave key. (In this
  build the enclave runs in the `simulated` profile: its operator can read
  everything. See [enclave.md](enclave.md).)
- Email addresses of people who sign in with email.

You **cannot**:

- Read findings, claims, or files. Members encrypt them on their own computers.
- Change the time of a finding, or change a finding after the fact. Anchors,
  the witness, and client checks show it.
- Swap a member's keys in secret. The change goes into the public log, and the
  member's app warns them. (You can do it in public, because the node signs
  sign-in assertions.)
- Show two different logs to two members without detection.

Members' apps check the node; they do not trust it. The witness runs on the
same server today, so it does not protect against a dishonest operator. An
independent witness is later work. Details: `spec/threat-model.md`.

## 10. Problems

- `cannot start: set ANAGRAM_DOMAIN ...`: the first start needs the
  variables in `anagram.env`.
- No certificate: check DNS and that ports 80 and 443 are open. `docker
  compose logs caddy` shows the ACME messages.
- ORCID says "redirect URI mismatch": the registered URI must be exactly
  `https://<domain>/auth/orcid/callback`.
- "dev mode (fake ORCID) is refused": remove `ANAGRAM_DEV_FAKE_ORCID`.
- Anchor errors on the organizer page: the node tries again. A TSA can be
  down for some hours; the other anchors still work.
