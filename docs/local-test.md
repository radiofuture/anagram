# Test a real deployment on this computer

This is the Docker deployment of [deploy.md](deploy.md), on a laptop, with no
public domain. It is not the in-process demo (`docs/demo.md`): the node runs in
its container behind Caddy with HTTPS, and each client is a separate process
with its own data folder.

Local mode differences (file `deploy/compose.local.yaml`):

- Address: `https://anagram.localhost:8443`. `*.localhost` names point to this
  computer. The port binds to 127.0.0.1 only.
- Caddy uses its own local CA, not Let's Encrypt. You trust its root
  certificate in the client (and the browser, if you want).
- **Dev mode**: the fake anchor (no independent time) and the fake ORCID (for
  the optional "Link your ORCID iD" only; entry is invite only, see
  `spec/identity.md`). The node prints a large warning. It refuses dev mode
  for any name that is not `localhost` or `*.localhost`.
- No matching on the node: matching runs only in the matching enclave of
  the network (`deploy/compose.enclave.yaml`, the `simulated` profile).

The Compose project name `anagram-e2e` keeps it apart from other containers.

## A. Automatic test (about 3 minutes after the first build)

Run the commands from the root of this repository.

```sh
deploy/local-e2e.sh            # build, start, test, tear down
deploy/local-e2e.sh --keep     # same, but leave it running
```

The script builds the image and starts Compose with two nodes and the
services of the matching network (log, 3 witnesses, roster; the enclave
instances start after the release). It reads the first organizer invite from the node log,
makes more invites with `docker compose exec node anagram node invite`, and
copies Caddy's root certificate to `deploy/local-ca.crt`. Then three people in
two labs use the real client over HTTPS, each with a separate client folder:

1. Chen and Okafor join with the `anagram join` CLI, and each makes a lab.
2. Ruiz joins the node and the Chen Lab with one lab invite link from Chen.
3. Lab space: Ruiz writes a note, Chen reads it, Okafor cannot.
4. Chen shares a finding with Okafor (the other lab). Okafor opens it, and
   Chen gets the read receipt.
5. Chen timestamps one finding with the CLI and verifies its file proof.
6. Matching through the enclave (`deploy/enclave_e2e.py`): the roster admits
   both nodes, the operator logs a release, the development clock moves past
   the 14-day notice, and the enclave writer and standby start. Four people
   (two on each node) turn matching on. A planted pair gets the reveal on
   the same day; a withdrawal stops a reveal; the writer restarts from its
   sealed state; the standby takes the line after a failover. The script
   then checks that the service logs hold no line text, key or email address.

It prints `[e2e] PASS`. Steps 1 to 4 are the function `lab_scenario` in
`deploy/local_e2e.py`. The offline suite runs the same function in process
(`tests/test_local_e2e_scenario.py`), with no Docker and no network.

## B. By hand, with the web UI in your browser

1. Start the node:

   ```sh
   docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml up -d --build --wait
   docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml logs node
   ```

   Copy the `FIRST ORGANIZER INVITE` link.

2. Get Caddy's root certificate and make a CA bundle for the client:

   ```sh
   docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml \
     cp caddy:/data/caddy/pki/authorities/local/root.crt deploy/local-ca.crt
   cat /etc/ssl/cert.pem deploy/local-ca.crt > /tmp/anagram-ca.pem
   export SSL_CERT_FILE=/tmp/anagram-ca.pem
   ```

   The Anagram client uses Python's `urllib`, which reads `SSL_CERT_FILE`.

3. For the browser (optional, so that the organizer page has no warning):
   open Keychain Access, drag `deploy/local-ca.crt` into the "login"
   keychain, open it, and set "When using this certificate" to "Always Trust".
   Remove it again after the test. Or accept the browser warning once for
   `https://anagram.localhost:8443`.

4. Start one local UI for each person, each with its own data folder and its
   own terminal (with `SSL_CERT_FILE` set):

   ```sh
   ANAGRAM_HOME=/tmp/anagram-chen uv run anagram ui
   ANAGRAM_HOME=/tmp/anagram-okafor uv run anagram ui
   ```

   Each opens a browser tab on a loopback port. Paste an invite link on the
   Join screen and click "Join with this link". Type your name (an email
   address is optional) and click "Join". The invite is the proof: there is
   no ORCID step. Then continue as in `docs/demo.md` ("Walk through"). More
   invites:

   ```sh
   docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml \
     exec node anagram node invite
   ```

5. Organizer page: in the UI of the person who used the first invite, open
   **Account** and click "Organizer page". It opens a one-time link to
   `https://anagram.localhost:8443/admin`.

6. Stop and delete everything (node data, Caddy CA, client folders):

   ```sh
   docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml down -v
   rm -rf /tmp/anagram-chen /tmp/anagram-okafor deploy/local-ca.crt
   ```

## C. Network matching on this computer

Matching runs only in the matching enclave of the network. The node only
relays sealed messages. The test network uses the `simulated` profile and
simulated engines (word overlap, no model, no cost). No paid model is called.

**Fastest: the in-process demo (no Docker).**

```sh
uv run anagram demo up --dir /tmp/anagram-demo --ready --day-seconds 60
```

The demo runs the matching network services in process, joins the other three
PIs, and leaves only Mei-Lin Chen for you. Open the printed link for Chen and
follow [demo.md](demo.md) ("Walk through" and "Faster: `--ready`"). With a
local model and the search index, **Draft from my work** on the **Network
matching** screen drafts new lines from your own files.

Stop with `uv run anagram demo down --dir /tmp/anagram-demo`.

**Docker (part B) with network matching.** Part A (`deploy/local-e2e.sh`)
runs the full enclave story. To connect a node by hand, see
[enclave.md](enclave.md), "Start a development network" and "Connect a node".

## D. Real anchors on the local node (optional)

Dev mode uses the fake anchor. To test real anchors (needs internet) in dev
mode, start with a new volume (`down -v` first; the anchors are set at
the first start only):

```sh
export ANAGRAM_ANCHORS="rfc3161:https://freetsa.org/tsr,rfc3161:http://timestamp.digicert.com,opentimestamps"
docker compose -p anagram-e2e -f deploy/compose.yaml -f deploy/compose.local.yaml up -d --build --wait
```

A real node never uses the fake anchor; a dev node may use real anchors. The
node anchors in batches of 30 seconds here. After a commit, wait one batch,
then run `anagram anchors refresh` and `anagram verify proof.json`. The output
lists "anchors that back this proof" (the TSA tokens are valid at once;
OpenTimestamps stays "pending" for some hours).
