# Matching through the network enclave: operator guide

This guide is for operators. It tells you how to run the enclave processes
of a network (the log, the witnesses, the roster, and the enclave
instances), and how to connect a community node to them. The protocol is
in [spec/enclave-trust.md](../spec/enclave-trust.md),
[spec/enclave-messages.md](../spec/enclave-messages.md) and
[spec/network.md](../spec/network.md).

## Read this first: the `simulated` profile

This build runs only the **`simulated` profile**. Use it for development and
tests. **It does not protect anything.**

What the simulated profile **does**:

- It runs the same protocol, messages and checks as the TEE profile. The
  apps seal each request to the enclave key, the nodes see only fixed-size
  sealed messages, and the enclave writes each state epoch to a
  transparency log that 3 witnesses cosign.
- It shows that the processes work together: daily uploads, slots, a
  both-or-neither reveal, a withdrawal, a restart from sealed state, and a
  writer failover.
- Its logs do not contain line text, keys, subjects or email addresses.

What the simulated profile **does not do**:

- **No confidentiality from the operator.** The enclave is an ordinary
  process. Its "attestation" is a signature by a development root key in
  `devnet.json`, and anyone with that key can make a valid attestation for
  any code. The sealed instance record is encrypted with a key in the same
  state directory. A person with access to the host can read every pack,
  every card and every answer.
- **No independent witnesses.** In a development network, one operator
  holds the keys of all 3 witnesses, the log, the roster and the release.
- **No real matching quality.** The embedder and the judge are the
  deterministic test engines. They show the data flow, not good matches.
- **No real clock.** Each process can read a development clock offset
  (`ANAGRAM_DEV_CLOCK_FILE`). The test moves all processes across days with
  it. Never set it in a real deployment.

Real privacy needs the **TEE profile** (attested hardware, independent
witnesses, separate key holders). The TEE profile is not in this build.
Do not give a simulated network to real people with real research plans.

## The processes

| Process | Command | Port | State |
| --- | --- | --- | --- |
| Log | `anagram log serve` | 8780 | `log.sqlite` (entries, checkpoints) |
| Witness 1, 2, 3 | `anagram witness serve --number N` | 8781 | `witness.sqlite` (the last cosigned size); witnesses 1 and 2 also keep the entries |
| Roster | `anagram roster serve` | 8782 | `roster.sqlite` (the roster chain) |
| Enclave writer | `anagram enclave serve --profile simulated --first-line` | 8790 | `instance.sealed`, `platform.key`; snapshots in the shared `--snapshots` directory |
| Enclave standby | `anagram enclave serve --profile simulated --standby-of URL` | 8790 | the same |
| Node | `anagram node serve` (or `node start` in Docker) | 8787 | the node directory |

Each process:

- writes JSON lines to stderr. Each line has `at`, `event`, `level`,
  `service` and only fields from a fixed list (counters, sizes, roles,
  instance IDs, error codes). A library message keeps only its template.
  An exception keeps only its type name.
- answers `GET /healthz` with `200` when it is ready, else `503`.
- stops on SIGTERM or SIGINT. It ends the open requests, stops its timer,
  and writes its state.
- keeps its state in its `--state` directory. After a restart it goes on
  from that state. An enclave instance goes on from the latest epoch that
  the witnesses cosigned.

The instances of one line must share the `--snapshots` directory (sealed
snapshots on untrusted storage). A standby loads the writer's latest
snapshot from it when it takes over.

## Start a development network

All commands run from the root of this repository. The example uses local ports; in
Docker, use the service names (see `deploy/compose.enclave.yaml`).

1. Make the keys and the pins (once):

   ```sh
   uv run anagram enclave devnet init --dir devnet \
     --network net.example.org --origin log.example.org/enclave
   ```

   `devnet/devnet.json` holds the public pins (network ID, roster key, log
   key, witness keys, release key, development root). Nodes and apps need
   it. `devnet/keys/SERVICE/key.json` is the key file of each service (log,
   roster, enclave, operator, witness-1 to witness-3; `--keys DIR` puts them
   in another directory). Give each service only its own file with
   `--key FILE`; then it reads no other key. Without `--key`, a command
   reads the key files under `devnet/keys/`, as in the steps below.

2. Start the witnesses, the log and the roster:

   ```sh
   uv run anagram witness serve --devnet devnet --number 1 --state st/w1 --log-url http://127.0.0.1:8780 --port 8781
   uv run anagram witness serve --devnet devnet --number 2 --state st/w2 --log-url http://127.0.0.1:8780 --port 8783
   uv run anagram witness serve --devnet devnet --number 3 --state st/w3 --log-url http://127.0.0.1:8780 --port 8784
   uv run anagram log serve --devnet devnet --state st/log \
     --witness http://127.0.0.1:8781 --witness http://127.0.0.1:8783 --witness http://127.0.0.1:8784
   uv run anagram roster serve --devnet devnet --state st/roster --log-url http://127.0.0.1:8780
   ```

   Give the witnesses in order (1, 2, 3). Witnesses 2 and 3 are the
   independent witnesses.

3. Admit each node (step "Connect a node", below, gives the record):

   ```sh
   uv run anagram roster admit --devnet devnet --state st/roster \
     --log-url http://127.0.0.1:8780 node-record.json
   ```

   The command checks the record form and the node ID. You must also check
   the domain and the person yourself (spec/network.md 3.3).

4. Log a release. Apps accept a release only after the 14-day notice
   period, so the release has `not_before` = now + 14 days + 1 hour:

   ```sh
   uv run anagram enclave release --devnet devnet --log-url http://127.0.0.1:8780 \
     --out release.json --answer-day 2 --min-people 2 --min-nodes 1
   ```

5. After the notice period, authorise the line. Give the two independent
   witnesses:

   ```sh
   uv run anagram enclave line --devnet devnet --log-url http://127.0.0.1:8780 \
     --release release.json --witness http://127.0.0.1:8783 --witness http://127.0.0.1:8784
   ```

6. Start the writer, then the standby:

   ```sh
   uv run anagram enclave serve --profile simulated --devnet devnet --release release.json \
     --state st/enclave-a --snapshots st/snapshots --log-url http://127.0.0.1:8780 \
     --roster-url http://127.0.0.1:8782 --first-line --port 8790
   uv run anagram enclave serve --profile simulated --devnet devnet --release release.json \
     --state st/enclave-b --snapshots st/snapshots --log-url http://127.0.0.1:8780 \
     --roster-url http://127.0.0.1:8782 --standby-of http://127.0.0.1:8790 --port 8791
   ```

   The enclave reads each node's control chain at the URL of its node
   record (`https://...`). If the enclave reaches a node at another
   address, give `--feed-rewrite https://node.example.org=http://node:8787`.

## Fail over to the standby

When the writer is lost, wait until all its leases end (24 hours after its
last epoch). Then name the standby the writer. Each independent witness
checks the rules again before it cosigns:

```sh
uv run anagram enclave failover --devnet devnet --log-url http://127.0.0.1:8780 \
  --release release.json --witness http://127.0.0.1:8783 --witness http://127.0.0.1:8784 \
  --writer INSTANCE_ID_OF_THE_STANDBY
```

`GET /healthz` of the standby gives its `instance_id`. The nodes find the
new writer by themselves: they send each request to the instance that
answered last, and try the next URL on `503`. Apps seal again each request
that gets `unknown_instance_key`.

## Find and remove a flooding node

A node can mint fake members to flood other people with proposals. The
enclave limits the harm: one person gets at most max(1, ceil(m / 50))
proposals from one other node in 4 weeks, where m is the number of live
packs of that node with a verified member credential in the current sweep
(spec/enclave-messages.md 6.5). A node of 500
members with matching on gives at most 10; a small node gives 1. A node
can take at most `new_members_per_month` new members in a month (the network policy,
default 200; spec/network.md 6.7 and 9). Daily renewals do not count; a
member who comes back after a removal counts again. A credential of a
member whose join is over the limit gets the receipt code
`issuance_limit`.

1. Read the new members of each node in the month from the log:

   ```sh
   curl -s 'http://127.0.0.1:8780/log/issuance?month=2026-11'
   ```

   A count near the limit each month, or much larger than the node's
   real growth, is a sign of flooding. Members who report many unwanted
   proposals from one node are another sign.

2. Trace the node through the invite tree. Each `node_admitted` event of
   the roster chain names its `endorser`: `roster`, or the node that
   invited it (spec/network.md 3.3):

   ```sh
   curl -s 'http://127.0.0.1:8782/net/roster/events?after=0'
   ```

   Find the event of the node, then its endorser, and the other nodes that
   the same endorser invited. Check them as well.

3. Remove the node. The enclave erases its members at once
   (spec/enclave-trust.md 7.1):

   ```sh
   uv run anagram roster remove --devnet devnet --state st/roster \
     --log-url http://127.0.0.1:8780 NODE_ID --reason abuse
   ```

   The endorser's invite quota (`node_invites_per_quarter`) limits how
   fast it can invite a replacement. If the endorser invited the flooding
   node on purpose, remove the endorser too.

## Connect a node (matching on)

Matching through the enclave is **off** by default. A node without the
config below does not change.

1. Turn it on, then restart the node:

   ```sh
   uv run anagram node enclave setup \
     --url http://enclave-a:8790 --url http://enclave-b:8790 \
     --log-url http://log:8780 --pins devnet/devnet.json \
     --affiliation "Example Lab" --admin admin@example.org
   ```

   This writes node.json `"enclave"`. In Docker, set these variables
   instead (they are read at each start): `ANAGRAM_ENCLAVE_URLS`,
   `ANAGRAM_ENCLAVE_LOG_URL`, `ANAGRAM_ENCLAVE_PINS`,
   `ANAGRAM_ENCLAVE_AFFILIATION`, `ANAGRAM_ENCLAVE_ADMIN`, and optionally
   `ANAGRAM_ENCLAVE_ROR`, `ANAGRAM_ENCLAVE_KIND`,
   `ANAGRAM_ENCLAVE_TICK_SECONDS`.

2. Give the node record to the roster operator:

   ```sh
   uv run anagram node enclave record > node-record.json
   ```

   The record has the node's network key (`keys/network-ed25519`). The node
   makes this key at `node init`, or at its first use for an older node.
   Back it up with the other node keys. The public URL must be `https://`.

3. Check the connection:

   ```sh
   uv run anagram node enclave status
   ```

   `log: ok` means that the node read a checkpoint with a witness quorum
   under the pins. `enclave: attested` means that the enclave's attestation
   bundle passes the same checks as in an app. The command exits with 1 if
   one of them fails.

With matching on, the node serves `/enclave/*` (the relay, for members),
`/net/credential` (member credentials, for members), `/net/control` and
`/net/node` (public), and `node serve` runs the relay timer.

`anagram node enclave off` turns it off again.

## The app

The local UI has a **Network matching** screen. A person enters the log URL
and the pins (`devnet.json`), writes or drafts their lines (the profile
lens drafts them with a local model), reads and approves the consent
statement, and turns matching on. The app then uploads each day (a pack
when matching is on, a cover when it is off) and reads the day's slot.
A person has 21 days to answer a proposal (with `--answer-day 7`; the
development value 2 gives 6 days). The app sends one sealed object at
each of the three checkpoints (day 7, 14 and 21): the answer at the first
checkpoint after the choice, else a filler of the same size, so the node
cannot see when the person chose. A person can choose 1 to 10 proposals a
week (default 3), under the release's `weekly_cap_max`. A proposal card
shows the match type and the person's own lines only. A reveal shows the
other person's card.

## Test it

- In one process: `uv run pytest tests/test_enclave_services.py
  tests/test_enclave_app_ui.py tests/test_enclave_processes.py`.
- In Docker: `deploy/local-e2e.sh` (Compose project `anagram-e2e` only).
  It runs the full story with 2 nodes and 4 people, and scans the logs.
- By hand, with no Docker: `uv run anagram demo up` (docs/demo.md) runs
  the log, the witnesses, the roster and one enclave instance as HTTP
  servers in the demo process (`anagram.sim.demonet`), with a development
  clock that moves one day each `--day-seconds`.
