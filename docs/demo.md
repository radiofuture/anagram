# Anagram demo community

Use the demo to test the local web UI. Everything runs on this
computer. All people, labs, institutions, and IDs are invented (`fake-`).

## Start

Run the commands from the root of this repository.

```sh
uv sync
uv run anagram demo up --dir /tmp/anagram-demo
```

The command:

1. Makes the synthetic community (`anagram.sim`) in `<dir>/sim`.
2. Starts the matching network of the demo in `<dir>/network`
   (`anagram.sim.demonet`, the `simulated` profile): the enclave log, its 3
   witnesses, the roster, and one enclave instance. They are the same
   services as in `deploy/compose.enclave.yaml`, but each one is an HTTP
   server on a loopback port in the demo process. No Docker is necessary.
3. Starts a local node in `<dir>/node` with fake anchors. The node has
   node.json "enclave" on: it only relays sealed messages to the enclave.
   Matching runs only in the enclave.
4. Makes one invite for each demo person. Entry is invite only: no ORCID.
5. Starts one local UI for each person on its own port, with the person's
   invite, name, and sim folder ready. A lab leader gets the whole lab folder.
6. Prints one link for each person. The links are also in `<dir>/demo.json`.

The enclave works in UTC days. The demo uses a development clock
(`ANAGRAM_DEV_CLOCK_FILE`, the file `<dir>/network/clock`): one demo day is
120 seconds (`--day-seconds`). At the first start the clock moves past the
14-day notice period of the release. Each demo day, the clock moves to the
next morning, and each app does its day's work: upload, proposals, answers,
and reveals. To start the next day at once:

```sh
uv run anagram demo day --dir /tmp/anagram-demo
```

People: Mei-Lin Chen (Chen Lab), Chidi Okafor (Okafor Lab), Eszter Varga
(Varga Lab), and Rachel Dumont (Helix Discovery Team). `--everyone` starts all
11 people.

Open each link in the browser. Each UI has its own cookie, so you can use one
browser window with one tab for each person.

## Walk through (one person)

1. Join: the invite and your name are ready on the Join screen. Click
   "Join". (An email address is optional.)
2. Save the recovery kit, tick "I saved my recovery kit", and continue.
3. Search your institution (for example "Northbridge"), choose "Make a new
   lab", and save. The sim folder is added as a source and timestamped.
4. Findings: open a draft, check the claim and files, click "Timestamp this
   finding". The proof page shows "Proven to exist by <date>".
5. Share: choose a ring. "Community" shares with all members who joined.
6. Network matching: the log URL and the pins of the demo network are
   set, and your lines ("I can offer", "I need") have a draft from your
   own files: the bullets under the offer headings ("Offer", "Assets",
   "What we can offer") and the need headings ("Need", "Gaps", "Asks",
   "What blocks us") of your notes and slides. A person whose files have
   no such bullets gets the lines of the lab profile. Edit the lines if you
   want and save them. Read the consent statement, approve it, and turn
   matching on.
7. The next demo day (at most 2 minutes), a proposal comes. It shows only
   your own lines. Fill in your card (name, institution, email) and click
   "Yes, introduce us".
8. Your answer goes out on the first answer day, 2 demo days after the
   proposal. When the other person also said yes, the reveal comes:
   "You and <name> both said yes", with the card of the other person.

Result with the drafted lines and the simulated engines (no model): Chen
and Okafor get a proposal, and Varga and Helix get one. A slot holds one item for each person
and day, so a second proposal or reveal can come one or more days later,
and the two people of a pair can get their reveals on different days. The
demo release gives 2 days to the first answer day. The enclave proposes a
pair only when both people's queues can deliver the proposal before that
day, so a third good fit of the same week waits for a later demo day
(spec/enclave-messages.md section 6.5).
The simulated engines match a want and an offer that share words, so an
edit of a line can add or remove a proposal.

## Faster: `--ready`

```sh
uv run anagram demo up --dir /tmp/anagram-demo --ready --day-seconds 60
```

Okafor, Varga, and Helix join, set their details, approve their drafted
lines, and turn matching on automatically. The demo says yes to each of
their proposals. Only Chen is left for you. Approve Chen's lines, turn
matching on, say yes to the proposals, and see the reveal with Okafor.

## Several nodes

```sh
uv run anagram demo up --dir /tmp/anagram-nodes --nodes 3 --ready --day-seconds 60
```

`--nodes 2` or `--nodes 3` starts more local nodes in the same process, each
with its own community, invites, and folder (`<dir>/node`, `<dir>/node-2`,
`<dir>/node-3`). Each lab goes to one node in turn: with 3 nodes, Chen and
Helix are on node 1, Okafor on node 2, and Varga on node 3 (with 2 nodes,
Varga is on node 1 and Helix on node 2). The roster of the demo network
admits every node, and every node relays to the one demo enclave, so a
match does not care about the node: Chen (node 1) and Okafor (node 2) get a
proposal and then the reveal, and the reveal names the other person's node
("Anagram demo node 2"). The start prints each node's address and each
person's link with the node.

A folder keeps its number of nodes: start it again with the same `--nodes`,
or use a new folder. `tests/test_demo_nodes.py` runs a 2-node demo to a
cross-node reveal.

## Stop and continue

```sh
uv run anagram demo down --dir /tmp/anagram-demo
```

The data stays in the folder. `demo up` with the same folder continues with
the same node address and the same people (new UI links). Delete the folder to
start again.

A folder that an older version of Anagram made is not used again: `demo up`
stops and tells you to use a new folder (`--dir`) or to delete the folder.

## Notes

- The demo process writes its log to `<dir>/demo.log`.
- The demo network is SIMULATED: development only, no privacy. The
  "Network matching" screen says so.
- The browser tests (`tests/test_ui_browser.py`,
  `tests/test_ui_browser_matching.py`) use the same `Demo` class in the test
  process.
