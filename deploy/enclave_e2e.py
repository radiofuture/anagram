"""The enclave part of the local end-to-end test (deploy/local_e2e.py).

SIMULATED PROFILE: the test proves the plumbing of the separate processes
(log, 3 witnesses, roster, enclave writer and standby, 2 nodes, 4 apps),
not privacy. It runs in the Compose project "anagram-e2e" only.

1. Admit node A and node B to the roster; log a release; move the
   development clock past the notice period; authorise the line; start
   enclave-a (writer) and enclave-b (standby); `anagram node enclave status`
   on both nodes.
2. Four people join (Alice and Carol at node A, Bob and Dan at node B) and
   turn matching on through the app part (`Client.enclave`).
3. The next day: four proposals. Alice, Bob and Dan say yes; Carol turns
   matching off (a withdrawal).
4. enclave-a restarts (`docker compose restart`): the same instance goes on
   from its sealed state.
5. Up to the answer day: Alice and Bob get the reveal on the same day; Dan
   gets none.
6. enclave-a stops. After its leases end (25 hours), the operator names
   enclave-b the writer; the people go on through the same node URLs.
7. The logs of all services hold no line text, subject key or email address.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

DAY = 86_400
HOUR = 3_600
NOTICE = 14 * DAY
SETTLE = 7.0  # seconds: some ticks of each service (2 s) after a clock move
NODES = {"A": ("node", "https://anagram.localhost"), "B": ("node-b", "https://anagram-b.localhost")}
LINES = {
    # name: (node, offer, want). Alice and Bob are the planted pair.
    "Alice": ("A", "Single-particle cryo-EM map refinement of membrane proteins",
              "Molecular dynamics simulations of membrane transporters"),
    "Bob": ("B", "Molecular dynamics simulations of membrane transporters",
            "Single-particle cryo-EM map refinement of membrane proteins"),
    "Carol": ("A", "Field surveys of alpine plant pollinators",
              "Bayesian phylogenetics of beetle radiations"),
    "Dan": ("B", "Bayesian phylogenetics of beetle radiations",
            "Field surveys of alpine plant pollinators"),
}  # fmt: skip
OPERATOR = "--devnet /devnet --key /keys/operator/key.json --log-url http://log:8780"
INDEPENDENT = "--witness http://witness-2:8781 --witness http://witness-3:8781"


def draft(offer: str, want: str) -> dict:
    return {
        "offers": [{"class": "method", "match_types": ["T1"], "scope": "both", "text": offer}],
        "wants": [{"class": "skill", "match_types": ["T1"], "scope": "both", "text": want}],
    }


def card(name: str) -> dict:
    return {
        "email": f"{name.lower()}@lab.example.org",
        "institution": "Test Lab",
        "lab": None,
        "name": name,
        "orcid": None,
    }


class Network:
    """The driver's handle on the Compose project and the development clock."""

    def __init__(self, compose: Callable[..., str], clock_file: Path, say, check) -> None:
        self.compose, self.clock_file, self.say, self.check = compose, clock_file, say, check

    def offset(self) -> int:
        return int(self.clock_file.read_text().strip() or 0)

    def now(self) -> int:
        return int(time.time()) + self.offset()

    def move_to(self, t: int) -> None:
        """Move every process to time `t` (the clock only goes forward)."""
        self.check(t >= self.now(), "the development clock goes forward only")
        # A new file, then a rename: a process never reads a file that is
        # empty for a moment (an empty file is offset 0, days in the past).
        tmp = self.clock_file.with_name(self.clock_file.name + ".new")
        tmp.write_text(f"{self.offset() + t - self.now()}\n")
        os.replace(tmp, self.clock_file)
        time.sleep(SETTLE)

    def operator(self, command: str) -> str:
        return self.compose("run", "--rm", "-T", "devnet", f"anagram enclave {command} {OPERATOR}")

    def health(self, service: str, port: int) -> dict:
        code = f"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:{port}/healthz').read().decode())"
        out = self.compose("exec", "-T", service, "python", "-c", code, check=False)
        try:
            return json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {}

    def wait_role(self, service: str, role: str, timeout: float = 90) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            h = self.health(service, 8790)
            if h.get("role") == role:
                return h
            time.sleep(2)
        raise SystemExit(f"[e2e] FAIL: {service} is not {role}: {self.health(service, 8790)}")


def start_line(net: Network) -> None:
    for label, (service, _) in NODES.items():
        record = net.compose("exec", "-T", service, "anagram", "node", "enclave", "record")
        record = record[record.index("{") :]
        out = net.compose("exec", "-T", "roster", "anagram", "roster", "admit", "--devnet", "/devnet",
                          "--key", "/key/key.json", "--state", "/data/roster", "--log-url", "http://log:8780", "-", input=record)  # fmt: skip
        net.check("Admitted" in out, out)
        net.say(f"roster: node {label} admitted")
    out = net.operator(
        "release --out /devnet/release.json --answer-day 2 --min-people 2 --min-nodes 1"
    )
    net.check("Release logged" in out, out)
    net.say("operator: release logged; moving the clock past the 14-day notice")
    net.move_to(net.now() + NOTICE + 2 * HOUR)
    out = net.operator(f"line --release /devnet/release.json {INDEPENDENT}")
    net.check("authorised" in out, out)
    net.compose("up", "-d", "--wait", "--wait-timeout", "120", "enclave-a")
    net.wait_role("enclave-a", "writer")
    net.compose("up", "-d", "--wait", "--wait-timeout", "120", "enclave-b")
    net.wait_role("enclave-b", "holder")
    net.say("enclave-a writes the line; enclave-b is the standby (holds the state key)")
    for service, _ in NODES.values():
        out = net.compose(
            "exec", "-T", service, "anagram", "node", "enclave", "status", check=False
        )
        net.check("enclave: attested" in out and "log: ok" in out, out)
    net.say("both nodes: `anagram node enclave status` is attested")


class People:
    def __init__(
        self, net: Network, join: Callable[[str, str, str], object], pins: dict, log_url: str
    ) -> None:
        self.net, self.join, self.pins, self.log_url = net, join, pins, log_url
        self.clients: dict[str, object] = {}

    def add(self, name: str) -> None:
        node, offer, want = LINES[name]
        c = self.join(node, name.lower(), name)
        c.enclave.set_settings(self.log_url, self.pins)
        c.enclave.set_draft(draft(offer, want))
        c.enclave.approve(c.enclave.consent()["statement_hash"])
        st = c.enclave.turn_on()
        self.net.check(st["on"] and st["uploaded_day"] is not None, (name, st))
        self.clients[name] = c

    def run_all(self) -> dict[str, dict]:
        return {name: c.enclave.run() for name, c in self.clients.items()}

    def morning(self, day: int) -> dict[str, dict]:
        """The cut of `day` and its epoch, then 08:00 and the node's fetch."""
        self.net.move_to(day * DAY - HOUR)
        self.net.move_to(day * DAY - HOUR + 11 * 60)
        self.net.move_to(day * DAY + 8 * HOUR)
        out = self.run_all()
        self.net.move_to(self.net.now() + 15 * 60)  # the epoch that releases the receipts
        return {**out, **self.run_all()}


def kinds(state: dict) -> list[str]:
    return [c["kind"] for c in state["cards"]]


def scan_logs(net: Network, people: People) -> None:
    services = ["log", "witness-1", "witness-2", "witness-3", "roster", "enclave-a", "enclave-b"]
    logs = net.compose("logs", "--no-color", *services, "node", "node-b")
    canaries = [t for _, offer, want in LINES.values() for t in (offer, want)]
    canaries += [card(n)["email"] for n in LINES]
    canaries += [c.enclave.person_key().public_bytes().hex() for c in people.clients.values()]
    found = [c[:24] for c in canaries if c in logs]
    net.check(not found, f"secrets in the service logs: {found}")
    service_lines = net.compose("logs", "--no-color", "--no-log-prefix", *services)
    for line in service_lines.splitlines():
        if line.strip():
            json.loads(line)  # each service line is one JSON object
    net.say("logs: no line text, subject key or email address; service logs are JSON")


def enclave_scenario(net: Network, join: Callable[[str, str, str], object]) -> dict:
    start_line(net)
    pins = json.loads(net.compose("exec", "-T", "node", "cat", "/devnet/devnet.json"))
    people = People(net, join, pins, "https://log.localhost:8443")
    for name in LINES:
        people.add(name)
    net.say("Alice and Carol (node A), Bob and Dan (node B) turned matching on")

    d1 = net.now() // DAY + 1
    states = people.morning(d1)
    for name in LINES:
        net.check("proposal" in kinds(states[name]), (name, states[name]["cards"]))
    for name in ("Alice", "Bob", "Dan"):
        c = people.clients[name]
        proposal = next(x for x in c.enclave.status()["cards"] if x["kind"] == "proposal")
        net.check(proposal["type"] == "research_fit", proposal)
        net.check(set(proposal["reasons"]) <= set(LINES[name][1:]), proposal)  # own lines only
        c.enclave.answer(proposal["id"], "yes", card(name))
    carol = people.clients.pop("Carol")
    net.check(carol.enclave.turn_off()["on"] is False, "Carol off")
    net.say("day 1: four proposals with own reasons only; Alice, Bob, Dan say yes; Carol withdraws")

    before = net.health("enclave-a", 8790)
    net.compose("restart", "enclave-a")
    after = net.wait_role("enclave-a", "writer")
    net.check(after["instance_id"] == before["instance_id"] and after["counter"] >= before["cosigned"],
              (before, after))  # fmt: skip
    net.say(
        f"enclave-a restarted from sealed state (counter {before['counter']} -> {after['counter']})"
    )

    reveals: dict[str, int] = {}
    for day in range(d1 + 1, d1 + 4):
        states = people.morning(day)
        for name in ("Alice", "Bob"):
            if "reveal" in kinds(states[name]):
                reveals.setdefault(name, day)
        net.check("reveal" not in kinds(states["Dan"]), "Dan must get no reveal")
    net.check(set(reveals) == {"Alice", "Bob"} and reveals["Alice"] == reveals["Bob"], reveals)
    alice = next(c for c in people.run_all()["Alice"]["cards"] if c["kind"] == "reveal")
    net.check(alice["card_of_peer"]["name"] == "Bob" and alice["node"]["affiliation"] == "Laboratory B",
              alice)  # fmt: skip
    net.say("both-or-neither: Alice and Bob got the reveal on the same day; Dan got none")

    standby = net.health("enclave-b", 8790)
    net.compose("stop", "enclave-a")
    net.move_to(net.now() + 25 * HOUR)  # every lease of the old writer ends
    out = net.operator(
        f"failover --release /devnet/release.json {INDEPENDENT} --writer {standby['instance_id']}"
    )
    net.check("Failover logged" in out, out)
    net.wait_role("enclave-b", "writer")
    day = net.now() // DAY + 1
    states = people.morning(day)
    for name, st in states.items():
        today = [r for r in st["receipts"] if r["day"] == day and r["status"] == "accepted"]
        net.check(today and st["open_requests"] == 0, (name, st["receipts"], st["open_requests"]))
    net.say("failover: enclave-b writes the line; the uploads of the next day are accepted")
    scan_logs(net, people)
    return {"nodes": 2, "people": 4, "reveals": 2, "withdrawals": 1, "restarts": 1, "failovers": 1}
