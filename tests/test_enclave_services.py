"""The enclave processes and the app, end to end in one process.

The services are the real apps of `anagram log|witness|roster|enclave
serve` and the node of `anagram node serve` with node.json "enclave" on
(tests/enclavestack.py). The people use the app part (`Client.enclave`,
`EnclaveMatching`): lines, approval, daily upload, slot, card, answer.

The story: Alice and Bob are a planted pair; both say yes and both get the
reveal. Carol and Dan get a proposal too; Dan says yes, and Carol turns
matching off (a withdrawal), so Dan gets no reveal.
Then the writer restarts from its sealed state, and then it stops; after
its leases end, the operator names the standby the writer, and the people
go on through the same node URL. The JSON logs of the services hold no
line text, no subject key and no email address.
"""

from __future__ import annotations

import io
import json
import logging

import pytest
from enclavestack import HOUR, Stack

from anagram.network.formats.strict import DAY
from anagram.network.matching.hosting.runtime import JsonFormatter

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
FIELD = "Field surveys of alpine plant pollinators"
PHYLO = "Bayesian phylogenetics of beetle radiations"


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


class People:
    def __init__(self, stack: Stack) -> None:
        self.stack = stack
        self.clients = {}

    def join(self, name: str, lines: dict):
        root = self.stack.root / "people" / name.lower()
        c = self.stack.net.join(root, f"fake-{name.lower()}", name).client
        c.enclave.connect = self.stack.connect
        c.enclave.set_settings("http://log.test", self.stack.pins.to_json())
        c.enclave.set_draft(lines)
        c.enclave.approve(c.enclave.consent()["statement_hash"])
        c.enclave.turn_on()
        self.clients[name] = c
        return c

    def run_all(self) -> dict[str, dict]:
        return {name: c.enclave.run() for name, c in self.clients.items()}


def morning(stack: Stack, people: People, day: int) -> dict[str, dict]:
    """The cut of `day` (23:00 the day before), then 08:00: each app runs."""
    stack.at(day * DAY - HOUR)
    stack.at(day * DAY + 8 * HOUR)
    return people.run_all()


def kinds(state: dict) -> list[str]:
    return [c["kind"] for c in state["cards"]]


@pytest.fixture(scope="module")
def story(tmp_path_factory) -> dict:
    out: dict = {}
    logs = io.StringIO()
    handler = logging.StreamHandler(logs)
    handler.setFormatter(JsonFormatter("test"))
    root_log = logging.getLogger("anagram")
    root_log.addHandler(handler)
    old_level = root_log.level
    root_log.setLevel(logging.INFO)
    try:
        stack = Stack(tmp_path_factory.mktemp("stack"))
        people = People(stack)
        d0 = stack.now() // DAY + 1
        stack.at(d0 * DAY + 9 * HOUR)
        alice = people.join("Alice", draft(CRYO, MD))
        bob = people.join("Bob", draft(MD, CRYO))
        carol = people.join("Carol", draft(FIELD, PHYLO))
        dan = people.join("Dan", draft(PHYLO, FIELD))
        out["d1"] = morning(stack, people, d0 + 1)
        for c, name in ((alice, "Alice"), (bob, "Bob"), (dan, "Dan")):
            proposal = next(x for x in c.enclave.status()["cards"] if x["kind"] == "proposal")
            c.enclave.answer(proposal["id"], "yes", card(name))
        out["carol_off"] = carol.enclave.turn_off()
        people.clients.pop("Carol")
        out["carol_receipts"] = carol.enclave.run()["receipts"]
        # The writer restarts (a new process from the sealed state).
        before = stack.hosts[0].health()
        stack.stop(0)
        out["restart"] = (before, stack.open_enclave(0).health())
        for day in range(d0 + 2, d0 + 5):
            out[f"d{day - d0}"] = morning(stack, people, day)
        # The writer stops for good; the standby takes the line.
        stack.stop(0)
        stack.at(stack.now() + 25 * HOUR)
        stack.operator().fail_over(stack.release.line_id, stack.hosts[1].instance.instance_id)
        stack.tick()
        out["failover"] = stack.hosts[1].health()
        out["failover_day"] = stack.now() // DAY + 1
        morning(stack, people, out["failover_day"])
        for _ in range(2):  # the receipts, and those of the requests sealed again
            stack.at(stack.now() + HOUR)
            out["after_failover"] = people.run_all()
        out["status"] = stack.parts.status()
        out["stack"], out["people"] = stack, people
        out["subjects"] = [
            c.enclave.person_key().public_bytes().hex() for c in (alice, bob, carol, dan)
        ]
    finally:
        root_log.removeHandler(handler)
        root_log.setLevel(old_level)
    out["logs"] = logs.getvalue()
    return out


def test_the_planted_pair_gets_proposals_with_own_reasons_only(story: dict) -> None:
    d1 = story["d1"]
    for name, mine in (("Alice", [CRYO, MD]), ("Bob", [MD, CRYO]), ("Dan", [PHYLO, FIELD])):
        proposal = next(c for c in d1[name]["cards"] if c["kind"] == "proposal")
        assert proposal["type"] == "research_fit"
        assert set(proposal["reasons"]) <= set(mine)  # card (a): own lines, no peer text
        assert proposal["answer_by"] is not None and proposal["choice"] == "unset"


def test_both_or_neither_reveal(story: dict) -> None:
    revealed = {}
    for key in ("d2", "d3", "d4"):
        for name in ("Alice", "Bob"):
            for c in story[key][name]["cards"]:
                if c["kind"] == "reveal":
                    revealed.setdefault(name, (key, c))
    assert set(revealed) == {"Alice", "Bob"}
    assert revealed["Alice"][0] == revealed["Bob"][0]  # the same day
    assert revealed["Alice"][1]["card_of_peer"]["name"] == "Bob"
    assert revealed["Bob"][1]["card_of_peer"]["name"] == "Alice"
    # Each reveal has an ID (the screen keys it and plays its motion once).
    ids = {revealed[n][1]["id"] for n in ("Alice", "Bob")}
    assert None not in ids and len(ids) == 2


def test_a_withdrawal_after_a_yes_gives_no_reveal(story: dict) -> None:
    assert story["carol_off"]["on"] is False and story["carol_off"]["approved"] is False
    for key in ("d2", "d3", "d4"):
        assert "reveal" not in kinds(story[key]["Dan"])
    assert {"reason": None, "status": "accepted"} in [
        {k: r[k] for k in ("reason", "status")} for r in story["carol_receipts"]
    ]


def test_a_restart_loads_the_sealed_state(story: dict) -> None:
    before, after = story["restart"]
    assert after["role"] == "writer" and after["instance_id"] == before["instance_id"]
    assert after["counter"] >= before["cosigned"]


def test_failover_names_the_standby_and_matching_goes_on(story: dict) -> None:
    assert story["failover"]["role"] == "writer"
    assert story["status"]["enclave"] == "attested"
    assert story["status"]["instance_id"] == story["failover"]["instance_id"]
    for state in story["after_failover"].values():
        assert state["open_requests"] == 0  # each request has its receipt
        today = [r for r in state["receipts"] if r["day"] == story["failover_day"]]
        assert {"day": story["failover_day"], "reason": None, "status": "accepted"} in today


def test_the_service_logs_hold_no_pack_text_key_or_subject(story: dict) -> None:
    logs = story["logs"]
    assert logs  # the services logged their events
    for line in logs.splitlines():
        json.loads(line)  # each line is one JSON object
    for canary in (CRYO, MD, FIELD, PHYLO, "Single-particle", "pollinators"):
        assert canary not in logs
    for subject in story["subjects"]:
        assert subject not in logs
    for name in ("Alice", "Bob", "Carol", "Dan"):
        assert name not in logs
        assert card(name)["email"] not in logs
