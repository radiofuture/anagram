"""Demo community for local tests: `anagram demo up` / `anagram demo down`.

`up` makes the synthetic community (`anagram.sim`), starts the matching
network of the demo (`anagram.sim.demonet`: the enclave log, its witnesses,
the roster and one enclave instance, simulated profile), starts a local node
(fake anchors) that relays sealed messages to the enclave, makes one invite
for each demo person, and starts one local UI for each person on its own
port. Each UI has the person's invite, name, and sim folder ready: the
person still clicks each step (join with the invite, recovery kit, details,
timestamp, share, network matching). The URLs go to the terminal and to
<dir>/demo.json.

Matching runs only in the enclave, in UTC days. A demo day lasts
`--day-seconds` (default 120): the demo moves the development clock to the
next morning and each app does its day's work (upload, slot, answers). The
network matching screen of each joined person has the log URL and the pins
set, and a draft of lines from the person's own files (`draft_from_files`:
the offer and need bullets of the notes and slides; the lab profile when the
files give none): the person reads the lines, approves the consent, and
turns matching on. A proposal comes the next morning; a reveal comes when
both people said yes.

By default there is one person for each lab: the PI (Chen, Okafor, Varga) and
the Helix team lead. `--everyone` starts all 11 people. `--ready` does every
step for all people except the first PI (Chen), and says yes to each
proposal for them, so that one tester can walk Chen's flow and see a reveal.

`--nodes 2` or `--nodes 3` starts more local nodes (one community each).
Each lab goes to one node in turn (Chen node 1, Okafor node 2, ...), the
roster admits every node, and all nodes relay to the one demo enclave, so
people of different nodes get proposals and reveals with each other.

All names and IDs are invented (`fake-` prefixes on the IDs; the screens show
no ID). Nothing leaves this computer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from anagram.local.index.extract import extract_pptx
from anagram.network.api import typed_draft
from anagram.shell.ui.institutions import StaticInstitutions
from anagram.shell.ui.server import UIServer, bind_local
from anagram.shell.ui.service import UIService
from anagram.sim import generate_community
from anagram.sim.demonet import DAY, HOUR, DemoNetwork, start_server

DEMO_FILE = "demo.json"
NODES_FILE = "nodes.json"  # the number of nodes of the demo folder
LARGE_BYTES = 256 * 1024
COMMUNITY = "Anagram demo community"
DAY_SECONDS = 120
MAX_NODES = 3
POLL = 2.0  # seconds between the checks of the day driver
MAX_LINES = 5  # a person beacon: at most 5 offers and 5 wants
LINE_CHARS = 140
OFFER_HEAD = re.compile(r"offer|asset", re.IGNORECASE)
WANT_HEAD = re.compile(r"need|gap|ask|block", re.IGNORECASE)


def node_dir(root: Path, n: int) -> Path:
    """The folder of demo node `n`. Node 1 keeps the folder of a one-node demo."""
    return root / ("node" if n == 1 else f"node-{n}")


def folder_nodes(root: Path) -> int | None:
    """The number of nodes of the demo folder `root`; None for a new folder.
    A folder of a one-node demo of older code has no nodes.json."""
    path = root / NODES_FILE
    if path.exists():
        return int(json.loads(path.read_text())["nodes"])
    return 1 if (root / "node").exists() else None


def nodes_text(root: Path, have: int) -> str:
    return (
        f"The demo folder {root} has {have} node(s). Start it with --nodes {have},"
        " or use a new folder (--dir)."
    )


def _bullets(text: str) -> tuple[list[str], list[str]]:
    """The bullets under the offer headings and under the need headings of
    a markdown text. A bullet may go on in the next indented lines."""
    offers: list[str] = []
    wants: list[str] = []
    side: list[str] | None = None
    for raw in text.splitlines():
        if raw.startswith("#"):
            head = raw.lstrip("#")
            side = offers if OFFER_HEAD.search(head) else wants if WANT_HEAD.search(head) else None
        elif side is not None and raw.startswith("- "):
            side.append(raw[2:].strip())
        elif side and raw.startswith("  ") and raw.strip():
            side[-1] += " " + raw.strip()
    return offers, wants


def _line(text: str) -> str:
    """One short line: the label of "Label of three words or more: details",
    else the whole text, at most 140 characters."""
    text = " ".join(text.split())
    label, colon, _ = text.partition(": ")
    if colon and len(label.split()) >= 3:
        text = label
    if len(text) <= LINE_CHARS:
        return text
    return text[: LINE_CHARS - 3].rsplit(" ", 1)[0] + "..."


def draft_from_files(folder: Path) -> tuple[list[str], list[str]]:
    """The offers and wants that the person's own files state: the bullets
    under an offer heading ("Offer", "Assets", "What we can offer") or a
    need heading ("Need", "Gaps", "Asks", "What blocks us") of the notes
    (`*.md`) and slides (`*.pptx`) in `folder`. At most 5 of each side, 140
    characters each. No line of the canaries (`Internal ref:`). The demo
    has no local model, so this simple reading stands in for the `profile`
    lens of the "Network matching" screen."""
    offers: list[str] = []
    wants: list[str] = []
    for path in sorted(folder.rglob("*")):
        if path.suffix == ".md":
            text = path.read_text(errors="replace")
        elif path.suffix == ".pptx":
            text = extract_pptx(path.read_bytes(), path.name, "").text
        else:
            continue
        o, w = _bullets(text)
        offers += o
        wants += w

    def clean(lines: list[str]) -> list[str]:
        out: list[str] = []
        for t in lines:
            t = _line(t)
            if t and "Internal ref" not in t and t not in out:
                out.append(t)
        return out[:MAX_LINES]

    return clean(offers), clean(wants)


def made_by_old_code(root: Path) -> bool:
    """True if older code made the demo folder `root`. Each demo node now
    has node.json "enclave" on. An older folder (matching on the node) also
    keeps people and keys in older forms, so the demo does not use it
    again."""
    path = root / "node" / "node.json"
    if not path.exists():
        return False
    try:
        enclave = json.loads(path.read_text()).get("enclave") or {}
    except (OSError, ValueError, AttributeError):
        return True
    return enclave.get("enabled") is not True


def old_folder_text(root: Path) -> str:
    return (
        f"An older version of Anagram made the demo folder {root}. Use a new folder"
        " (--dir), or delete this folder and start the demo again."
    )


@dataclass
class DemoPerson:
    slug: str
    name: str
    role: str
    orcid: str
    lab: dict[str, Any]
    folder: Path
    service: UIService
    email: str = ""
    institution: str = ""
    auto: bool = False  # the demo answers yes for this person (`--ready`)
    server: UIServer | None = None
    node: int = 1  # the demo node of the person (1, 2, 3)
    own: Path | None = None  # the person's own files (the drafts of the lines)

    @property
    def url(self) -> str:
        return self.server.url if self.server else ""


@dataclass
class DemoNode:
    """One local node of the demo: its own community, invites, and relay."""

    n: int
    home: Any  # NodeHome
    url: str
    identity: Any
    server: Any
    enclave: Any  # NodeEnclave
    ticker: Any = None  # the relay timer
    labs: Any = None  # LabService

    @property
    def name(self) -> str:
        return COMMUNITY if self.n == 1 else f"{COMMUNITY} {self.n}"


@dataclass
class Demo:
    root: Path
    everyone: bool = False
    day_seconds: int = DAY_SECONDS
    large_bytes: int = LARGE_BYTES
    node_count: int = 1
    people: list[DemoPerson] = field(default_factory=list)
    nodes: list[DemoNode] = field(default_factory=list)
    node_url: str = ""  # the URL of node 1

    def start(self) -> Demo:
        from anagram.network.api import Ticker

        if not 1 <= self.node_count <= MAX_NODES:
            raise ValueError(f"a demo has 1 to {MAX_NODES} nodes")
        if made_by_old_code(self.root):
            raise RuntimeError(old_folder_text(self.root))
        have = folder_nodes(self.root)
        if have is not None and have != self.node_count:
            raise RuntimeError(nodes_text(self.root, have))
        self.root.mkdir(parents=True, exist_ok=True)
        sim_dir = self.root / "sim"
        if not (sim_dir / "ground_truth.json").exists():
            generate_community(sim_dir, seed=0, large_bytes=self.large_bytes)
        self.truth = json.loads((sim_dir / "ground_truth.json").read_text())
        # The network first: it sets the development clock of this process.
        self.network = DemoNetwork(self.root / "network")
        self.network.start_services()

        self.nodes = [self._start_node(n) for n in range(1, self.node_count + 1)]
        (self.root / NODES_FILE).write_text(json.dumps({"nodes": self.node_count}) + "\n")
        first = self.nodes[0]
        self.node_url, self.identity, self.enclave = first.url, first.identity, first.enclave
        self.network.relays = [x.enclave.relay for x in self.nodes]
        self.network.start_line([(x.home, x.url) for x in self.nodes])
        for x in self.nodes:
            x.ticker = Ticker(f"enclave-relay-{x.n}", x.enclave.relay.tick, 2.0).start()

        # The names are invented; the screen shows only the name (no "fake"
        # text on screen). The ids keep their `fake-` prefix.
        institutions = StaticInstitutions(
            {"id": i["id"], "label": i["name"]} for i in self.truth["institutions"]
        )
        labs = {lab["id"]: lab for lab in self.truth["labs"]}
        order = [lab["id"] for lab in self.truth["labs"]]
        for p in self.truth["people"]:
            if not self.everyone and p["role"] != "pi":
                continue
            lab = labs[p["lab_id"]]
            # Each lab is on one node, in turn: Chen 1, Okafor 2, ...
            node = self.nodes[order.index(lab["id"]) % self.node_count]
            slug = Path(p["path"]).name
            # A lab leader indexes the whole lab folder; others their own folder.
            folder = sim_dir / (lab["path"] if p["role"] == "pi" else p["path"])
            home = self.root / "people" / slug
            svc = UIService(home, institutions=institutions)
            if not svc.joined() and not svc.state.load():
                invite = node.home.admission(node.identity).create_invite(None, 30)
                svc.join.prepare(
                    invite["invite_url"],
                    login_hint=p["orcid"],
                    name=p["name"],
                    sources=[{"kind": "folder", "path": str(folder)}],
                )
            inst = next(i for i in self.truth["institutions"] if i["id"] == lab["institution_id"])
            person = DemoPerson(
                slug, p["name"], p["role"], p["orcid"], lab, folder, svc, p["email"], inst["name"]
            )
            person.node, person.own = node.n, sim_dir / p["path"]
            person.server = UIServer(svc).start()
            self.people.append(person)
        self.write_file()
        return self

    def _start_node(self, n: int) -> DemoNode:
        from anagram.shell.node.home import NodeHome

        nh: Any = NodeHome(node_dir(self.root, n))
        # A second `up` in the same folder keeps the node address: the members'
        # configs and the signed trust document name it.
        # The socket stays bound until the node server takes it (no launch race).
        sock = (
            bind_local(urllib.parse.urlsplit(nh.config()["public_url"]).port or 0)
            if nh.exists()
            else bind_local()
        )
        url = f"http://127.0.0.1:{sock.getsockname()[1]}"
        if not nh.exists():
            nh.create(
                origin="demo.anagram/log" if n == 1 else f"demo-{n}.anagram/log",
                community=COMMUNITY if n == 1 else f"{COMMUNITY} {n}",
                public_url=url,
                orcid_mode="fake",
            )
        nh.set_enclave(self.network.node_settings(n))
        app, identity = nh.app_parts()
        server = start_server(app, sock, "node" if n == 1 else f"node-{n}")
        return DemoNode(n, nh, url, identity, server, app.state.enclave, labs=app.state.labs)

    def start_days(self) -> None:
        """Start the day driver (a thread; `stop` ends it)."""
        self._done = threading.Event()
        self.day_now = threading.Event()  # set: the next day starts at the next check
        self._days = threading.Thread(target=self._drive, daemon=True, name="demo-days")
        self._days.start()

    def write_file(self) -> None:
        doc = {
            "node": self.node_url,
            "nodes": [{"n": x.n, "name": x.name, "url": x.url} for x in self.nodes],
            "people": [
                {"lab": p.lab["name"], "name": p.name, "node": p.node, "role": p.role, "url": p.url}
                for p in self.people
            ],
            "day_seconds": self.day_seconds,
            "pid": os.getpid(),
        }
        (self.root / DEMO_FILE).write_text(json.dumps(doc, indent=2) + "\n")

    def stop(self) -> None:
        if getattr(self, "_days", None):
            self._done.set()
            self._days.join(60)
        servers = [p.server for p in self.people if p.server]
        for s in servers:
            s.begin_stop()
        for s in servers:
            s.finish_stop()
        for x in self.nodes:
            if x.ticker:
                x.ticker.stop()
            if x.labs is not None:
                x.labs.stop()
        if getattr(self, "network", None):  # the enclave reads the nodes: it stops first
            self.network.stop()
        for x in self.nodes:
            x.server.should_exit = True
        for x in self.nodes:
            x.server.thread.join(15)
            x.enclave.close()
        f = self.root / DEMO_FILE
        if f.exists():
            f.unlink()

    def person(self, slug_or_lab: str) -> DemoPerson:
        for p in self.people:
            if slug_or_lab in (p.slug, p.lab["slug"], p.lab["id"]):
                return p
        raise KeyError(slug_or_lab)

    # ------------------------------------------------------------ days

    def _drive(self) -> None:
        """Every `POLL` seconds: set up network matching for each person who
        joined. Every `day_seconds`, or when `day_now` is set (`anagram demo
        day`): one matching day. An error waits for the next pass (the demo
        keeps running)."""
        last = time.monotonic()
        while not self._done.wait(POLL):
            try:
                for p in self.people:
                    self.set_up_matching(p)
                if self.day_now.is_set() or time.monotonic() - last >= self.day_seconds:
                    self.day_now.clear()
                    last = time.monotonic()
                    day = datetime.fromtimestamp(self.next_day() * DAY, UTC).date()
                    print(f"Demo day {day.isoformat()} done.", flush=True)
            except Exception as exc:  # noqa: BLE001 - the demo keeps running
                print(f"Demo day: {type(exc).__name__}: {exc}", flush=True)

    def next_day(self) -> int:
        """The cut of the next day (23:00) and its epoch, then 08:00: each
        app does its day's work; one hour later the apps read the receipts.
        Then the demo says yes for the `--ready` people. Return the day."""
        net = self.network
        day = net.now() // DAY + 1
        net.at(day * DAY - HOUR)
        net.at(day * DAY + 8 * HOUR)
        self.run_all()
        net.at(net.now() + HOUR)
        self.run_all()
        for p in self.people:
            if p.auto:
                self.say_yes(p)
        return day

    def run_all(self) -> None:
        for p in self.people:
            if p.service.joined():
                p.service.enclave.tick()  # the day's work, when the person is on

    def set_up_matching(self, person: DemoPerson) -> None:
        """For a person who joined: the enclave log URL and the pins, and a
        draft of lines (not approved, not sent)."""
        svc = person.service
        if not svc.joined() or svc.state.get("demo_matching_set_up"):
            return
        st = svc.enclave.state()
        if not st["set_up"]:
            st = svc.enclave.setup(self.network.url["log"], self.network.pins.to_json())
        if not st["draft"]:
            svc.enclave.save_draft(typed_draft(*self.draft_lines(person)))
        svc.state.update(demo_matching_set_up=True)

    def draft_lines(self, person: DemoPerson) -> tuple[list[str], list[str]]:
        """The offers and wants that the person's own files state
        (`draft_from_files`). A side that the files do not state comes from
        the lab profile (for example a lab member with only a notebook)."""
        offers, wants = draft_from_files(person.own) if person.own else ([], [])
        profile = person.lab["profile"]
        return (
            offers or [x["label"] for x in profile["offers"]],
            wants or [x["label"] for x in profile["needs"]],
        )

    def card(self, person: DemoPerson) -> dict[str, str | None]:
        return {
            "email": person.email,
            "institution": person.institution,
            "lab": person.lab["name"],
            "name": person.name,
            "orcid": None,
        }

    def say_yes(self, person: DemoPerson) -> None:
        """Yes to each open proposal of `person`."""
        svc = person.service
        for c in svc.enclave.state()["cards"]:
            if c["kind"] == "proposal" and c["choice"] == "unset":
                svc.enclave.answer(c["id"], "yes", self.card(person))

    # ------------------------------------------------------------ autopilot

    def ready_all(self) -> list[str]:
        """`--ready`: do every step for each person but the first PI (the
        tester). The lab leaders go first, and each leader adds the members of
        the lab before they set their identity. A member of a lab that does
        not exist yet (the lab of the tester) only joins. Return one sentence
        for each person whose steps stopped."""
        rest = self.people[1:]
        stopped = []
        for p in [x for x in rest if x.role == "pi"] + [x for x in rest if x.role != "pi"]:
            try:
                in_lab = p.role == "pi" or self._add_to_lab(p)
                self.autopilot(p, approve=in_lab)
                p.auto = in_lab
            except Exception as exc:  # the demo keeps running
                stopped.append(f"Autopilot for {p.name} stopped: {exc}")
        return stopped

    def _add_to_lab(self, member: DemoPerson) -> bool:
        """The leader of the lab of `member` adds the member to the lab, as
        on the lab page. False if the lab does not exist yet."""
        leader = next(
            (x for x in self.people if x.role == "pi" and x.lab["id"] == member.lab["id"]), None
        )
        if leader is None or leader is self.people[0] or not leader.service.joined():
            return False
        labs = leader.service.labs.mine()
        if not labs:
            return False
        self._join(member)
        if not member.service.labs.mine():
            with member.service.session() as c:
                subject = c.device.subject
            leader.service.labs.add(labs[0]["id"], {"person": subject})
        return True

    def _join(self, person: DemoPerson) -> None:
        svc = person.service
        if not svc.joined():
            # The join with the invite only (the name from `prepare`).
            svc.join.start_join()
            task = svc.join.task
            if task is None or task.thread is None:
                raise RuntimeError("demo join task did not start")
            task.thread.join(120)
            if task.state != "joined":
                raise RuntimeError(f"demo join failed: {task.error}")
        if not svc.state.get("kit_saved"):
            svc.account.kit_saved()

    def autopilot(self, person: DemoPerson, approve: bool = True) -> None:
        """Do every UI step for one person through the same service methods
        that the web page calls. A member needs the lab first (`ready_all`)."""
        svc = person.service
        self._join(person)
        ov = svc.account.overview()
        if not ov.get("institution"):
            inst = next(
                i for i in self.truth["institutions"] if i["id"] == person.lab["institution_id"]
            )
            mine = svc.labs.mine()
            if person.role == "pi":
                kw = {"new_lab": person.lab["name"]} if not mine else {"lab_id": mine[0]["id"]}
            else:
                kw = {"lab_id": mine[0]["id"]} if mine else {}
            svc.account.set_identity(person.name, inst["id"], inst["name"], **kw)
        if not approve:
            return
        self.set_up_matching(person)
        if not svc.enclave.state()["approved"]:
            svc.enclave.approve(svc.enclave.consent()["statement_hash"])
        if not svc.enclave.state()["on"]:
            svc.enclave.set_on(True)


# ------------------------------------------------------------------ commands


def serve(
    root: Path,
    everyone: bool,
    ready: bool,
    day_seconds: int,
    nodes: int = 1,
) -> int:
    demo = Demo(root, everyone=everyone, day_seconds=day_seconds, node_count=nodes).start()
    if ready:
        for line in demo.ready_all():
            print(line, flush=True)
    demo.start_days()
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    if hasattr(signal, "SIGUSR1"):  # `anagram demo day`
        signal.signal(signal.SIGUSR1, lambda *_: demo.day_now.set())
    print(f"Demo running. Nodes: {', '.join(x.url for x in demo.nodes)}", flush=True)
    done.wait()
    demo.stop()
    return 0


def summary(doc: dict[str, Any], root: Path) -> list[str]:
    """The lines that `up` prints: each node, each person with the link
    and the node, and how the days go on."""
    nodes = doc.get("nodes") or [{"n": 1, "name": COMMUNITY, "url": doc["node"]}]
    many = len(nodes) > 1
    out = [
        f"Anagram demo: {len(nodes)} node(s), matching through the demo enclave"
        " (simulated profile, development only)."
    ]
    out += [f"  Node {x['n']}: {x['url']}  ({x['name']})" for x in nodes]
    out.append("People (open each link in its own tab):")
    for p in doc["people"]:
        where = f", node {p.get('node', 1)}" if many else ""
        out.append(f"  {p['name']} ({p['lab']}{where}): {p['url']}")
    out.append(
        f"Days: one demo day is {doc['day_seconds']} s and the next day starts by itself."
        f" Start the next day now: uv run anagram demo day --dir {root}"
    )
    out.append(f"Stop: uv run anagram demo down --dir {root}")
    return out


def up(
    root: Path,
    *,
    everyone: bool,
    ready: bool,
    day_seconds: int,
    nodes: int = 1,
) -> int:
    """Start the demo in a background process and print the URLs."""
    root = root.resolve()
    f = root / DEMO_FILE
    if f.exists():
        print(f"A demo already runs in {root}. Run `anagram demo down --dir {root}` first.")
        return 1
    if made_by_old_code(root):
        print(old_folder_text(root))
        return 1
    have = folder_nodes(root)
    if have is not None and have != nodes:
        print(nodes_text(root, have))
        return 1
    root.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "anagram.sim.demo",
        "serve",
        "--dir",
        str(root),
        "--day-seconds",
        str(day_seconds),
        "--nodes",
        str(nodes),
    ]
    if everyone:
        cmd.append("--everyone")
    if ready:
        cmd.append("--ready")
    log = open(root / "demo.log", "ab")  # the child keeps it
    proc = subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True)  # noqa: S603
    end = time.monotonic() + 180
    while not f.exists():
        if proc.poll() is not None or time.monotonic() > end:
            print(f"The demo did not start. See {root / 'demo.log'}.")
            return 1
        time.sleep(0.2)
    for line in summary(json.loads(f.read_text()), root):
        print(line)
    return 0


def day(root: Path) -> int:
    """Ask the running demo to start the next matching day now."""
    f = root.resolve() / DEMO_FILE
    if not f.exists() or not hasattr(signal, "SIGUSR1"):
        print("No demo runs here.")
        return 1
    try:
        os.kill(json.loads(f.read_text())["pid"], signal.SIGUSR1)
    except ProcessLookupError:
        print("No demo runs here.")
        return 1
    print("The next demo day starts in a few seconds. The apps show it when it is done.")
    return 0


def down(root: Path) -> int:
    f = root.resolve() / DEMO_FILE
    if not f.exists():
        print("No demo runs here.")
        return 1
    pid = json.loads(f.read_text())["pid"]
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        f.unlink()
    # The demo ends its matching day first (`Demo.stop`), so wait up to 90 s.
    for _ in range(900):
        if not f.exists():
            break
        time.sleep(0.1)
    if f.exists():
        print("The demo did not stop in 90 s. Try `demo down` again.")
        return 1
    print("Demo stopped. The data stays in the folder; `demo up` again continues it.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anagram.sim.demo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--dir", required=True)
    s.add_argument("--everyone", action="store_true")
    s.add_argument("--ready", action="store_true")
    s.add_argument("--day-seconds", type=int, default=DAY_SECONDS)
    s.add_argument("--nodes", type=int, default=1, choices=range(1, MAX_NODES + 1))
    a = ap.parse_args(argv)
    return serve(Path(a.dir), a.everyone, a.ready, a.day_seconds, a.nodes)


if __name__ == "__main__":
    raise SystemExit(main())
