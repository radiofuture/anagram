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
set, and a draft of lines from the lab profile: the person reads the lines,
approves the consent, and turns matching on. A proposal comes the next
morning; a reveal comes when both people said yes.

By default there is one person for each lab: the PI (Chen, Okafor, Varga) and
the Helix team lead. `--everyone` starts all 11 people. `--ready` does every
step for all people except the first PI (Chen), and says yes to each
proposal for them, so that one tester can walk Chen's flow and see a reveal.

All names and IDs are invented (`fake-` prefixes on the IDs; the screens show
no ID). Nothing leaves this computer.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from anagram.network.api import typed_draft
from anagram.shell.ui.institutions import StaticInstitutions
from anagram.shell.ui.server import UIServer, bind_local
from anagram.shell.ui.service import UIService
from anagram.sim import generate_community
from anagram.sim.demonet import DAY, HOUR, DemoNetwork, start_server

DEMO_FILE = "demo.json"
LARGE_BYTES = 256 * 1024
COMMUNITY = "Anagram demo community"
DAY_SECONDS = 120
POLL = 2.0  # seconds between the checks of the day driver


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
    lab: dict
    folder: Path
    service: UIService
    email: str = ""
    institution: str = ""
    auto: bool = False  # the demo answers yes for this person (`--ready`)
    server: UIServer | None = None

    @property
    def url(self) -> str:
        return self.server.url if self.server else ""


@dataclass
class Demo:
    root: Path
    everyone: bool = False
    day_seconds: int = DAY_SECONDS
    large_bytes: int = LARGE_BYTES
    people: list[DemoPerson] = field(default_factory=list)
    node_url: str = ""

    def start(self) -> Demo:
        from anagram.network.api import Ticker
        from anagram.shell.node.home import NodeHome

        if made_by_old_code(self.root):
            raise RuntimeError(old_folder_text(self.root))
        self.root.mkdir(parents=True, exist_ok=True)
        sim_dir = self.root / "sim"
        if not (sim_dir / "ground_truth.json").exists():
            generate_community(sim_dir, seed=0, large_bytes=self.large_bytes)
        self.truth = json.loads((sim_dir / "ground_truth.json").read_text())
        # The network first: it sets the development clock of this process.
        self.network = DemoNetwork(self.root / "network")
        self.network.start_services()

        nh = NodeHome(self.root / "node")
        # A second `up` in the same folder keeps the node address: the members'
        # configs and the signed trust document name it.
        # The socket stays bound until the node server takes it (no launch race).
        sock = (
            bind_local(urllib.parse.urlsplit(nh.config()["public_url"]).port or 0)
            if nh.exists()
            else bind_local()
        )
        port = sock.getsockname()[1]
        self.node_url = f"http://127.0.0.1:{port}"
        if not nh.exists():
            nh.create(
                origin="demo.anagram/log",
                community=COMMUNITY,
                public_url=self.node_url,
                orcid_mode="fake",
            )
        nh.set_enclave(self.network.node_settings())
        app, self.identity = nh.app_parts()
        self._node = start_server(app, sock, "node")
        self.enclave = app.state.enclave
        self.network.relay = self.enclave.relay
        self.network.start_line(nh, self.node_url)
        self._relay = Ticker("enclave-relay", self.enclave.relay.tick, 2.0).start()

        # The names are invented; the screen shows only the name (no "fake"
        # text on screen). The ids keep their `fake-` prefix.
        institutions = StaticInstitutions(
            {"id": i["id"], "label": i["name"]} for i in self.truth["institutions"]
        )
        labs = {lab["id"]: lab for lab in self.truth["labs"]}
        for p in self.truth["people"]:
            if not self.everyone and p["role"] != "pi":
                continue
            lab = labs[p["lab_id"]]
            slug = Path(p["path"]).name
            # A lab leader indexes the whole lab folder; others their own folder.
            folder = sim_dir / (lab["path"] if p["role"] == "pi" else p["path"])
            home = self.root / "people" / slug
            svc = UIService(home, institutions=institutions)
            if not svc.joined() and not svc.state.load():
                invite = nh.admission(self.identity).create_invite(None, 30)["invite_url"]
                svc.join.prepare(
                    invite,
                    login_hint=p["orcid"],
                    name=p["name"],
                    sources=[{"kind": "folder", "path": str(folder)}],
                )
            inst = next(i for i in self.truth["institutions"] if i["id"] == lab["institution_id"])
            person = DemoPerson(
                slug, p["name"], p["role"], p["orcid"], lab, folder, svc, p["email"], inst["name"]
            )
            person.server = UIServer(svc).start()
            self.people.append(person)
        self.write_file()
        return self

    def start_days(self) -> None:
        """Start the day driver (a thread; `stop` ends it)."""
        self._done = threading.Event()
        self._days = threading.Thread(target=self._drive, daemon=True, name="demo-days")
        self._days.start()

    def write_file(self) -> None:
        doc = {
            "node": self.node_url,
            "people": [
                {"lab": p.lab["name"], "name": p.name, "role": p.role, "url": p.url}
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
        for p in self.people:
            if p.server:
                p.server.stop()
        if getattr(self, "_relay", None):
            self._relay.stop()
        if getattr(self, "network", None):  # the enclave reads the node: it stops first
            self.network.stop()
        if getattr(self, "_node", None):
            self._node.should_exit = True
            self._node.thread.join(15)
        if getattr(self, "enclave", None):
            self.enclave.close()
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
        joined. Every `day_seconds`: one matching day. An error waits for
        the next pass (the demo keeps running)."""
        last = time.monotonic()
        while not self._done.wait(POLL):
            try:
                for p in self.people:
                    self.set_up_matching(p)
                if time.monotonic() - last >= self.day_seconds:
                    last = time.monotonic()
                    self.next_day()
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
        draft of lines from the lab profile (not approved, not sent)."""
        svc = person.service
        if not svc.joined() or svc.state.get("demo_matching_set_up"):
            return
        st = svc.enclave.state()
        if not st["set_up"]:
            st = svc.enclave.setup(self.network.url["log"], self.network.pins.to_json())
        if not st["draft"]:
            profile = person.lab["profile"]
            svc.enclave.save_draft(
                typed_draft(
                    [x["label"] for x in profile["offers"]], [x["label"] for x in profile["needs"]]
                )
            )
        svc.state.update(demo_matching_set_up=True)

    def card(self, person: DemoPerson) -> dict:
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
            svc.join.task.thread.join(120)
            if svc.join.task.state != "joined":
                raise RuntimeError(f"demo join failed: {svc.join.task.error}")
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
) -> int:
    demo = Demo(root, everyone=everyone, day_seconds=day_seconds).start()
    if ready:
        for line in demo.ready_all():
            print(line, flush=True)
    demo.start_days()
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    print(f"Demo running. Node: {demo.node_url}", flush=True)
    done.wait()
    demo.stop()
    return 0


def up(
    root: Path,
    *,
    everyone: bool,
    ready: bool,
    day_seconds: int,
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
    doc = json.loads(f.read_text())
    print(f"Anagram demo community. Node: {doc['node']}")
    print(f"Matching: demo enclave (simulated profile); one day is {doc['day_seconds']} s.")
    for p in doc["people"]:
        print(f"  {p['name']} ({p['lab']}): {p['url']}")
    print(f"Stop: uv run anagram demo down --dir {root}")
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
    a = ap.parse_args(argv)
    return serve(Path(a.dir), a.everyone, a.ready, a.day_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
