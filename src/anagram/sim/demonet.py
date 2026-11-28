"""The matching network of the demo, in the demo process (simulated profile).

Matching runs only in the matching enclave of the network. The demo runs
the services of a development network (as `deploy/compose.enclave.yaml`
does with one container each) as real HTTP servers on loopback ports, in
one process: the enclave log, its 3 witnesses, the roster, and one enclave
instance (the writer of the line; no standby). The roster admits each demo
node (1 to 3), and each node relays sealed messages to the enclave, as a
deployed node does.

SIMULATED PROFILE: development only, no privacy. Nothing leaves this
computer.

Time: the matching enclave works in UTC days. The demo sets
`ANAGRAM_DEV_CLOCK_FILE` (`anagram.core.devclock`) to `<dir>/clock`, so the
services, the node and the apps read one development clock. `at(t)` moves
it forward and runs each timer once before and once after the next epoch
(10 minutes), as `tests/enclavestack.py` does. The first start moves the
clock past the notice period of the release (14 days).

Layout of <dir>:

    devnet/         the keys of the services and devnet.json (the pins)
    clock           the offset of the development clock, in seconds
    ports.json      the loopback ports of the services (kept for a restart)
    release.json    the release of the line
    services/<name> the state of each service
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from anagram.core.devclock import ENV, OffsetClock
from anagram.network.api import (
    DevNet,
    EnclaveHost,
    EntryWitness,
    HttpCosigner,
    HttpFeed,
    HttpLog,
    LogService,
    LogStore,
    Operator,
    ReleaseFile,
    RosterService,
    RosterStore,
    TransparencyLog,
    enclave_app,
    init_devnet,
    log_app,
    node_record,
    roster_app,
    witness_app,
    witness_name,
)
from anagram.network.matching.trust.release import NOTICE
from anagram.network.matching.trust.translog import Cosigner
from anagram.shell.ui.server import bind_local

NETWORK = "net.demo.localhost"
ORIGIN = "log.demo.localhost/enclave"
# The roster record of the node needs an https URL (spec/network.md 2.3).
# The enclave reads the node's control chain at this URL, and the feed
# rewrites it to the loopback address of the demo node.
RECORD_URL = "https://node.demo.localhost"
SERVICES = ("log", "witness-1", "witness-2", "witness-3", "roster", "enclave")
DAY = 86_400
HOUR = 3_600
EPOCH_GAP = 660  # past the next epoch of the writer (10 minutes)
# Days to the first answer checkpoint of a proposal: short, so a demo
# reveal comes soon. The sweep proposes a pair only when both queues can
# deliver the copy in time (enclave-messages.md 6.5); the others wait.
DEMO_ANSWER_DAY = 2


def record_url(n: int) -> str:
    """The https URL in the roster record of demo node `n`."""
    return RECORD_URL if n == 1 else f"https://node-{n}.demo.localhost"


def start_server(app: Any, sock: Any, name: str) -> Any:
    """Run `app` on the bound socket `sock` in a thread (uvicorn), and wait
    until it serves."""
    import uvicorn

    server: Any = uvicorn.Server(
        uvicorn.Config(app, log_level="warning", timeout_graceful_shutdown=2)
    )
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True, name=f"demo-{name}"
    )
    thread.start()
    end = time.monotonic() + 30
    while not server.started:
        if time.monotonic() > end or not thread.is_alive():
            raise RuntimeError(f"the demo {name} service did not start")
        time.sleep(0.02)
    server.thread = thread
    return server


@dataclass
class DemoNetwork:
    root: Path
    servers: list[Any] = field(default_factory=list)
    clients: list[httpx.Client] = field(default_factory=list)
    host: EnclaveHost | None = None
    relays: list[Any] = field(default_factory=list)  # `NodeEnclave.relay` of each node

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.clock_file = self.root / "clock"
        # Every part of this process reads it; `stop` puts the old value back.
        self._old_env = os.environ.get(ENV)
        os.environ[ENV] = str(self.clock_file)
        self.clock = OffsetClock(self.clock_file)
        self.socks = self._bind()
        self.url = {n: f"http://127.0.0.1:{s.getsockname()[1]}" for n, s in self.socks.items()}
        devnet = self.root / "devnet"
        if (devnet / "devnet.json").exists():
            self.devnet = DevNet(devnet)
        else:
            self.devnet = init_devnet(devnet, NETWORK, ORIGIN)
        self.pins = self.devnet.pins()

    # ---- setup ------------------------------------------------------------

    def _bind(self) -> dict[str, Any]:
        """One loopback socket for each service. A restart binds the same
        ports: the node and the apps keep the URLs."""
        path = self.root / "ports.json"
        old = json.loads(path.read_text()) if path.exists() else {}
        socks = {name: bind_local(old.get(name, 0)) for name in SERVICES}
        ports = {name: s.getsockname()[1] for name, s in socks.items()}
        path.write_text(json.dumps(ports, indent=2) + "\n")
        return socks

    def node_settings(self, n: int = 1) -> dict[str, Any]:
        """node.json "enclave" of demo node `n` (1, 2, 3)."""
        tag = "" if n == 1 else f" {n}"
        admin = "organizer@demo.localhost" if n == 1 else f"organizer-{n}@demo.localhost"
        return {
            "enabled": True,
            "log_url": self.url["log"],
            "pins": self.pins.to_json(),
            "record": {"admin": admin, "affiliation": f"Anagram demo node{tag}"},
            "tick_seconds": 2.0,
            "urls": [self.url["enclave"]],
        }

    def now(self) -> int:
        return int(self.clock())

    def _dir(self, name: str) -> Path:
        d = self.root / "services" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _client(self, name: str) -> httpx.Client:
        c = httpx.Client(base_url=self.url[name], timeout=15)
        self.clients.append(c)
        return c

    def http_log(self) -> HttpLog:
        return HttpLog(ORIGIN, self.pins.roots, self._client("log"))

    def start_services(self) -> None:
        """The witnesses, the log and the roster."""
        cosigners: list[Cosigner] = []
        for n in (1, 2, 3):
            name = f"witness-{n}"
            pin = next(w for w in self.pins.witnesses if w.name == witness_name(NETWORK, n))
            cosign, entry = self.devnet.witness_keys(n)
            d = self._dir(name)
            witness = EntryWitness(
                pin.name,
                cosign,
                entry,
                pin.reads_entries,
                self.pins.roots.log_key,
                self.pins.roots,
                self.now,
                state=d / "witness.sqlite",
                store=LogStore(d / "entries.sqlite") if pin.reads_entries else None,
            )
            app = witness_app(witness, self.http_log())
            self.servers.append(start_server(app, self.socks[name], name))
            cosigners.append(HttpCosigner(pin.name, self._client(name)))
        log = TransparencyLog(
            ORIGIN,
            self.devnet.key("log"),
            self.pins.roots,
            self.now,
            cosigners,
            LogStore(self._dir("log") / "log.sqlite"),
        )
        self.log_service = LogService(log, self.now)
        self.servers.append(start_server(log_app(self.log_service), self.socks["log"], "log"))
        self.roster = RosterService(
            NETWORK,
            self.devnet.key("roster"),
            RosterStore(self._dir("roster") / "roster.sqlite"),
            self.http_log(),
            self.now,
        )
        self.servers.append(start_server(roster_app(self.roster), self.socks["roster"], "roster"))

    def start_line(self, nodes: list[tuple[Any, str]]) -> None:
        """First start: admit each node (its `NodeHome` and loopback URL), log
        a release, move past the notice period, and authorise the line. Then
        (each start) open the enclave instance from its state directory."""
        release_path = self.root / "release.json"
        first = not release_path.exists()
        if first:
            for n, (nh, _) in enumerate(nodes, start=1):
                self.roster.admit(node_record(nh.enclave_config(), nh.network_key(), record_url(n)))
            operator = Operator(
                self.devnet,
                self.http_log(),
                [self._client("witness-2"), self._client("witness-3")],
                self.now,
            )
            release = operator.release(answer_day=DEMO_ANSWER_DAY, min_people=2, min_nodes=1)
            self.move_to(self.now() + NOTICE + 2 * HOUR)
            self.tick()
            operator.authorise_line(release)
            release.write(release_path)
        release = ReleaseFile.read(release_path)
        rewrite = {record_url(n): url for n, (_, url) in enumerate(nodes, start=1)}
        feed = HttpFeed(self._client("roster"), rewrite)
        self.host = EnclaveHost.open(
            self._dir("enclave"),
            release,
            self.pins.roots,
            self.http_log(),
            feed,
            self.now,
            self.devnet.key("dev-root"),
            self._dir("snapshots"),
        )
        app = enclave_app(self.host, first_line=first)
        self.servers.append(start_server(app, self.socks["enclave"], "enclave"))
        self.tick()

    # ---- time -------------------------------------------------------------

    def move_to(self, t: int) -> None:
        """Move the development clock to `t` (forward only). A new file, then
        a rename: no part reads an empty file (offset 0) for a moment."""
        offset = max(self.clock.offset(), self.clock.offset() + t - self.now())
        tmp = self.clock_file.with_name(self.clock_file.name + ".new")
        tmp.write_text(f"{offset}\n")
        os.replace(tmp, self.clock_file)

    def tick(self) -> None:
        """Each timer once, in the order of the data: roster, log, enclave,
        node relays."""
        self.roster.tick()
        self.log_service.tick()
        if self.host is not None:  # the relays need the enclave
            self.host.tick()
            for relay in self.relays:
                relay.tick()

    def at(self, t: int) -> None:
        """Move to `t` with a timer run before and after the next epoch, so
        that the writer commits what it made."""
        self.move_to(t)
        self.tick()
        self.move_to(t + EPOCH_GAP)
        self.tick()

    def stop(self) -> None:
        for c in self.clients:
            c.close()
        for server in reversed(self.servers):
            server.should_exit = True
        for server in reversed(self.servers):
            server.thread.join(15)
        for sock in self.socks.values():
            sock.close()
        if self._old_env is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = self._old_env
