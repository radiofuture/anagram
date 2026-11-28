"""The processes of a development network, in one test process.

Each service is its real FastAPI app (`log_app`, `witness_app`,
`roster_app`, `enclave_app`) behind a `TestClient`; the services talk to
each other only through these clients, as the processes of the Docker
end-to-end test do over HTTP. The timers do not run: a test moves the
clock with `Stack.at`, which runs each timer once before and once after the
next epoch. All parts share the node's test clock, and all state is under
one directory, so `Stack.restart` opens an instance from its sealed state
as a new process does.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from conftest import NODE_URL, make_net
from fastapi.testclient import TestClient

from anagram.network.matching.hosting.clients import HttpFeed, HttpLog
from anagram.network.matching.hosting.enclave import EnclaveHost, enclave_app
from anagram.network.matching.hosting.log import HttpCosigner, LogService, log_app
from anagram.network.matching.hosting.roster import RosterService, RosterStore, roster_app
from anagram.network.matching.hosting.tools.devnet import init_devnet, witness_name
from anagram.network.matching.hosting.tools.operator import Operator
from anagram.network.matching.hosting.witness import witness_app
from anagram.network.matching.trust.release import NOTICE
from anagram.network.matching.trust.translog import EntryWitness, LogStore, TransparencyLog

NETWORK = "net.anagram.test"
ORIGIN = "log.anagram.test/enclave"
LOG_URL = "http://log.test"
ROSTER_URL = "http://roster.test"
ENCLAVE_URLS = ("http://enclave-a.test", "http://enclave-b.test")
HOUR = 3_600


class Lazy:
    """The client of `url` at the time of each call: the log and the
    witnesses need each other, and a stopped process changes its client."""

    def __init__(self, clients: dict, url: str) -> None:
        self.clients, self.url = clients, url

    def close(self) -> None:
        # Stack owns the shared TestClients in self.clients; callers closing
        # their view must not close the shared client for other callers.
        pass

    def __getattr__(self, name: str):
        return getattr(self.clients[self.url], name)


def _refused(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.devnet = init_devnet(root / "devnet", NETWORK, ORIGIN)
        self.pins = self.devnet.pins()
        self.clients: dict[str, object] = {}
        self.hosts: list[EnclaveHost | None] = [None, None]
        self.net = make_net(root, enclave_parts=self._node_parts)
        self.clock = self.net.clock
        self._services()
        self._start_line()

    def now(self) -> int:
        return int(self.clock())

    # ---- connections ---------------------------------------------------------

    def connect(self, url: str, token: str | None = None):
        """A client of the service at `url`: one of this stack, or the node
        with the member session `token`."""
        if url.rstrip("/") == NODE_URL:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            return TestClient(self.net.tc.app, base_url=NODE_URL, headers=headers)
        return Lazy(self.clients, url.rstrip("/"))

    def _node_parts(self, nh, clock):
        nh.set_enclave(
            {
                "enabled": True,
                "log_url": LOG_URL,
                "pins": self.pins.to_json(),
                "record": {"admin": "admin@node.test", "affiliation": "Test Lab"},
                "urls": list(ENCLAVE_URLS),
            }
        )
        self.parts = nh.enclave(clock, connect=self.connect)
        self.node_record = nh.node_record()
        return self.parts

    # ---- services ------------------------------------------------------------

    def _dir(self, name: str) -> Path:
        d = self.root / "services" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _services(self) -> None:
        cosigners = []
        for n in (1, 2, 3):
            pin = next(w for w in self.pins.witnesses if w.name == witness_name(NETWORK, n))
            cosign, entry = self.devnet.witness_keys(n)
            d = self._dir(f"witness-{n}")
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
            url = f"http://witness-{n}.test"
            self.clients[url] = TestClient(witness_app(witness, self.http_log()), base_url=url)
            cosigners.append(HttpCosigner(pin.name, self.clients[url]))
        log = TransparencyLog(
            ORIGIN,
            self.devnet.key("log"),
            self.pins.roots,
            self.now,
            cosigners,
            LogStore(self._dir("log") / "log.sqlite"),
        )
        self.log_service = LogService(log, self.now)
        self.clients[LOG_URL] = TestClient(log_app(self.log_service), base_url=LOG_URL)
        self.roster = RosterService(
            NETWORK,
            self.devnet.key("roster"),
            RosterStore(self._dir("roster") / "roster.sqlite"),
            self.http_log(),
            self.now,
        )
        self.clients[ROSTER_URL] = TestClient(roster_app(self.roster), base_url=ROSTER_URL)

    def http_log(self) -> HttpLog:
        return HttpLog(ORIGIN, self.pins.roots, Lazy(self.clients, LOG_URL))

    def operator(self) -> Operator:
        independent = [self.clients["http://witness-2.test"], self.clients["http://witness-3.test"]]
        return Operator(self.devnet, self.http_log(), independent, self.now)

    def open_enclave(self, n: int, first_line: bool = False) -> EnclaveHost:
        """Start the process of enclave `n` (0 or 1) from its state directory."""
        feed = HttpFeed(Lazy(self.clients, ROSTER_URL), every=0, connect=self.connect)
        host = EnclaveHost.open(
            self._dir(f"enclave-{n}"),
            self.release,
            self.pins.roots,
            self.http_log(),
            feed,
            self.now,
            self.devnet.key("dev-root"),
            self._dir("snapshots"),
        )
        if n == 1:
            host.standby_of = Lazy(self.clients, ENCLAVE_URLS[0])
        url = ENCLAVE_URLS[n]
        self.clients[url] = TestClient(enclave_app(host, first_line=first_line), base_url=url)
        host.start(first_line)
        self.hosts[n] = host
        return host

    def stop(self, n: int) -> None:
        """The process of enclave `n` stops: its URL refuses connections."""
        self.hosts[n].save()
        self.hosts[n] = None
        self.clients[ENCLAVE_URLS[n]] = httpx.Client(
            transport=httpx.MockTransport(_refused), base_url=ENCLAVE_URLS[n]
        )

    def _start_line(self) -> None:
        self.roster.start()
        self.roster.admit(self.node_record)
        self.release = self.operator().release(answer_day=2, min_people=2, min_nodes=1)
        self.clock.t = self.now() + NOTICE + 2 * HOUR  # past the notice period
        self.tick()
        self.operator().authorise_line(self.release)
        self.open_enclave(0, first_line=True)
        self.open_enclave(1)
        self.tick()

    # ---- time ------------------------------------------------------------------

    def tick(self) -> None:
        self.roster.tick()
        self.log_service.tick()
        for host in self.hosts:
            if host is not None:
                host.tick()
        if any(u in self.clients for u in ENCLAVE_URLS):
            self.parts.relay.tick()

    def at(self, t: int) -> None:
        """Move the clock to `t`, with a timer run before and after the next
        epoch (10 minutes), so that the writer commits what it made."""
        self.clock.t = t
        self.tick()
        self.clock.t = t + 660
        self.tick()
