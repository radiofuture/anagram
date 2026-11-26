"""HTTP clients of the log and of the control feed.

`HttpLog` is the enclave log as a remote party uses it:

- the read API of spec/enclave-trust.md 2.1 (`checkpoint`, `read`,
  `covering`), with each read checked against a cosigned checkpoint under
  the pinned roots (`view`);
- the write API (`append`, `append_instance_key`): only the log service
  takes entries (2.1). A refusal comes back as `Refused` with its code.

It is the `LogPort` of an enclave instance, the `IssueLog` of a node's
credential issuer, and the `LogReader` of an app. Inclusion proofs and
roots come from the checked entries, not from the log.

`HttpFeed` is the control feed of spec/network.md 8.7 (`FeedPort` of an
instance): roster events from the roster service, node events from each
node at its record URL. Events are signed, so a mirror URL is as good as
the record URL (`rewrite`, for a private network).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import merkle
from anagram.network.formats.roster import ROSTER
from anagram.network.formats.strict import Refused
from anagram.network.matching.trust.follow import LogFollower, checkpoint_size
from anagram.network.matching.trust.log_routes import MAX_ENTRIES
from anagram.network.matching.trust.logview import LogView
from anagram.network.matching.trust.roots import Roots

log = logging.getLogger(__name__)
WRITE = "/log/write"


def _refusal(r: httpx.Response) -> Refused:
    try:
        body = r.json()
    except ValueError:
        body = {}
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return Refused(str(detail.get("code", "unavailable")), str(detail.get("detail", "")))
    return Refused("unavailable", f"log answered {r.status_code}")


@dataclass
class HttpLog:
    origin: str
    roots: Roots
    http: httpx.Client  # base URL of the log service
    follower: LogFollower = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.follower = LogFollower(self, self.roots)

    def _get(self, path: str, **params: int) -> httpx.Response:
        try:
            r = self.http.get(path, params=params or None)
        except httpx.HTTPError as exc:
            raise Refused("unavailable", f"log: {exc}") from exc
        if r.status_code != 200:
            raise _refusal(r)
        return r

    # ---- read API ------------------------------------------------------------

    def checkpoint(self) -> str:
        return self._get("/log/checkpoint").text

    def covering(self, index: int) -> str:
        return self._get(f"/log/checkpoint/covering/{index}").text

    def read(self, start: int, end: int) -> list[JsonObject]:
        out: list[JsonObject] = []
        while start < end:
            stop = min(end, start + MAX_ENTRIES)
            out += self._get("/log/entries", start=start, end=stop).json()["entries"]
            start = stop
        return out

    def view(self) -> LogView:
        """The entries under the latest cosigned checkpoint, each checked."""
        note = self.checkpoint()
        with self._lock:
            return self.follower.follow(note)

    # ---- what a party computes from the checked entries -----------------------

    def _leaves(self, size: int) -> list[bytes]:
        view = self.view()
        if size > len(view.entries):
            raise Refused("unavailable", "no cosigned checkpoint of that size yet")
        return [merkle.leaf_hash(canonical_json(e)) for e in view.entries[:size]]

    def root_at(self, size: int) -> bytes:
        return merkle.root(self._leaves(size))

    def inclusion(self, index: int, size: int) -> list[str]:
        tree = merkle.list_subtree(self._leaves(size))
        return [h.hex() for h in merkle.inclusion_path(tree, index, size)]

    # ---- write API ------------------------------------------------------------

    def _post(self, path: str, body: JsonObject) -> int:
        try:
            r = self.http.post(f"{WRITE}/{path}", json=body)
        except httpx.HTTPError as exc:
            raise Refused("unavailable", f"log: {exc}") from exc
        if r.status_code != 200:
            raise _refusal(r)
        return int(r.json()["index"])

    def append(self, entry: JsonObject) -> int:
        return self._post("entries", {"entry": entry})

    def append_instance_key(self, entry: JsonObject, document: JsonObject) -> int:
        return self._post("instance-keys", {"document": document, "entry": entry})

    def wait_cosigned(self, index: int, timeout: float = 30.0, every: float = 0.5) -> str:
        """The first cosigned checkpoint that holds entry `index`."""
        end = time.monotonic() + timeout
        while True:
            note = self.checkpoint()
            if checkpoint_size(note) > index:
                return note
            if time.monotonic() > end:
                raise Refused("unavailable", "no cosigned checkpoint holds the entry")
            time.sleep(every)


@dataclass
class HttpFeed:
    """Control events (spec/network.md 8.7), fetched at most every
    `every` seconds for each chain. A failed fetch gives no new events; the
    enclave then refuses the credentials of that chain as stale."""

    roster: httpx.Client  # base URL of the roster service
    rewrite: dict[str, str] = field(default_factory=dict)  # record URL prefix -> mirror
    every: float = 5.0
    clock: Callable[[], float] = time.monotonic
    connect: Callable[[str], httpx.Client] = lambda url: httpx.Client(base_url=url, timeout=10)
    chains: dict[str, list[JsonObject]] = field(default_factory=dict)
    fetched: dict[str, float] = field(default_factory=dict)
    urls: dict[str, str] = field(default_factory=dict)  # node ID -> record URL
    _nodes: dict[str, httpx.Client] = field(default_factory=dict)

    def events(self, chain: str, after: int) -> list[JsonObject]:
        if self.clock() - self.fetched.get(chain, -self.every) >= self.every:
            self.fetched[chain] = self.clock()
            self._fetch(chain)
        return self.chains.get(chain, [])[after:]

    def _fetch(self, chain: str) -> None:
        have = self.chains.setdefault(chain, [])
        try:
            if chain == ROSTER:
                r = self.roster.get("/net/roster/events", params={"after": len(have)})
            else:
                r = self._node(chain).get("/net/control", params={"after": len(have)})
            r.raise_for_status()
            new = r.json()["events"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning(
                "control feed %s: %s", "roster" if chain == ROSTER else "node", type(exc).__name__
            )
            return
        have += new
        if chain == ROSTER:
            for e in new:
                if e.get("kind") in ("node_admitted", "node_updated"):
                    node = e["body"]["node"]
                    self.urls[node["id"]] = node["url"]

    def _node(self, node: str) -> httpx.Client:
        url = self.urls.get(node)
        if url is None:
            raise httpx.HTTPError("node not in the roster")
        for prefix, mirror in self.rewrite.items():
            if url.startswith(prefix):
                url = mirror + url[len(prefix) :]
                break
        if node not in self._nodes:
            self._nodes[node] = self.connect(url)
        return self._nodes[node]

    def close(self) -> None:
        """Close the client of the roster and the client of each node."""
        self.roster.close()
        for client in self._nodes.values():
            client.close()
        self._nodes.clear()
