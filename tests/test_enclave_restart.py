"""A node keeps each app request while the writer restarts.

A restart of the writer (a new process from its sealed state) takes some
seconds. In that time the writer refuses connections, or a connection that
the node holds closes, and the standby answers `503`. The Docker end-to-end
test once lost an app request there ("relay refused"). The node now tries
the line again for up to `RESTART_WAIT` seconds, with a new node request
signature each time.

No test here depends on time: the relay's `sleep` is a hook. The hook
starts the writer again (`Stack.open_enclave`), so the writer comes back
while the node waits, at a fixed point. The `timer` of the bound test is a
counter that each sleep moves forward.
"""

from __future__ import annotations

import httpx
import pytest
from enclavestack import ENCLAVE_URLS, HOUR, Stack

from anagram.core.crypto.signing import SigningKey
from anagram.network.formats import enclave as m
from anagram.network.formats.strict import DAY
from anagram.network.matching.node.enclave_relay import (
    RESTART_WAIT,
    EnclaveRelay,
    EnclaveUnavailable,
    FailoverLink,
)

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
UPLOAD = bytes(m.SIZES[m.CLASS_UPLOAD])  # a body of the right length


def draft(offer: str, want: str) -> dict:
    return {
        "offers": [{"class": "method", "match_types": ["T1"], "scope": "both", "text": offer}],
        "wants": [{"class": "skill", "match_types": ["T1"], "scope": "both", "text": want}],
    }


class ClosesOnce:
    """The writer's client, where the first request meets a connection that
    the old process closed (`RemoteProtocolError`, as httpx gives it)."""

    def __init__(self, inner) -> None:
        self.inner, self.closed = inner, False

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        if not self.closed:
            self.closed = True
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return self.inner.request(method, url, **kwargs)


@pytest.fixture
def joined(tmp_path):
    """A stack with one person who has matching on, on the morning of a new day."""
    stack = Stack(tmp_path)
    day = stack.now() // DAY + 1
    stack.at(day * DAY + 9 * HOUR)
    c = stack.net.join(tmp_path / "people" / "alice", "fake-alice", "Alice").client
    c.enclave.connect = stack.connect
    c.enclave.set_settings("http://log.test", stack.pins.to_json())
    c.enclave.set_draft(draft(CRYO, MD))
    c.enclave.approve(c.enclave.consent()["statement_hash"])
    c.enclave.turn_on()
    stack.at((day + 1) * DAY + 8 * HOUR)  # the next day: a new upload is due
    return stack, c


@pytest.mark.parametrize("gone", ["restarting", "connection_closed"])
def test_an_app_request_waits_for_the_writer_and_is_kept(joined, gone) -> None:
    stack, alice = joined
    relay = stack.parts.relay
    waits: list[float] = []

    if gone == "restarting":
        stack.stop(0)  # the writer's URL refuses connections; the standby answers 503

        def sleep(seconds: float) -> None:
            waits.append(seconds)
            if stack.hosts[0] is None:
                stack.open_enclave(0)  # the new process, from the sealed state
    else:
        stack.clients[ENCLAVE_URLS[0]] = ClosesOnce(stack.clients[ENCLAVE_URLS[0]])

        def sleep(seconds: float) -> None:
            waits.append(seconds)

    relay.sleep = sleep
    state = alice.enclave.run()  # the upload of the day goes out through the node
    assert len(waits) == 1  # one wait, then the writer took the request
    today = stack.now() // DAY
    assert state["uploaded_day"] == today and state["open_requests"] == 1
    stack.at(stack.now() + HOUR)  # the epoch that releases the receipt
    state = alice.enclave.run()
    assert state["open_requests"] == 0
    assert {"day": today, "reason": None, "status": "accepted"} in state["receipts"]


def test_the_relay_timer_does_not_wait(joined) -> None:
    """The timer (day batches) tries again at its next tick, and the
    operator's status check reports at once: neither holds a thread."""
    stack, _ = joined
    stack.stop(0)
    stack.parts.relay.sleep = lambda s: pytest.fail("the timer waited")
    stack.tick()
    assert stack.parts.status()["enclave"] == "unreachable"
    assert stack.parts.relay.fetch_batch(stack.now() // DAY + 2) is False


def test_the_wait_has_an_end() -> None:
    """With no writer for `RESTART_WAIT` seconds, the app gets `502` (the
    relay raises `EnclaveUnavailable`) or the last `503`; each try has a new
    nonce, so a writer that saw an earlier try does not refuse it as a replay."""

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    nonces: list[str] = []

    def standby(request: httpx.Request) -> httpx.Response:
        nonces.append(request.headers["anagram-nonce"])
        return httpx.Response(503)

    now = [0.0]

    def relay_for(*clients: httpx.Client) -> EnclaveRelay:
        def sleep(seconds: float) -> None:
            now[0] += seconds

        return EnclaveRelay(
            "node-a",
            SigningKey.generate(),
            "log.test/enclave",
            FailoverLink(list(clients)),  # type: ignore[arg-type]
            lambda: 0,
            b"\x07" * 32,
            sleep=sleep,
            timer=lambda: now[0],
        )

    down = httpx.Client(transport=httpx.MockTransport(refused), base_url="http://a.test")
    with pytest.raises(EnclaveUnavailable):
        relay_for(down).forward("uploads", UPLOAD)
    assert now[0] >= RESTART_WAIT
    now[0] = 0.0
    waiting = httpx.Client(transport=httpx.MockTransport(standby), base_url="http://b.test")
    with pytest.raises(EnclaveUnavailable, match="503"):
        relay_for(down, waiting).forward("uploads", UPLOAD)
    assert now[0] >= RESTART_WAIT
    assert len(nonces) > 2 and len(set(nonces)) == len(nonces)
