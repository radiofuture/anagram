"""The enclave host process: the event loop and the host lock, durable
files, and the key file of each service."""

from __future__ import annotations

import json
import stat
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from anagram.core.files import atomic_write
from anagram.network.formats import enclave as m
from anagram.network.formats.strict import Refused
from anagram.network.matching.enclave.http import relay_router
from anagram.network.matching.enclave.state import NotReady
from anagram.network.matching.hosting.enclave import EnclaveHost, SealedFile, enclave_app
from anagram.network.matching.hosting.tools.devnet import SERVICE_KEYS, DevNet, init_devnet


class SlowLog:
    """A log that does not answer until the test lets it."""

    def __init__(self) -> None:
        self.go = threading.Event()
        self.waiting = threading.Event()

    def view(self) -> None:
        self.waiting.set()
        self.go.wait(10)


@dataclass
class FakeInstance:
    """What `EnclaveHost` uses of an instance. Its tick and its node check
    read the slow log under the host lock, as a real instance can."""

    log: SlowLog
    release: Any = None
    role: str = "writer"
    document: Any = field(default_factory=dict)
    journal: Any = None
    instance_id: str = "i" * 32
    line_id: str = "l" * 32
    platform: Any = field(default_factory=lambda: SimpleNamespace(profile="simulated"))
    # The host's log: the tick's read before the lock is quick; the slow
    # read comes under the lock.
    host: Any = field(default_factory=lambda: SimpleNamespace(log=SimpleNamespace(view=dict)))

    def tick(self) -> None:
        self.log.view()

    def check_node(self, *_: object) -> str:
        self.log.view()
        return "node"

    def take(self, *_: object) -> None:
        pass

    def sealed_record(self) -> dict:
        return {}

    def hand_off(self, document: object, *_: object, **__: object) -> dict:
        raise Refused("bad_attestation", "the fake checks nothing")

    def check_ready(self, note: object) -> None:
        raise Refused("handoff_not_successor", "the fake has no handoff")


def test_a_slow_log_does_not_block_healthz(tmp_path) -> None:
    """A tick and a relay request wait on the slow log (under the host
    lock); `/healthz` still answers at once."""
    slow = SlowLog()
    host = EnclaveHost(FakeInstance(slow), SealedFile(tmp_path))  # type: ignore[arg-type]
    # `with`: one event loop serves every request, as uvicorn does. The
    # ticker of the lifespan does not run in the test.
    with TestClient(enclave_app(host, tick_every=1_000)) as client:
        tick = threading.Thread(target=host.tick)
        post = threading.Thread(
            target=client.post,
            args=("/v1/relay/uploads",),
            kwargs={"content": b"\0" * m.SIZES[m.CLASS_UPLOAD]},
        )
        tick.start()
        assert slow.waiting.wait(5)
        post.start()
        time.sleep(0.2)  # the relay request reaches the route
        try:
            start = time.monotonic()
            r = client.get("/healthz")
            assert r.status_code == 200 and r.json()["role"] == "writer"
            assert time.monotonic() - start < 2
        finally:
            slow.go.set()
            tick.join(10)
            post.join(10)


def test_atomic_write_makes_a_private_file_and_leaves_no_temporary_file(tmp_path) -> None:
    path = tmp_path / "state.bin"
    atomic_write(path, b"one")
    atomic_write(path, b"two")
    assert path.read_bytes() == b"two"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.bin"]


def test_atomic_write_keeps_the_old_file_when_the_write_fails(tmp_path, monkeypatch) -> None:
    path = tmp_path / "state.bin"
    atomic_write(path, b"old")

    def broken(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("anagram.core.files.os.replace", broken)
    with pytest.raises(OSError, match="disk full"):
        atomic_write(path, b"new")
    assert path.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["state.bin"]


def test_the_sealed_record_is_written_only_when_it_changes(tmp_path) -> None:
    sealed = SealedFile(tmp_path)
    assert stat.S_IMODE((tmp_path / "platform.key").stat().st_mode) == 0o600
    sealed.write({"role": "writer"})
    first = sealed.path.read_bytes()
    sealed.write({"role": "writer"})
    assert sealed.path.read_bytes() == first  # a new seal would have a new nonce
    again = SealedFile(tmp_path)
    assert again.read() == {"role": "writer"}
    again.write({"role": "writer"})
    assert sealed.path.read_bytes() == first
    again.write({"role": "retired"})
    assert again.read() == {"role": "retired"}


def test_devnet_init_writes_one_key_file_for_each_service(tmp_path) -> None:
    """M10: each service file holds only the keys of its service, and a
    process with `--key FILE` reads no other key."""
    net = init_devnet(tmp_path / "devnet", "net.anagram.test", "log.anagram.test/enclave")
    for service, names in SERVICE_KEYS.items():
        path = net.keys_dir / service / "key.json"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert sorted(json.loads(path.read_text())["keys"]) == sorted(names)
    log_only = DevNet(net.dir, key_file=net.keys_dir / "log" / "key.json")
    assert log_only.key("log").public_bytes() == net.key("log").public_bytes()
    with pytest.raises(FileNotFoundError, match="roster"):
        log_only.key("roster")
    assert net.pins().roster_key == net.key("roster").public_bytes().hex()


class _Front:
    """A front end whose post raises the refusal under test."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def post(self, *_: object) -> None:
        raise self.exc


@pytest.mark.parametrize(
    ("exc", "status"),
    [(m.BadLength(), 400), (Refused("unavailable", "log"), 500), (NotReady(), 503)],
)
def test_only_a_bad_length_is_a_400(exc: Exception, status: int) -> None:
    """Review M1: the relay maps the length refusal to `400`, not every
    ValueError; a refusal of the log stays a server error."""
    app = FastAPI()
    app.include_router(relay_router(_Front(exc)))  # type: ignore[arg-type]
    http = TestClient(app, raise_server_exceptions=False)
    assert http.post("/v1/relay/uploads", content=b"x").status_code == status


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/handoff/standby", {"document": {"junk": 1}}),
        ("/v1/handoff/finish", {}),
        ("/v1/handoff/finish", {"ready": {"signer": "00"}}),
    ],
)
def test_a_handoff_route_refuses_with_409(tmp_path, path: str, body: dict) -> None:
    """The handoff routes give the refusal code and change nothing."""
    fake = FakeInstance(SlowLog(), release=SimpleNamespace(entry={}))
    host = EnclaveHost(fake, SealedFile(tmp_path))  # type: ignore[arg-type]
    client = TestClient(enclave_app(host, tick_every=1_000))  # no lifespan: no start
    r = client.post(path, json=body)
    assert r.status_code == 409 and "code" in r.json()["detail"]
